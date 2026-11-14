"""Canonical manifest generation from a persisted audit result."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

from .audit import AuditResult, SourceRecord
from .config import LocalConfig


class ManifestError(ValueError):
    """Raised when an audit cannot be used to generate a manifest."""


class InputChangedError(ManifestError):
    """Raised when the audit file no longer matches its recorded hash."""


class Manifest:
    """Context Pack manifest.

    ``to_dict`` is intentionally derived only from the supplied audit and
    configuration.  It does not make authority decisions; those decisions are
    represented as records already observed by the audit.
    """

    def __init__(  # noqa: PLR0913, PLR0917
        self,
        config: LocalConfig,
        audit: AuditResult,
        repo_root: Path,
        revision: str,
        audit_hash: str | None = None,
        config_hash: str | None = None,
        task_brief_hash: str | None = None,
        audit_data: dict[str, Any] | None = None,
    ) -> None:  # noqa: PLR0913, PLR0917
        self.config = config
        self.audit = audit
        self.repo_root = repo_root.resolve()
        self.revision = revision
        self.audit_hash = audit_hash or _hash_json(audit_data or _audit_to_dict(audit))
        self.config_hash = config_hash or _hash_json(config.model_dump(mode="json"))
        self.task_brief_hash = task_brief_hash or _task_brief_hash(config, self.repo_root)
        self.audit_data = audit_data or {}

    def to_dict(self) -> dict[str, Any]:
        """Convert the manifest to canonical structured data."""
        sources = _source_dicts(self.audit_data, self.audit, self.repo_root)
        included = [source for source in sources if source.get("included") is True]
        excluded = [
            {"path": source["path"], "reason": source.get("exclusion_reason") or "excluded"}
            for source in sources
            if source.get("included") is not True
            and source.get("configured", True)
            and not source.get("informational", False)
        ]
        informational = [
            source
            for source in sources
            if source.get("informational", False) or source.get("configured") is False
        ]
        blocked = _list_from_audit(self.audit_data, "blocked_sources")
        conflicts = _list_from_audit(self.audit_data, "conflicts")
        task_preview = _task_preview(self.audit_data, self.config, self.repo_root)

        return {
            "audit_hash": self.audit_hash,
            "blocked_sources": sorted(blocked),
            "config_hash": self.config_hash,
            "considered_sources": sources,
            "conflicts": conflicts,
            "excluded_sources": excluded + informational,
            "included_sources": included,
            "repo_root": self.repo_root.as_posix(),
            "revision": self.revision,
            "task_brief_hash": self.task_brief_hash,
            "task_identity": {
                "hash": self.task_brief_hash,
                "preview": task_preview,
            },
            "timestamp": _timestamp(self.audit_data),
        }

    def to_json(self) -> str:
        """Return canonical JSON with stable keys and LF line endings."""
        return json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True, indent=2) + "\n"

    def to_yaml(self) -> str:
        """Convert manifest to YAML for the legacy context-pack format."""
        return str(yaml.dump(self.to_dict(), sort_keys=False, default_flow_style=False))

    def save(self, output_path: Path) -> None:
        """Save the canonical JSON manifest."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(self.to_json(), encoding="utf-8", newline="\n")


def _hash_json(value: Any) -> str:
    """Hash a JSON value using the same canonical representation everywhere."""
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _hash_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _audit_to_dict(audit: AuditResult) -> dict[str, Any]:
    return {
        "sources": [
            {"path": str(source.path), "source_class": source.source_class}
            for source in audit.sources
        ],
        "missing_required": audit.missing_required,
        "errors": audit.errors,
    }


def _normalise_path(value: str | Path, repo_root: Path) -> str:
    path = Path(value)
    if path.is_absolute():
        try:
            return path.relative_to(repo_root).as_posix()
        except ValueError:
            return path.as_posix()
    return path.as_posix()


def _source_dicts(
    audit_data: dict[str, Any], audit: AuditResult, repo_root: Path
) -> list[dict[str, Any]]:
    raw_sources: list[dict[str, Any]] = []
    raw_value = audit_data.get("sources")
    if isinstance(raw_value, list):
        raw_sources = [item for item in raw_value if isinstance(item, dict)]
    else:
        raw_sources = [
            {
                "path": str(source.path),
                "source_class": source.source_class,
                "included": source.included,
                "configured": source.configured,
                "required": source.required,
                "readable": source.readable,
                "raw_hash": source.raw_hash,
                "exclusion_reason": source.exclusion_reason,
            }
            for source in audit.sources
        ]

    result: list[dict[str, Any]] = []
    for raw in raw_sources:
        if not isinstance(raw.get("path"), str):
            raise ManifestError
        source: dict[str, Any] = dict(raw)
        source["path"] = _normalise_path(source["path"], repo_root)
        source.pop("absolute_path", None)
        result.append(source)
    return sorted(result, key=lambda source: source["path"])


def _list_from_audit(audit_data: dict[str, Any], key: str) -> list[Any]:
    value = audit_data.get(key, [])
    if not isinstance(value, list):
        raise ManifestError
    return sorted(value, key=lambda item: json.dumps(item, sort_keys=True, default=str))


def _task_brief_hash(config: LocalConfig, repo_root: Path) -> str:
    path_value = config.task_overlay.task_brief_path or config.task_brief_path
    if not path_value:
        return hashlib.sha256(b"").hexdigest()
    path = repo_root / path_value
    return _hash_file(path) if path.is_file() else hashlib.sha256(b"").hexdigest()


def _task_preview(audit_data: dict[str, Any], config: LocalConfig, repo_root: Path) -> str:
    value = audit_data.get("task_brief_preview") or audit_data.get("task_brief")
    if not isinstance(value, str):
        path_value = config.task_overlay.task_brief_path or config.task_brief_path
        if path_value and (repo_root / path_value).is_file():
            value = (repo_root / path_value).read_text(encoding="utf-8")
        else:
            value = ""
    return value[:200]


def _timestamp(audit_data: dict[str, Any]) -> str:
    value = audit_data.get("timestamp")
    if isinstance(value, str) and value:
        return value
    return datetime.now(UTC).isoformat()


def _audit_path_hash_matches(audit_data: dict[str, Any], actual_hash: str) -> bool:
    expected = audit_data.get("audit_hash") or audit_data.get("input_hash")
    return expected is None or (isinstance(expected, str) and expected.lower() == actual_hash)


def load_audit(audit_path: Path) -> tuple[dict[str, Any], str]:
    """Load and validate an audit JSON document, returning its raw hash."""
    try:
        raw = audit_path.read_bytes()
        data = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ManifestError from exc
    if not isinstance(data, dict) or not isinstance(data.get("sources", []), list):
        raise ManifestError
    actual_hash = hashlib.sha256(raw).hexdigest()
    if not _audit_path_hash_matches(data, actual_hash):
        raise InputChangedError
    return data, actual_hash


def audit_result_from_dict(data: dict[str, Any]) -> AuditResult:
    """Convert persisted audit records to the compatibility audit object."""
    result = AuditResult()
    for raw in data.get("sources", []):
        if not isinstance(raw, dict) or not isinstance(raw.get("path"), str):
            raise ManifestError
        source = SourceRecord(
            path=Path(raw["path"]),
            source_class="instruction",
            required=bool(raw.get("required", False)),
            configured=True,
            readable=bool(raw.get("readable", False)),
            read_error=raw.get("read_error"),
            raw_hash=raw.get("raw_hash"),
            included=bool(raw.get("included", False)),
            exclusion_reason=raw.get("exclusion_reason"),
            path_scope=str(raw.get("path_scope", "/")),
            precedence=int(raw.get("precedence", 100)),
            is_conflict=bool(raw.get("is_conflict", False)),
            conflict_detail=raw.get("conflict_detail"),
        )
        result.sources.append(source)
    return result


def run_manifest(audit_path: Path, out_path: Path) -> int:
    """Load an audit, generate its manifest, and return the specified exit code."""
    try:
        audit_data, audit_hash = load_audit(audit_path)
        audit = audit_result_from_dict(audit_data)
        repo_root = Path(audit_data.get("repo_root", audit_path.parent.parent)).resolve()
        config_data = audit_data.get("config")
        config = LocalConfig(**config_data) if isinstance(config_data, dict) else LocalConfig()
        manifest = Manifest(
            config,
            audit,
            repo_root,
            str(audit_data.get("revision", "unknown")),
            audit_hash=audit_hash,
            config_hash=audit_data.get("config_hash"),
            task_brief_hash=audit_data.get("task_brief_hash"),
            audit_data=audit_data,
        )
        manifest.save(out_path)
        if audit_data.get("blocked_sources") or audit_data.get("errors"):
            return 10
        else:  # noqa: RET505
            return 0
    except InputChangedError:
        return 11
    except ManifestError:
        return 2


def generate_manifest(
    config: LocalConfig, audit: AuditResult, repo_root: Path, revision: str
) -> Manifest:
    """Generate a manifest from an in-memory audit result."""
    return Manifest(config, audit, repo_root, revision)
