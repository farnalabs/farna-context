"""Deterministic Phase 3 Context Pack compilation."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import LocalConfig, SecretPatterns
from .exceptions import InputChangedError, InvalidManifestError, SecretDetectedError
from .secrets import scan_bytes
from .utils import canonical_json_bytes, normalise_path, sha256_bytes

COMPILER_IDENTITY = {
    "name": "farna-context-compiler",
    "version": "0.3.0",
    "contract_revision": "poc-1",
}


@dataclass(frozen=True)
class ContextPack:
    """Compiled JSON pack and its canonical identity hash."""

    payload: dict[str, Any]
    pack_hash: str

    def to_json(self) -> bytes:
        """Return canonical pack bytes."""
        return canonical_json_bytes(self.payload)

    def create(self, output_path: Path) -> None:
        """Write the pack atomically enough for this local POC."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(self.to_json())

    def get_size(self) -> int:
        """Return canonical output size."""
        return len(self.to_json())


def _load_json(path: Path) -> tuple[dict[str, Any], bytes]:
    try:
        raw = path.read_bytes()
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InvalidManifestError(f"Invalid JSON input: {path}") from exc  # noqa: TRY003
    if not isinstance(value, dict):
        raise InvalidManifestError(f"Expected JSON object: {path}")  # noqa: TRY003
    return value, raw


def _validate_manifest(manifest: dict[str, Any]) -> None:
    if not isinstance(manifest.get("sources"), list) and not isinstance(
        manifest.get("considered_sources"), list
    ):
        raise InvalidManifestError("Manifest must contain sources or considered_sources")  # noqa: TRY003
    records = manifest.get("sources", manifest.get("considered_sources"))
    assert isinstance(records, list)
    for record in records:
        if not isinstance(record, dict) or not isinstance(record.get("path"), str):
            raise InvalidManifestError("Each source record needs a path")  # noqa: TRY003
        path = record["path"]
        normalised = normalise_path(path)
        path_parts = normalised.split("/")
        if normalised.startswith(("/", "\\")) or ":" in normalised or ".." in path_parts:
            raise InvalidManifestError(f"Unsafe manifest path: {path}")  # noqa: TRY003


def _config_paths(
    config_data: dict[str, Any], _config_path: Path, repo_root: Path
) -> tuple[Path | None, SecretPatterns]:
    task_path = config_data.get("task_brief_path")
    overlay = config_data.get("task_overlay")
    if isinstance(overlay, dict) and overlay.get("task_brief_path"):
        task_path = overlay["task_brief_path"]
    task = repo_root / task_path if isinstance(task_path, str) else None
    secret_data = config_data.get("secret_patterns", {})
    if not isinstance(secret_data, dict):
        secret_data = {}
    patterns = SecretPatterns(
        literal_values=list(secret_data.get("literal_values", [])),
        named_detectors=list(secret_data.get("named_detectors", [])),
    )
    return task, patterns


def _records(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    value = manifest.get("sources", manifest.get("considered_sources", []))
    assert isinstance(value, list)
    return sorted(
        (dict(item) for item in value if isinstance(item, dict)),
        key=lambda item: normalise_path(str(item["path"])),
    )


def compile_manifest(  # noqa: PLR0912, PLR0915
    manifest_path: Path,
    output_path: Path,
    config_path: Path | None = None,
) -> ContextPack:
    """Compile a manifest and its local snapshotted inputs into a deterministic pack."""
    manifest, manifest_bytes = _load_json(manifest_path)
    _validate_manifest(manifest)
    config_path = config_path or manifest_path.parent / "config.json"
    if not config_path.is_file():
        config_path = manifest_path.parent / ".farna-context" / "config.json"
    if config_path.is_file():
        config_data, config_bytes = _load_json(config_path)
    else:
        config_data, config_bytes = {}, b"{}"
    repo_value = manifest.get("repo_root")
    if not isinstance(repo_value, str):
        raise InvalidManifestError("Manifest needs repo_root")  # noqa: TRY003
    repo_root = Path(repo_value).resolve()
    task_path, patterns = _config_paths(config_data, config_path, repo_root)
    task_bytes = task_path.read_bytes() if task_path and task_path.is_file() else b""
    source_snapshots: list[tuple[dict[str, Any], bytes]] = []
    omissions: list[dict[str, Any]] = []
    selected: list[dict[str, Any]] = []
    for record in _records(manifest):
        path = normalise_path(str(record["path"]))
        source_path = repo_root / path
        if record.get("included") is not True:
            omissions.append({"path": path, "reason": record.get("exclusion_reason", "excluded")})
            continue
        try:
            data = source_path.read_bytes()
        except OSError as exc:
            if record.get("required"):
                raise InvalidManifestError(f"Required source unreadable: {path}") from exc  # noqa: TRY003
            omissions.append({"path": path, "reason": "unreadable"})
            continue
        source_snapshots.append((record, data))

    for record, data in source_snapshots:
        path = normalise_path(str(record["path"]))
        findings = scan_bytes(data, path, patterns)
        raw_hash = sha256_bytes(data)
        if findings:
            omissions.append(
                {
                    "path": path,
                    "reason": "secret_pattern_match",
                    "detectors": sorted({f.detector for f in findings}),
                }
            )
            if record.get("required"):
                raise SecretDetectedError(  # noqa: TRY003
                    f"Secret pattern matched required source: {path}"
                )
            continue
        selected.append(
            {
                "path": path,
                "source_class": record.get("source_class", "unknown"),
                "raw_source_sha256": raw_hash,
                "emitted_sha256": sha256_bytes(data),
                "required": bool(record.get("required", False)),
                "evidence_origin": "observed",
                "content_base64": base64.b64encode(data).decode("ascii"),
            }
        )

    for record, original_data in source_snapshots:
        source_path = repo_root / normalise_path(str(record["path"]))
        current_data = source_path.read_bytes() if source_path.is_file() else None
        if current_data != original_data:
            raise InputChangedError(  # noqa: TRY003
                "INPUT_CHANGED: source bytes changed during compilation"
            )
    if task_path and (not task_path.is_file() or task_path.read_bytes() != task_bytes):
        raise InputChangedError("INPUT_CHANGED: task bytes changed during compilation")  # noqa: TRY003
    if config_path.is_file() and config_path.read_bytes() != config_bytes:
        raise InputChangedError("INPUT_CHANGED: config bytes changed during compilation")  # noqa: TRY003

    selected.sort(key=lambda item: item["path"])
    omissions.sort(key=lambda item: item["path"])
    manifest_identity = sha256_bytes(manifest_bytes)
    payload: dict[str, Any] = {
        "compiler_identity": COMPILER_IDENTITY,
        "fixture_identity": {
            "harness_fixture": config_data.get(
                "harness_fixture", manifest.get("harness_fixture", "unknown")
            )
        },
        "task_identity": {"task_brief_sha256": sha256_bytes(task_bytes)},
        "manifest_identity": {"manifest_sha256": manifest_identity},
        "config_sha256": sha256_bytes(config_bytes),
        "selected_sources": selected,
        "omitted_sources": omissions,
        "evidence_origins": {"sources": "observed", "selection": "derived", "pack_hash": "derived"},
    }
    pack_hash = sha256_bytes(canonical_json_bytes(payload))
    payload["pack_hash"] = pack_hash
    pack = ContextPack(payload, pack_hash)
    pack.create(output_path)
    return pack


def compile_context_pack(
    _config: LocalConfig, audit: Any, repo_root: Path, revision: str
) -> ContextPack:
    """Compatibility wrapper for earlier in-memory callers."""
    records: list[dict[str, Any]] = []
    for source in audit.sources:
        records.append(
            {
                "path": str(source.path.relative_to(repo_root)),
                "included": source.included,
                "required": source.required,
                "source_class": source.source_class,
                "exclusion_reason": source.exclusion_reason,
            }
        )
    payload: dict[str, Any] = {
        "revision": revision,
        "repo_root": str(repo_root),
        "sources": records,
    }
    temporary = repo_root / ".farna-context" / "manifest.json"
    temporary.write_bytes(canonical_json_bytes(payload))
    return compile_manifest(temporary, repo_root / ".farna-context" / "pack.json")
