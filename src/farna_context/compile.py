"""Deterministic Phase 3 Context Pack compilation."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .audit import generated_artifact_reason
from .config import SecretPatterns
from .exceptions import (
    InputChangedError,
    InvalidManifestError,
    RequiredSourceError,
    SecretDetectedError,
)
from .secrets import DETECTOR_REGISTRY_VERSION, scan_bytes, validate_detector_names
from .utils import (
    atomic_write_bytes,
    canonical_json_bytes,
    safe_source_path,
    sha256_bytes,
    validate_relative_path,
)

COMPILER_IDENTITY = {
    "name": "farna-context-compiler",
    "version": "0.3.1",
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
        """Write the pack atomically and never leave a partial artefact."""
        atomic_write_bytes(output_path, self.to_json())

    def get_size(self) -> int:
        """Return canonical output size."""
        return len(self.to_json())


def _load_json(path: Path) -> tuple[dict[str, Any], bytes]:
    try:
        raw = path.read_bytes()
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InvalidManifestError("Invalid JSON input") from exc  # noqa: TRY003
    if not isinstance(value, dict):
        raise InvalidManifestError("Expected JSON object")  # noqa: TRY003
    return value, raw


def _validate_manifest(manifest: dict[str, Any]) -> None:
    records = manifest.get("sources", manifest.get("considered_sources"))
    if not isinstance(records, list):
        raise InvalidManifestError("Manifest must contain sources or considered_sources")  # noqa: TRY003
    for record in records:
        if not isinstance(record, dict) or not isinstance(record.get("path"), str):
            raise InvalidManifestError("Each source record needs a path")  # noqa: TRY003
        try:
            validate_relative_path(record["path"])
        except ValueError as exc:
            raise InvalidManifestError("Unsafe manifest path") from exc  # noqa: TRY003
    repo_value = manifest.get("repo_root")
    if not isinstance(repo_value, str):
        raise InvalidManifestError("Manifest needs repo_root")  # noqa: TRY003


def _config_paths(
    config_data: dict[str, Any], repo_root: Path
) -> tuple[Path | None, SecretPatterns]:
    task_path = config_data.get("task_brief_path")
    overlay = config_data.get("task_overlay")
    if isinstance(overlay, dict) and overlay.get("task_brief_path"):
        task_path = overlay["task_brief_path"]
    task: Path | None = None
    if isinstance(task_path, str):
        try:
            candidate = Path(task_path)
            if candidate.is_absolute():
                task = candidate.resolve(strict=True)
                if task.is_symlink():
                    raise InvalidManifestError("Invalid task path")  # noqa: TRY003
            else:
                task = safe_source_path(repo_root, task_path)
            if not task.is_file():
                raise InvalidManifestError("Invalid task path")  # noqa: TRY003
        except OSError as exc:
            raise InvalidManifestError("Invalid task path") from exc  # noqa: TRY003
    secret_data = config_data.get("secret_patterns", {})
    if not isinstance(secret_data, dict):
        raise InvalidManifestError("Invalid secret detector configuration")  # noqa: TRY003
    literal_values = secret_data.get("literal_values", [])
    named_detectors = secret_data.get("named_detectors", [])
    if not isinstance(literal_values, list) or not all(
        isinstance(item, str) for item in literal_values
    ):
        raise InvalidManifestError("Invalid secret detector configuration")  # noqa: TRY003
    if not isinstance(named_detectors, list) or not all(
        isinstance(item, str) for item in named_detectors
    ):
        raise InvalidManifestError("Invalid secret detector configuration")  # noqa: TRY003
    try:
        validate_detector_names(named_detectors)
    except ValueError as exc:
        raise InvalidManifestError("Invalid secret detector configuration") from exc  # noqa: TRY003
    return task, SecretPatterns(literal_values=literal_values, named_detectors=named_detectors)


def _records(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    value = manifest.get("sources", manifest.get("considered_sources", []))
    assert isinstance(value, list)
    return sorted(
        (dict(item) for item in value if isinstance(item, dict)),
        key=lambda item: validate_relative_path(str(item["path"])),
    )


def _required_issue(record: dict[str, Any], reason: str) -> RequiredSourceError:
    path = str(record.get("path", "<unknown>"))
    return RequiredSourceError(f"Required source unavailable: {path} ({reason})")


def compile_manifest(  # noqa: PLR0912, PLR0915
    manifest_path: Path,
    output_path: Path,
    config_path: Path | None = None,
) -> ContextPack:
    """Compile a manifest and snapshotted inputs into a deterministic pack."""
    manifest, manifest_bytes = _load_json(manifest_path)
    _validate_manifest(manifest)
    if config_path is None:
        raise InvalidManifestError("Config path is required")  # noqa: TRY003
    config_data, config_bytes = _load_json(config_path)
    repo_value = manifest["repo_root"]
    assert isinstance(repo_value, str)
    repo_root = Path(repo_value).resolve(strict=True)
    task_path, patterns = _config_paths(config_data, repo_root)
    task_bytes = task_path.read_bytes() if task_path else b""
    source_snapshots: list[tuple[dict[str, Any], Path, bytes]] = []
    omissions: list[dict[str, Any]] = []
    selected: list[dict[str, Any]] = []
    for record in _records(manifest):
        path = validate_relative_path(str(record["path"]))
        generated_reason = generated_artifact_reason(Path(path))
        if generated_reason is not None:
            omissions.append({"path": path, "reason": generated_reason})
            continue
        required = bool(record.get("required", False))
        if record.get("included") is not True:
            if required:
                raise _required_issue(record, "not included")
            omissions.append({"path": path, "reason": record.get("exclusion_reason", "excluded")})
            continue
        try:
            source_path = safe_source_path(repo_root, path)
            data = source_path.read_bytes()
        except ValueError as exc:
            if required:
                raise _required_issue(record, "unsafe") from exc
            raise InvalidManifestError("Unsafe source path") from exc  # noqa: TRY003
        except OSError as exc:
            if required:
                raise _required_issue(record, "unreadable") from exc
            omissions.append({"path": path, "reason": "unreadable"})
            continue
        if record.get("is_conflict") or record.get("conflict_detail"):
            if required:
                raise _required_issue(record, "authority conflict")
            omissions.append({"path": path, "reason": "authority_conflict"})
            continue
        source_snapshots.append((record, source_path, data))

    for record, _source_path, data in source_snapshots:
        path = validate_relative_path(str(record["path"]))
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
                raise SecretDetectedError("Secret pattern matched required source")  # noqa: TRY003
            continue
        selected.append(
            {
                "path": path,
                "source_class": record.get("source_class", "unknown"),
                "raw_source_sha256": raw_hash,
                "emitted_sha256": raw_hash,
                "emission": "identical_to_raw_source",
                "required": bool(record.get("required", False)),
                "evidence_origin": "observed",
                "content_base64": base64.b64encode(data).decode("ascii"),
            }
        )

    if manifest_path.read_bytes() != manifest_bytes:
        raise InputChangedError("INPUT_CHANGED: manifest bytes changed during compilation")  # noqa: TRY003
    if config_path.read_bytes() != config_bytes:
        raise InputChangedError("INPUT_CHANGED: config bytes changed during compilation")  # noqa: TRY003
    if task_path and task_path.read_bytes() != task_bytes:
        raise InputChangedError("INPUT_CHANGED: task bytes changed during compilation")  # noqa: TRY003
    for record, source_path, original_data in source_snapshots:
        try:
            current_path = safe_source_path(repo_root, str(record["path"]))
            current_data = current_path.read_bytes()
        except (OSError, ValueError) as exc:
            raise InputChangedError(  # noqa: TRY003
                "INPUT_CHANGED: source path changed during compilation"
            ) from exc
        if current_path != source_path or current_data != original_data:
            raise InputChangedError("INPUT_CHANGED: source bytes changed during compilation")  # noqa: TRY003

    selected.sort(key=lambda item: item["path"])
    omissions.sort(key=lambda item: item["path"])
    manifest_identity = sha256_bytes(canonical_json_bytes(manifest))
    payload: dict[str, Any] = {
        "compiler_identity": COMPILER_IDENTITY,
        "fixture_identity": {
            "harness_fixture": config_data.get("harness_fixture", "unknown"),
            "secret_detector_registry": DETECTOR_REGISTRY_VERSION,
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


def compile_context_pack(*_args: Any, **_kwargs: Any) -> ContextPack:
    """Removed compatibility wrapper; compilation requires explicit paths."""
    raise InvalidManifestError("Explicit --manifest and --out paths are required")  # noqa: TRY003
