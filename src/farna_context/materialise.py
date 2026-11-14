"""File emitter adapter for Farna Context."""

from __future__ import annotations

import base64
import shutil
import tempfile
from pathlib import Path
from typing import Any

from .audit import AuditResult
from .compile import _load_json as load_pack_json
from .config import LocalConfig
from .manifest import generate_manifest
from .utils import (
    atomic_write_bytes,
    canonical_json_bytes,
    prepare_output_directory,
    reject_reparse_components,
    safe_source_path,
    sha256_bytes,
    validate_relative_path,
)


class MaterialiseResult:
    """Result of materialisation."""

    def __init__(self) -> None:
        self.written_files: list[Path] = []
        self.errors: list[str] = []


def materialise_files(
    config: LocalConfig,
    audit: AuditResult,
    repo_root: Path,
    output_dir: Path,
    mode: str = "files",
) -> MaterialiseResult:
    """Materialise source files to an output directory."""
    _ = mode
    result = MaterialiseResult()
    prepare_output_directory(output_dir)

    all_files = [source.path for source in audit.sources if source.included]
    if not audit.sources:
        all_files = (
            list(audit.instruction_files)
            + list(audit.explicit_files)
            + list(audit.skills_files)
            + list(audit.scoped_files)
        )

    for file_path in all_files:
        try:
            rel_path = file_path.relative_to(repo_root)
            relative = validate_relative_path(rel_path)
            source_path = safe_source_path(repo_root, relative)
            dest_path = output_dir / relative
            prepare_output_directory(dest_path.parent)
            atomic_write_bytes(dest_path, source_path.read_bytes())
            result.written_files.append(dest_path)
        except (ValueError, OSError) as e:
            result.errors.append(f"Failed to copy {file_path}: {e}")

    try:
        manifest = generate_manifest(config, audit, repo_root, "HEAD")
        manifest_path = output_dir / validate_relative_path(config.output_files.manifest)
        prepare_output_directory(manifest_path.parent)
        atomic_write_bytes(manifest_path, manifest.to_json().encode("utf-8"))
        result.written_files.append(manifest_path)
    except Exception as e:
        result.errors.append(f"Failed to write manifest: {e}")

    return result


def _load_pack(pack_path: Path) -> dict[str, Any]:
    """Load and validate a compiled pack before creating any output."""
    pack, _ = load_pack_json(pack_path)
    selected = pack.get("selected_sources")
    pack_hash = pack.get("pack_hash")
    if not isinstance(selected, list) or not isinstance(pack_hash, str):
        raise ValueError("Invalid context pack")  # noqa: TRY003, TRY004
    expected_hash = sha256_bytes(
        canonical_json_bytes({k: v for k, v in pack.items() if k != "pack_hash"})
    )
    if pack_hash != expected_hash:
        raise ValueError("Context pack hash mismatch")  # noqa: TRY003
    for item in selected:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            raise ValueError("Context pack contains an invalid output path")  # noqa: TRY003, TRY004
        validate_relative_path(item["path"])
        if not isinstance(item.get("content_base64"), str) or not isinstance(
            item.get("emitted_sha256"), str
        ):
            raise ValueError("Context pack contains an invalid output")  # noqa: TRY003, TRY004
        try:
            content = base64.b64decode(item["content_base64"], validate=True)
        except ValueError as exc:
            raise ValueError("Context pack contains invalid output content") from exc  # noqa: TRY003
        if sha256_bytes(content) != item["emitted_sha256"]:
            raise ValueError("Context pack output hash mismatch")  # noqa: TRY003
    return pack


def materialise_pack(pack_path: Path, parent: Path, plan_path: Path) -> dict[str, Any]:
    """Materialise a pack into a fresh operation directory and write its plan."""
    pack_path = pack_path.resolve(strict=True)
    if not pack_path.is_file() or pack_path.is_symlink():
        raise ValueError("Unsafe pack path")  # noqa: TRY003
    reject_reparse_components(pack_path)
    if parent.exists():
        reject_reparse_components(parent)
    prepare_output_directory(parent)
    pack = _load_pack(pack_path)
    operation_dir = Path(tempfile.mkdtemp(prefix="materialisation-", dir=parent))
    try:
        reject_reparse_components(operation_dir)
        outputs: list[dict[str, str]] = []
        for item in pack["selected_sources"]:
            relative = validate_relative_path(item["path"])
            content = base64.b64decode(item["content_base64"], validate=True)
            destination = operation_dir / relative
            prepare_output_directory(destination.parent)
            atomic_write_bytes(destination, content)
            outputs.append({"path": relative, "sha256": item["emitted_sha256"]})
        plan = {
            "schema_version": "1.0",
            "pack_path": str(pack_path),
            "pack_hash": pack["pack_hash"],
            "output_dir": str(operation_dir),
            "outputs": outputs,
        }
        prepare_output_directory(plan_path.parent)
        atomic_write_bytes(plan_path, canonical_json_bytes(plan))
    except Exception:
        shutil.rmtree(operation_dir, ignore_errors=True)
        raise
    return plan


def materialise_to_stdout(config: LocalConfig, audit: AuditResult, repo_root: Path) -> str:
    """Materialise source files to stdout (concatenated)."""
    manifest = generate_manifest(config, audit, repo_root, "HEAD")
    output = [manifest.to_yaml(), "---"]
    all_files = (
        list(audit.instruction_files)
        + list(audit.explicit_files)
        + list(audit.skills_files)
        + list(audit.scoped_files)
    )
    for file_path in sorted(set(all_files)):
        try:
            rel_path = file_path.relative_to(repo_root)
            output.append(f"\n# File: {rel_path}\n")
            with file_path.open() as f:
                output.append(f.read())
        except (ValueError, OSError) as e:
            output.append(f"\n# Error reading {file_path}: {e}\n")
    return "\n".join(output)
