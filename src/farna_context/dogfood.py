"""Dogfood preparation for the Improve Internal Docs pipeline."""

from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
from typing import Any

from .config import SecretPatterns
from .materialise import materialise_typed_context
from .secrets import scan_bytes
from .typed_context import TypedContextPack
from .utils import (
    atomic_write_bytes,
    canonical_json_bytes,
    prepare_output_directory,
    reject_reparse_components,
)

_DEFAULT_DETECTORS = [
    "api_key",
    "aws_access_key_id",
    "aws_secret_access_key",
    "database_url",
    "github_token",
    "private_key",
    "slack_token",
]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _regular_file(path: Path, label: str) -> Path:
    resolved = path.expanduser().resolve(strict=True)
    reject_reparse_components(resolved)
    if not resolved.is_file():
        raise ValueError(f"{label} is not a regular file: {path}")  # noqa: TRY003
    return resolved


def _private_files(values: str | None) -> list[Path]:
    if not values:
        return []
    result: list[Path] = []
    for raw in values.split(os.pathsep):
        if not raw.strip():
            continue
        path = Path(raw).expanduser().resolve(strict=True)
        reject_reparse_components(path)
        if path.is_file():
            result.append(path)
        elif path.is_dir():
            result.extend(
                child
                for child in sorted(path.rglob("*"))
                if child.is_file() and ".git" not in child.parts
            )
        else:
            raise ValueError(f"Private context path is not a file or directory: {raw}")  # noqa: TRY003
    return result


def _repo_context_files(repo_root: Path) -> list[Path]:
    files = {
        path
        for name in ("AGENTS.md", "CLAUDE.md")
        for path in repo_root.rglob(name)
        if path.is_file() and ".git" not in path.parts
    }
    return sorted(files)


def _display_path(path: Path, repo_root: Path) -> str:
    try:
        return path.relative_to(repo_root).as_posix()
    except ValueError:
        return f"private/{path.name}"


def _build_pack(repo_root: Path, task_path: Path, private_paths: str | None) -> TypedContextPack:
    patterns = SecretPatterns(named_detectors=_DEFAULT_DETECTORS)
    sources = [(path, "rule") for path in _repo_context_files(repo_root)]
    sources.extend((path, "rule") for path in _private_files(private_paths))
    task = _regular_file(task_path, "Task")
    items: list[dict[str, Any]] = []
    for index, (path, context_type) in enumerate(sources):
        content = path.read_bytes()
        relative = _display_path(path, repo_root)
        if scan_bytes(content, str(path), patterns):
            raise ValueError(f"Secret detected in context source: {path}")  # noqa: TRY003
        items.append(
            {
                "item_id": f"instruction-{index:04d}",
                "context_type": context_type,
                "source_path": relative,
                "scope": {"path_glob": "**/*"},
                "authority_status": "observed",
                "evidence_status": "observed",
                "delivery_mode": None,
                "content_base64": base64.b64encode(content).decode("ascii"),
                "source_sha256": hashlib.sha256(content).hexdigest(),
            }
        )
    task_content = task.read_bytes()
    if scan_bytes(task_content, str(task), patterns):
        raise ValueError(f"Secret detected in task source: {task}")  # noqa: TRY003
    items.append(
        {
            "item_id": "task",
            "context_type": "general",
            "source_path": "task.txt",
            "authority_status": "observed",
            "evidence_status": "observed",
            "delivery_mode": None,
            "content_base64": base64.b64encode(task_content).decode("ascii"),
            "source_sha256": hashlib.sha256(task_content).hexdigest(),
        }
    )
    payload: dict[str, Any] = {
        "schema_version": "typed-context-alpha-1",
        "items": items,
        "omitted": [],
        "secret_detector_names": sorted(patterns.named_detectors),
        "secret_literal_detector_count": 0,
        "identity": {
            "repo_root": str(repo_root),
            "private_overlay_provided": bool(private_paths),
        },
    }
    pack_hash = TypedContextPack.canonical_hash(payload)
    payload["pack_hash"] = pack_hash
    return TypedContextPack(payload, pack_hash, patterns)


def prepare_dogfood(  # noqa: PLR0913
    *,
    repo_root: Path,
    task_path: Path,
    profile: str,
    pipeline: str | None,
    harness: str,
    out: Path,
    staging_parent: Path,
    private_paths: str | None = None,
) -> dict[str, Any]:
    """Prepare an inspectable dogfood pack without launching a harness."""
    if harness != "opencode":
        raise ValueError("Dogfood preparation currently supports only --harness opencode")  # noqa: TRY003
    if not profile.strip():
        raise ValueError("Profile must not be empty")  # noqa: TRY003
    root = repo_root.expanduser().resolve(strict=True)
    reject_reparse_components(root)
    if not root.is_dir():
        raise ValueError("Repository root is not a directory")  # noqa: TRY003
    output = out.expanduser().resolve()
    staging = staging_parent.expanduser().resolve()
    prepare_output_directory(output)
    reject_reparse_components(output)
    prepare_output_directory(staging)
    reject_reparse_components(staging)

    configured_private_paths = private_paths or os.environ.get("FARNA_CONTEXT_PRIVATE_PATHS")
    pack = _build_pack(root, task_path, configured_private_paths)
    pack_path = output / "pack.json"
    atomic_write_bytes(pack_path, pack.to_json())
    materialisation_path = output / "materialisation.json"
    materialisation = materialise_typed_context(
        pack,
        repo_root=root,
        staging_parent=staging,
        harness=harness,
    )
    materialisation["provenance"] = {
        "preparation": "observed",
        "harness_consumption": "unobserved",
    }
    atomic_write_bytes(materialisation_path, canonical_json_bytes(materialisation))
    operation_dir = Path(str(materialisation["output_dir"]))
    general_path = operation_dir / "general-context.md"
    general_path.write_text(str(materialisation.get("general_context", "")), encoding="utf-8")
    launch_command = (
        f"cd {root} && FARNA_CONTEXT_MATERIALISATION={operation_dir} "
        "opencode run --command improve-docs -- --mode internal --path docs "
        "--max-files 12 < /dev/null"
    )
    launch_path = output / "launch.json"
    launch = {
        "schema_version": "farna-context-dogfood-launch-1",
        "profile": profile,
        "pipeline": pipeline or profile,
        "harness": harness,
        "repo_root": str(root),
        "pack_path": str(pack_path),
        "pack_sha256": _sha256(pack_path),
        "materialisation_path": str(materialisation_path),
        "materialisation_sha256": _sha256(materialisation_path),
        "materialisation_dir": str(operation_dir),
        "general_context_path": str(general_path),
        "command": launch_command,
        "provenance": {"preparation": "observed", "harness_consumption": "unobserved"},
    }
    atomic_write_bytes(launch_path, canonical_json_bytes(launch))
    receipt_path = output / "receipt.json"
    receipt = {
        "schema_version": "farna-context-dogfood-receipt-1",
        "status": "prepared",
        "profile": profile,
        "pipeline": pipeline or profile,
        "repo_root": str(root),
        "private_overlay_provided": bool(configured_private_paths),
        "pack": {"path": str(pack_path), "sha256": _sha256(pack_path)},
        "materialisation": {
            "path": str(materialisation_path),
            "sha256": _sha256(materialisation_path),
        },
        "launch": {"path": str(launch_path), "sha256": _sha256(launch_path)},
        "provenance": {"preparation": "observed", "harness_consumption": "unobserved"},
    }
    atomic_write_bytes(receipt_path, canonical_json_bytes(receipt))
    return {**receipt, "launch_command": launch_command}
