"""File emitter adapter for Farna Context."""

from __future__ import annotations

import base64
import binascii
import shutil
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .audit import AuditResult
from .compile import _load_json as load_pack_json
from .config import LocalConfig, SecretPatterns
from .context_types import (
    MAX_GENERAL_SIZE_BYTES,
    ResolvedDelivery,
    ShadowFilePolicy,
    decide_shadow_file_cleanup,
    shadow_file_preflight,
)
from .manifest import generate_manifest
from .secrets import scan_bytes
from .typed_context import DeliveryMode, TypedContextPack
from .utils import (
    atomic_write_bytes,
    canonical_json_bytes,
    prepare_output_directory,
    reject_reparse_components,
    safe_source_path,
    sha256_bytes,
    validate_relative_path,
)


def _raise_collision() -> None:
    raise ValueError("Artefact destination collision")  # noqa: TRY003


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


def _decode_content(item: dict[str, Any]) -> bytes:
    encoded = item.get("content_base64")
    if not isinstance(encoded, str):
        raise TypeError("Context pack contains invalid output content")  # noqa: TRY003
    try:
        return base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("Context pack contains invalid output content") from exc  # noqa: TRY003


def _load_pack(
    pack_path: Path,
    *,
    secret_patterns: SecretPatterns | None = None,
) -> dict[str, Any]:
    """Load, hash-check, decode, and rescan a compiled pack before output."""
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
    patterns = secret_patterns or SecretPatterns()
    seen_paths: set[str] = set()
    for item in selected:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            raise ValueError("Context pack contains an invalid output path")  # noqa: TRY003, TRY004
        relative = validate_relative_path(item["path"])
        if relative in seen_paths:
            raise ValueError("Context pack contains duplicate output paths")  # noqa: TRY003
        seen_paths.add(relative)
        emitted_hash = item.get("emitted_sha256")
        if not isinstance(emitted_hash, str):
            raise TypeError("Context pack contains an invalid output")  # noqa: TRY003
        content = _decode_content(item)
        if sha256_bytes(content) != emitted_hash:
            raise ValueError("Context pack output hash mismatch")  # noqa: TRY003
        if scan_bytes(content, relative, patterns):
            raise ValueError("Context pack contains secret-bearing output")  # noqa: TRY003
        if item.get("context_type") == "general" and len(content) > MAX_GENERAL_SIZE_BYTES:
            raise ValueError("General context exceeds size limit")  # noqa: TRY003
        item["path"] = relative
        item["_decoded_content"] = content
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


def _raise_invalid_shadow_policy() -> None:
    raise TypeError("Shadow file item has invalid policy")  # noqa: TRY003


def _raise_shadow_concurrent_change(destination: str) -> None:
    raise ValueError(f"Shadow destination changed during materialisation: {destination}")  # noqa: TRY003


def _shadow_plan(
    item: dict[str, Any],
    content: bytes,
    repo_root: Path,
    ignore_checker: Callable[[Path, str], bool] | None,
) -> tuple[dict[str, Any], Path, bytes, str | None, bytes | None] | dict[str, Any]:
    """Validate one shadow item and capture its pre-write state."""
    item_id = str(item["item_id"])
    source = str(item["source_path"])
    shadow_policy = item.get("shadow_policy")
    if not isinstance(shadow_policy, dict):
        _raise_invalid_shadow_policy()
    policy = ShadowFilePolicy.model_validate(shadow_policy)
    shadow_destination = policy.destination
    decision = shadow_file_preflight(repo_root, shadow_destination, ignore_checker=ignore_checker)
    if not decision.safe:
        return {
            "item_id": item_id,
            "status": "blocked",
            "reason": decision.reason,
            "source_path": source,
        }

    destination_path = (
        repo_root.resolve(strict=True) / validate_relative_path(shadow_destination)
    ).resolve()
    try:
        destination_path.relative_to(repo_root.resolve(strict=True))
    except ValueError as exc:
        raise ValueError("Shadow destination escapes repo root") from exc  # noqa: TRY003
    previous = destination_path.read_bytes() if destination_path.exists() else None
    previous_hash = sha256_bytes(previous) if previous is not None else None
    if previous is not None and not policy.overwrite:
        return {
            "item_id": item_id,
            "status": "blocked",
            "reason": "destination_exists_overwrite_disabled",
            "source_path": source,
        }
    reject_reparse_components(destination_path.parent)
    outcome: dict[str, Any] = {
        "item_id": item_id,
        "status": "materialised",
        "destination": shadow_destination,
        "sha256": sha256_bytes(content),
        "generated": previous is None,
    }
    if previous_hash is not None:
        outcome["previous_sha256"] = previous_hash
    return outcome, destination_path, content, previous_hash, previous


def _rollback_shadows(
    applied: list[tuple[Path, str, bytes | None, str | None]],
) -> list[str]:
    """Restore only files still carrying this operation's bytes."""
    errors: list[str] = []
    for path, new_hash, previous, previous_hash in reversed(applied):
        try:
            if not path.exists() or sha256_bytes(path.read_bytes()) != new_hash:
                errors.append(f"rollback refused for {path}: file changed concurrently")
                continue
            if previous is None:
                path.unlink()
            else:
                atomic_write_bytes(path, previous)
                if previous_hash is None or sha256_bytes(path.read_bytes()) != previous_hash:
                    errors.append(f"rollback verification failed for {path}")
        except OSError as exc:
            errors.append(f"rollback failed for {path}: {exc}")
    return errors


def materialise_typed_context(  # noqa: PLR0912, PLR0913, PLR0915
    pack: dict[str, Any] | TypedContextPack,
    *,
    repo_root: Path,
    staging_parent: Path,
    harness: str = "opencode",
    ignore_checker: Callable[[Path, str], bool] | None = None,
    secret_patterns: SecretPatterns | None = None,
) -> dict[str, Any]:
    """Materialise typed items and record a decision for every item."""
    compiled_patterns: SecretPatterns | None = None
    if isinstance(pack, TypedContextPack):
        compiled_patterns = pack.secret_patterns
        pack = pack.payload
    pack_hash = pack.get("pack_hash")
    if not isinstance(pack_hash, str):
        raise TypeError("Invalid typed context pack")  # noqa: TRY003, TRY004
    TypedContextPack(pack, pack_hash).validate_integrity()
    patterns = (
        secret_patterns
        or compiled_patterns
        or SecretPatterns(named_detectors=list(pack.get("secret_detector_names", [])))
    )
    literal_count = pack.get("secret_literal_detector_count", 0)
    if not isinstance(literal_count, int) or literal_count < 0:
        raise ValueError("Invalid typed context secret policy")  # noqa: TRY003
    if literal_count and not patterns.literal_values:
        raise ValueError("Typed context literal secret policy is unavailable")  # noqa: TRY003
    if len(patterns.literal_values) != literal_count:
        raise ValueError("Typed context literal secret policy mismatch")  # noqa: TRY003
    decoded_items: list[tuple[dict[str, Any], bytes]] = []
    for raw_item in pack.get("items", []):
        if not isinstance(raw_item, dict):
            raise TypeError("Invalid typed context item")  # noqa: TRY003, TRY004, TRY301
        content = _decode_content(raw_item)
        source = str(raw_item.get("source_path", ""))
        declared_hash = raw_item.get("source_sha256")
        if not isinstance(declared_hash, str) or sha256_bytes(content) != declared_hash:
            raise ValueError("Typed context pack output hash mismatch")  # noqa: TRY003
        if scan_bytes(content, source, patterns):
            raise ValueError("Typed context pack contains secret-bearing output")  # noqa: TRY003
        if raw_item.get("context_type") == "general" and len(content) > MAX_GENERAL_SIZE_BYTES:
            raise ValueError("General context exceeds size limit")  # noqa: TRY003
        decoded_items.append((raw_item, content))
    prepare_output_directory(staging_parent)
    operation_dir = Path(tempfile.mkdtemp(prefix="typed-context-", dir=staging_parent))
    outcomes: list[dict[str, Any]] = []
    general: list[str] = []
    applied_shadows: list[tuple[Path, str, bytes | None, str | None]] = []
    try:
        used_destinations: set[str] = set()
        shadow_plans: dict[str, tuple[dict[str, Any], Path, bytes, str | None, bytes | None]] = {}
        blocked_shadows: list[dict[str, Any]] = []
        for item, content in decoded_items:
            if item.get("context_type") != "shadow_file":
                continue
            planned = _shadow_plan(item, content, repo_root, ignore_checker)
            if isinstance(planned, dict):
                blocked_shadows.append(planned)
                continue
            outcome, destination, shadow_bytes, previous_hash, previous = planned
            staged = operation_dir / "shadow-stage" / validate_relative_path(outcome["destination"])
            prepare_output_directory(staged.parent)
            atomic_write_bytes(staged, shadow_bytes)
            shadow_plans[str(item["item_id"])] = (
                outcome,
                destination,
                shadow_bytes,
                previous_hash,
                previous,
            )
        if blocked_shadows:
            outcomes.extend(blocked_shadows)
            return {
                "schema_version": "typed-materialisation-alpha-1",
                "pack_hash": pack_hash,
                "output_dir": str(operation_dir),
                "general_context": "",
                "outcomes": outcomes,
            }
        for item, content in decoded_items:
            item_id = str(item["item_id"])
            item_type = str(item["context_type"])
            source = str(item["source_path"])
            mode = item.get("delivery_mode")
            status = "materialised"
            reason: str | None = None
            if item_type == "rule":
                status = "adapter_required" if harness == "opencode" else "materialised"
                reason = (
                    "harness lacks native scoped-rule capability"
                    if status == "adapter_required"
                    else "scoped rule retained"
                )
            elif item_type == "general":
                try:
                    general.append(content.decode("utf-8"))
                except UnicodeDecodeError as exc:
                    raise ValueError("General context is not valid UTF-8") from exc  # noqa: TRY003
            elif item_type == "artefact":
                if mode == DeliveryMode.REFERENCE_ONLY.value:
                    reason = "reference recorded; content not copied"
                elif mode == DeliveryMode.MOUNT_IF_SUPPORTED.value:
                    status, reason = (
                        "adapter_required",
                        "requested mount delivery requires an adapter",
                    )
                elif mode == DeliveryMode.COPY_TO_STAGING.value:
                    destination_name = source
                    if destination_name in used_destinations:
                        _raise_collision()
                    used_destinations.add(destination_name)
                    destination = operation_dir / validate_relative_path(destination_name)
                    prepare_output_directory(destination.parent)
                    atomic_write_bytes(destination, content)
                    reason = "copied to staging"
                else:
                    status, reason = (
                        "adapter_required",
                        "requested artefact delivery is unsupported",
                    )
            elif item_type == "shadow_file":
                outcome, destination, shadow_bytes, previous_hash, previous = shadow_plans[item_id]
                if destination.exists():
                    current_hash = sha256_bytes(destination.read_bytes())
                    if current_hash != previous_hash:
                        _raise_shadow_concurrent_change(str(outcome["destination"]))
                prepare_output_directory(destination.parent)
                atomic_write_bytes(destination, shadow_bytes)
                applied_shadows.append((destination, outcome["sha256"], previous, previous_hash))
                outcomes.append(outcome)
                continue
            outcomes.append(
                {"item_id": item_id, "status": status, "reason": reason, "source_path": source}
            )
        return {
            "schema_version": "typed-materialisation-alpha-1",
            "pack_hash": pack_hash,
            "output_dir": str(operation_dir),
            "general_context": "\n\n".join(general),
            "outcomes": outcomes,
        }
    except Exception as exc:
        rollback_errors = _rollback_shadows(applied_shadows)
        shutil.rmtree(operation_dir, ignore_errors=True)
        if rollback_errors:
            raise RuntimeError(
                "Typed context materialisation failed; rollback incomplete: "
                + "; ".join(rollback_errors)
            ) from exc
        raise


def cleanup_typed_shadow(repo_root: Path, delivery: ResolvedDelivery) -> dict[str, Any]:
    """Apply hash-aware cleanup only when the generated file is unchanged."""
    decision = decide_shadow_file_cleanup(repo_root, delivery)
    if decision.should_delete:
        (repo_root / delivery.destination).unlink()
    return decision.model_dump(mode="json")


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
