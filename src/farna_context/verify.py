"""Read-only verification for Farna Context materialisations and packs."""

from __future__ import annotations

import base64
import binascii
import json
from pathlib import Path
from typing import Any

from .exceptions import InvalidManifestError
from .utils import canonical_json_bytes, reject_reparse_components, sha256_bytes, sha256_file


class VerificationResult:
    """Result of an integrity verification."""

    def __init__(self) -> None:
        self.verified = False
        self.mismatches: list[dict[str, str]] = []
        self.errors: list[str] = []


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InvalidManifestError("Unable to load verification plan") from exc  # noqa: TRY003
    if not isinstance(value, dict):
        raise InvalidManifestError("Verification plan must be a JSON object")  # noqa: TRY003
    return value


def _expected_sources(plan: dict[str, Any]) -> list[dict[str, Any]]:
    value = plan.get("included_sources")
    if not isinstance(value, list):
        considered = plan.get("considered_sources", plan.get("sources", []))
        if not isinstance(considered, list):
            considered = []
        value = [item for item in considered if isinstance(item, dict) and item.get("included")]
    if not isinstance(value, list):
        raise InvalidManifestError("Verification plan has no included_sources")  # noqa: TRY003
    sources: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            raise InvalidManifestError("Verification plan contains an invalid source")  # noqa: TRY003
        expected_hash = item.get("emitted_sha256") or item.get("raw_hash")
        if not isinstance(expected_hash, str):
            raise InvalidManifestError("Verification plan source has no hash")  # noqa: TRY003
        sources.append({"path": item["path"], "hash": expected_hash})
    return sources


def _record_mismatch(result: VerificationResult, file: str, expected: str, actual: str) -> None:
    result.mismatches.append({"file": file, "expected_hash": expected, "actual_hash": actual})


def _contained_output_path(output_path: Path, relative_path: str) -> Path:
    """Return an output path only when it stays inside a fresh, regular directory."""
    root = output_path.resolve(strict=True)
    if not root.is_dir() or output_path.is_symlink():
        raise ValueError("Unsafe materialisation output")  # noqa: TRY003
    reject_reparse_components(output_path)
    relative = Path(relative_path)
    candidate = output_path / relative
    reject_reparse_components(candidate.parent)
    try:
        candidate.parent.resolve(strict=True).relative_to(root)
    except (OSError, ValueError) as exc:
        raise ValueError("Unsafe materialisation output") from exc  # noqa: TRY003
    if candidate.exists() and candidate.is_symlink():
        raise ValueError("Unsafe materialisation output")  # noqa: TRY003
    return candidate


def _verify_materialised_directory(
    plan: dict[str, Any], output_path: Path, result: VerificationResult
) -> None:
    try:
        reject_reparse_components(output_path)
        for source in _expected_sources(plan):
            path = _contained_output_path(output_path, source["path"])
            if not path.is_file():
                result.errors.append(f"Expected output not found: {source['path']}")
                continue
            actual_hash = sha256_file(path)
            if actual_hash != source["hash"]:
                _record_mismatch(result, source["path"], source["hash"], actual_hash)
    except (OSError, ValueError) as exc:
        result.errors.append(str(exc))


def _verify_pack(plan: dict[str, Any], output_path: Path, result: VerificationResult) -> None:
    pack = _load_json(output_path)
    pack_hash = pack.get("pack_hash")
    if not isinstance(pack_hash, str):
        result.errors.append("Pack has no pack_hash")
    else:
        expected_pack_hash = sha256_bytes(
            canonical_json_bytes({k: v for k, v in pack.items() if k != "pack_hash"})
        )
        if pack_hash != expected_pack_hash:
            _record_mismatch(result, "pack_hash", expected_pack_hash, pack_hash)

    selected = pack.get("selected_sources")
    if not isinstance(selected, list):
        result.errors.append("Pack has no selected_sources")
        return
    expected = {source["path"]: source["hash"] for source in _expected_sources(plan)}
    actual_paths: set[str] = set()
    for item in selected:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            result.errors.append("Pack contains an invalid selected source")
            continue
        path = item["path"]
        actual_paths.add(path)
        declared_hash = item.get("emitted_sha256")
        expected_hash = expected.get(path)
        content = item.get("content_base64")
        if not isinstance(declared_hash, str) or expected_hash is None:
            result.errors.append(f"Unexpected output source: {path}")
            continue
        if not isinstance(content, str):
            result.errors.append(f"Pack source has no embedded content: {path}")
            continue
        try:
            embedded_bytes = base64.b64decode(content, validate=True)
        except (binascii.Error, ValueError):
            result.errors.append(f"Pack source has invalid embedded content: {path}")
            continue
        actual_hash = sha256_bytes(embedded_bytes)
        if actual_hash != declared_hash:
            _record_mismatch(result, path, declared_hash, actual_hash)
        if declared_hash != expected_hash:
            _record_mismatch(result, path, expected_hash, declared_hash)
    for path in sorted(set(expected) - actual_paths):
        result.errors.append(f"Expected output source not found in pack: {path}")


def verify_all(plan_path: Path, output_path: Path) -> VerificationResult:
    """Verify an existing materialisation plan and output without writing files."""
    result = VerificationResult()
    try:
        plan = _load_json(plan_path)
        if output_path.is_dir():
            _verify_materialised_directory(plan, output_path, result)
        elif output_path.is_file():
            _verify_pack(plan, output_path, result)
        else:
            result.errors.append(f"Output path not found: {output_path}")
    except (OSError, ValueError, InvalidManifestError) as exc:
        result.errors.append(str(exc))
    result.verified = not result.mismatches and not result.errors
    return result
