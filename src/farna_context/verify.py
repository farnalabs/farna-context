"""Read-only verification for Farna Context materialisations and packs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .exceptions import InvalidManifestError
from .utils import canonical_json_bytes, sha256_bytes, sha256_file


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


def _verify_materialised_directory(
    plan: dict[str, Any], output_path: Path, result: VerificationResult
) -> None:
    for source in _expected_sources(plan):
        path = output_path / source["path"]
        if not path.is_file():
            result.errors.append(f"Expected output not found: {source['path']}")
            continue
        actual_hash = sha256_file(path)
        if actual_hash != source["hash"]:
            _record_mismatch(result, source["path"], source["hash"], actual_hash)


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
        actual_hash = item.get("emitted_sha256")
        expected_hash = expected.get(path)
        if not isinstance(actual_hash, str) or expected_hash is None:
            result.errors.append(f"Unexpected output source: {path}")
        elif actual_hash != expected_hash:
            _record_mismatch(result, path, expected_hash, actual_hash)
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
