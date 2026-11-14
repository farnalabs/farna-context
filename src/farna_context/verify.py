"""Hash verification for Farna Context."""

import hashlib
import zipfile
from pathlib import Path
from typing import Any

from .audit import AuditResult
from .compile import compile_context_pack
from .config import LocalConfig
from .manifest import Manifest, generate_manifest


class VerificationResult:
    """Result of hash verification."""

    def __init__(self) -> None:
        self.verified: bool = False
        self.mismatches: list[dict[str, Any]] = []
        self.errors: list[str] = []


def compute_hash(file_path: Path, algorithm: str = "sha256") -> str:
    """Compute hash of a file.

    Args:
        file_path: Path to file.
        algorithm: Hash algorithm (sha256, sha512, md5).

    Returns:
        Hex digest of the hash.
    """
    hasher = hashlib.new(algorithm)
    with file_path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def verify_manifest(manifest: Manifest, manifest_path: Path) -> VerificationResult:
    """Verify manifest file matches expected content.

    Args:
        manifest: Expected manifest.
        manifest_path: Path to actual manifest file.

    Returns:
        VerificationResult.
    """
    result = VerificationResult()

    try:
        expected_yaml = manifest.to_yaml()
        actual_yaml = manifest_path.read_text()

        if expected_yaml == actual_yaml:
            result.verified = True
        else:
            result.mismatches.append(
                {
                    "file": str(manifest_path),
                    "expected_hash": hashlib.sha256(expected_yaml.encode()).hexdigest(),
                    "actual_hash": hashlib.sha256(actual_yaml.encode()).hexdigest(),
                }
            )
    except Exception as e:
        result.errors.append(f"Failed to verify manifest: {e}")

    return result


def verify_context_pack(pack_path: Path, manifest: Manifest) -> VerificationResult:
    """Verify context pack contents match manifest.

    Args:
        pack_path: Path to context pack ZIP.
        manifest: Expected manifest.

    Returns:
        VerificationResult.
    """
    result = VerificationResult()

    try:
        with zipfile.ZipFile(pack_path, "r") as zf:
            # Verify manifest in pack
            try:
                pack_manifest = zf.read("manifest.yaml").decode("utf-8")
                expected_manifest = manifest.to_yaml()
                if pack_manifest != expected_manifest:
                    result.mismatches.append(
                        {
                            "file": "manifest.yaml",
                            "expected_hash": hashlib.sha256(expected_manifest.encode()).hexdigest(),
                            "actual_hash": hashlib.sha256(pack_manifest.encode()).hexdigest(),
                        }
                    )
            except KeyError:
                result.errors.append("manifest.yaml not found in context pack")

            # Verify all source files listed in manifest
            manifest_data = manifest.to_dict()
            for rel_file in manifest_data.get("files", []):
                arcname = f"sources/{rel_file}"
                try:
                    pack_content = zf.read(arcname)
                    source_path = Path(manifest.repo_root) / rel_file
                    if source_path.exists():
                        source_content = source_path.read_bytes()
                        if pack_content != source_content:
                            result.mismatches.append(
                                {
                                    "file": rel_file,
                                    "expected_hash": hashlib.sha256(source_content).hexdigest(),
                                    "actual_hash": hashlib.sha256(pack_content).hexdigest(),
                                }
                            )
                    else:
                        result.errors.append(f"Source file not found: {rel_file}")
                except KeyError:
                    result.errors.append(f"File not found in pack: {rel_file}")

        result.verified = len(result.mismatches) == 0 and len(result.errors) == 0

    except Exception as e:
        result.errors.append(f"Failed to verify context pack: {e}")

    return result


def verify_all(
    config: LocalConfig, audit_result: AuditResult, repo_root: Path, revision: str
) -> VerificationResult:
    """Run all verifications.

    Args:
        config: Local configuration.
        audit_result: Audit results.
        repo_root: Repository root path.
        revision: Git revision.

    Returns:
        Combined VerificationResult.
    """
    manifest = generate_manifest(config, audit_result, repo_root, revision)
    compile_context_pack(config, audit_result, repo_root, revision)

    # Verify manifest file
    manifest_path = Path(config.output_files.manifest)
    result = verify_manifest(manifest, manifest_path)

    # Verify context pack
    pack_path = Path(config.output_files.context_pack)
    if pack_path.exists():
        pack_result = verify_context_pack(pack_path, manifest)
        result.mismatches.extend(pack_result.mismatches)
        result.errors.extend(pack_result.errors)

    result.verified = len(result.mismatches) == 0 and len(result.errors) == 0
    return result
