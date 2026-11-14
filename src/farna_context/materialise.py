"""File emitter adapter for Farna Context."""

import shutil
from pathlib import Path

from .audit import AuditResult
from .config import LocalConfig
from .manifest import generate_manifest


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
    """Materialise source files to an output directory.

    Args:
        config: Local configuration.
        audit: Audit results.
        repo_root: Repository root path.
        output_dir: Output directory.
        mode: Materialisation mode (files, stdin, stdout, api).

    Returns:
        MaterialiseResult with written files and any errors.
    """
    _ = mode  # Unused for now, kept for API compatibility
    result = MaterialiseResult()
    output_dir.mkdir(parents=True, exist_ok=True)

    all_files = (
        list(audit.instruction_files)
        + list(audit.explicit_files)
        + list(audit.skills_files)
        + list(audit.scoped_files)
    )

    for file_path in all_files:
        try:
            rel_path = file_path.relative_to(repo_root)
            dest_path = output_dir / rel_path
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(file_path, dest_path)
            result.written_files.append(dest_path)
        except (ValueError, OSError) as e:
            result.errors.append(f"Failed to copy {file_path}: {e}")

    # Also write manifest
    try:
        manifest = generate_manifest(config, audit, repo_root, "HEAD")
        manifest_path = output_dir / config.output_files.manifest
        manifest.save(manifest_path)
        result.written_files.append(manifest_path)
    except Exception as e:
        result.errors.append(f"Failed to write manifest: {e}")

    return result


def materialise_to_stdout(
    config: LocalConfig,
    audit: AuditResult,
    repo_root: Path,
) -> str:
    """Materialise source files to stdout (concatenated).

    Args:
        config: Local configuration.
        audit: Audit results.
        repo_root: Repository root path.

    Returns:
        Concatenated file contents as string.
    """
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
