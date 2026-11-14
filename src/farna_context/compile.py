"""Context Pack compilation for Farna Context."""

import contextlib
import zipfile
from pathlib import Path

from .audit import AuditResult
from .config import LocalConfig
from .manifest import Manifest, generate_manifest


class ContextPack:
    """Compiled Context Pack."""

    def __init__(self, manifest: Manifest, repo_root: Path) -> None:
        self.manifest = manifest
        self.repo_root = repo_root

    def create(self, output_path: Path) -> None:
        """Create the context pack ZIP file.

        Args:
            output_path: Path to write the ZIP file.
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
            # Add manifest
            manifest_data = self.manifest.to_yaml()
            zf.writestr("manifest.yaml", manifest_data)

            # Add all source files
            all_files = (
                list(self.manifest.audit.instruction_files)
                + list(self.manifest.audit.explicit_files)
                + list(self.manifest.audit.skills_files)
                + list(self.manifest.audit.scoped_files)
            )

            for file_path in all_files:
                try:
                    rel_path = file_path.relative_to(self.repo_root)
                    arcname = f"sources/{rel_path}"
                    zf.write(file_path, arcname)
                except ValueError:
                    # File outside repo_root, skip
                    pass

    def get_size(self) -> int:
        """Get the size of the context pack in bytes (approximate)."""
        # This is a rough estimate; actual size would require creating the ZIP
        total = 0
        all_files = (
            list(self.manifest.audit.instruction_files)
            + list(self.manifest.audit.explicit_files)
            + list(self.manifest.audit.skills_files)
            + list(self.manifest.audit.scoped_files)
        )
        for file_path in all_files:
            with contextlib.suppress(OSError, ValueError):
                total += file_path.stat().st_size
        # Add manifest size
        total += len(self.manifest.to_yaml().encode("utf-8"))
        return total


def compile_context_pack(
    config: LocalConfig, audit: AuditResult, repo_root: Path, revision: str
) -> ContextPack:
    """Compile a context pack from audit results.

    Args:
        config: Local configuration.
        audit: Audit results.
        repo_root: Repository root path.
        revision: Git revision.

    Returns:
        ContextPack object.
    """
    manifest = generate_manifest(config, audit, repo_root, revision)
    return ContextPack(manifest, repo_root)
