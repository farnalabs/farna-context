"""Manifest generation for Farna Context."""

from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

from .audit import AuditResult
from .config import LocalConfig


class Manifest:
    """Context Pack manifest."""

    def __init__(
        self,
        config: LocalConfig,
        audit: AuditResult,
        repo_root: Path,
        revision: str,
    ) -> None:
        self.config = config
        self.audit = audit
        self.repo_root = repo_root
        self.revision = revision

    def to_dict(self) -> dict[str, Any]:
        """Convert manifest to dictionary."""
        all_files = (
            list(self.audit.instruction_files)
            + list(self.audit.explicit_files)
            + list(self.audit.skills_files)
            + list(self.audit.scoped_files)
        )

        # Make paths relative to repo_root
        rel_files = []
        for f in all_files:
            try:
                rel = f.relative_to(self.repo_root)
                rel_files.append(str(rel))
            except ValueError:
                # File outside repo_root, skip
                pass

        return {
            "version": "1.0",
            "revision": self.revision,
            "repo_root": str(self.repo_root),
            "harness_fixture": self.config.harness_fixture,
            "source_scope": self.config.source_scope.model_dump(),
            "task_overlay": self.config.task_overlay.model_dump(),
            "files": sorted(set(rel_files)),
            "file_count": len(set(rel_files)),
            "missing_required": self.audit.missing_required,
            "errors": self.audit.errors,
        }

    def to_yaml(self) -> str:
        """Convert manifest to YAML string."""
        return yaml.dump(self.to_dict(), sort_keys=False, default_flow_style=False)  # type: ignore[no-any-return]

    def save(self, output_path: Path) -> None:
        """Save manifest to file."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w") as f:
            f.write(self.to_yaml())


def generate_manifest(
    config: LocalConfig, audit: AuditResult, repo_root: Path, revision: str
) -> Manifest:
    """Generate manifest from audit results.

    Args:
        config: Local configuration.
        audit: Audit results.
        repo_root: Repository root path.
        revision: Git revision.

    Returns:
        Manifest object.
    """
    return Manifest(config, audit, repo_root, revision)
