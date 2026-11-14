"""Source discovery and audit for Farna Context."""

from pathlib import Path

from .config import LocalConfig


class AuditResult:
    """Result of source audit."""

    def __init__(self) -> None:
        self.instruction_files: list[Path] = []
        self.explicit_files: list[Path] = []
        self.skills_files: list[Path] = []
        self.scoped_files: list[Path] = []
        self.missing_required: list[str] = []
        self.errors: list[str] = []


def _discover_instruction_files(config: LocalConfig, repo_root: Path, result: AuditResult) -> None:
    """Discover instruction files via glob patterns."""
    scope = config.source_scope
    for pattern in scope.instruction_files:
        matches = list(repo_root.rglob(pattern))
        result.instruction_files.extend(matches)


def _discover_explicit_files(config: LocalConfig, repo_root: Path, result: AuditResult) -> None:
    """Add explicit files."""
    scope = config.source_scope
    for explicit in scope.explicit_instruction_files:
        path = repo_root / explicit
        if path.exists():
            result.explicit_files.append(path)
        else:
            result.errors.append(f"Explicit file not found: {explicit}")


def _discover_skills_files(config: LocalConfig, repo_root: Path, result: AuditResult) -> None:
    """Discover skills/rules directory."""
    scope = config.source_scope
    if scope.skills_rules_dir:
        skills_dir = repo_root / scope.skills_rules_dir
        if skills_dir.exists():
            result.skills_files.extend(skills_dir.rglob("*"))
        else:
            result.errors.append(f"Skills directory not found: {scope.skills_rules_dir}")


def _discover_scoped_files(config: LocalConfig, repo_root: Path, result: AuditResult) -> None:
    """Discover files under path scopes."""
    scope = config.source_scope
    for path_scope in scope.path_scopes:
        scope_path = repo_root / path_scope
        if scope_path.exists():
            if scope_path.is_file():
                result.scoped_files.append(scope_path)
            else:
                result.scoped_files.extend(scope_path.rglob("*"))
        else:
            result.errors.append(f"Path scope not found: {path_scope}")


def _check_required_patterns(config: LocalConfig, repo_root: Path, result: AuditResult) -> None:
    """Check required patterns."""
    scope = config.source_scope
    for required in scope.required:
        matches = list(repo_root.rglob(required))
        if not matches:
            result.missing_required.append(required)


def _deduplicate_results(result: AuditResult) -> None:
    """Deduplicate result lists."""
    result.instruction_files = sorted(set(result.instruction_files))
    result.explicit_files = sorted(set(result.explicit_files))
    result.skills_files = sorted(set(result.skills_files))
    result.scoped_files = sorted(set(result.scoped_files))


def discover_sources(config: LocalConfig, repo_root: Path) -> AuditResult:
    """Discover source files based on configuration.

    Args:
        config: Local configuration.
        repo_root: Repository root path.

    Returns:
        AuditResult with discovered files.
    """
    result = AuditResult()

    _discover_instruction_files(config, repo_root, result)
    _discover_explicit_files(config, repo_root, result)
    _discover_skills_files(config, repo_root, result)
    _discover_scoped_files(config, repo_root, result)
    _check_required_patterns(config, repo_root, result)
    _deduplicate_results(result)

    return result


def audit_sources(config: LocalConfig, repo_root: Path) -> AuditResult:
    """Perform full source audit.

    Args:
        config: Local configuration.
        repo_root: Repository root path.

    Returns:
        AuditResult with all discovered files and any errors.
    """
    return discover_sources(config, repo_root)
