"""Source discovery and audit for Farna Context."""

import hashlib
import json
import os
import stat
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel

from .config import LocalConfig

# Constants for path safety checks
MIN_DRIVE_LETTER_LEN = 2
DRIVE_LETTER_COLON_IDX = 1


class SourceRecord(BaseModel):
    """Record of a discovered source file."""

    path: str  # repository-relative POSIX path
    source_class: str  # "agents_md", "claude_md", "explicit", "skills_rules", "task_brief"
    path_scope: str  # repository-relative scope from config
    precedence: int  # from config
    required: bool  # from config
    readable: bool = False
    read_error: str | None = None
    raw_hash: str | None = None  # SHA-256 of raw bytes
    included: bool = False
    exclusion_reason: str | None = None
    is_conflict: bool = False
    conflict_detail: str | None = None


class AuditResult(BaseModel):
    """Result of source audit."""

    repo_root: str
    revision: str
    sources: list[SourceRecord]
    task_brief_hash: str
    config_hash: str
    timestamp: str


@dataclass
class SourceDiscoveryContext:
    """Context for source discovery helper functions."""

    sources: list[SourceRecord]
    precedence_map: dict[str, int]
    required_patterns: list[str]


def _is_windows_reparse_point(path: Path) -> bool:
    """Check if a path is a Windows reparse point (junction, symlink, mount point)."""
    if os.name != "nt":
        return False
    try:
        file_attrs = path.stat().st_file_attributes  # type: ignore[attr-defined]
        return bool(file_attrs & stat.FILE_ATTRIBUTE_REPARSE_POINT)
    except (AttributeError, OSError):
        return False


def check_source_safety(path: Path, repo_root: Path) -> tuple[bool, str | None]:
    """Check path for safety: no absolute/drive/UNC/NUL/../alt-stream,
    no symlink/junction/reparse traversal.

    Args:
        path: Path to check.
        repo_root: Repository root path.

    Returns:
        Tuple of (is_safe, error_reason).
    """
    error_reason: str | None = None
    is_safe = True

    # Resolve paths
    try:
        repo_root_resolved = repo_root.resolve()
        path_resolved = path.resolve()
    except (OSError, RuntimeError) as e:
        return False, f"Path resolution failed: {e}"

    # Check if path is within repo_root
    try:
        rel_path = path_resolved.relative_to(repo_root_resolved)
    except ValueError:
        return False, "Path is outside repository root"

    # Check for symlinks, junctions, reparse points in the path
    # Walk up from path to repo_root checking each component
    current = path_resolved
    while current not in (repo_root_resolved, current.parent) and is_safe:
        try:
            if current.is_symlink():
                is_safe = False
                error_reason = f"Symlink detected: {current}"
            elif _is_windows_reparse_point(current):
                is_safe = False
                error_reason = f"Reparse point detected: {current}"
        except OSError:
            pass  # Can't check, assume safe
        current = current.parent

    # Additional safety checks on the relative path string
    path_str = str(rel_path)
    has_drive_letter = (
        len(path_str) >= MIN_DRIVE_LETTER_LEN and path_str[DRIVE_LETTER_COLON_IDX] == ":"
    )
    is_alt_stream = ":" in path_str and not has_drive_letter

    if is_safe and Path(path_str).is_absolute():
        is_safe = False
        error_reason = "Absolute path not allowed"
    if is_safe and has_drive_letter:
        is_safe = False
        error_reason = "Drive letter path not allowed"
    if is_safe and (path_str.startswith("\\\\") or path_str.startswith("//")):
        is_safe = False
        error_reason = "UNC path not allowed"
    if is_safe and (path_str.upper() == "NUL" or path_str.upper().startswith("NUL.")):
        is_safe = False
        error_reason = "NUL device path not allowed"
    if is_safe and ".." in Path(path_str).parts:
        is_safe = False
        error_reason = "Parent directory traversal not allowed"
    if is_safe and is_alt_stream:
        is_safe = False
        error_reason = "Alternate data stream path not allowed"

    return is_safe, error_reason


def read_source_content(repo_root: Path, source: SourceRecord) -> tuple[bytes | None, str | None]:
    """Read source file, return (content_bytes, error_message).
    Update source.readable and read_error.

    Args:
        repo_root: Repository root path.
        source: SourceRecord to read.

    Returns:
        Tuple of (content_bytes, error_message). Content is None if error.
    """
    abs_path = repo_root / source.path

    # Safety check
    is_safe, error = check_source_safety(abs_path, repo_root)
    if not is_safe:
        source.readable = False
        source.read_error = error
        return None, error

    try:
        # Check if it's a regular file
        if not abs_path.is_file():
            source.readable = False
            source.read_error = "Not a regular file"
            return None, "Not a regular file"

        # Read raw bytes
        content = abs_path.read_bytes()

        # Compute SHA-256 hash
        sha256_hash = hashlib.sha256(content).hexdigest()
        source.raw_hash = sha256_hash
        source.readable = True
        source.read_error = None

    except FileNotFoundError:
        source.readable = False
        source.read_error = "File not found"
        return None, "File not found"
    except PermissionError:
        source.readable = False
        source.read_error = "Permission denied"
        return None, "Permission denied"
    except OSError as e:
        source.readable = False
        source.read_error = f"OS error: {e}"
        return None, f"OS error: {e}"

    return content, None


def _add_source_if_safe(
    ctx: SourceDiscoveryContext,
    rel_path: str,
    source_class: str,
    path_scope: str,
) -> None:
    """Add a source record if not already present."""
    if any(s.path == rel_path for s in ctx.sources):
        return
    ctx.sources.append(
        SourceRecord(
            path=rel_path,
            source_class=source_class,
            path_scope=path_scope,
            precedence=ctx.precedence_map.get(rel_path, 999),
            required=rel_path in ctx.required_patterns,
        )
    )


def _discover_agents_md(
    repo_root: Path,
    ctx: SourceDiscoveryContext,
) -> None:
    """Discover AGENTS.md files."""
    for agents_path in repo_root.rglob("AGENTS.md"):
        if agents_path.is_file():
            rel_path = agents_path.relative_to(repo_root).as_posix()
            is_safe, _ = check_source_safety(agents_path, repo_root)
            if is_safe:
                _add_source_if_safe(ctx, rel_path, "agents_md", "")


def _discover_claude_md(
    repo_root: Path,
    ctx: SourceDiscoveryContext,
) -> None:
    """Discover CLAUDE.md files."""
    for claude_path in repo_root.rglob("CLAUDE.md"):
        if claude_path.is_file():
            rel_path = claude_path.relative_to(repo_root).as_posix()
            is_safe, _ = check_source_safety(claude_path, repo_root)
            if is_safe:
                _add_source_if_safe(ctx, rel_path, "claude_md", "")


def _discover_explicit_files(
    repo_root: Path,
    explicit_files: list[str],
    ctx: SourceDiscoveryContext,
) -> None:
    """Discover explicit instruction files."""
    for explicit in explicit_files:
        abs_path = repo_root / explicit
        if abs_path.exists() and abs_path.is_file():
            rel_path = explicit
            is_safe, _ = check_source_safety(abs_path, repo_root)
            if is_safe:
                _add_source_if_safe(ctx, rel_path, "explicit", explicit)


def _discover_skills_rules(
    repo_root: Path,
    skills_rules_dir: str | None,
    ctx: SourceDiscoveryContext,
) -> None:
    """Discover skills/rules directory files."""
    if not skills_rules_dir:
        return

    skills_dir = repo_root / skills_rules_dir
    if not (skills_dir.exists() and skills_dir.is_dir()):
        return

    is_safe, _ = check_source_safety(skills_dir, repo_root)
    if not is_safe:
        return

    for skill_file in skills_dir.rglob("*"):
        if skill_file.is_file():
            rel_path = skill_file.relative_to(repo_root).as_posix()
            is_safe, _ = check_source_safety(skill_file, repo_root)
            if is_safe:
                _add_source_if_safe(ctx, rel_path, "skills_rules", skills_rules_dir)


def _discover_task_brief(
    repo_root: Path,
    task_brief_path: str | None,
    ctx: SourceDiscoveryContext,
) -> None:
    """Discover task brief file."""
    if not task_brief_path:
        return

    abs_path = repo_root / task_brief_path
    if abs_path.exists() and abs_path.is_file():
        rel_path = task_brief_path
        is_safe, _ = check_source_safety(abs_path, repo_root)
        if is_safe:
            _add_source_if_safe(ctx, rel_path, "task_brief", task_brief_path)


def _discover_instruction_files(
    repo_root: Path,
    instruction_files: list[str],
    ctx: SourceDiscoveryContext,
) -> None:
    """Discover instruction files from glob patterns."""
    for pattern in instruction_files:
        for match_path in repo_root.rglob(pattern):
            if match_path.is_file():
                rel_path = match_path.relative_to(repo_root).as_posix()
                is_safe, _ = check_source_safety(match_path, repo_root)
                if is_safe:
                    _add_source_if_safe(ctx, rel_path, "explicit", pattern)


def _discover_path_scopes(
    repo_root: Path,
    path_scopes: list[str],
    ctx: SourceDiscoveryContext,
) -> None:
    """Discover files from path scopes."""
    for path_scope in path_scopes:
        scope_path = repo_root / path_scope
        if not scope_path.exists():
            continue

        is_safe, _ = check_source_safety(scope_path, repo_root)
        if not is_safe:
            continue

        if scope_path.is_file():
            rel_path = scope_path.relative_to(repo_root).as_posix()
            _add_source_if_safe(ctx, rel_path, "explicit", path_scope)
        else:
            for scoped_file in scope_path.rglob("*"):
                if scoped_file.is_file():
                    rel_path = scoped_file.relative_to(repo_root).as_posix()
                    is_safe, _ = check_source_safety(scoped_file, repo_root)
                    if is_safe:
                        _add_source_if_safe(ctx, rel_path, "explicit", path_scope)


def discover_sources(config: LocalConfig, repo_root: Path) -> list[SourceRecord]:
    """Discover all configured sources, return SourceRecord list with path,
    class, scope, precedence, required.

    Args:
        config: Local configuration.
        repo_root: Repository root path.

    Returns:
        List of SourceRecord objects.
    """
    scope = config.source_scope
    precedence_map = {path: idx for idx, path in enumerate(scope.precedence)}
    required_patterns = list(scope.required)

    ctx = SourceDiscoveryContext(
        sources=[],
        precedence_map=precedence_map,
        required_patterns=required_patterns,
    )

    # 1. AGENTS.md - exact basename match
    _discover_agents_md(repo_root, ctx)

    # 2. CLAUDE.md - exact basename match
    _discover_claude_md(repo_root, ctx)

    # 3. Explicit instruction files
    _discover_explicit_files(repo_root, scope.explicit_instruction_files, ctx)

    # 4. Skills/rules directory
    _discover_skills_rules(repo_root, scope.skills_rules_dir, ctx)

    # 5. Task brief
    task_brief_path = config.task_brief_path or config.task_overlay.task_brief_path
    _discover_task_brief(repo_root, task_brief_path, ctx)

    # 6. Instruction files glob patterns
    _discover_instruction_files(repo_root, scope.instruction_files, ctx)

    # 7. Path scopes
    _discover_path_scopes(repo_root, scope.path_scopes, ctx)

    # Sort by precedence, then by path
    ctx.sources.sort(key=lambda s: (s.precedence, s.path))

    return ctx.sources


def audit_sources(config: LocalConfig, repo_root: Path, revision: str) -> AuditResult:
    """Perform full source audit.

    Args:
        config: Local configuration.
        repo_root: Repository root path.
        revision: Git revision.

    Returns:
        AuditResult with all discovered sources.
    """
    sources = discover_sources(config, repo_root)

    # Read content for each source to compute hashes
    for source in sources:
        read_source_content(repo_root, source)

    # Compute task brief hash
    task_brief_hash = ""
    task_brief_path = config.task_brief_path or config.task_overlay.task_brief_path
    if task_brief_path:
        abs_path = repo_root / task_brief_path
        if abs_path.exists() and abs_path.is_file():
            content = abs_path.read_bytes()
            task_brief_hash = hashlib.sha256(content).hexdigest()

    # Compute config hash
    config_dict = config.model_dump(mode="json")
    config_json = json.dumps(config_dict, sort_keys=True)
    config_hash = hashlib.sha256(config_json.encode()).hexdigest()

    return AuditResult(
        repo_root=str(repo_root),
        revision=revision,
        sources=sources,
        task_brief_hash=task_brief_hash,
        config_hash=config_hash,
        timestamp=datetime.now(UTC).isoformat(),
    )
