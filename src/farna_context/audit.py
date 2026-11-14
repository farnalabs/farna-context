"""Source discovery and audit for Farna Context."""

import hashlib
import json
import stat
import sys
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from .authority import SourceRecord as AuthoritySourceRecord
from .authority import resolve_authority
from .config import LocalConfig, load_config
from .git import check_dirty_tree, get_revision
from .utils import reject_reparse_components

# Type alias for source classification
SourceClass = Literal["instruction", "explicit", "skills", "scoped"]

_SOURCE_CLASS_NAMES = {
    "instruction": "agents_md",
    "explicit": "explicit",
    "skills": "skills_rules",
    "scoped": "scoped",
}

_GENERATED_DIRECTORY_NAMES = frozenset(
    {
        "__pycache__",
        ".eggs",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "build",
        "dist",
        "downloads",
        "develop-eggs",
        "eggs",
        "htmlcov",
        "parts",
        "sdist",
        "var",
        "wheels",
    }
)
_GENERATED_FILE_NAMES = frozenset({".Python", ".coverage", ".installed.cfg"})
_GENERATED_FILE_SUFFIXES = (".egg", ".egg-info", ".pyc", ".pyo")
_GENERATED_ARTIFACT_REASON = "Generated artifact excluded (bytecode, cache, or packaging output)"


def generated_artifact_reason(path: Path) -> str | None:
    """Return a stable exclusion reason for generated repository artifacts."""
    if any(component in _GENERATED_DIRECTORY_NAMES for component in path.parts):
        return _GENERATED_ARTIFACT_REASON
    if path.name in _GENERATED_FILE_NAMES or path.name.endswith(_GENERATED_FILE_SUFFIXES):
        return _GENERATED_ARTIFACT_REASON
    return None


@dataclass
class SourceRecord:
    """Record for a single discovered source file."""

    path: Path
    source_class: SourceClass
    required: bool = False
    configured: bool = True
    readable: bool | None = None
    read_error: str | None = None
    raw_hash: str | None = None
    included: bool = False
    exclusion_reason: str | None = None
    path_scope: str = "/"
    precedence: int = 100
    is_conflict: bool = False
    conflict_detail: str | None = None


@dataclass
class AuditResult:
    """Result of source audit."""

    # Source records
    sources: list[SourceRecord] = field(default_factory=list)

    # Counts
    total_discovered: int = 0
    total_readable: int = 0
    total_included: int = 0
    total_excluded: int = 0
    total_conflicts: int = 0
    total_informational: int = 0

    # Per-class breakdown
    by_class: dict[SourceClass, dict[str, int]] = field(default_factory=dict)

    # Legacy fields for backward compatibility
    instruction_files: list[Path] = field(default_factory=list)
    explicit_files: list[Path] = field(default_factory=list)
    skills_files: list[Path] = field(default_factory=list)
    scoped_files: list[Path] = field(default_factory=list)
    missing_required: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Initialize per-class breakdown."""
        for cls in ("instruction", "explicit", "skills", "scoped"):
            self.by_class[cls] = {
                "discovered": 0,
                "readable": 0,
                "included": 0,
                "excluded": 0,
                "informational": 0,
            }


def _discover_instruction_files(
    config: LocalConfig, repo_root: Path, sources: list[SourceRecord]
) -> None:
    """Discover instruction files via glob patterns."""
    scope = config.source_scope
    for pattern in scope.instruction_files:
        matches = list(repo_root.rglob(pattern))
        for match in matches:
            if match.is_file():
                sources.append(
                    SourceRecord(
                        path=match,
                        source_class="instruction",
                        required=False,
                        configured=True,
                    )
                )


def _discover_explicit_files(
    config: LocalConfig, repo_root: Path, sources: list[SourceRecord]
) -> None:
    """Add explicit files."""
    scope = config.source_scope
    for explicit in scope.explicit_instruction_files:
        path = repo_root / explicit
        sources.append(
            SourceRecord(
                path=path,
                source_class="explicit",
                required=False,
                configured=True,
            )
        )


def _append_discovered_file(
    path: Path,
    source_class: SourceClass,
    sources: list[SourceRecord],
) -> None:
    """Record a discovered file, retaining generated artifacts as exclusions."""
    reason = generated_artifact_reason(path)
    sources.append(
        SourceRecord(
            path=path,
            source_class=source_class,
            required=False,
            configured=True,
            exclusion_reason=reason,
        )
    )


def _discover_skills_files(
    config: LocalConfig, repo_root: Path, sources: list[SourceRecord]
) -> None:
    """Discover skills/rules directory."""
    scope = config.source_scope
    if scope.skills_rules_dir:
        skills_dir = repo_root / scope.skills_rules_dir
        if skills_dir.exists():
            for file_path in skills_dir.rglob("*"):
                if file_path.is_file():
                    _append_discovered_file(file_path, "skills", sources)
        else:
            # Missing skills directory - will be caught by required check if needed
            pass


def _discover_scoped_files(
    config: LocalConfig, repo_root: Path, sources: list[SourceRecord]
) -> None:
    """Discover files under path scopes."""
    scope = config.source_scope
    for path_scope in scope.path_scopes:
        scope_path = repo_root / path_scope
        if scope_path.exists():
            if scope_path.is_file():
                sources.append(
                    SourceRecord(
                        path=scope_path,
                        source_class="scoped",
                        required=False,
                        configured=True,
                    )
                )
            else:
                for file_path in scope_path.rglob("*"):
                    if file_path.is_file():
                        sources.append(
                            SourceRecord(
                                path=file_path,
                                source_class="scoped",
                                required=False,
                                configured=True,
                            )
                        )
        else:
            # Missing path scope - will be caught by required check if needed
            pass


def _mark_required_sources(
    sources: list[SourceRecord], config: LocalConfig, repo_root: Path
) -> None:
    """Mark sources as required based on required patterns."""
    scope = config.source_scope
    for required_pattern in scope.required:
        matches = list(repo_root.rglob(required_pattern))
        if matches:
            for match in matches:
                if match.is_file():
                    # Find matching source and mark as required
                    for src in sources:
                        if src.path == match:
                            src.required = True
                            break
                    else:
                        # Source not in our list (e.g., discovered via required
                        # but not other scopes) - add it as informational
                        sources.append(
                            SourceRecord(
                                path=match,
                                source_class="instruction",
                                required=True,
                                configured=False,
                            )
                        )


def _deduplicate_sources(sources: list[SourceRecord]) -> list[SourceRecord]:
    """Deduplicate sources by path, keeping the first occurrence with merged metadata."""
    seen: dict[Path, SourceRecord] = {}
    for src in sources:
        if src.path in seen:
            # Merge metadata - keep required=True if any source has it
            existing = seen[src.path]
            existing.required = existing.required or src.required
            existing.configured = existing.configured or src.configured
        else:
            seen[src.path] = src
    return list(seen.values())


def discover_sources(config: LocalConfig, repo_root: Path) -> list[SourceRecord]:
    """Discover source files based on configuration.

    Args:
        config: Local configuration.
        repo_root: Repository root path.

    Returns:
        List of SourceRecord objects.
    """
    sources: list[SourceRecord] = []

    _discover_instruction_files(config, repo_root, sources)
    _discover_explicit_files(config, repo_root, sources)
    _discover_skills_files(config, repo_root, sources)
    _discover_scoped_files(config, repo_root, sources)
    _mark_required_sources(sources, config, repo_root)

    return _deduplicate_sources(sources)


def read_source_content(source_path: Path) -> tuple[bytes | None, str | None]:
    """Read source file content as bytes.

    Returns:
        Tuple of (content_bytes, error_message). If successful, error_message is None.
        If failed, content_bytes is None and error_message describes the failure.
    """
    error: str | None = None
    content: bytes | None = None

    try:
        reject_reparse_components(source_path)
    except ValueError:
        error = f"Unsafe source path: {source_path}"

    if error is None and not source_path.exists():
        error = f"File not found: {source_path}"
    elif error is None and not source_path.is_file():
        error = f"Not a file: {source_path}"
    elif error is None:
        try:
            if not stat.S_ISREG(source_path.stat().st_mode):
                error = f"Not a regular file: {source_path}"
            else:
                content = source_path.read_bytes()
        except PermissionError:
            error = f"Permission denied: {source_path}"
        except OSError as e:
            error = f"OS error reading {source_path}: {e}"
        except Exception as e:
            error = f"Unexpected error reading {source_path}: {e}"

    if error is None and content is not None:
        # Check if it's likely a binary file by looking for null bytes
        # or by checking if it's valid UTF-8
        if b"\x00" in content:
            # This is likely a binary file
            pass
        else:
            # Try to decode as UTF-8 to verify it's text
            with suppress(UnicodeDecodeError):
                content.decode("utf-8")

    return content, error


def assess_readability(sources: list[SourceRecord], _repo_root: Path) -> list[SourceRecord]:
    """
    For each source, attempt to read content.
    Update source.readable, source.read_error, source.raw_hash.
    Required unreadable sources are flagged but not excluded here (blocked at compile).
    """
    for src in sources:
        content, error = read_source_content(src.path)
        if error is not None:
            src.readable = False
            src.read_error = error
            src.raw_hash = None
        else:
            src.readable = True
            src.read_error = None
            # Compute SHA-256 of raw bytes
            if content is not None:
                src.raw_hash = hashlib.sha256(content).hexdigest()
            else:
                src.raw_hash = None
    return sources


def make_inclusion_decisions(
    sources: list[SourceRecord], _config: LocalConfig, repo_root: Path
) -> list[SourceRecord]:
    """
    Determine inclusion/exclusion for each source based on:
    - readability (unreadable optional -> exclude with reason)
    - safety (unsafe paths -> exclude with reason)
    - required flag (required unreadable/unsafe -> will block at compile)
    - configured status (unconfigured discovered files -> informational only)
    Update source.included, source.exclusion_reason
    """
    for src in sources:
        # Check if source is unconfigured (discovered via required patterns
        # but not in configured scopes)
        if not src.configured:
            src.included = False
            src.exclusion_reason = "Unconfigured source (discovered via required pattern only)"
            continue

        generated_reason = generated_artifact_reason(src.path)
        if generated_reason is not None:
            src.included = False
            src.exclusion_reason = generated_reason
            continue

        # Check readability
        if src.readable is False:
            if src.required:
                src.included = False
                src.exclusion_reason = f"Required source unreadable: {src.read_error}"
            else:
                src.included = False
                src.exclusion_reason = f"Optional source unreadable: {src.read_error}"
            continue

        # Check safety (path traversal, etc.) - already validated in config,
        # but double-check. Ensure the path is within the repo_root.
        try:
            src.path.resolve().relative_to(repo_root.resolve())
        except ValueError:
            src.included = False
            src.exclusion_reason = f"Unsafe path (outside repo): {src.path}"
            continue

        # Safe, readable, configured -> included
        src.included = True
        src.exclusion_reason = None

    return sources


def _update_legacy_fields(result: AuditResult) -> None:
    """Update legacy fields for backward compatibility."""
    for src in result.sources:
        if src.source_class == "instruction":
            result.instruction_files.append(src.path)
        elif src.source_class == "explicit":
            result.explicit_files.append(src.path)
        elif src.source_class == "skills":
            result.skills_files.append(src.path)
        elif src.source_class == "scoped":
            result.scoped_files.append(src.path)

    # Sort for consistency
    result.instruction_files.sort()
    result.explicit_files.sort()
    result.skills_files.sort()
    result.scoped_files.sort()


def _update_counts(result: AuditResult) -> None:
    """Update count fields from sources."""
    result.total_discovered = len(result.sources)
    result.total_readable = sum(1 for s in result.sources if s.readable)
    result.total_included = sum(1 for s in result.sources if s.included)
    result.total_excluded = sum(1 for s in result.sources if not s.included and s.configured)
    result.total_informational = sum(1 for s in result.sources if not s.configured)

    result.total_conflicts = sum(1 for source in result.sources if source.is_conflict)

    # Per-class breakdown
    for src in result.sources:
        cls = src.source_class
        result.by_class[cls]["discovered"] += 1
        if src.readable:
            result.by_class[cls]["readable"] += 1
        if src.included:
            result.by_class[cls]["included"] += 1
        elif src.configured:
            result.by_class[cls]["excluded"] += 1
        else:
            result.by_class[cls]["informational"] += 1


@dataclass
class AuditContext:
    """Context for collecting audit results."""

    config: LocalConfig
    repo_root: Path
    revision: str
    sources: list[SourceRecord]
    task_brief_hash: str
    config_hash: str


def collect_audit_result(context: AuditContext) -> AuditResult:
    """Build the complete AuditResult for output."""
    result = AuditResult(sources=context.sources)
    _update_legacy_fields(result)
    _update_counts(result)
    return result


def audit_sources(config: LocalConfig, repo_root: Path) -> list[SourceRecord]:
    """Perform full source audit and return source records.

    Args:
        config: Local configuration.
        repo_root: Repository root path.

    Returns:
        List of SourceRecord objects with readability and inclusion decisions.
    """
    sources = discover_sources(config, repo_root)
    sources = assess_readability(sources, repo_root)
    return make_inclusion_decisions(sources, config, repo_root)


def _config_hash(config: LocalConfig, config_path: Path | None) -> str:
    """Hash the canonical configuration, falling back to its model data."""
    if config_path is not None and config_path.exists():
        raw = config_path.read_bytes()
    else:
        raw = json.dumps(
            config.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
        ).encode()
    return hashlib.sha256(raw).hexdigest()


def _task_brief_hash(config: LocalConfig, repo_root: Path) -> str:
    """Return the task brief hash, or an empty hash when no brief is configured."""
    brief = config.task_overlay.task_brief_path or config.task_brief_path
    if brief is None:
        return ""
    path = repo_root / brief
    if not path.is_file():
        return ""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _source_path_scope(config: LocalConfig, path: Path, repo_root: Path) -> str:
    """Find the longest configured scope containing a source."""
    relative = path.relative_to(repo_root)
    matches = [
        scope
        for scope in config.source_scope.path_scopes
        if str(relative).startswith(scope.rstrip("/") + "/") or str(relative) == scope
    ]
    return "/" if not matches else max(matches, key=len)


def _source_precedence(config: LocalConfig, source_class: SourceClass) -> int:
    """Resolve configured precedence, retaining a stable default."""
    names = {_SOURCE_CLASS_NAMES[source_class], source_class}
    for index, item in enumerate(config.source_scope.precedence):
        if item in names:
            return index
    return 100


def _apply_authority(sources: list[SourceRecord], config: LocalConfig, repo_root: Path) -> None:
    """Decorate records with authority and conflict information."""
    authority_sources = [
        AuthoritySourceRecord(
            path=str(source.path.relative_to(repo_root)),
            path_scope=source.path_scope,
            precedence=source.precedence,
            source_type=source.source_class,
            is_required=source.required,
            is_readable=source.readable is not False,
            is_safe=source.included or source.exclusion_reason is not None,
        )
        for source in sources
    ]
    authority = resolve_authority(authority_sources, config, "")
    conflicts_by_path: dict[str, list[str]] = {}
    for conflict in authority.conflicts:
        for path in conflict.source_paths:
            conflicts_by_path.setdefault(path, []).extend(
                other for other in conflict.source_paths if other != path
            )
    for source in sources:
        relative = str(source.path.relative_to(repo_root))
        details = conflicts_by_path.get(relative, [])
        source.is_conflict = bool(details)
        source.conflict_detail = ", ".join(sorted(set(details))) if details else None
        if source.is_conflict:
            source.included = False
            source.exclusion_reason = "Authority conflict"


def _source_to_json(source: SourceRecord, repo_root: Path) -> dict[str, Any]:
    """Serialize a source record using the audit.json contract."""
    return {
        "path": str(source.path.relative_to(repo_root)),
        "source_class": _SOURCE_CLASS_NAMES[source.source_class],
        "path_scope": source.path_scope,
        "precedence": source.precedence,
        "required": source.required,
        "readable": source.readable is True,
        "read_error": source.read_error,
        "raw_hash": source.raw_hash,
        "included": source.included,
        "exclusion_reason": source.exclusion_reason,
        "is_conflict": source.is_conflict,
        "conflict_detail": source.conflict_detail,
    }


def _audit_payload(
    result: AuditResult,
    repo_root: Path,
    revision: str,
    config_hash: str,
    task_hash: str,
) -> dict[str, Any]:
    """Build the canonical audit JSON payload."""
    by_class = {key: value["discovered"] for key, value in result.by_class.items()}
    return {
        "repo_root": str(repo_root.resolve()),
        "revision": revision,
        "config_hash": config_hash,
        "task_brief_hash": task_hash,
        "timestamp": datetime.now(UTC).isoformat(),
        "sources": [_source_to_json(source, repo_root) for source in result.sources],
        "summary": {
            "total_discovered": result.total_discovered,
            "total_readable": result.total_readable,
            "total_included": result.total_included,
            "total_excluded": result.total_excluded,
            "total_conflicts": result.total_conflicts,
            "total_informational": result.total_informational,
            "by_class": by_class,
        },
    }


def run_audit(config_path: Path, out_path: Path) -> int:
    """Run the full audit, write canonical audit.json, and return its exit code."""
    try:
        config = load_config(config_path)
        config_dir = config_path.parent
        if config_dir.name == ".farna-context":
            config_dir = config_dir.parent
        repo_root = config.get_repo_root_path(config_dir)
        revision = get_revision(repo_root)
        initial_dirty = check_dirty_tree(repo_root)
        sources = audit_sources(config, repo_root)
        for source in sources:
            source.path_scope = _source_path_scope(config, source.path, repo_root)
            source.precedence = _source_precedence(config, source.source_class)
        _apply_authority(sources, config, repo_root)
        config_hash = _config_hash(config, config_path)
        task_hash = _task_brief_hash(config, repo_root)
        result = collect_audit_result(
            AuditContext(config, repo_root, revision, sources, task_hash, config_hash)
        )
        payload = _audit_payload(result, repo_root, revision, config_hash, task_hash)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(  # noqa: T201
            f"Audit: {result.total_discovered} discovered, "
            f"{result.total_included} included, {result.total_conflicts} conflicts",
            file=sys.stdout,
        )
        if initial_dirty:
            print(  # noqa: T201
                f"Blocking issue: input changed ({len(initial_dirty)} dirty paths)",
                file=sys.stdout,
            )
            return 11
        blocking = any(
            source.required and (not source.readable or source.is_conflict) for source in sources
        )
        return 10 if blocking else 0  # noqa: TRY300
    except (ValueError, OSError, json.JSONDecodeError):
        return 2
