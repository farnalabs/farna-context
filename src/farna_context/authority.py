"""Mechanical authority resolution and conflict detection for Farna Context.

Implements PRD §2.3 authority rules:
1. Each source record has explicit repository-relative path scope and ordered precedence from config
2. Nearest applicable scope narrows which records apply — does NOT make prose semantically superior
3. Two instruction records with overlapping applicability at the same scope = conflict
4. NO semantic contradiction inference in free-form prose (no model, no NLP)
5. Task brief is input, not authority. Task overlay is separate bounded config section,
   applicable only where explicitly identified. Cannot replace/delete repository sources.
6. Task overlay overlapping repository instruction at same scope = conflict unless
   field explicitly listed as additive
7. Required unreadable/unsafe/conflicting → blocks relevant command
8. Optional conflicting → excluded, reason recorded
9. Unconfigured discovered files → informational only, not included, cannot affect authority
10. Manifest is derived explanation, not authority layer
"""

from pathlib import Path

from pydantic import BaseModel, Field

from .config import LocalConfig, SourceScope, TaskOverlay


class SourceRecord(BaseModel):
    """A single source record with its authority metadata."""

    path: str
    path_scope: str
    precedence: int
    source_type: str  # "instruction", "explicit", "skills", "scoped", "task_overlay"
    is_required: bool = False
    is_readable: bool = True
    is_safe: bool = True


class AuthorityDecision(BaseModel):
    """Decision for a single source record after authority resolution."""

    source: SourceRecord
    applicable: bool
    narrowed_by: str | None = None  # which scope narrowed it
    conflict_with: list[str] = Field(default_factory=list)  # paths of conflicting sources
    is_conflict: bool = False
    conflict_reason: str | None = None


class ConflictRecord(BaseModel):
    """Record of a detected conflict."""

    source_paths: list[str]
    scope: str
    reason: str  # same_scope_same_precedence,
    # task_overlay_replacement, task_overlay_unapproved_overlap
    severity: str  # "blocks" or "excludes"


class AuthorityResult(BaseModel):
    """Result of authority resolution."""

    decisions: list[AuthorityDecision]
    conflicts: list[ConflictRecord]
    blocked_sources: list[str]
    excluded_sources: list[str]


def _path_scope_matches(source_scope: str, task_scope: str) -> bool:
    """Check if source's path_scope is a prefix of task_scope.

    Path scope matching: source.path_scope is prefix of task_scope
    """
    if not source_scope:
        return True  # Empty scope matches everything
    source_parts = Path(source_scope).parts
    task_parts = Path(task_scope).parts
    if len(source_parts) > len(task_parts):
        return False
    return source_parts == task_parts[: len(source_parts)]


def _find_nearest_scope(source: SourceRecord, task_scope: str) -> str | None:
    """Find the nearest applicable scope (longest matching prefix).

    Returns the path_scope if it matches, None otherwise.
    """
    if _path_scope_matches(source.path_scope, task_scope):
        return source.path_scope
    return None


def _group_by_scope_and_precedence(
    sources: list[SourceRecord],
) -> dict[tuple[str, int], list[SourceRecord]]:
    """Group sources by (path_scope, precedence) tuple.

    Same scope + same precedence = conflict
    """
    groups: dict[tuple[str, int], list[SourceRecord]] = {}
    for source in sources:
        key = (source.path_scope, source.precedence)
        groups.setdefault(key, []).append(source)
    return groups


def _check_task_overlay_conflicts(
    sources: list[SourceRecord],
    _task_overlay: TaskOverlay,
    allowed_overlay_fields: set[str] | None = None,
) -> list[ConflictRecord]:
    """Check task overlay against repository sources for same-scope overlaps.

    Task overlay overlapping repository instruction at same scope = conflict
    unless field explicitly listed as additive.
    """
    if allowed_overlay_fields is None:
        allowed_overlay_fields = {"extra_sources", "exclude_patterns"}

    conflicts: list[ConflictRecord] = []

    # Find task overlay sources
    overlay_sources = [s for s in sources if s.source_type == "task_overlay"]
    repo_sources = [s for s in sources if s.source_type != "task_overlay"]

    for overlay in overlay_sources:
        for repo in repo_sources:
            if overlay.path_scope == repo.path_scope:
                # Check if this is an approved additive field
                # For simplicity, we check if the overlay path matches any allowed field
                is_approved = any(
                    overlay.path.endswith(field) or field in overlay.path
                    for field in allowed_overlay_fields
                )

                if not is_approved:
                    conflicts.append(
                        ConflictRecord(
                            source_paths=[overlay.path, repo.path],
                            scope=overlay.path_scope,
                            reason="task_overlay_unapproved_overlap",
                            severity="blocks",
                        )
                    )
                else:
                    # Approved additive overlap - check if it tries to replace
                    conflicts.append(
                        ConflictRecord(
                            source_paths=[overlay.path, repo.path],
                            scope=overlay.path_scope,
                            reason="task_overlay_replacement",
                            severity="excludes",
                        )
                    )

    return conflicts


def _filter_applicable_sources(sources: list[SourceRecord], task_scope: str) -> list[SourceRecord]:
    """Filter sources that apply to the task scope."""
    applicable: list[SourceRecord] = []
    for source in sources:
        if _find_nearest_scope(source, task_scope) is not None:
            applicable.append(source)
    return applicable


def _process_scope_conflicts(
    groups: dict[tuple[str, int], list[SourceRecord]],
) -> tuple[list[AuthorityDecision], list[ConflictRecord], list[str]]:
    """Process same-scope-same-precedence conflicts."""
    decisions: list[AuthorityDecision] = []
    conflicts: list[ConflictRecord] = []
    blocked_sources: list[str] = []

    for (scope, _precedence), group in groups.items():
        if len(group) > 1:
            conflict_paths = [s.path for s in group]
            conflict = ConflictRecord(
                source_paths=conflict_paths,
                scope=scope,
                reason="same_scope_same_precedence",
                severity="blocks",
            )
            conflicts.append(conflict)

            for source in group:
                blocked_sources.append(source.path)
                decisions.append(
                    AuthorityDecision(
                        source=source,
                        applicable=True,
                        narrowed_by=scope,
                        conflict_with=[p for p in conflict_paths if p != source.path],
                        is_conflict=True,
                        conflict_reason="same_scope_same_precedence",
                    )
                )
        else:
            source = group[0]
            decisions.append(
                AuthorityDecision(
                    source=source,
                    applicable=True,
                    narrowed_by=scope,
                    conflict_with=[],
                    is_conflict=False,
                    conflict_reason=None,
                )
            )

    return decisions, conflicts, blocked_sources


def _process_overlay_conflicts(
    overlay_conflicts: list[ConflictRecord],
    decisions: list[AuthorityDecision],
    blocked_sources: list[str],
    excluded_sources: list[str],
) -> None:
    """Process task overlay conflicts and update decisions."""
    for conflict in overlay_conflicts:
        for path in conflict.source_paths:
            if conflict.severity == "blocks" and path not in blocked_sources:
                blocked_sources.append(path)
            elif conflict.severity == "excludes" and path not in excluded_sources:
                excluded_sources.append(path)

            for decision in decisions:
                if decision.source.path == path:
                    decision.is_conflict = True
                    decision.conflict_with = [p for p in conflict.source_paths if p != path]
                    decision.conflict_reason = conflict.reason
                    break


def _process_readability_conflicts(
    applicable_sources: list[SourceRecord],
    decisions: list[AuthorityDecision],
    blocked_sources: list[str],
    excluded_sources: list[str],
) -> None:
    """Process required/optional unreadable/unsafe source conflicts."""
    # Required but unreadable/unsafe -> blocks
    for source in applicable_sources:
        if source.is_required and (not source.is_readable or not source.is_safe):
            if source.path not in blocked_sources:
                blocked_sources.append(source.path)
            for decision in decisions:
                if decision.source.path == source.path:
                    decision.is_conflict = True
                    decision.conflict_reason = (
                        "required_unreadable" if not source.is_readable else "required_unsafe"
                    )
                    break

    # Optional but unreadable/unsafe -> excludes
    for source in applicable_sources:
        if not source.is_required and (not source.is_readable or not source.is_safe):
            if source.path not in excluded_sources:
                excluded_sources.append(source.path)
            for decision in decisions:
                if decision.source.path == source.path:
                    decision.is_conflict = True
                    decision.conflict_reason = (
                        "optional_unreadable" if not source.is_readable else "optional_unsafe"
                    )
                    break


def resolve_authority(
    sources: list[SourceRecord],
    config: LocalConfig,
    task_scope: str,
) -> AuthorityResult:
    """Apply mechanical authority resolution.

    1. Filter sources by path_scope prefix matching task_scope
    2. For each source, find nearest applicable scope (longest prefix match)
    3. Group by (path_scope, precedence) - same scope + same precedence = conflict
    4. Check task overlay fields against repository sources for same-scope overlap
    5. Mark conflicts, determine blocked/excluded
    6. Never infer semantic contradiction in prose
    """
    applicable_sources = _filter_applicable_sources(sources, task_scope)
    groups = _group_by_scope_and_precedence(applicable_sources)

    decisions, conflicts, blocked_sources = _process_scope_conflicts(groups)
    excluded_sources: list[str] = []

    overlay_conflicts = _check_task_overlay_conflicts(sources, config.task_overlay)
    conflicts.extend(overlay_conflicts)

    _process_overlay_conflicts(overlay_conflicts, decisions, blocked_sources, excluded_sources)
    _process_readability_conflicts(applicable_sources, decisions, blocked_sources, excluded_sources)

    return AuthorityResult(
        decisions=decisions,
        conflicts=conflicts,
        blocked_sources=blocked_sources,
        excluded_sources=excluded_sources,
    )


def check_task_overlay_conflicts(
    sources: list[SourceRecord],
    task_overlay: TaskOverlay,
) -> list[ConflictRecord]:
    """Check task overlay against repository sources for same-scope overlaps."""
    return _check_task_overlay_conflicts(sources, task_overlay)


class AuditFiles(BaseModel):
    """Container for audit-discovered files."""

    instruction_files: list[Path] = Field(default_factory=list)
    explicit_files: list[Path] = Field(default_factory=list)
    skills_files: list[Path] = Field(default_factory=list)
    scoped_files: list[Path] = Field(default_factory=list)


def _find_matching_scope(scope: SourceScope, rel_path: Path) -> str:
    """Find the nearest (longest) matching path_scope for a relative path."""
    matching_scope = ""
    for ps in scope.path_scopes:
        if _path_scope_matches(ps, str(rel_path)) and (
            not matching_scope or len(ps) > len(matching_scope)
        ):
            matching_scope = ps
    return matching_scope


class SourceRecordParams(BaseModel):
    """Parameters for creating a SourceRecord."""

    rel_path: Path
    matching_scope: str
    precedence: int
    source_type: str
    is_required: bool = False
    is_readable: bool = True
    is_safe: bool = True


def _create_source_record(params: SourceRecordParams) -> SourceRecord:
    """Create a SourceRecord with common parameters."""
    return SourceRecord(
        path=str(params.rel_path),
        path_scope=params.matching_scope,
        precedence=params.precedence,
        source_type=params.source_type,
        is_required=params.is_required,
        is_readable=params.is_readable,
        is_safe=params.is_safe,
    )


class AddFileSourcesParams(BaseModel):
    """Parameters for _add_file_sources."""

    sources: list[SourceRecord]
    files: list[Path]
    repo_root: Path
    scope: SourceScope
    precedence_map: dict[str, int]
    source_type: str
    is_required: bool = False


def _add_file_sources(params: AddFileSourcesParams) -> list[SourceRecord]:
    """Add source records for a list of files with matching scope."""
    new_sources: list[SourceRecord] = []
    for f in params.files:
        rel_path = f.relative_to(params.repo_root)
        matching_scope = _find_matching_scope(params.scope, rel_path)
        precedence = params.precedence_map.get(matching_scope, 999)
        new_sources.append(
            _create_source_record(
                SourceRecordParams(
                    rel_path=rel_path,
                    matching_scope=matching_scope,
                    precedence=precedence,
                    source_type=params.source_type,
                    is_required=params.is_required,
                    is_readable=f.exists() and f.is_file(),
                )
            )
        )
    return new_sources


def create_source_records(
    config: LocalConfig,
    repo_root: Path,
    audit_files: AuditFiles,
    task_scope: str = "",
) -> list[SourceRecord]:
    """Create SourceRecord objects from audit results and config."""
    sources: list[SourceRecord] = []
    scope = config.source_scope

    # Build precedence map from config
    precedence_map = {path: idx for idx, path in enumerate(scope.precedence)}

    # Instruction files
    sources.extend(
        _add_file_sources(
            AddFileSourcesParams(
                sources=[],
                files=audit_files.instruction_files,
                repo_root=repo_root,
                scope=scope,
                precedence_map=precedence_map,
                source_type="instruction",
                is_required=False,
            )
        )
    )

    # Explicit files
    sources.extend(
        _add_file_sources(
            AddFileSourcesParams(
                sources=[],
                files=audit_files.explicit_files,
                repo_root=repo_root,
                scope=scope,
                precedence_map=precedence_map,
                source_type="explicit",
                is_required=True,
            )
        )
    )

    # Skills files
    for f in audit_files.skills_files:
        rel_path = f.relative_to(repo_root)
        matching_scope = scope.skills_rules_dir or ""
        precedence = precedence_map.get(matching_scope, 999)
        sources.append(
            _create_source_record(
                SourceRecordParams(
                    rel_path=rel_path,
                    matching_scope=matching_scope,
                    precedence=precedence,
                    source_type="skills",
                    is_required=False,
                    is_readable=f.exists() and f.is_file(),
                )
            )
        )

    # Scoped files
    sources.extend(
        _add_file_sources(
            AddFileSourcesParams(
                sources=[],
                files=audit_files.scoped_files,
                repo_root=repo_root,
                scope=scope,
                precedence_map=precedence_map,
                source_type="scoped",
                is_required=False,
            )
        )
    )

    # Task overlay sources (if task brief exists)
    if config.task_overlay.task_brief_path:
        brief_path = repo_root / config.task_overlay.task_brief_path
        if brief_path.exists():
            rel_path = brief_path.relative_to(repo_root)
            # Use task_scope for task overlay to enable conflict detection
            sources.append(
                _create_source_record(
                    SourceRecordParams(
                        rel_path=rel_path,
                        matching_scope=task_scope,
                        precedence=-1,
                        source_type="task_overlay",
                        is_required=False,
                        is_readable=True,
                    )
                )
            )

    # Extra sources from task overlay
    for pattern in config.task_overlay.extra_sources:
        matches = list(repo_root.rglob(pattern))
        for f in matches:
            rel_path = f.relative_to(repo_root)
            matching_scope = _find_matching_scope(scope, rel_path)
            sources.append(
                _create_source_record(
                    SourceRecordParams(
                        rel_path=rel_path,
                        matching_scope=matching_scope,
                        precedence=-1,
                        source_type="task_overlay",
                        is_required=False,
                        is_readable=f.exists() and f.is_file(),
                    )
                )
            )

    return sources
