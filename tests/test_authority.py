"""Tests for authority resolution and conflict detection."""

from pathlib import Path
from tempfile import TemporaryDirectory

from src.farna_context.authority import (
    AuditFiles,
    AuthorityDecision,
    AuthorityResult,
    ConflictRecord,
    SourceRecord,
    _find_nearest_scope,
    _group_by_scope_and_precedence,
    _path_scope_matches,
    check_task_overlay_conflicts,
    create_source_records,
    resolve_authority,
)
from src.farna_context.config import LocalConfig, SourceScope, TaskOverlay


def test_path_scope_matching():
    """Test path scope prefix matching."""
    # Empty scope matches everything
    assert _path_scope_matches("", "any/path") is True
    assert _path_scope_matches("", "") is True

    # Exact match
    assert _path_scope_matches("src", "src") is True
    assert _path_scope_matches("src/module", "src/module") is True

    # Prefix match
    assert _path_scope_matches("src", "src/module/file.py") is True
    assert _path_scope_matches("src/module", "src/module/sub/file.py") is True

    # No match
    assert _path_scope_matches("src/module", "src/other/file.py") is False
    assert _path_scope_matches("src/module/sub", "src/module") is False


def test_find_nearest_scope():
    """Test finding nearest applicable scope."""
    source = SourceRecord(
        path="src/module/file.py",
        path_scope="src/module",
        precedence=0,
        source_type="instruction",
    )

    # Should match
    assert _find_nearest_scope(source, "src/module/file.py") == "src/module"
    assert _find_nearest_scope(source, "src/module/sub/file.py") == "src/module"

    # Should not match
    assert _find_nearest_scope(source, "src/other/file.py") is None


def test_group_by_scope_and_precedence():
    """Test grouping sources by scope and precedence."""
    sources = [
        SourceRecord(path="a.py", path_scope="src", precedence=0, source_type="instruction"),
        SourceRecord(path="b.py", path_scope="src", precedence=0, source_type="instruction"),
        SourceRecord(path="c.py", path_scope="src", precedence=1, source_type="instruction"),
        SourceRecord(path="d.py", path_scope="lib", precedence=0, source_type="instruction"),
    ]

    groups = _group_by_scope_and_precedence(sources)

    # Should have 3 groups: (src, 0), (src, 1), (lib, 0)
    expected_group_count = 3
    expected_conflict_group_size = 2
    expected_single_group_size = 1
    assert len(groups) == expected_group_count
    assert len(groups[("src", 0)]) == expected_conflict_group_size  # Conflict group
    assert len(groups[("src", 1)]) == expected_single_group_size
    assert len(groups[("lib", 0)]) == expected_single_group_size


def test_same_scope_same_precedence_conflict():
    """Test detection of same-scope-same-precedence conflicts."""
    sources = [
        SourceRecord(path="a.py", path_scope="src", precedence=0, source_type="instruction"),
        SourceRecord(path="b.py", path_scope="src", precedence=0, source_type="instruction"),
        SourceRecord(path="c.py", path_scope="src", precedence=1, source_type="instruction"),
    ]

    config = LocalConfig(
        source_scope=SourceScope(path_scopes=["src"], precedence=["src"]),
        task_overlay=TaskOverlay(),
    )

    result = resolve_authority(sources, config, "src/module/file.py")

    # Should have 1 conflict
    expected_conflict_count = 1
    expected_conflicted_sources = {"a.py", "b.py"}
    expected_conflicted_decisions = 2
    assert len(result.conflicts) == expected_conflict_count
    assert result.conflicts[0].reason == "same_scope_same_precedence"
    assert result.conflicts[0].severity == "blocks"
    assert set(result.conflicts[0].source_paths) == expected_conflicted_sources

    # Both conflicting sources should be blocked
    assert "a.py" in result.blocked_sources
    assert "b.py" in result.blocked_sources
    assert "c.py" not in result.blocked_sources

    # Decisions should reflect conflict
    conflict_decisions = [d for d in result.decisions if d.is_conflict]
    assert len(conflict_decisions) == expected_conflicted_decisions
    for d in conflict_decisions:
        assert d.conflict_reason == "same_scope_same_precedence"


def test_no_conflict_different_precedence():
    """Test no conflict when same scope but different precedence."""
    sources = [
        SourceRecord(path="a.py", path_scope="src", precedence=0, source_type="instruction"),
        SourceRecord(path="b.py", path_scope="src", precedence=1, source_type="instruction"),
    ]

    config = LocalConfig(
        source_scope=SourceScope(path_scopes=["src"], precedence=["src"]),
        task_overlay=TaskOverlay(),
    )

    result = resolve_authority(sources, config, "src/module/file.py")

    assert len(result.conflicts) == 0
    assert len(result.blocked_sources) == 0
    assert len(result.excluded_sources) == 0


def test_no_conflict_different_scope():
    """Test no conflict when different scope."""
    sources = [
        SourceRecord(path="a.py", path_scope="src", precedence=0, source_type="instruction"),
        SourceRecord(path="b.py", path_scope="lib", precedence=0, source_type="instruction"),
    ]

    config = LocalConfig(
        source_scope=SourceScope(path_scopes=["src", "lib"], precedence=["src", "lib"]),
        task_overlay=TaskOverlay(),
    )

    result = resolve_authority(sources, config, "src/module/file.py")

    assert len(result.conflicts) == 0


def test_task_overlay_unapproved_overlap_conflict():
    """Test task overlay overlapping repo source at same scope = conflict."""
    sources = [
        SourceRecord(
            path="task_brief.md",
            path_scope="src",  # Same scope as repo source
            precedence=-1,
            source_type="task_overlay",
        ),
        SourceRecord(
            path="src/instructions.md",
            path_scope="src",
            precedence=0,
            source_type="instruction",
        ),
    ]

    config = LocalConfig(
        source_scope=SourceScope(path_scopes=["src"], precedence=["src"]),
        task_overlay=TaskOverlay(task_brief_path="task_brief.md"),
    )

    result = resolve_authority(sources, config, "src/module/file.py")

    # Should detect task overlay conflict
    overlay_conflicts = [c for c in result.conflicts if "task_overlay" in c.reason]
    assert len(overlay_conflicts) == 1
    assert overlay_conflicts[0].reason == "task_overlay_unapproved_overlap"
    assert overlay_conflicts[0].severity == "blocks"


def test_task_overlay_approved_additive():
    """Test task overlay with approved additive field."""
    sources = [
        SourceRecord(
            path="extra_source.py",
            path_scope="src",
            precedence=-1,
            source_type="task_overlay",
        ),
        SourceRecord(
            path="src/instructions.md",
            path_scope="src",
            precedence=0,
            source_type="instruction",
        ),
    ]

    config = LocalConfig(
        source_scope=SourceScope(path_scopes=["src"], precedence=["src"]),
        task_overlay=TaskOverlay(extra_sources=["extra_source.py"]),
    )

    result = resolve_authority(sources, config, "src/module/file.py")

    # Should have replacement conflict (excludes, not blocks)
    overlay_conflicts = [c for c in result.conflicts if "task_overlay" in c.reason]
    assert len(overlay_conflicts) == 1
    assert overlay_conflicts[0].reason == "task_overlay_unapproved_overlap"
    assert overlay_conflicts[0].severity == "blocks"


def test_required_unreadable_blocks():
    """Test required but unreadable source blocks command."""
    sources = [
        SourceRecord(
            path="required.py",
            path_scope="src",
            precedence=0,
            source_type="explicit",
            is_required=True,
            is_readable=False,
        ),
    ]

    config = LocalConfig(
        source_scope=SourceScope(path_scopes=["src"], precedence=["src"]),
        task_overlay=TaskOverlay(),
    )

    result = resolve_authority(sources, config, "src/module/file.py")

    assert "required.py" in result.blocked_sources
    decision = next(d for d in result.decisions if d.source.path == "required.py")
    assert decision.is_conflict
    assert decision.conflict_reason == "required_unreadable"


def test_optional_unreadable_excludes():
    """Test optional but unreadable source is excluded."""
    sources = [
        SourceRecord(
            path="optional.py",
            path_scope="src",
            precedence=0,
            source_type="instruction",
            is_required=False,
            is_readable=False,
        ),
    ]

    config = LocalConfig(
        source_scope=SourceScope(path_scopes=["src"], precedence=["src"]),
        task_overlay=TaskOverlay(),
    )

    result = resolve_authority(sources, config, "src/module/file.py")

    assert "optional.py" in result.excluded_sources
    assert "optional.py" not in result.blocked_sources
    decision = next(d for d in result.decisions if d.source.path == "optional.py")
    assert decision.is_conflict
    assert decision.conflict_reason == "optional_unreadable"


def test_optional_unsafe_excludes():
    """Test optional but unsafe source is excluded."""
    sources = [
        SourceRecord(
            path="unsafe.py",
            path_scope="src",
            precedence=0,
            source_type="instruction",
            is_required=False,
            is_safe=False,
        ),
    ]

    config = LocalConfig(
        source_scope=SourceScope(path_scopes=["src"], precedence=["src"]),
        task_overlay=TaskOverlay(),
    )

    result = resolve_authority(sources, config, "src/module/file.py")

    assert "unsafe.py" in result.excluded_sources
    assert "unsafe.py" not in result.blocked_sources
    decision = next(d for d in result.decisions if d.source.path == "unsafe.py")
    assert decision.is_conflict
    assert decision.conflict_reason == "optional_unsafe"


def test_create_source_records_from_audit():
    """Test creating source records from audit results."""
    with TemporaryDirectory() as tmpdir:
        repo_root = Path(tmpdir)

        # Create test files
        (repo_root / "src").mkdir()
        (repo_root / "src" / "instructions.md").write_text("# Instructions")
        (repo_root / "explicit.md").write_text("# Explicit")
        (repo_root / "skills").mkdir()
        (repo_root / "skills" / "rule.md").write_text("# Rule")

        config = LocalConfig(
            source_scope=SourceScope(
                instruction_files=["*.md"],
                explicit_instruction_files=["explicit.md"],
                skills_rules_dir="skills",
                path_scopes=["src", "skills"],
                precedence=["skills", "src"],
            ),
            task_overlay=TaskOverlay(),
        )

        audit_files = AuditFiles(
            instruction_files=[repo_root / "src" / "instructions.md"],
            explicit_files=[repo_root / "explicit.md"],
            skills_files=[repo_root / "skills" / "rule.md"],
            scoped_files=[],
        )

        sources = create_source_records(
            config=config,
            repo_root=repo_root,
            audit_files=audit_files,
            task_scope="src",
        )

        expected_source_count = 3
        assert len(sources) == expected_source_count

        # Check instruction file
        inst = next(s for s in sources if s.source_type == "instruction")
        assert inst.path == "src/instructions.md"
        assert inst.path_scope == "src"
        assert inst.precedence == 1  # "src" is second in precedence

        # Check explicit file
        expl = next(s for s in sources if s.source_type == "explicit")
        assert expl.path == "explicit.md"
        assert expl.path_scope == ""
        assert expl.is_required is True

        # Check skills file
        skill = next(s for s in sources if s.source_type == "skills")
        assert skill.path == "skills/rule.md"
        assert skill.path_scope == "skills"
        assert skill.precedence == 0  # "skills" is first in precedence


def test_task_brief_creates_task_overlay_source():
    """Test that task brief creates a task_overlay source record."""
    with TemporaryDirectory() as tmpdir:
        repo_root = Path(tmpdir)
        (repo_root / "task_brief.md").write_text("# Task Brief")

        config = LocalConfig(
            source_scope=SourceScope(
                path_scopes=["src"],
                precedence=["src"],
            ),
            task_overlay=TaskOverlay(task_brief_path="task_brief.md"),
        )

        audit_files = AuditFiles(
            instruction_files=[],
            explicit_files=[],
            skills_files=[],
            scoped_files=[],
        )

        sources = create_source_records(
            config=config,
            repo_root=repo_root,
            audit_files=audit_files,
            task_scope="src",
        )

        overlay = next((s for s in sources if s.source_type == "task_overlay"), None)
        assert overlay is not None
        assert overlay.path == "task_brief.md"
        assert overlay.path_scope == "src"
        assert overlay.precedence == -1


def test_extra_sources_creates_task_overlay_sources():
    """Test that extra_sources creates task_overlay source records."""
    with TemporaryDirectory() as tmpdir:
        repo_root = Path(tmpdir)
        (repo_root / "extra").mkdir()
        (repo_root / "extra" / "file.md").write_text("# Extra")

        config = LocalConfig(
            source_scope=SourceScope(
                path_scopes=["src", "extra"],
                precedence=["extra", "src"],
            ),
            task_overlay=TaskOverlay(extra_sources=["extra/*.md"]),
        )

        audit_files = AuditFiles(
            instruction_files=[],
            explicit_files=[],
            skills_files=[],
            scoped_files=[],
        )

        sources = create_source_records(
            config=config,
            repo_root=repo_root,
            audit_files=audit_files,
            task_scope="src",
        )

        overlays = [s for s in sources if s.source_type == "task_overlay"]
        assert len(overlays) == 1
        assert overlays[0].path == "extra/file.md"
        assert overlays[0].path_scope == "extra"
        assert overlays[0].precedence == -1


def test_scope_narrowing_nearest_match():
    """Test that nearest (longest) matching scope is used."""
    with TemporaryDirectory() as tmpdir:
        repo_root = Path(tmpdir)
        (repo_root / "src" / "module").mkdir(parents=True)
        (repo_root / "src" / "module" / "file.py").write_text("# File")

        config = LocalConfig(
            source_scope=SourceScope(
                instruction_files=["**/*.py"],
                path_scopes=["src", "src/module"],
                precedence=["src/module", "src"],
            ),
            task_overlay=TaskOverlay(),
        )

        audit_files = AuditFiles(
            instruction_files=[repo_root / "src" / "module" / "file.py"],
            explicit_files=[],
            skills_files=[],
            scoped_files=[],
        )

        sources = create_source_records(
            config=config,
            repo_root=repo_root,
            audit_files=audit_files,
            task_scope="src",
        )

        inst = next(s for s in sources if s.source_type == "instruction")
        # Should match the more specific scope "src/module"
        assert inst.path_scope == "src/module"
        assert inst.precedence == 0  # "src/module" is first in precedence


def test_check_task_overlay_conflicts_function():
    """Test the standalone check_task_overlay_conflicts function."""
    sources = [
        SourceRecord(
            path="task_brief.md",
            path_scope="src",
            precedence=-1,
            source_type="task_overlay",
        ),
        SourceRecord(
            path="src/instructions.md",
            path_scope="src",
            precedence=0,
            source_type="instruction",
        ),
    ]

    task_overlay = TaskOverlay(task_brief_path="task_brief.md")

    conflicts = check_task_overlay_conflicts(sources, task_overlay)

    assert len(conflicts) == 1
    assert conflicts[0].reason == "task_overlay_unapproved_overlap"
    assert conflicts[0].severity == "blocks"
    assert set(conflicts[0].source_paths) == {"task_brief.md", "src/instructions.md"}


def test_authority_result_structure():
    """Test that AuthorityResult has the expected structure."""
    sources = [
        SourceRecord(path="a.py", path_scope="src", precedence=0, source_type="instruction"),
    ]

    config = LocalConfig(
        source_scope=SourceScope(path_scopes=["src"], precedence=["src"]),
        task_overlay=TaskOverlay(),
    )

    result = resolve_authority(sources, config, "src/file.py")

    assert isinstance(result, AuthorityResult)
    assert hasattr(result, "decisions")
    assert hasattr(result, "conflicts")
    assert hasattr(result, "blocked_sources")
    assert hasattr(result, "excluded_sources")
    assert isinstance(result.decisions, list)
    assert isinstance(result.conflicts, list)
    assert isinstance(result.blocked_sources, list)
    assert isinstance(result.excluded_sources, list)


def test_conflict_record_fields():
    """Test ConflictRecord has all required fields."""
    conflict = ConflictRecord(
        source_paths=["a.py", "b.py"],
        scope="src",
        reason="same_scope_same_precedence",
        severity="blocks",
    )

    assert conflict.source_paths == ["a.py", "b.py"]
    assert conflict.scope == "src"
    assert conflict.reason == "same_scope_same_precedence"
    assert conflict.severity == "blocks"


def test_authority_decision_fields():
    """Test AuthorityDecision has all required fields."""
    source = SourceRecord(path="a.py", path_scope="src", precedence=0, source_type="instruction")
    decision = AuthorityDecision(
        source=source,
        applicable=True,
        narrowed_by="src",
        conflict_with=["b.py"],
        is_conflict=True,
        conflict_reason="same_scope_same_precedence",
    )

    assert decision.source == source
    assert decision.applicable is True
    assert decision.narrowed_by == "src"
    assert decision.conflict_with == ["b.py"]
    assert decision.is_conflict is True
    assert decision.conflict_reason == "same_scope_same_precedence"
