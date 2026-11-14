"""Tests for audit module."""

import tempfile
from pathlib import Path

from src.farna_context.audit import (
    AuditContext,
    AuditResult,
    SourceRecord,
    assess_readability,
    collect_audit_result,
    discover_sources,
    make_inclusion_decisions,
    read_source_content,
)
from src.farna_context.config import LocalConfig, SourceScope

# Constants for test assertions
SHA256_HEX_LENGTH = 64
EXPECTED_FILE_COUNT_TWO = 2
EXPECTED_FILE_COUNT_THREE = 3


class TestReadSourceContent:
    """Tests for read_source_content function."""

    def test_read_existing_text_file(self):
        """Test reading an existing text file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            test_file = tmpdir_path / "test.txt"
            test_file.write_text("Hello, world!")

            content, error = read_source_content(test_file)
            assert error is None
            assert content == b"Hello, world!"

    def test_read_existing_binary_file(self):
        """Test reading a binary file (with null bytes)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            test_file = tmpdir_path / "test.bin"
            test_file.write_bytes(b"\x00\x01\x02\x03")

            content, error = read_source_content(test_file)
            assert error is None
            assert content == b"\x00\x01\x02\x03"

    def test_read_nonexistent_file(self):
        """Test reading a non-existent file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            test_file = tmpdir_path / "nonexistent.txt"

            content, error = read_source_content(test_file)
            assert content is None
            assert "File not found" in error

    def test_read_directory(self):
        """Test reading a directory (should fail)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            test_dir = tmpdir_path / "subdir"
            test_dir.mkdir()

            content, error = read_source_content(test_dir)
            assert content is None
            assert "Not a file" in error


class TestAssessReadability:
    """Tests for assess_readability function."""

    def test_assess_readable_files(self):
        """Test assessing readability of readable files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            test_file = tmpdir_path / "test.txt"
            test_file.write_text("Hello, world!")

            sources = [
                SourceRecord(
                    path=test_file,
                    source_class="instruction",
                    required=False,
                    configured=True,
                )
            ]

            result = assess_readability(sources, tmpdir_path)
            assert result[0].readable is True
            assert result[0].read_error is None
            assert result[0].raw_hash is not None
            assert len(result[0].raw_hash) == SHA256_HEX_LENGTH  # SHA-256 hex

    def test_assess_unreadable_file(self):
        """Test assessing readability of unreadable file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            test_file = tmpdir_path / "nonexistent.txt"

            sources = [
                SourceRecord(
                    path=test_file,
                    source_class="instruction",
                    required=False,
                    configured=True,
                )
            ]

            result = assess_readability(sources, tmpdir_path)
            assert result[0].readable is False
            assert result[0].read_error is not None
            assert "File not found" in result[0].read_error
            assert result[0].raw_hash is None

    def test_assess_required_unreadable_file(self):
        """Test assessing readability of required but unreadable file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            test_file = tmpdir_path / "nonexistent.txt"

            sources = [
                SourceRecord(
                    path=test_file,
                    source_class="instruction",
                    required=True,
                    configured=True,
                )
            ]

            result = assess_readability(sources, tmpdir_path)
            assert result[0].readable is False
            assert result[0].read_error is not None
            assert result[0].raw_hash is None
            # Required flag is preserved for later exclusion decision
            assert result[0].required is True


class TestMakeInclusionDecisions:
    """Tests for make_inclusion_decisions function."""

    def test_include_readable_configured_file(self):
        """Test including a readable, configured file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            test_file = tmpdir_path / "test.txt"
            test_file.write_text("Hello, world!")

            sources = [
                SourceRecord(
                    path=test_file,
                    source_class="instruction",
                    required=False,
                    configured=True,
                    readable=True,
                    read_error=None,
                    raw_hash="abc123",
                )
            ]

            config = LocalConfig()
            result = make_inclusion_decisions(sources, config, tmpdir_path)
            assert result[0].included is True
            assert result[0].exclusion_reason is None

    def test_exclude_unreadable_optional_file(self):
        """Test excluding an unreadable optional file."""
        sources = [
            SourceRecord(
                path=Path("nonexistent.txt"),
                source_class="instruction",
                required=False,
                configured=True,
                readable=False,
                read_error="File not found: nonexistent.txt",
                raw_hash=None,
            )
        ]

        config = LocalConfig()
        result = make_inclusion_decisions(sources, config, Path())
        assert result[0].included is False
        assert result[0].exclusion_reason is not None
        assert "Optional source unreadable" in result[0].exclusion_reason

    def test_exclude_unreadable_required_file(self):
        """Test excluding an unreadable required file."""
        sources = [
            SourceRecord(
                path=Path("nonexistent.txt"),
                source_class="instruction",
                required=True,
                configured=True,
                readable=False,
                read_error="File not found: nonexistent.txt",
                raw_hash=None,
            )
        ]

        config = LocalConfig()
        result = make_inclusion_decisions(sources, config, Path())
        assert result[0].included is False
        assert result[0].exclusion_reason is not None
        assert "Required source unreadable" in result[0].exclusion_reason

    def test_exclude_unconfigured_file(self):
        """Test excluding an unconfigured (informational) file."""
        sources = [
            SourceRecord(
                path=Path("discovered.txt"),
                source_class="instruction",
                required=True,
                configured=False,
                readable=True,
                read_error=None,
                raw_hash="abc123",
            )
        ]

        config = LocalConfig()
        result = make_inclusion_decisions(sources, config, Path())
        assert result[0].included is False
        assert result[0].exclusion_reason is not None
        assert "Unconfigured source" in result[0].exclusion_reason


class TestDiscoverSources:
    """Tests for discover_sources function."""

    def test_discover_instruction_files(self):
        """Test discovering instruction files via glob patterns."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            (tmpdir_path / "instructions").mkdir()
            (tmpdir_path / "instructions" / "guide.md").write_text("# Guide")
            (tmpdir_path / "instructions" / "rules.md").write_text("# Rules")
            (tmpdir_path / "other.txt").write_text("Other")

            config = LocalConfig(source_scope=SourceScope(instruction_files=["instructions/*.md"]))

            sources = discover_sources(config, tmpdir_path)
            assert len(sources) == EXPECTED_FILE_COUNT_TWO
            assert all(s.source_class == "instruction" for s in sources)
            assert all(s.configured for s in sources)

    def test_discover_explicit_files(self):
        """Test discovering explicit files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            (tmpdir_path / "explicit.md").write_text("# Explicit")

            config = LocalConfig(
                source_scope=SourceScope(explicit_instruction_files=["explicit.md"])
            )

            sources = discover_sources(config, tmpdir_path)
            assert len(sources) == 1
            assert sources[0].source_class == "explicit"
            assert sources[0].configured is True

    def test_discover_skills_files(self):
        """Test discovering skills/rules directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            skills_dir = tmpdir_path / "skills"
            skills_dir.mkdir()
            (skills_dir / "skill1.md").write_text("# Skill 1")
            (skills_dir / "skill2.md").write_text("# Skill 2")

            config = LocalConfig(source_scope=SourceScope(skills_rules_dir="skills"))

            sources = discover_sources(config, tmpdir_path)
            assert len(sources) == EXPECTED_FILE_COUNT_TWO
            assert all(s.source_class == "skills" for s in sources)

    def test_discover_scoped_files(self):
        """Test discovering files under path scopes."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            src_dir = tmpdir_path / "src"
            src_dir.mkdir()
            (src_dir / "main.py").write_text("print('hello')")
            (src_dir / "utils.py").write_text("def util(): pass")

            config = LocalConfig(source_scope=SourceScope(path_scopes=["src/"]))

            sources = discover_sources(config, tmpdir_path)
            assert len(sources) == EXPECTED_FILE_COUNT_TWO
            assert all(s.source_class == "scoped" for s in sources)

    def test_mark_required_sources(self):
        """Test marking sources as required."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            (tmpdir_path / "README.md").write_text("# Readme")
            (tmpdir_path / "guide.md").write_text("# Guide")

            config = LocalConfig(
                source_scope=SourceScope(instruction_files=["*.md"], required=["README.md"])
            )

            sources = discover_sources(config, tmpdir_path)
            readme_source = next(s for s in sources if s.path.name == "README.md")
            guide_source = next(s for s in sources if s.path.name == "guide.md")
            assert readme_source.required is True
            assert guide_source.required is False

    def test_deduplicate_sources(self):
        """Test deduplication of sources discovered via multiple scopes."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            (tmpdir_path / "README.md").write_text("# Readme")

            config = LocalConfig(
                source_scope=SourceScope(
                    instruction_files=["*.md"],
                    explicit_instruction_files=["README.md"],
                    required=["README.md"],
                )
            )

            sources = discover_sources(config, tmpdir_path)
            # Should only have one source for README.md
            readme_sources = [s for s in sources if s.path.name == "README.md"]
            assert len(readme_sources) == 1
            assert readme_sources[0].required is True
            assert readme_sources[0].configured is True


class TestCollectAuditResult:
    """Tests for collect_audit_result function."""

    def test_collect_audit_result_basic(self):
        """Test collecting audit result with basic sources."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            test_file = tmpdir_path / "test.txt"
            test_file.write_text("Hello, world!")

            sources = [
                SourceRecord(
                    path=test_file,
                    source_class="instruction",
                    required=False,
                    configured=True,
                    readable=True,
                    read_error=None,
                    raw_hash="abc123",
                    included=True,
                    exclusion_reason=None,
                )
            ]

            config = LocalConfig()
            audit_context = AuditContext(
                config=config,
                repo_root=tmpdir_path,
                revision="abc123",
                sources=sources,
                task_brief_hash="task_hash",
                config_hash="config_hash",
            )
            result = collect_audit_result(audit_context)

            assert isinstance(result, AuditResult)
            assert result.total_discovered == 1
            assert result.total_readable == 1
            assert result.total_included == 1
            assert result.total_excluded == 0
            assert result.total_informational == 0
            assert len(result.sources) == 1
            assert result.by_class["instruction"]["discovered"] == 1
            assert result.by_class["instruction"]["readable"] == 1
            assert result.by_class["instruction"]["included"] == 1

    def test_collect_audit_result_with_excluded(self):
        """Test collecting audit result with excluded sources."""
        sources = [
            SourceRecord(
                path=Path("included.txt"),
                source_class="instruction",
                required=False,
                configured=True,
                readable=True,
                read_error=None,
                raw_hash="abc123",
                included=True,
                exclusion_reason=None,
            ),
            SourceRecord(
                path=Path("excluded.txt"),
                source_class="explicit",
                required=False,
                configured=True,
                readable=False,
                read_error="File not found",
                raw_hash=None,
                included=False,
                exclusion_reason="Optional source unreadable: File not found",
            ),
            SourceRecord(
                path=Path("informational.txt"),
                source_class="instruction",
                required=True,
                configured=False,
                readable=True,
                read_error=None,
                raw_hash="def456",
                included=False,
                exclusion_reason="Unconfigured source",
            ),
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            config = LocalConfig()
            audit_context = AuditContext(
                config=config,
                repo_root=Path(tmpdir),
                revision="abc123",
                sources=sources,
                task_brief_hash="task_hash",
                config_hash="config_hash",
            )
            result = collect_audit_result(audit_context)

            assert result.total_discovered == EXPECTED_FILE_COUNT_THREE
            assert result.total_readable == EXPECTED_FILE_COUNT_TWO
            assert result.total_included == 1
            assert result.total_excluded == 1
            assert result.total_informational == 1
            assert result.by_class["instruction"]["discovered"] == EXPECTED_FILE_COUNT_TWO
            assert result.by_class["explicit"]["discovered"] == 1


class TestAuditResult:
    """Tests for AuditResult dataclass."""

    def test_audit_result_defaults(self):
        """Test AuditResult default values."""
        result = AuditResult()
        assert result.sources == []
        assert result.total_discovered == 0
        assert result.total_readable == 0
        assert result.total_included == 0
        assert result.total_excluded == 0
        assert result.total_conflicts == 0
        assert result.total_informational == 0
        assert "instruction" in result.by_class
        assert "explicit" in result.by_class
        assert "skills" in result.by_class
        assert "scoped" in result.by_class


class TestFullAuditPipeline:
    """Integration tests for the full audit pipeline."""

    def test_full_audit_pipeline(self):
        """Test the complete audit pipeline: discover -> assess -> decide -> collect."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            # Create test files
            (tmpdir_path / "README.md").write_text("# Readme")
            (tmpdir_path / "guide.md").write_text("# Guide")
            instructions_dir = tmpdir_path / "instructions"
            instructions_dir.mkdir()
            (instructions_dir / "rule.md").write_text("# Rule")

            # Create config
            config = LocalConfig(
                source_scope=SourceScope(
                    instruction_files=["*.md", "instructions/*.md"],
                    explicit_instruction_files=["README.md"],
                    required=["README.md"],
                )
            )

            # Run full pipeline
            sources = discover_sources(config, tmpdir_path)
            sources = assess_readability(sources, tmpdir_path)
            sources = make_inclusion_decisions(sources, config, tmpdir_path)
            audit_context = AuditContext(
                config=config,
                repo_root=tmpdir_path,
                revision="abc123",
                sources=sources,
                task_brief_hash="task_hash",
                config_hash="config_hash",
            )
            result = collect_audit_result(audit_context)

            # Verify results
            assert result.total_discovered == EXPECTED_FILE_COUNT_THREE
            assert result.total_readable == EXPECTED_FILE_COUNT_THREE
            assert result.total_included == EXPECTED_FILE_COUNT_THREE
            assert result.total_excluded == 0
            assert result.total_informational == 0

            # Check README.md is marked as required
            readme_src = next(s for s in result.sources if s.path.name == "README.md")
            assert readme_src.required is True
            assert readme_src.included is True

    def test_full_audit_with_missing_required(self):
        """Test audit with missing required file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            (tmpdir_path / "guide.md").write_text("# Guide")

            config = LocalConfig(
                source_scope=SourceScope(
                    instruction_files=["*.md"],
                    required=["README.md"],  # This file doesn't exist
                )
            )

            sources = discover_sources(config, tmpdir_path)
            sources = assess_readability(sources, tmpdir_path)
            sources = make_inclusion_decisions(sources, config, tmpdir_path)
            audit_context = AuditContext(
                config=config,
                repo_root=tmpdir_path,
                revision="abc123",
                sources=sources,
                task_brief_hash="task_hash",
                config_hash="config_hash",
            )
            result = collect_audit_result(audit_context)

            # Only guide.md should be discovered
            assert result.total_discovered == 1
            # The missing required file is not in sources (handled at compile time)

    def test_full_audit_with_unreadable_optional(self):
        """Test audit with unreadable optional file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            (tmpdir_path / "README.md").write_text("# Readme")
            # missing.txt doesn't exist

            config = LocalConfig(
                source_scope=SourceScope(
                    instruction_files=["*.md"],
                    explicit_instruction_files=["missing.txt"],
                )
            )

            sources = discover_sources(config, tmpdir_path)
            sources = assess_readability(sources, tmpdir_path)
            sources = make_inclusion_decisions(sources, config, tmpdir_path)
            audit_context = AuditContext(
                config=config,
                repo_root=tmpdir_path,
                revision="abc123",
                sources=sources,
                task_brief_hash="task_hash",
                config_hash="config_hash",
            )
            result = collect_audit_result(audit_context)

            assert result.total_discovered == EXPECTED_FILE_COUNT_TWO
            assert result.total_readable == 1
            assert result.total_included == 1
            assert result.total_excluded == 1
            assert result.total_informational == 0

            # Check the excluded source
            missing_src = next(s for s in result.sources if s.path.name == "missing.txt")
            assert missing_src.included is False
            assert "Optional source unreadable" in missing_src.exclusion_reason
