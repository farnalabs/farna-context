"""Tests for config module."""

import tempfile
from pathlib import Path

import pytest

from src.farna_context.config import (
    LocalConfig,
    SourceScope,
    TaskOverlay,
    OutputFiles,
    SecretPatterns,
    load_config,
    save_config,
)


class TestSourceScope:
    """Tests for SourceScope validation."""

    def test_valid_paths(self):
        """Test that valid relative paths are accepted."""
        scope = SourceScope(
            instruction_files=["*.md", "docs/**/*.md"],
            explicit_instruction_files=["README.md", "src/main.py"],
            path_scopes=["src/", "tests/"],
            precedence=["explicit", "instruction"],
            required=["README.md"],
        )
        assert scope.instruction_files == ["*.md", "docs/**/*.md"]

    def test_absolute_path_rejected(self):
        """Test that absolute paths are rejected."""
        with pytest.raises(ValueError, match="Unsafe path"):
            SourceScope(instruction_files=["/absolute/path"])

    def test_parent_traversal_rejected(self):
        """Test that parent directory traversal is rejected."""
        with pytest.raises(ValueError, match="Unsafe path"):
            SourceScope(instruction_files=["../outside"])

    def test_drive_letter_rejected(self):
        """Test that Windows drive letters are rejected."""
        with pytest.raises(ValueError, match="Unsafe path"):
            SourceScope(instruction_files=["C:\\path"])

    def test_unc_path_rejected(self):
        """Test that UNC paths are rejected."""
        with pytest.raises(ValueError, match="Unsafe path"):
            SourceScope(instruction_files=["//server/share"])

    def test_nul_device_rejected(self):
        """Test that NUL device is rejected."""
        with pytest.raises(ValueError, match="Unsafe path"):
            SourceScope(instruction_files=["NUL"])

    def test_alternate_data_stream_rejected(self):
        """Test that alternate data streams are rejected."""
        with pytest.raises(ValueError, match="Unsafe path"):
            SourceScope(instruction_files=["file:stream"])


class TestTaskOverlay:
    """Tests for TaskOverlay validation."""

    def test_valid_paths(self):
        """Test that valid relative paths are accepted."""
        overlay = TaskOverlay(
            task_brief_path="brief.md",
            extra_sources=["extra/*.md"],
            exclude_patterns=["*.tmp"],
        )
        assert overlay.task_brief_path == "brief.md"

    def test_none_values_allowed(self):
        """Test that None values are allowed."""
        overlay = TaskOverlay(task_brief_path=None)
        assert overlay.task_brief_path is None


class TestLocalConfig:
    """Tests for LocalConfig."""

    def test_default_config(self):
        """Test default configuration values."""
        config = LocalConfig()
        assert config.repo_root == "."
        assert config.harness_fixture == "opencode"
        assert config.staging_parent == ".farna-context/staging"
        assert isinstance(config.source_scope, SourceScope)
        assert isinstance(config.task_overlay, TaskOverlay)
        assert isinstance(config.output_files, OutputFiles)
        assert isinstance(config.secret_patterns, SecretPatterns)

    def test_harness_fixture_validation(self):
        """Test harness fixture validation."""
        config = LocalConfig(harness_fixture="opencode")
        assert config.harness_fixture == "opencode"

        with pytest.raises(ValueError, match="Unknown harness fixture"):
            LocalConfig(harness_fixture="unknown")

    def test_repo_root_path_resolution(self):
        """Test repo root path resolution."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            # Config file is in repo root
            config_dir = tmpdir_path

            # Test with current directory
            config = LocalConfig(repo_root=".")
            resolved = config.get_repo_root_path(config_dir)
            assert resolved == tmpdir_path.resolve()

    def test_staging_path_resolution(self):
        """Test staging path resolution."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            config_dir = tmpdir_path / ".farna-context"
            config_dir.mkdir()

            config = LocalConfig(staging_parent="staging")
            resolved = config.get_staging_path(config_dir)
            assert resolved == (tmpdir_path / ".farna-context" / "staging").resolve()


class TestConfigPersistence:
    """Tests for config load/save."""

    def test_save_and_load(self):
        """Test saving and loading config."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.json"

            config = LocalConfig(
                repo_root=".",
                harness_fixture="claude",
                staging_parent="custom/staging",
            )
            save_config(config, config_path)

            loaded = load_config(config_path)
            assert loaded.repo_root == "."
            assert loaded.harness_fixture == "claude"
            assert loaded.staging_parent == "custom/staging"