"""Tests for git module."""

import subprocess
import tempfile
from pathlib import Path

import pytest

from src.farna_context.constants import ExitCode
from src.farna_context.git import (
    GitError,
    check_dirty_tree,
    get_repo_root,
    get_revision,
    is_repo_clean,
)


class TestGitUtils:
    """Tests for Git utilities."""

    def test_get_repo_root(self):
        """Test finding repo root from subdirectory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_path = Path(tmpdir) / "test_repo"
            repo_path.mkdir()

            # Initialize git repo
            subprocess.run(["git", "init"], cwd=repo_path, check=True, capture_output=True)
            subprocess.run(
                ["git", "config", "user.email", "test@test.com"], cwd=repo_path, check=True
            )
            subprocess.run(["git", "config", "user.name", "Test"], cwd=repo_path, check=True)

            # Create a file and commit
            (repo_path / "README.md").write_text("# Test")
            subprocess.run(["git", "add", "README.md"], cwd=repo_path, check=True)
            subprocess.run(["git", "commit", "-m", "Initial"], cwd=repo_path, check=True)

            # Create subdirectory
            subdir = repo_path / "sub" / "dir"
            subdir.mkdir(parents=True)

            # Should find repo root from subdirectory
            found_root = get_repo_root(subdir)
            assert found_root == repo_path.resolve()

    def test_get_repo_root_not_found(self):
        """Test error when no git repo found."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with pytest.raises(GitError) as exc_info:
                get_repo_root(Path(tmpdir))
            assert exc_info.value.exit_code == ExitCode.REPO_NOT_FOUND

    def test_get_revision(self):
        """Test getting HEAD revision."""
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_path = Path(tmpdir) / "test_repo"
            repo_path.mkdir()

            subprocess.run(["git", "init"], cwd=repo_path, check=True, capture_output=True)
            subprocess.run(
                ["git", "config", "user.email", "test@test.com"], cwd=repo_path, check=True
            )
            subprocess.run(["git", "config", "user.name", "Test"], cwd=repo_path, check=True)

            (repo_path / "README.md").write_text("# Test")
            subprocess.run(["git", "add", "README.md"], cwd=repo_path, check=True)
            subprocess.run(["git", "commit", "-m", "Initial"], cwd=repo_path, check=True)

            revision = get_revision(repo_path)
            assert len(revision) == 40  # noqa: PLR2004
            assert all(c in "0123456789abcdef" for c in revision)

    def test_check_dirty_tree_clean(self):
        """Test clean tree detection."""
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_path = Path(tmpdir) / "test_repo"
            repo_path.mkdir()

            subprocess.run(["git", "init"], cwd=repo_path, check=True, capture_output=True)
            subprocess.run(
                ["git", "config", "user.email", "test@test.com"], cwd=repo_path, check=True
            )
            subprocess.run(["git", "config", "user.name", "Test"], cwd=repo_path, check=True)

            (repo_path / "README.md").write_text("# Test")
            subprocess.run(["git", "add", "README.md"], cwd=repo_path, check=True)
            subprocess.run(["git", "commit", "-m", "Initial"], cwd=repo_path, check=True)

            changed = check_dirty_tree(repo_path)
            assert changed == []

            is_clean = is_repo_clean(repo_path)
            assert is_clean is True

    def test_check_dirty_tree_unstaged(self):
        """Test detection of unstaged changes."""
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_path = Path(tmpdir) / "test_repo"
            repo_path.mkdir()

            subprocess.run(["git", "init"], cwd=repo_path, check=True, capture_output=True)
            subprocess.run(
                ["git", "config", "user.email", "test@test.com"], cwd=repo_path, check=True
            )
            subprocess.run(["git", "config", "user.name", "Test"], cwd=repo_path, check=True)

            (repo_path / "README.md").write_text("# Test")
            subprocess.run(["git", "add", "README.md"], cwd=repo_path, check=True)
            subprocess.run(["git", "commit", "-m", "Initial"], cwd=repo_path, check=True)

            # Modify file without staging
            (repo_path / "README.md").write_text("# Modified")

            changed = check_dirty_tree(repo_path)
            assert "README.md" in changed

            is_clean = is_repo_clean(repo_path)
            assert is_clean is False

    def test_check_dirty_tree_staged(self):
        """Test detection of staged changes."""
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_path = Path(tmpdir) / "test_repo"
            repo_path.mkdir()

            subprocess.run(["git", "init"], cwd=repo_path, check=True, capture_output=True)
            subprocess.run(
                ["git", "config", "user.email", "test@test.com"], cwd=repo_path, check=True
            )
            subprocess.run(["git", "config", "user.name", "Test"], cwd=repo_path, check=True)

            (repo_path / "README.md").write_text("# Test")
            subprocess.run(["git", "add", "README.md"], cwd=repo_path, check=True)
            subprocess.run(["git", "commit", "-m", "Initial"], cwd=repo_path, check=True)

            # Modify and stage
            (repo_path / "README.md").write_text("# Staged")
            subprocess.run(["git", "add", "README.md"], cwd=repo_path, check=True)

            changed = check_dirty_tree(repo_path)
            assert "README.md" in changed

    def test_check_dirty_tree_untracked(self):
        """Test detection of untracked files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_path = Path(tmpdir) / "test_repo"
            repo_path.mkdir()

            subprocess.run(["git", "init"], cwd=repo_path, check=True, capture_output=True)
            subprocess.run(
                ["git", "config", "user.email", "test@test.com"], cwd=repo_path, check=True
            )
            subprocess.run(["git", "config", "user.name", "Test"], cwd=repo_path, check=True)

            (repo_path / "README.md").write_text("# Test")
            subprocess.run(["git", "add", "README.md"], cwd=repo_path, check=True)
            subprocess.run(["git", "commit", "-m", "Initial"], cwd=repo_path, check=True)

            # Add untracked file
            (repo_path / "new_file.txt").write_text("new")

            changed = check_dirty_tree(repo_path)
            assert "new_file.txt" in changed

    def test_check_dirty_tree_with_scope(self):
        """Test dirty tree check with scope filter."""
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_path = Path(tmpdir) / "test_repo"
            repo_path.mkdir()

            subprocess.run(["git", "init"], cwd=repo_path, check=True, capture_output=True)
            subprocess.run(
                ["git", "config", "user.email", "test@test.com"], cwd=repo_path, check=True
            )
            subprocess.run(["git", "config", "user.name", "Test"], cwd=repo_path, check=True)

            (repo_path / "README.md").write_text("# Test")
            src_dir = repo_path / "src"
            src_dir.mkdir()
            (src_dir / "main.py").write_text("print('hello')")
            subprocess.run(["git", "add", "."], cwd=repo_path, check=True)
            subprocess.run(["git", "commit", "-m", "Initial"], cwd=repo_path, check=True)

            # Modify both
            (repo_path / "README.md").write_text("# Modified")
            (repo_path / "src" / "main.py").write_text("print('world')")

            # Check only src/
            changed = check_dirty_tree(repo_path, scope=["src/"])
            assert "src/main.py" in changed
            assert "README.md" not in changed
