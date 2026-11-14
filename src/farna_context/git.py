"""Git utilities for Farna Context."""

from pathlib import Path

from git import GitCommandError, InvalidGitRepositoryError, Repo

from .constants import ExitCode

# Error messages
ERR_NO_REPO = "No Git repository found"
ERR_INVALID_REPO = "Not a valid Git repository"
ERR_HEAD_REVISION = "Failed to get HEAD revision"
ERR_TRACKED_CHANGES = "Failed to check tracked changes"
ERR_UNTRACKED_FILES = "Failed to check untracked files"


class GitError(Exception):
    """Git operation error with exit code."""

    def __init__(self, message: str, exit_code: ExitCode = ExitCode.GIT_ERROR) -> None:
        super().__init__(message)
        self.exit_code = exit_code


def get_repo_root(path: Path | str) -> Path:
    """Find the Git repository root from a given path.

    Args:
        path: Starting path to search from.

    Returns:
        Absolute path to the repository root.

    Raises:
        GitError: If no Git repository is found.
    """
    path = Path(path).resolve()
    try:
        repo = Repo(path, search_parent_directories=True)
        working_dir = repo.working_tree_dir
        if working_dir is None:
            raise GitError(ERR_INVALID_REPO, ExitCode.REPO_NOT_FOUND)
        return Path(working_dir).resolve()
    except InvalidGitRepositoryError as e:
        raise GitError(ERR_NO_REPO, ExitCode.REPO_NOT_FOUND) from e


def get_revision(repo_root: Path | str) -> str:
    """Get the exact HEAD SHA of the repository.

    Args:
        repo_root: Path to the repository root.

    Returns:
        Full 40-character SHA of HEAD.

    Raises:
        GitError: If the repository is not valid or HEAD cannot be resolved.
    """
    repo_root = Path(repo_root).resolve()
    try:
        repo = Repo(repo_root)
    except InvalidGitRepositoryError as e:
        raise GitError(ERR_INVALID_REPO, ExitCode.REPO_NOT_FOUND) from e
    else:
        head_commit = repo.head.commit
        return head_commit.hexsha
    try:
        return head_commit.hexsha
    except (ValueError, GitCommandError) as e:
        raise GitError(ERR_HEAD_REVISION, ExitCode.GIT_ERROR) from e


def check_dirty_tree(repo_root: Path | str, scope: list[str] | None = None) -> list[str]:
    """Check for tracked or untracked changes under the given scope.

    Args:
        repo_root: Path to the repository root.
        scope: Optional list of path prefixes to restrict the check to.
               If None, checks the entire repository.

    Returns:
        List of changed file paths (relative to repo_root). Empty if clean.

    Raises:
        GitError: If the repository is not valid.
    """
    repo_root = Path(repo_root).resolve()
    try:
        repo = Repo(repo_root)
    except InvalidGitRepositoryError as e:
        raise GitError(ERR_INVALID_REPO, ExitCode.REPO_NOT_FOUND) from e

    changed_files = []

    # Check tracked changes (staged and unstaged)
    try:
        diff_index = repo.index.diff(None)  # unstaged
        diff_staged = repo.index.diff("HEAD")  # staged
        for diff in list(diff_index) + list(diff_staged):
            file_path = diff.a_path or diff.b_path
            if file_path and _matches_scope(file_path, scope):
                changed_files.append(file_path)
    except GitCommandError as e:
        raise GitError(ERR_TRACKED_CHANGES, ExitCode.GIT_ERROR) from e

    # Check untracked files
    try:
        untracked = repo.untracked_files
        for file_path in untracked:
            if _matches_scope(file_path, scope):
                changed_files.append(file_path)
    except GitCommandError as e:
        raise GitError(ERR_UNTRACKED_FILES, ExitCode.GIT_ERROR) from e

    return sorted(set(changed_files))


def _matches_scope(file_path: str, scope: list[str] | None) -> bool:
    """Check if a file path matches any of the scope prefixes."""
    if scope is None:
        return True
    for prefix in scope:
        if file_path.startswith(prefix.rstrip("/") + "/") or file_path == prefix:
            return True
    return False


def get_current_branch(repo_root: Path | str) -> str | None:
    """Get the current branch name.

    Args:
        repo_root: Path to the repository root.

    Returns:
        Current branch name, or None if in detached HEAD state.
    """
    repo_root = Path(repo_root).resolve()
    try:
        repo = Repo(repo_root)
    except (InvalidGitRepositoryError, TypeError, AttributeError):
        return None
    else:
        if repo.head.is_detached:
            return None
        return repo.active_branch.name


def is_repo_clean(repo_root: Path | str, scope: list[str] | None = None) -> bool:
    """Check if the repository has no changes under the given scope.

    Args:
        repo_root: Path to the repository root.
        scope: Optional list of path prefixes to restrict the check to.

    Returns:
        True if no changes, False otherwise.
    """
    changed = check_dirty_tree(repo_root, scope)
    return len(changed) == 0
