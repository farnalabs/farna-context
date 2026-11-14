"""Local Config schema for Farna Context."""

import json
from pathlib import Path

from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Error messages
ERR_UNSAFE_PATH = "Unsafe path"
ERR_UNKNOWN_HARNESS = "Unknown harness fixture"
DRIVE_LETTER_MIN_LENGTH = 2


class SourceScope(BaseModel):
    """Configuration for source discovery scope."""

    instruction_files: list[str] = Field(
        default_factory=list,
        description="Glob patterns for instruction files to include",
    )
    explicit_instruction_files: list[str] = Field(
        default_factory=list,
        description="Explicit file paths to include (bypasses glob matching)",
    )
    skills_rules_dir: str | None = Field(
        default=None,
        description="Directory containing skills/rules to include",
    )
    path_scopes: list[str] = Field(
        default_factory=list,
        description="Path prefixes to restrict source discovery to",
    )
    precedence: list[str] = Field(
        default_factory=list,
        description="Precedence order for conflicting sources",
    )
    required: list[str] = Field(
        default_factory=list,
        description="Required source patterns that must match at least one file",
    )

    @field_validator(
        "instruction_files",
        "explicit_instruction_files",
        "path_scopes",
        "precedence",
        "required",
        mode="before",
    )
    @classmethod
    def validate_paths(cls, v: list[str]) -> list[str]:
        """Validate that paths are repository-relative and safe."""
        for path in v:
            if not cls._is_safe_path(path):
                raise ValueError(ERR_UNSAFE_PATH)
        return v

    @staticmethod
    def _is_safe_path(path: str) -> bool:
        """Check if a path is repository-relative and safe."""
        # No absolute paths
        if Path(path).is_absolute():
            return False
        # No drive letters (Windows)
        if len(path) >= DRIVE_LETTER_MIN_LENGTH and path[1] == ":":
            return False
        # No UNC paths
        if path.startswith("\\\\") or path.startswith("//"):
            return False
        # No NUL device
        if path.upper() == "NUL" or path.upper().startswith("NUL."):
            return False
        # No parent directory traversal
        if ".." in Path(path).parts:
            return False
        # No alternate data streams (Windows)
        has_colon = ":" in path
        is_drive_letter = len(path) >= DRIVE_LETTER_MIN_LENGTH and path[1] == ":"
        return not (has_colon and not is_drive_letter)


class TaskOverlay(BaseModel):
    """Task-specific overlay configuration."""

    task_brief_path: str | None = Field(
        default=None,
        description="Path to task brief file",
    )
    extra_sources: list[str] = Field(
        default_factory=list,
        description="Additional source patterns for this task",
    )
    exclude_patterns: list[str] = Field(
        default_factory=list,
        description="Patterns to exclude from source discovery",
    )

    @field_validator("task_brief_path", "extra_sources", "exclude_patterns", mode="before")
    @classmethod
    def validate_paths(cls, v: list[str] | str | None) -> list[str] | str | None:
        """Validate that paths are repository-relative and safe."""
        if v is None:
            return v
        paths = [v] if isinstance(v, str) else v
        for path in paths:
            if path and not SourceScope._is_safe_path(path):
                raise ValueError(ERR_UNSAFE_PATH)
        return v


class OutputFiles(BaseModel):
    """Output file configuration."""

    manifest: str = Field(
        default="manifest.yaml",
        description="Manifest output file name",
    )
    context_pack: str = Field(
        default="context_pack.zip",
        description="Context pack output file name",
    )
    receipt: str = Field(
        default="receipt.json",
        description="Receipt output file name",
    )


class SecretPatterns(BaseModel):
    """Secret detection patterns."""

    patterns: list[str] = Field(
        default_factory=lambda: [
            r"(?i)(api[_-]?key|secret|token|password|passwd)\s*[:=]\s*['\"]?[a-zA-Z0-9_\-]{20,}['\"]?",
            r"(?i)(aws[_-]?access[_-]?key|aws[_-]?secret[_-]?key)\s*[:=]\s*['\"]?[A-Z0-9]{20,}['\"]?",
            r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
            r"sk-[a-zA-Z0-9]{32,}",
            r"gh[pousr]_[a-zA-Z0-9]{36,}",
            r"xox[baprs]-[a-zA-Z0-9-]{10,}",
        ],
        description="Regex patterns for secret detection",
    )
    exclude_paths: list[str] = Field(
        default_factory=list,
        description="Paths to exclude from secret scanning",
    )

    @field_validator("exclude_paths", mode="before")
    @classmethod
    def validate_paths(cls, v: list[str]) -> list[str]:
        """Validate that paths are repository-relative and safe."""
        for path in v:
            if not SourceScope._is_safe_path(path):
                raise ValueError(ERR_UNSAFE_PATH)
        return v


class LocalConfig(BaseSettings):
    """Local configuration for Farna Context."""

    model_config = SettingsConfigDict(
        env_prefix="FARNA_CONTEXT_",
        case_sensitive=False,
        extra="ignore",
    )

    repo_root: str = Field(
        default=".",
        description="Repository root path (relative to config file location)",
    )
    revision: str | None = Field(
        default=None,
        description="Git revision to use (defaults to HEAD)",
    )
    source_scope: SourceScope = Field(
        default_factory=SourceScope,
        description="Source discovery scope configuration",
    )
    harness_fixture: str = Field(
        default="opencode",
        description="Harness fixture identifier",
    )
    task_brief_path: str | None = Field(
        default=None,
        description="Path to task brief file",
    )
    staging_parent: str = Field(
        default=".farna-context/staging",
        description="Parent directory for staging area",
    )
    task_overlay: TaskOverlay = Field(
        default_factory=TaskOverlay,
        description="Task-specific overlay configuration",
    )
    output_files: OutputFiles = Field(
        default_factory=OutputFiles,
        description="Output file names",
    )
    secret_patterns: SecretPatterns = Field(
        default_factory=SecretPatterns,
        description="Secret detection patterns",
    )

    @field_validator("repo_root", "staging_parent", "task_brief_path", mode="before")
    @classmethod
    def validate_repo_paths(cls, v: str | None) -> str | None:
        """Validate repository-relative paths."""
        if v is None:
            return v
        if not SourceScope._is_safe_path(v):
            raise ValueError(ERR_UNSAFE_PATH)
        return v

    @field_validator("harness_fixture")
    @classmethod
    def validate_harness_fixture(cls, v: str) -> str:
        """Validate harness fixture is known."""
        known = {"opencode", "claude", "cursor", "generic"}
        if v not in known:
            raise ValueError(ERR_UNKNOWN_HARNESS)
        return v

    def get_repo_root_path(self, config_dir: Path) -> Path:
        """Resolve repo_root to an absolute path."""
        repo_root = Path(self.repo_root)
        if repo_root.is_absolute():
            return repo_root.resolve()
        return (config_dir / repo_root).resolve()

    def get_staging_path(self, config_dir: Path) -> Path:
        """Resolve staging_parent to an absolute path."""
        staging = Path(self.staging_parent)
        if staging.is_absolute():
            return staging.resolve()
        return (config_dir / staging).resolve()


def load_config(config_path: Path) -> LocalConfig:
    """Load configuration from a JSON file."""
    with config_path.open() as f:
        data = json.load(f)
    return LocalConfig(**data)


def save_config(config: LocalConfig, config_path: Path) -> None:
    """Save configuration to a JSON file."""
    config_path.parent.mkdir(parents=True, exist_ok=True)
    with config_path.open("w") as f:
        json.dump(config.model_dump(mode="json"), f, indent=2)
