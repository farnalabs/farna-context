"""Local Config schema for Farna Context."""

import json
import stat
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Error messages
ERR_UNSAFE_PATH = "Unsafe path"
ERR_UNKNOWN_HARNESS = "Unknown harness fixture"
DRIVE_LETTER_MIN_LENGTH = 2


def _is_safe_operational_path(value: str) -> bool:
    """Reject device, traversal, ADS, and malformed operational paths."""
    if not value or "\x00" in value:
        return False
    normalised = value.replace("\\", "/")
    path = Path(normalised)
    has_drive_prefix = len(normalised) >= DRIVE_LETTER_MIN_LENGTH and normalised[1] == ":"
    if normalised.startswith("//") or (has_drive_prefix and not path.is_absolute()):
        return False
    if any(part == ".." for part in path.parts):
        return False
    if any(
        ":" in part and not (len(part) == DRIVE_LETTER_MIN_LENGTH and part[1] == ":")
        for part in path.parts
    ):
        return False
    return not any(part.upper() == "NUL" or part.upper().startswith("NUL.") for part in path.parts)


def _resolve_operational_path(value: str, base: Path) -> Path:
    """Resolve an operational path while retaining links for safety checks."""
    path = Path(value)
    return path if path.is_absolute() else base / path


def _reject_reparse_components(path: Path) -> None:
    """Reject symlink/reparse components in an operational path."""
    current = Path(path.anchor) if path.anchor else Path()
    for component in path.parts if not path.anchor else path.parts[1:]:
        current /= component
        if current.is_symlink():
            raise ValueError(ERR_UNSAFE_PATH)


def _require_regular_path(path: Path, *, directory: bool = False) -> Path:
    """Require a regular existing file or directory, without symlink traversal."""
    try:
        _reject_reparse_components(path)
        if not path.exists():
            raise ValueError(ERR_UNSAFE_PATH)
        mode = path.stat().st_mode
    except OSError as exc:
        raise ValueError(ERR_UNSAFE_PATH) from exc
    if directory and not stat.S_ISDIR(mode):
        raise ValueError(ERR_UNSAFE_PATH)
    if not directory and not stat.S_ISREG(mode):
        raise ValueError(ERR_UNSAFE_PATH)
    return path


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

    @field_validator("task_brief_path", mode="before")
    @classmethod
    def validate_task_brief_path(cls, v: str | None) -> str | None:
        """Validate the operational task brief path."""
        if v is not None and not _is_safe_operational_path(v):
            raise ValueError(ERR_UNSAFE_PATH)
        return v

    @field_validator("extra_sources", "exclude_patterns", mode="before")
    @classmethod
    def validate_source_paths(cls, v: list[str]) -> list[str]:
        """Validate repository-relative overlay source paths."""
        for path in v:
            if not SourceScope._is_safe_path(path):
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
    """Fixture-versioned literal values and named fixed detectors."""

    literal_values: list[str] = Field(default_factory=list)
    named_detectors: list[str] = Field(default_factory=list)
    patterns: list[str] = Field(default_factory=list, description="Legacy field; not executed")
    exclude_paths: list[str] = Field(default_factory=list)

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
    def validate_operational_paths(cls, v: str | None) -> str | None:
        """Validate designated operational paths, which may be absolute."""
        if v is None:
            return v
        if not isinstance(v, str) or not _is_safe_operational_path(v):
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
        """Resolve and validate repo_root as a regular directory."""
        path = _resolve_operational_path(self.repo_root, config_dir)
        return _require_regular_path(path, directory=True)

    def get_staging_path(self, config_dir: Path) -> Path:
        """Resolve staging_parent as a safe directory location."""
        path = _resolve_operational_path(self.staging_parent, config_dir)
        _reject_reparse_components(path.parent)
        path.mkdir(parents=True, exist_ok=True)
        return _require_regular_path(path, directory=True)

    def get_task_brief_path(self, config_dir: Path) -> Path | None:
        """Resolve and validate the configured regular task brief, if any."""
        value = self.task_overlay.task_brief_path or self.task_brief_path
        if value is None:
            return None
        return _require_regular_path(_resolve_operational_path(value, config_dir))


def _normalise_fixture_data(data: dict[str, Any]) -> dict[str, Any]:
    """Adapt the signed-off dogfood fixture shape to the typed config model."""
    normalised = dict(data)
    raw_sources = normalised.pop("sources", None)
    if isinstance(normalised.get("source_scope"), str):
        normalised.pop("source_scope")
    if isinstance(raw_sources, dict):
        normalised["source_scope"] = {
            "instruction_files": raw_sources.get("instruction_files", []),
            "explicit_instruction_files": raw_sources.get("explicit_instruction_files", []),
            "skills_rules_dir": raw_sources.get("skills_rules_dir"),
            "path_scopes": list(raw_sources.get("path_scopes", {}).keys()),
            "precedence": list(raw_sources.get("precedence", {}).keys()),
            "required": list(raw_sources.get("required", {}).keys()),
        }
    raw_output = normalised.get("output_files")
    if isinstance(raw_output, list):
        normalised["output_files"] = OutputFiles()
    return normalised


def load_config(config_path: Path) -> LocalConfig:
    """Load configuration from a JSON file."""
    with config_path.open() as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise TypeError("Config must be a JSON object")  # noqa: TRY003
    return LocalConfig(**_normalise_fixture_data(data))


def save_config(config: LocalConfig, config_path: Path) -> None:
    """Save configuration to a JSON file."""
    config_path.parent.mkdir(parents=True, exist_ok=True)
    with config_path.open("w") as f:
        json.dump(config.model_dump(mode="json"), f, indent=2)
