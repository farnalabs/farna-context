# ruff: noqa: TRY003

"""Typed alpha context delivery domain model.

Alpha context items are explicit about whether they are instructions or references:
``rule`` items are scoped instructions, ``general`` items are bounded unscoped
context, ``artefact`` items are opaque references, and ``shadow_file`` items are
generated runtime files. Shadow files are delivery materialisations, never
authority sources. This module contains validation and filesystem preflight only;
it does not write files, edit ``.gitignore``, or handle secrets.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
from collections.abc import Callable
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

MAX_ARTEFACT_SIZE_BYTES = 10 * 1024 * 1024
MAX_GENERAL_SIZE_BYTES = 256 * 1024
_MIME_RE = re.compile(r"^[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*$")
_ALLOWED_SHADOW_NAMES = frozenset({"AGENTS.md", "CLAUDE.md"})
_CONTROL_CHAR_LIMIT = 32


class ContextType(StrEnum):
    """The four explicit alpha context domains."""

    RULE = "rule"
    GENERAL = "general"
    ARTEFACT = "artefact"
    SHADOW_FILE = "shadow_file"


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class RuleScope(_StrictModel):
    """Repository-relative selection scope for a rule."""

    path_glob: str | None = None
    operation_scope: str | None = None

    @field_validator("path_glob")
    @classmethod
    def validate_path_glob(cls, value: str | None) -> str | None:
        if value is None:
            return value
        _validate_relative_pattern(value, label="path glob")
        return value

    @field_validator("operation_scope")
    @classmethod
    def validate_operation_scope(cls, value: str | None) -> str | None:
        if value is None:
            return value
        if not value.strip() or any(ord(char) < _CONTROL_CHAR_LIMIT for char in value):
            raise ValueError("operation scope must be a non-empty safe string")  # noqa: TRY003
        return value

    @model_validator(mode="after")
    def require_scope(self) -> Self:
        if self.path_glob is None and self.operation_scope is None:
            raise ValueError("a rule scope needs a path_glob or operation_scope")  # noqa: TRY003
        return self


class ArtefactMetadata(_StrictModel):
    """Metadata for an opaque reference artefact; content is never held here."""

    mime_type: str
    extension: str | None = None
    size_bytes: int = Field(ge=0, le=MAX_ARTEFACT_SIZE_BYTES)
    sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @field_validator("mime_type")
    @classmethod
    def validate_mime_type(cls, value: str) -> str:
        if not _MIME_RE.fullmatch(value.lower()):
            raise ValueError("mime_type must be a valid type/subtype")  # noqa: TRY003
        return value.lower()

    @field_validator("extension")
    @classmethod
    def validate_extension(cls, value: str | None) -> str | None:
        if value is None:
            return value
        if not re.fullmatch(r"\.[a-z0-9][a-z0-9._-]*", value.lower()):
            raise ValueError("extension must be a simple file extension")  # noqa: TRY003
        return value.lower()

    @model_validator(mode="after")
    def validate_common_metadata(self) -> Self:
        if self.extension == ".pdf" and self.mime_type != "application/pdf":
            raise ValueError(".pdf artefacts must use application/pdf")
        if self.extension in {".md", ".markdown"} and self.mime_type not in {
            "text/markdown",
            "text/plain",
        }:
            raise ValueError("Markdown extensions need a text/markdown or text/plain MIME type")
        return self


class ShadowFilePolicy(_StrictModel):
    """Policy for a generated harness-convention file."""

    destination: str
    overwrite: bool = False
    generated: bool = True

    @field_validator("destination")
    @classmethod
    def validate_destination(cls, value: str) -> str:
        _validate_relative_pattern(value, label="shadow destination", allow_glob=False)
        path = PurePosixPath(value)
        if path.name not in _ALLOWED_SHADOW_NAMES:
            raise ValueError("shadow destination must end in AGENTS.md or CLAUDE.md")
        if ".git" in path.parts:
            raise ValueError("shadow destination cannot be inside .git")
        return value

    @model_validator(mode="after")
    def require_generated(self) -> Self:
        if not self.generated:
            raise ValueError("shadow files must be marked as generated")
        return self


class ContextItem(_StrictModel):
    """A validated context item without content or secret-bearing values."""

    item_id: str = Field(min_length=1)
    context_type: ContextType
    source_path: str = Field(min_length=1)
    rule_scope: RuleScope | None = None
    artefact_metadata: ArtefactMetadata | None = None
    shadow_file_policy: ShadowFilePolicy | None = None
    instructional: bool = False
    size_bytes: int = Field(default=0, ge=0, le=MAX_GENERAL_SIZE_BYTES)

    @field_validator("source_path")
    @classmethod
    def validate_source_path(cls, value: str) -> str:
        _validate_relative_pattern(value, label="source path", allow_glob=False)
        return value

    @model_validator(mode="after")
    def validate_semantics(self) -> Self:
        expected = {
            ContextType.RULE: (self.rule_scope, True, None, None),
            ContextType.GENERAL: (None, False, None, None),
            ContextType.ARTEFACT: (None, False, self.artefact_metadata, None),
            ContextType.SHADOW_FILE: (None, False, None, self.shadow_file_policy),
        }
        required_scope, expected_instructional, required_metadata, required_policy = expected[
            self.context_type
        ]
        if self.context_type is ContextType.RULE and self.rule_scope is None:
            raise ValueError("rule items require rule_scope")
        if required_scope is None and self.rule_scope is not None:
            raise ValueError("only rule items may have rule_scope")
        if self.instructional != expected_instructional:
            raise ValueError(
                f"{self.context_type.value} items have instructional={expected_instructional}"
            )
        if self.context_type is ContextType.ARTEFACT and required_metadata is None:
            raise ValueError("artefact items require artefact_metadata")
        if self.context_type is not ContextType.ARTEFACT and self.artefact_metadata is not None:
            raise ValueError("only artefact items may have artefact_metadata")
        if self.context_type is ContextType.SHADOW_FILE and required_policy is None:
            raise ValueError("shadow_file items require shadow_file_policy")
        if self.context_type is not ContextType.SHADOW_FILE and self.shadow_file_policy is not None:
            raise ValueError("only shadow_file items may have shadow_file_policy")
        return self


class ResolvedDelivery(_StrictModel):
    """Recorded delivery/materialisation facts, including the generated hash."""

    delivery_id: str = Field(min_length=1)
    item_id: str = Field(min_length=1)
    destination: str
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    generated: bool = True

    @field_validator("destination")
    @classmethod
    def validate_destination(cls, value: str) -> str:
        _validate_relative_pattern(value, label="delivery destination", allow_glob=False)
        return value


class ShadowPreflightDecision(_StrictModel):
    """Observed result of checking whether a shadow destination is safe to write."""

    destination: str
    absolute_path: str
    safe: bool
    ignored: bool
    reason: str


class CleanupDecision(_StrictModel):
    """Hash-aware, non-mutating cleanup decision."""

    destination: str
    safe: bool
    should_delete: bool
    reason: str


def shadow_file_preflight(
    repo_root: Path,
    destination: str,
    *,
    ignore_checker: Callable[[Path, str], bool] | None = None,
) -> ShadowPreflightDecision:
    """Check that a generated shadow destination is ignored, without changing the repo.

    The default checker runs ``git check-ignore --quiet -- <destination>`` from
    ``repo_root``. An injected checker receives the root and repository-relative
    destination, which keeps tests deterministic. A missing/non-git root or an
    unignored destination is unsafe. This function never creates or edits
    ``.gitignore``.
    """

    policy = ShadowFilePolicy(destination=destination)
    root = repo_root.resolve()
    absolute = (root / policy.destination).resolve()
    try:
        absolute.relative_to(root)
    except ValueError as exc:
        raise ValueError("shadow destination escapes repo root") from exc

    checker = ignore_checker or _git_check_ignore
    ignored = checker(root, policy.destination)
    reason = "destination is ignored by git" if ignored else "destination is not ignored by git"
    return ShadowPreflightDecision(
        destination=policy.destination,
        absolute_path=str(absolute),
        safe=ignored,
        ignored=ignored,
        reason=reason,
    )


def decide_shadow_file_cleanup(repo_root: Path, delivery: ResolvedDelivery) -> CleanupDecision:
    """Permit deletion only for a generated file whose current bytes match its hash."""

    path = (repo_root.resolve() / delivery.destination).resolve()
    try:
        path.relative_to(repo_root.resolve())
    except ValueError as exc:
        raise ValueError("delivery destination escapes repo root") from exc
    if not delivery.generated:
        return CleanupDecision(
            destination=delivery.destination,
            safe=False,
            should_delete=False,
            reason="delivery is not marked generated",
        )
    if not path.exists():
        return CleanupDecision(
            destination=delivery.destination,
            safe=True,
            should_delete=False,
            reason="generated file is already absent",
        )
    if not path.is_file() or path.is_symlink():
        return CleanupDecision(
            destination=delivery.destination,
            safe=False,
            should_delete=False,
            reason="destination is not a regular file",
        )
    current_hash = hashlib.sha256(path.read_bytes()).hexdigest()
    if current_hash != delivery.sha256:
        return CleanupDecision(
            destination=delivery.destination,
            safe=False,
            should_delete=False,
            reason="generated file changed since delivery; refusing cleanup",
        )
    return CleanupDecision(
        destination=delivery.destination,
        safe=True,
        should_delete=True,
        reason="generated file matches recorded delivery hash",
    )


def _validate_relative_pattern(value: str, *, label: str, allow_glob: bool = True) -> None:
    if not value or "\x00" in value or value.startswith(("/", "\\", "~")):
        raise ValueError(f"{label} must be repository-relative")
    if not allow_glob and any(char in value for char in "*?[]"):
        raise ValueError(f"{label} must be a path, not a glob")
    normalised = value.replace("\\", "/")
    parts = PurePosixPath(normalised).parts
    if ".." in parts or any(
        not part or any(ord(char) < _CONTROL_CHAR_LIMIT for char in part) for part in parts
    ):
        raise ValueError(f"{label} contains an unsafe path component")
    if not allow_glob and normalised != value:
        raise ValueError(f"{label} must use repository-relative POSIX separators")


def _git_check_ignore(repo_root: Path, destination: str) -> bool:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_root), "check-ignore", "--quiet", "--", destination],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0
