"""Deterministic serialisation, hashing, and path-validation helpers."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any


def normalise_path(value: str | Path) -> str:
    """Return a repository-relative-style POSIX path."""
    return str(value).replace("\\", "/")


def validate_relative_path(value: str | Path) -> str:
    """Validate and normalise a path that must be repository-relative."""
    text = normalise_path(value)
    if not text or "\x00" in text:
        raise ValueError("Unsafe path")  # noqa: TRY003
    if text.startswith(("/", "//")) or (len(text) >= 2 and text[1] == ":"):  # noqa: PLR2004
        raise ValueError("Unsafe path")  # noqa: TRY003
    parts = text.split("/")
    if any(part == ".." for part in parts) or any(":" in part for part in parts):
        raise ValueError("Unsafe path")  # noqa: TRY003
    if parts[0].upper() == "NUL" or any(part.upper().startswith("NUL.") for part in parts):
        raise ValueError("Unsafe path")  # noqa: TRY003
    return "/".join(part for part in parts if part not in ("", "."))


def _is_reparse_point(path: Path) -> bool:
    """Return whether a path is a symlink or Windows reparse point."""
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode):
        return True
    reparse_flag = 0x0400
    return bool(getattr(info, "st_file_attributes", 0) & reparse_flag)


def safe_source_path(repo_root: Path, relative_path: str | Path) -> Path:
    """Resolve a regular source file without following links or leaving the repo."""
    relative = validate_relative_path(relative_path)
    root = repo_root.resolve(strict=True)
    candidate = root / relative
    current = root
    for component in Path(relative).parts:
        current = current / component
        try:
            if _is_reparse_point(current):
                raise ValueError("Unsafe source path")  # noqa: TRY003
        except FileNotFoundError as exc:
            raise FileNotFoundError("Source file is not regular") from exc  # noqa: TRY003
    if not candidate.exists() or not candidate.is_file():
        raise FileNotFoundError("Source file is not regular")  # noqa: TRY003
    resolved = candidate.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError("Unsafe source path") from exc  # noqa: TRY003
    if not stat.S_ISREG(resolved.stat().st_mode):
        raise ValueError("Source file is not regular")  # noqa: TRY003
    return resolved


def canonical_json_bytes(value: Any) -> bytes:
    """Encode a value using the shared canonical JSON representation."""
    text = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return (text + "\n").encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    """Return a lower-case SHA-256 digest."""
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    """Hash exact file bytes."""
    return sha256_bytes(path.read_bytes())


def identity_payload(value: dict[str, Any], hash_field: str) -> dict[str, Any]:
    """Copy a payload while excluding its self-referential hash."""
    return {key: item for key, item in value.items() if key != hash_field}


def atomic_write_bytes(output_path: Path, data: bytes) -> None:
    """Write bytes through a durable same-directory temporary file and rename."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = output_path.with_name(f".{output_path.name}.tmp-{os.getpid()}")
    try:
        with temp_path.open("wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        temp_path.replace(output_path)
    finally:
        temp_path.unlink(missing_ok=True)
