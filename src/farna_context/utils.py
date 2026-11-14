"""Deterministic serialisation and hashing helpers."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def normalise_path(value: str | Path) -> str:
    """Return a repository-relative-style POSIX path without changing content paths."""
    return str(value).replace("\\", "/")


def canonical_json_bytes(value: Any) -> bytes:
    """Encode a value using the POC canonical JSON representation."""
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
