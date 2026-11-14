"""Small typed models used by Phase 3 compilation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Snapshot:
    """Exact bytes and digest captured at operation start."""

    path: str
    data: bytes
    sha256: str


@dataclass(frozen=True)
class SourceMaterial:
    """Source selected for compilation, with raw and emitted identities."""

    path: str
    source_class: str
    data: bytes
    raw_sha256: str
    emitted_sha256: str
    required: bool
    evidence_origin: str = "observed"


JSON = dict[str, Any]
