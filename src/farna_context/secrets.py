"""Explicit, deterministic secret-pattern scanning."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config import SecretPatterns


@dataclass(frozen=True)
class SecretFinding:
    """A non-sensitive description of a matched pattern."""

    path: str
    detector: str
    line: int | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialise without the matched secret value."""
        result: dict[str, Any] = {"path": self.path, "detector": self.detector}
        if self.line is not None:
            result["line"] = self.line
        return result


@dataclass
class SecretScanResult:
    """Secret scan result."""

    findings: list[SecretFinding] = field(default_factory=list)
    scanned_files: int = 0
    errors: list[str] = field(default_factory=list)

    def has_secrets(self) -> bool:
        """Whether a configured detector matched."""
        return bool(self.findings)


DETECTORS: dict[str, bytes] = {
    "aws_access_key_id": b"AKIA",
    "aws_secret_access_key": b"aws_secret_access_key",
    "github_token": b"ghp_",
    "slack_token": b"xoxb-",
    "database_url": b"postgresql://",
    "api_key": b"api_key",
    "private_key": b"-----BEGIN ",
}


def _literal_findings(data: bytes, path: str, literals: list[str]) -> list[SecretFinding]:
    findings: list[SecretFinding] = []
    for literal in literals:
        if literal and literal.encode("utf-8") in data:
            findings.append(SecretFinding(path, "configured_literal"))
    return findings


def scan_bytes(data: bytes, path: str, patterns: SecretPatterns) -> list[SecretFinding]:
    """Scan bytes with only configured literals and fixed detector names."""
    findings = _literal_findings(data, path, patterns.literal_values)
    for name in patterns.named_detectors:
        marker = DETECTORS.get(name)
        if marker is None:
            raise ValueError(f"Unknown secret detector: {name}")  # noqa: TRY003
        if marker in data:
            findings.append(SecretFinding(path, name))
    return findings


def scan_file(file_path: Path, patterns: SecretPatterns) -> list[SecretFinding]:
    """Scan one file without decoding or evaluating source bytes."""
    return scan_bytes(file_path.read_bytes(), file_path.as_posix(), patterns)


def scan_sources(sources: list[tuple[str, bytes]], patterns: SecretPatterns) -> SecretScanResult:
    """Scan selected source bytes."""
    result = SecretScanResult()
    for path, data in sources:
        result.scanned_files += 1
        result.findings.extend(scan_bytes(data, path, patterns))
    return result
