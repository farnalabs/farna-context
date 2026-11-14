"""Explicit, deterministic secret-pattern scanning."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config import SecretPatterns

DETECTOR_REGISTRY_VERSION = "2026-11-14.1"


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


_DETECTOR_PATTERNS: dict[str, re.Pattern[bytes]] = {
    "aws_access_key_id": re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),
    "aws_secret_access_key": re.compile(rb"(?i)aws_secret_access_key\s*[:=]"),
    "github_token": re.compile(rb"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    "slack_token": re.compile(rb"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    "database_url": re.compile(rb"\b(?:postgres(?:ql)?|mysql|mariadb)://[^\s]+"),
    "api_key": re.compile(rb"(?i)\bapi[_-]?key\s*[:=]"),
    "private_key": re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
}


def validate_detector_names(names: list[str]) -> None:
    """Reject unknown detector names before any source bytes are read."""
    unknown = sorted(set(names) - set(_DETECTOR_PATTERNS))
    if unknown:
        raise ValueError("Invalid secret detector configuration")  # noqa: TRY003


def _literal_findings(data: bytes, path: str, literals: list[str]) -> list[SecretFinding]:
    findings: list[SecretFinding] = []
    for literal in literals:
        if literal and literal.encode("utf-8") in data:
            findings.append(SecretFinding(path, "configured_literal"))
    return findings


def scan_bytes(data: bytes, path: str, patterns: SecretPatterns) -> list[SecretFinding]:
    """Scan bytes with configured literals and versioned fixed detectors."""
    validate_detector_names(patterns.named_detectors)
    findings = _literal_findings(data, path, patterns.literal_values)
    for name in patterns.named_detectors:
        if _DETECTOR_PATTERNS[name].search(data):
            findings.append(SecretFinding(path, name))
    return findings


def scan_file(file_path: Path, patterns: SecretPatterns) -> list[SecretFinding]:
    """Scan one file without decoding or evaluating source bytes."""
    validate_detector_names(patterns.named_detectors)
    return scan_bytes(file_path.read_bytes(), file_path.as_posix(), patterns)


def scan_sources(sources: list[tuple[str, bytes]], patterns: SecretPatterns) -> SecretScanResult:
    """Scan selected source bytes."""
    validate_detector_names(patterns.named_detectors)
    result = SecretScanResult()
    for path, data in sources:
        result.scanned_files += 1
        result.findings.extend(scan_bytes(data, path, patterns))
    return result
