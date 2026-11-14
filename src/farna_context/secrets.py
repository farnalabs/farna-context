"""Secret pattern scanning for Farna Context."""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .audit import AuditResult
from .config import SecretPatterns


@dataclass
class SecretFinding:
    """A secret finding in a file."""

    file_path: Path
    line_number: int
    pattern: str
    matched_text: str
    context: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "file": str(self.file_path),
            "line": self.line_number,
            "pattern": self.pattern,
            "matched_text": self.matched_text[:100],  # Truncate for safety
            "context": self.context[:200],
        }


class SecretScanResult:
    """Result of secret scanning."""

    def __init__(self) -> None:
        self.findings: list[SecretFinding] = []
        self.scanned_files: int = 0
        self.errors: list[str] = []

    def has_secrets(self) -> bool:
        """Check if any secrets were found."""
        return len(self.findings) > 0


def scan_file(file_path: Path, patterns: SecretPatterns) -> list[SecretFinding]:
    """Scan a single file for secrets.

    Args:
        file_path: Path to file to scan.
        patterns: Secret patterns configuration.

    Returns:
        List of SecretFinding objects.
    """
    findings: list[SecretFinding] = []

    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except (OSError, UnicodeDecodeError):
        # Skip binary/unreadable files
        return findings

    lines = content.splitlines()
    for line_num, line in enumerate(lines, 1):
        for pattern in patterns.patterns:
            try:
                matches = re.finditer(pattern, line)
                for match in matches:
                    findings.append(
                        SecretFinding(
                            file_path=file_path,
                            line_number=line_num,
                            pattern=pattern,
                            matched_text=match.group(0),
                            context=line.strip(),
                        )
                    )
            except re.error:
                # Invalid regex pattern, skip
                pass

    return findings


def scan_sources(
    audit_result: AuditResult,
    patterns: SecretPatterns,
    repo_root: Path,
) -> SecretScanResult:
    """Scan all source files for secrets.

    Args:
        audit_result: Audit results containing source files.
        patterns: Secret patterns configuration.
        repo_root: Repository root path.

    Returns:
        SecretScanResult with findings.
    """
    result = SecretScanResult()

    all_files = (
        list(audit_result.instruction_files)
        + list(audit_result.explicit_files)
        + list(audit_result.skills_files)
        + list(audit_result.scoped_files)
    )

    # Build exclude set
    exclude_set: set[Path] = set()
    for exclude in patterns.exclude_paths:
        exclude_path = repo_root / exclude
        try:
            if exclude_path.is_dir():
                for f in exclude_path.rglob("*"):
                    if f.is_file():
                        exclude_set.add(f.resolve())
            else:
                exclude_set.add(exclude_path.resolve())
        except (OSError, ValueError):
            pass

    for file_path in all_files:
        try:
            resolved = file_path.resolve()
            if resolved in exclude_set:
                continue

            findings = scan_file(file_path, patterns)
            result.findings.extend(findings)
            result.scanned_files += 1
        except Exception as e:
            result.errors.append(f"Failed to scan {file_path}: {e}")

    return result
