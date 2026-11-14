"""Tests for explicit secret scanning."""

import pytest

from src.farna_context.config import SecretPatterns
from src.farna_context.secrets import DETECTOR_REGISTRY_VERSION, scan_bytes, scan_sources


def test_literal_and_named_detector_findings_are_non_sensitive() -> None:
    patterns = SecretPatterns(literal_values=["top-secret"], named_detectors=["github_token"])
    findings = scan_bytes(b"top-secret ghp_123456789012345678901234", "source.md", patterns)
    assert {finding.detector for finding in findings} == {"configured_literal", "github_token"}
    assert "top-secret" not in str(findings[0].to_dict())


def test_unknown_detector_is_rejected_before_source_scan() -> None:
    with pytest.raises(ValueError, match="Invalid secret detector configuration"):
        scan_bytes(b"content", "source.md", SecretPatterns(named_detectors=["regex"]))


def test_registry_is_versioned() -> None:
    assert DETECTOR_REGISTRY_VERSION


def test_bare_marker_does_not_match() -> None:
    patterns = SecretPatterns(named_detectors=["github_token", "api_key"])
    assert not scan_bytes(b"ghp_ api_key is a field name", "source.md", patterns)


def test_scan_sources_counts_inputs() -> None:
    result = scan_sources([("a.md", b"safe"), ("b.md", b"safe")], SecretPatterns())
    expected_files = 2
    assert result.scanned_files == expected_files
    assert not result.has_secrets()
