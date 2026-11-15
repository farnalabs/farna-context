"""Tests for the honest OpenCode scoped-rule adapter."""

from __future__ import annotations

import json
from pathlib import Path

from src.farna_context.opencode_adapter import (
    ADAPTER_ID,
    AdapterStatus,
    discover_opencode_capabilities,
    materialise_opencode_rules,
)


def test_discovery_attributes_glob_support_to_plugin_not_core() -> None:
    capability = discover_opencode_capabilities()

    assert capability.native_path_glob_rules is False
    assert capability.plugin_scoped_rules is True
    assert capability.plugin_id == "opencode-rules"
    assert capability.supported_scope_fields == ("path_glob",)
    assert "OpenCode core" in capability.evidence


def test_materialise_preserves_scope_in_plugin_rule_and_manifest(tmp_path: Path) -> None:
    result = materialise_opencode_rules(
        [
            (
                {
                    "item_id": "python-rule",
                    "source_path": "rules/python.md",
                    "scope": {"path_glob": "src/**/*.py"},
                },
                b"Use the project conventions.",
            )
        ],
        tmp_path,
    )

    assert result.status is AdapterStatus.MATERIALISED
    assert result.artifact_path == "manifest.json"
    manifest = json.loads((tmp_path / "manifest.json").read_text(encoding="utf-8"))
    rule = manifest["rules"][0]
    generated = tmp_path / rule["filename"]
    text = generated.read_text(encoding="utf-8")
    assert f"# generated-by: {ADAPTER_ID}@1" in text
    assert '  - "src/**/*.py"' in text
    assert "Use the project conventions." in text
    assert rule["scope"] == {"path_glob": "src/**/*.py", "operation_scope": None}


def test_unsupported_operation_scope_is_adapter_required_without_flattening(
    tmp_path: Path,
) -> None:
    result = materialise_opencode_rules(
        [
            (
                {
                    "item_id": "operation-rule",
                    "source_path": "rules/operation.md",
                    "scope": {"operation_scope": "deploy"},
                },
                b"Deploy carefully.",
            )
        ],
        tmp_path,
    )

    assert result.status is AdapterStatus.ADAPTER_REQUIRED
    assert "operation_scope" in result.reason
    assert not list(tmp_path.rglob("*.md"))
    assert not (tmp_path / "manifest.json").exists()


def test_manifest_is_byte_deterministic(tmp_path: Path) -> None:
    rules = [
        (
            {
                "item_id": "b",
                "source_path": "rules/b.md",
                "scope": {"path_glob": "b/**/*.py"},
            },
            b"B",
        ),
        (
            {
                "item_id": "a",
                "source_path": "rules/a.md",
                "scope": {"path_glob": "a/**/*.py"},
            },
            b"A",
        ),
    ]
    first_dir = tmp_path / "one"
    second_dir = tmp_path / "two"

    materialise_opencode_rules(rules, first_dir)
    materialise_opencode_rules(rules, second_dir)

    assert (first_dir / "manifest.json").read_bytes() == (second_dir / "manifest.json").read_bytes()
