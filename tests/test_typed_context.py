"""Tests for typed context compilation and materialisation."""

from __future__ import annotations

import json
from pathlib import Path

from src.farna_context.config import SecretPatterns
from src.farna_context.context_types import ContextType, RuleScope
from src.farna_context.materialise import materialise_typed_context
from src.farna_context.typed_context import (
    DeliveryMode,
    compile_typed_context,
    compile_typed_context_data,
)


def _manifest(repo: Path) -> dict[str, object]:
    return {
        "repo_root": str(repo),
        "items": [
            {
                "item_id": "rule",
                "context_type": "rule",
                "source_path": "rule.md",
                "scope": {"path_glob": "src/**/*.py"},
            },
            {"item_id": "general", "context_type": "general", "source_path": "general.md"},
            {
                "item_id": "pdf",
                "context_type": "artefact",
                "source_path": "paper.pdf",
                "delivery_mode": "reference_only",
            },
        ],
    }


def test_mixed_pack_is_deterministic_and_preserves_rule_scope(tmp_path: Path) -> None:
    (tmp_path / "rule.md").write_text("rule", encoding="utf-8")
    (tmp_path / "general.md").write_text("general", encoding="utf-8")
    (tmp_path / "paper.pdf").write_bytes(b"pdf")
    first = compile_typed_context_data(_manifest(tmp_path))
    second = compile_typed_context_data(_manifest(tmp_path))
    assert first == second
    rule = next(item for item in first["items"] if item["item_id"] == "rule")
    assert rule["context_type"] == ContextType.RULE.value
    assert rule["scope"] == RuleScope(path_glob="src/**/*.py").model_dump(mode="json")
    assert "timestamp" not in json.dumps(first)


def test_binary_metadata_is_opaque_and_copy_is_safe(tmp_path: Path) -> None:
    (tmp_path / "image.png").write_bytes(b"PNG")
    pack = compile_typed_context_data(
        {
            "repo_root": str(tmp_path),
            "items": [
                {
                    "item_id": "image",
                    "context_type": "artefact",
                    "source_path": "image.png",
                    "delivery_mode": "copy_to_staging",
                }
            ],
        }
    )
    plan = materialise_typed_context(
        pack | {"pack_hash": "a" * 64}, repo_root=tmp_path, staging_parent=tmp_path / "stage"
    )
    assert plan["outcomes"][0]["status"] == "materialised"
    assert (Path(plan["output_dir"]) / "image.png").read_bytes() == b"PNG"
    assert pack["items"][0]["artefact_metadata"]["sha256"]


def test_reference_only_and_scoped_rule_report_correct_outcomes(tmp_path: Path) -> None:
    (tmp_path / "rule.md").write_text("rule", encoding="utf-8")
    (tmp_path / "audio.wav").write_bytes(b"audio")
    pack = compile_typed_context_data(
        {
            "repo_root": str(tmp_path),
            "items": [
                {
                    "item_id": "rule",
                    "context_type": "rule",
                    "source_path": "rule.md",
                    "scope": {"path_glob": "*.py"},
                },
                {"item_id": "audio", "context_type": "artefact", "source_path": "audio.wav"},
            ],
        }
    )
    plan = materialise_typed_context(
        pack | {"pack_hash": "b" * 64}, repo_root=tmp_path, staging_parent=tmp_path / "stage"
    )
    outcomes = {item["item_id"]: item for item in plan["outcomes"]}
    assert outcomes["rule"]["status"] == "adapter_required"
    assert outcomes["audio"]["status"] == "materialised"
    assert not (Path(plan["output_dir"]) / "audio.wav").exists()


def test_secret_artefact_is_omitted_without_leaking_value(tmp_path: Path) -> None:
    (tmp_path / "secret.bin").write_bytes(b"api_key=do-not-leak")
    pack = compile_typed_context_data(
        {
            "repo_root": str(tmp_path),
            "items": [
                {
                    "item_id": "secret",
                    "context_type": "artefact",
                    "source_path": "secret.bin",
                    "delivery_mode": "copy_to_staging",
                }
            ],
        },
        secret_patterns=SecretPatterns(named_detectors=["api_key"]),
    )
    assert pack["items"] == []
    assert pack["omitted"][0]["reason"] == "secret_pattern_match"
    assert "do-not-leak" not in json.dumps(pack)


def test_general_context_and_pack_hash_are_stable(tmp_path: Path) -> None:
    (tmp_path / "general.md").write_text("hello", encoding="utf-8")
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "repo_root": str(tmp_path),
                "items": [
                    {"item_id": "general", "context_type": "general", "source_path": "general.md"}
                ],
            }
        ),
        encoding="utf-8",
    )
    first = compile_typed_context(manifest_path, tmp_path / "one.json")
    second = compile_typed_context(manifest_path, tmp_path / "two.json")
    assert first.pack_hash == second.pack_hash
    assert first.payload["items"][0]["context_type"] == "general"
    assert DeliveryMode.REFERENCE_ONLY.value == "reference_only"
