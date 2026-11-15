"""Tests for typed context compilation and materialisation."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from src.farna_context.config import SecretPatterns
from src.farna_context.context_types import ContextType, RuleScope
from src.farna_context.materialise import materialise_typed_context
from src.farna_context.typed_context import (
    DeliveryMode,
    TypedContextPack,
    compile_typed_context,
    compile_typed_context_data,
)
from src.farna_context.utils import sha256_bytes


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
    payload = {**pack, "pack_hash": "a" * 64}
    payload["pack_hash"] = TypedContextPack.canonical_hash(payload)
    plan = materialise_typed_context(payload, repo_root=tmp_path, staging_parent=tmp_path / "stage")
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
    payload = {**pack, "pack_hash": "b" * 64}
    payload["pack_hash"] = TypedContextPack.canonical_hash(payload)
    plan = materialise_typed_context(payload, repo_root=tmp_path, staging_parent=tmp_path / "stage")
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


def _hashed_payload(pack: dict[str, object]) -> dict[str, object]:
    payload = {**pack, "pack_hash": "invalid"}
    payload["pack_hash"] = TypedContextPack.canonical_hash(payload)
    return payload


def test_materialise_rejects_tampered_pack_before_creating_output(tmp_path: Path) -> None:
    (tmp_path / "file.txt").write_text("safe", encoding="utf-8")
    pack = compile_typed_context_data(
        {
            "repo_root": str(tmp_path),
            "items": [{"item_id": "file", "context_type": "general", "source_path": "file.txt"}],
        }
    )
    tampered = _hashed_payload(
        {**pack, "items": [{**pack["items"][0], "content_base64": "dGFtcGVyZWQ="}]}
    )

    with pytest.raises(ValueError, match="output hash mismatch|secret-bearing"):
        materialise_typed_context(tampered, repo_root=tmp_path, staging_parent=tmp_path / "stage")
    assert not list((tmp_path / "stage").glob("typed-context-*"))


def test_materialise_rescans_injected_secret_bytes(tmp_path: Path) -> None:
    (tmp_path / "file.txt").write_text("safe", encoding="utf-8")
    pack = compile_typed_context_data(
        {
            "repo_root": str(tmp_path),
            "items": [{"item_id": "file", "context_type": "general", "source_path": "file.txt"}],
        },
        secret_patterns=SecretPatterns(named_detectors=["api_key"]),
    )
    injected_bytes = b"api_key=leak"
    injected = {
        **pack,
        "items": [
            {
                **pack["items"][0],
                "content_base64": base64.b64encode(injected_bytes).decode("ascii"),
                "source_sha256": sha256_bytes(injected_bytes),
            }
        ],
    }
    injected["pack_hash"] = TypedContextPack.canonical_hash(injected)

    with pytest.raises(ValueError, match="secret-bearing"):
        materialise_typed_context(injected, repo_root=tmp_path, staging_parent=tmp_path / "stage")


def test_general_context_size_boundary_is_enforced(tmp_path: Path) -> None:
    boundary = b"x" * (256 * 1024)
    (tmp_path / "general.md").write_bytes(boundary)
    pack = compile_typed_context_data(
        {
            "repo_root": str(tmp_path),
            "items": [
                {"item_id": "general", "context_type": "general", "source_path": "general.md"}
            ],
        }
    )
    assert len(pack["items"]) == 1
    (tmp_path / "too-large.md").write_bytes(boundary + b"x")
    oversized = compile_typed_context_data(
        {
            "repo_root": str(tmp_path),
            "items": [
                {"item_id": "general", "context_type": "general", "source_path": "too-large.md"}
            ],
        }
    )
    assert not oversized["items"]
    assert oversized["omitted"][0]["reason"] == "general_context_too_large"


def test_mount_mode_is_explicitly_adapter_required(tmp_path: Path) -> None:
    (tmp_path / "asset.bin").write_bytes(b"asset")
    pack = compile_typed_context_data(
        {
            "repo_root": str(tmp_path),
            "items": [
                {
                    "item_id": "asset",
                    "context_type": "artefact",
                    "source_path": "asset.bin",
                    "delivery_mode": "mount_if_supported",
                }
            ],
        }
    )
    plan = materialise_typed_context(
        _hashed_payload(pack), repo_root=tmp_path, staging_parent=tmp_path / "stage"
    )
    assert plan["outcomes"][0]["status"] == "adapter_required"
    assert not list(Path(plan["output_dir"]).rglob("asset.bin"))


def test_duplicate_basenames_preserve_source_relative_paths(tmp_path: Path) -> None:
    (tmp_path / "one").mkdir()
    (tmp_path / "two").mkdir()
    (tmp_path / "one" / "same.txt").write_text("one", encoding="utf-8")
    (tmp_path / "two" / "same.txt").write_text("two", encoding="utf-8")
    pack = compile_typed_context_data(
        {
            "repo_root": str(tmp_path),
            "items": [
                {
                    "item_id": "one",
                    "context_type": "artefact",
                    "source_path": "one/same.txt",
                    "delivery_mode": "copy_to_staging",
                },
                {
                    "item_id": "two",
                    "context_type": "artefact",
                    "source_path": "two/same.txt",
                    "delivery_mode": "copy_to_staging",
                },
            ],
        }
    )
    plan = materialise_typed_context(
        _hashed_payload(pack), repo_root=tmp_path, staging_parent=tmp_path / "stage"
    )
    output = Path(plan["output_dir"])
    assert (output / "one" / "same.txt").read_text(encoding="utf-8") == "one"
    assert (output / "two" / "same.txt").read_text(encoding="utf-8") == "two"


def test_general_materialise_rejects_oversized_payload(tmp_path: Path) -> None:
    oversized = {
        "schema_version": "typed-context-alpha-1",
        "items": [
            {
                "item_id": "general",
                "context_type": "general",
                "source_path": "general.md",
                "delivery_mode": None,
                "content_base64": base64.b64encode(b"x" * (256 * 1024 + 1)).decode("ascii"),
                "source_sha256": sha256_bytes(b"x" * (256 * 1024 + 1)),
            }
        ],
        "omitted": [],
        "secret_detector_names": [],
    }
    oversized["pack_hash"] = TypedContextPack.canonical_hash(oversized)
    with pytest.raises(ValueError, match="General context exceeds size limit"):
        materialise_typed_context(oversized, repo_root=tmp_path, staging_parent=tmp_path / "stage")


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
