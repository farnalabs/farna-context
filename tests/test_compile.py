"""Tests for deterministic Phase 3 compilation."""

import json
from pathlib import Path

import pytest

from src.farna_context.compile import compile_manifest
from src.farna_context.exceptions import (
    InputChangedError,
    InvalidManifestError,
    SecretDetectedError,
)
from src.farna_context.utils import canonical_json_bytes, sha256_bytes


def _fixture(tmp_path: Path, *, secret: bool = False) -> tuple[Path, Path, Path]:
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "AGENTS.md"
    source.write_bytes(b"instructions\n")
    task = repo / "task.txt"
    task.write_bytes(b"task\n")
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps(
            {
                "repo_root": str(repo),
                "harness_fixture": "fixture",
                "task_brief_path": "task.txt",
                "secret_patterns": {
                    "literal_values": ["literal-secret"] if secret else [],
                    "named_detectors": [],
                },
            }
        ),
        encoding="utf-8",
    )
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "repo_root": str(repo),
                "sources": [
                    {
                        "path": "AGENTS.md",
                        "included": True,
                        "required": False,
                        "source_class": "instruction",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return manifest, config, source


def test_canonical_json_is_stable() -> None:
    first = canonical_json_bytes({"b": 2, "a": [1, 2]})
    second = canonical_json_bytes({"a": [1, 2], "b": 2})
    assert first == second
    assert first.endswith(b"\n")
    assert sha256_bytes(first) == sha256_bytes(second)


def test_pack_structure_and_hash(tmp_path: Path) -> None:
    manifest, config, _source = _fixture(tmp_path)
    output = tmp_path / "pack.json"
    pack = compile_manifest(manifest, output, config)
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["pack_hash"] == pack.pack_hash
    assert data["compiler_identity"]["name"] == "farna-context-compiler"
    assert data["selected_sources"][0]["path"] == "AGENTS.md"
    assert (
        data["selected_sources"][0]["raw_source_sha256"]
        == data["selected_sources"][0]["emitted_sha256"]
    )
    assert "repo" not in json.dumps(data)


def test_secret_source_is_omitted_without_raw_hash(tmp_path: Path) -> None:
    manifest, config, source = _fixture(tmp_path, secret=True)
    source.write_bytes(b"literal-secret\n")
    output = tmp_path / "pack.json"
    pack = compile_manifest(manifest, output, config)
    assert not pack.payload["selected_sources"]
    omitted = pack.payload["omitted_sources"][0]
    assert omitted["reason"] == "secret_pattern_match"
    assert "raw_source_sha256" not in json.dumps(pack.payload)


def test_required_secret_blocks(tmp_path: Path) -> None:
    manifest, config, source = _fixture(tmp_path, secret=True)
    source.write_bytes(b"literal-secret\n")
    data = json.loads(manifest.read_text(encoding="utf-8"))
    data["sources"][0]["required"] = True
    manifest.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(SecretDetectedError):
        compile_manifest(manifest, tmp_path / "pack.json", config)


def test_invalid_manifest_rejected(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"repo_root": str(tmp_path), "sources": [{"path": "../x"}]}))
    with pytest.raises(InvalidManifestError):
        compile_manifest(manifest, tmp_path / "pack.json")


def test_input_mutation_is_detected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    manifest, config, source = _fixture(tmp_path)
    original = source.read_bytes()
    real_read = Path.read_bytes
    changed = False

    def mutate(path: Path) -> bytes:
        nonlocal changed
        value = real_read(path)
        if path == source and not changed:
            changed = True
            source.write_bytes(b"changed\n")
        return value

    monkeypatch.setattr(Path, "read_bytes", mutate)
    with pytest.raises(InputChangedError):
        compile_manifest(manifest, tmp_path / "pack.json", config)
    source.write_bytes(original)
