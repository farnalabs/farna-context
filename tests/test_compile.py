"""Tests for deterministic Phase 3 compilation."""

import json
from pathlib import Path

import pytest

from src.farna_context.compile import compile_manifest
from src.farna_context.exceptions import (
    InputChangedError,
    InvalidManifestError,
    RequiredSourceError,
    SecretDetectedError,
)
from src.farna_context.utils import atomic_write_bytes, canonical_json_bytes, sha256_bytes


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


def test_manifest_identity_ignores_json_formatting(tmp_path: Path) -> None:
    manifest, config, _source = _fixture(tmp_path)
    first = compile_manifest(manifest, tmp_path / "one.json", config)
    data = json.loads(manifest.read_text(encoding="utf-8"))
    manifest.write_text(json.dumps(data, indent=4), encoding="utf-8")
    second = compile_manifest(manifest, tmp_path / "two.json", config)
    assert first.payload["manifest_identity"] == second.payload["manifest_identity"]


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
    assert data["selected_sources"][0]["emission"] == "identical_to_raw_source"
    assert data["fixture_identity"]["secret_detector_registry"]
    assert "repo" not in json.dumps(data)


def test_required_excluded_source_blocks(tmp_path: Path) -> None:
    manifest, config, _source = _fixture(tmp_path)
    data = json.loads(manifest.read_text(encoding="utf-8"))
    data["sources"][0].update(required=True, included=False)
    manifest.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(RequiredSourceError, match="Required source unavailable"):
        compile_manifest(manifest, tmp_path / "pack.json", config)


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


def test_symlink_source_is_rejected(tmp_path: Path) -> None:
    manifest, config, _source = _fixture(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    link = tmp_path / "repo" / "linked.md"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"platform cannot create symlink: {exc}")
    data = json.loads(manifest.read_text(encoding="utf-8"))
    data["sources"][0].update(path="linked.md", required=True)
    manifest.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(RequiredSourceError):
        compile_manifest(manifest, tmp_path / "pack.json", config)


def test_manifest_mutation_is_detected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    manifest, config, source = _fixture(tmp_path)
    original = manifest.read_bytes()
    real_read = Path.read_bytes
    changed = False

    def mutate(path: Path) -> bytes:
        nonlocal changed
        value = real_read(path)
        if path == source and not changed:
            changed = True
            manifest.write_bytes(b"{}")
        return value

    monkeypatch.setattr(Path, "read_bytes", mutate)
    with pytest.raises(InputChangedError):
        compile_manifest(manifest, tmp_path / "pack.json", config)
    manifest.write_bytes(original)


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


def test_atomic_write_rejects_symlinked_output_parent(tmp_path: Path) -> None:
    """A symlinked parent cannot redirect an atomic write outside its destination."""
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = outside / "victim.txt"
    victim.write_bytes(b"unchanged")
    parent = tmp_path / "output"
    try:
        parent.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"platform cannot create symlink: {exc}")

    with pytest.raises(ValueError, match="Unsafe output path"):
        atomic_write_bytes(parent / "child.json", b"new")

    assert victim.read_bytes() == b"unchanged"
    assert not (outside / "child.json").exists()


def test_atomic_write_rejects_preexisting_temp_symlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A symlink at a candidate temp path cannot overwrite its victim."""
    output = tmp_path / "pack.json"
    victim = tmp_path / "victim.txt"
    victim.write_bytes(b"unchanged")
    temp = tmp_path / ".pack.json.tmp-fixed"
    temp.symlink_to(victim)
    monkeypatch.setattr("src.farna_context.utils.secrets.token_hex", lambda _size: "fixed")
    with pytest.raises(FileExistsError):
        atomic_write_bytes(output, b"new")
    assert victim.read_bytes() == b"unchanged"
    assert not output.exists()


def test_explicit_config_is_required(tmp_path: Path) -> None:
    manifest, _config, _source = _fixture(tmp_path)
    with pytest.raises(InvalidManifestError, match="Config path is required"):
        compile_manifest(manifest, tmp_path / "pack.json")
