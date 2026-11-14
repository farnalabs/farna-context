"""Tests for read-only Phase 3 verification."""

import hashlib
import json
from pathlib import Path

from src.farna_context.compile import compile_manifest
from src.farna_context.verify import verify_all


def _fixture(tmp_path: Path) -> tuple[Path, Path, Path]:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "AGENTS.md").write_text("safe\n", encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "repo_root": str(repo),
                "considered_sources": [
                    {
                        "path": "AGENTS.md",
                        "included": True,
                        "raw_hash": "",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"repo_root": str(repo)}), encoding="utf-8")
    return manifest, config, repo


def test_verify_pack_is_read_only_and_checks_pack_hash(tmp_path: Path) -> None:
    manifest, config, repo = _fixture(tmp_path)
    source_hash = hashlib.sha256((repo / "AGENTS.md").read_bytes()).hexdigest()
    data = json.loads(manifest.read_text(encoding="utf-8"))
    data["considered_sources"][0]["raw_hash"] = source_hash
    manifest.write_text(json.dumps(data), encoding="utf-8")
    output = tmp_path / "pack.json"
    compile_manifest(manifest, output, config)
    before = output.read_bytes()

    result = verify_all(manifest, output)

    assert result.verified
    assert output.read_bytes() == before


def test_verify_reports_missing_expected_output(tmp_path: Path) -> None:
    manifest, _config, _repo = _fixture(tmp_path)
    result = verify_all(manifest, tmp_path / "missing-pack.json")
    assert not result.verified
    assert result.errors == [f"Output path not found: {tmp_path / 'missing-pack.json'}"]
