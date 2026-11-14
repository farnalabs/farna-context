"""CLI compile command smoke tests."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from src.farna_context.cli import app
from src.farna_context.constants import ExitCode


def _inputs(tmp_path: Path, source: bytes = b"safe\n") -> tuple[Path, Path, Path]:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "AGENTS.md").write_bytes(source)
    (repo / "task.txt").write_text("task\n", encoding="utf-8")
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"repo_root": str(repo)}), encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps({"repo_root": str(repo), "sources": [{"path": "AGENTS.md", "included": True}]}),
        encoding="utf-8",
    )
    return manifest, config, tmp_path / "pack.json"


def test_secrets_scans_non_instruction_sources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Secrets scans explicit, skills, and scoped source classes too."""
    repo = tmp_path / "repo"
    (repo / "skills").mkdir(parents=True)
    (repo / "scoped").mkdir()
    (repo / "explicit.txt").write_text("api_key = hidden", encoding="utf-8")
    (repo / "skills" / "rule.md").write_text("safe", encoding="utf-8")
    (repo / "scoped" / "source.md").write_text("safe", encoding="utf-8")
    (repo / ".git").mkdir()
    monkeypatch.setattr("src.farna_context.cli.get_revision", lambda _root: "test")
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps(
            {
                "repo_root": str(repo),
                "source_scope": {
                    "explicit_instruction_files": ["explicit.txt"],
                    "skills_rules_dir": "skills",
                    "path_scopes": ["scoped"],
                },
                "secret_patterns": {"named_detectors": ["api_key"]},
            }
        ),
        encoding="utf-8",
    )
    result = CliRunner().invoke(app, ["secrets", "--config", str(config)])
    assert result.exit_code == int(ExitCode.SECRET_DETECTED)
    assert "api_key" in result.stdout
    assert "hidden" not in result.stdout


def test_compile_command_writes_pack(tmp_path: Path) -> None:
    manifest, config, output = _inputs(tmp_path)
    result = CliRunner().invoke(
        app, ["compile", "--manifest", str(manifest), "--config", str(config), "--out", str(output)]
    )
    assert result.exit_code == 0
    assert output.is_file()
    assert "Pack hash:" in result.stdout


def test_compile_requires_manifest_out_and_config(tmp_path: Path) -> None:
    manifest, config, output = _inputs(tmp_path)
    runner = CliRunner()
    assert runner.invoke(
        app, ["compile", "--config", str(config), "--out", str(output)]
    ).exit_code == int(ExitCode.INVALID_ARGS)
    assert runner.invoke(
        app, ["compile", "--manifest", str(manifest), "--config", str(config)]
    ).exit_code == int(ExitCode.INVALID_ARGS)
    assert runner.invoke(
        app, ["compile", "--manifest", str(manifest), "--out", str(output)]
    ).exit_code == int(ExitCode.INVALID_ARGS)


def test_compile_invalid_manifest_returns_two(tmp_path: Path) -> None:
    manifest, config, output = _inputs(tmp_path)
    manifest.write_text("{}", encoding="utf-8")
    result = CliRunner().invoke(
        app, ["compile", "--manifest", str(manifest), "--config", str(config), "--out", str(output)]
    )
    assert result.exit_code == int(ExitCode.INVALID_ARGS)


def test_compile_secret_returns_twelve(tmp_path: Path) -> None:
    manifest, config, output = _inputs(tmp_path, b"literal-secret\n")
    config.write_text(
        json.dumps(
            {
                "repo_root": str(tmp_path / "repo"),
                "secret_patterns": {"literal_values": ["literal-secret"]},
            }
        ),
        encoding="utf-8",
    )
    data = json.loads(manifest.read_text(encoding="utf-8"))
    data["sources"][0]["required"] = True
    manifest.write_text(json.dumps(data), encoding="utf-8")
    result = CliRunner().invoke(
        app, ["compile", "--manifest", str(manifest), "--config", str(config), "--out", str(output)]
    )
    assert result.exit_code == int(ExitCode.SECRET_DETECTED)


def test_compile_required_missing_returns_ten(tmp_path: Path) -> None:
    manifest, config, output = _inputs(tmp_path)
    data = json.loads(manifest.read_text(encoding="utf-8"))
    data["sources"][0].update(path="missing.md", required=True)
    manifest.write_text(json.dumps(data), encoding="utf-8")
    result = CliRunner().invoke(
        app, ["compile", "--manifest", str(manifest), "--config", str(config), "--out", str(output)]
    )
    assert result.exit_code == int(ExitCode.REQUIRED_ISSUE)
