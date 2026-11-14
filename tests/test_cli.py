"""CLI compile command smoke tests."""

import hashlib
import json
from pathlib import Path

import pytest
from git import Repo
from typer.testing import CliRunner

from src.farna_context.audit import audit_sources
from src.farna_context.cli import app
from src.farna_context.config import LocalConfig, SourceScope
from src.farna_context.constants import ExitCode


def _inputs(tmp_path: Path, source: bytes = b"safe\n") -> tuple[Path, Path, Path]:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "AGENTS.md").write_bytes(source)
    (repo / "task.txt").write_text("task\n", encoding="utf-8")
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"repo_root": str(repo)}), encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    source_hash = hashlib.sha256((repo / "AGENTS.md").read_bytes()).hexdigest()
    manifest.write_text(
        json.dumps(
            {
                "repo_root": str(repo),
                "sources": [{"path": "AGENTS.md", "included": True, "raw_hash": source_hash}],
            }
        ),
        encoding="utf-8",
    )
    return manifest, config, tmp_path / "pack.json"


def test_generated_bytecode_is_not_discovered_in_skills_directory(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    skills = repo / "backend" / "scripts" / "skills"
    (skills / "__pycache__").mkdir(parents=True)
    (skills / "rule.md").write_text("safe", encoding="utf-8")
    (skills / "__pycache__" / "rule.cpython-312.pyc").write_bytes(b"bytecode")
    git_repo = Repo.init(repo)
    (repo / "README.md").write_text("fixture", encoding="utf-8")
    git_repo.index.add(["README.md"])
    git_repo.index.commit("fixture")
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps(
            {
                "repo_root": str(repo),
                "source_scope": {"skills_rules_dir": "backend/scripts"},
            }
        ),
        encoding="utf-8",
    )

    result = CliRunner().invoke(app, ["secrets", "--config", str(config)])
    sources = audit_sources(
        LocalConfig(source_scope=SourceScope(skills_rules_dir="backend/scripts")), repo
    )

    assert result.exit_code == 0
    assert "No secrets found in 1 files" in result.stdout
    assert [source.path for source in sources if source.included] == [skills / "rule.md"]
    excluded = next(
        source
        for source in sources
        if source.path == skills / "__pycache__" / "rule.cpython-312.pyc"
    )
    assert (
        excluded.exclusion_reason
        == "Generated artifact excluded (bytecode, cache, or packaging output)"
    )


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


def test_help_lists_commands() -> None:
    result = CliRunner().invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "farna-context" in result.stdout
    assert "compile" in result.stdout


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


def test_secrets_database_url_fixture_is_expected_finding(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "example.txt").write_text(
        "postgresql://user:password@localhost/db\n",
        encoding="utf-8",
    )
    git_repo = Repo.init(repo)
    (repo / ".gitkeep").write_text("fixture", encoding="utf-8")
    git_repo.index.add([".gitkeep"])
    git_repo.index.commit("fixture")
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps(
            {
                "repo_root": str(repo),
                "source_scope": {"explicit_instruction_files": ["example.txt"]},
                "secret_patterns": {"named_detectors": ["database_url"]},
            }
        ),
        encoding="utf-8",
    )
    result = CliRunner().invoke(app, ["secrets", "--config", str(config)])
    assert result.exit_code == int(ExitCode.SECRET_DETECTED)
    assert "database_url" in result.stdout
    assert "No secrets found" not in result.stdout


def test_clean_fixture_full_sequence_reaches_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "AGENTS.md").write_text("instructions\n", encoding="utf-8")
    git_repo = Repo.init(repo)
    git_repo.index.add(["AGENTS.md"])
    git_repo.index.commit("fixture")
    monkeypatch.chdir(repo)
    runner = CliRunner()

    assert runner.invoke(app, ["init"]).exit_code == 0
    git_repo.index.add([".farna-context/config.json"])
    git_repo.index.commit("add context config")
    audit_path = repo / ".farna-context" / "audit.json"
    manifest_path = repo / ".farna-context" / "manifest.json"
    pack_path = repo / ".farna-context" / "pack.json"
    receipt_path = repo / ".farna-context" / "receipt.json"
    assert runner.invoke(app, ["audit", "--out", str(audit_path)]).exit_code == 0
    assert (
        runner.invoke(
            app, ["manifest", "--audit", str(audit_path), "--out", str(manifest_path)]
        ).exit_code
        == 0
    )
    assert (
        runner.invoke(
            app,
            [
                "compile",
                "--manifest",
                str(manifest_path),
                "--config",
                str(repo / ".farna-context" / "config.json"),
                "--out",
                str(pack_path),
            ],
        ).exit_code
        == 0
    )
    assert (
        runner.invoke(
            app, ["verify", "--plan", str(manifest_path), "--out", str(pack_path)]
        ).exit_code
        == 0
    )
    receipt_result = runner.invoke(app, ["receipt", "--output", str(receipt_path)])

    assert receipt_result.exit_code == 0
    assert receipt_path.is_file()


def test_verify_command_checks_existing_pack_without_recompiling(tmp_path: Path) -> None:
    manifest, config, output = _inputs(tmp_path)
    compiled = CliRunner().invoke(
        app,
        ["compile", "--manifest", str(manifest), "--config", str(config), "--out", str(output)],
    )
    assert compiled.exit_code == 0
    result = CliRunner().invoke(app, ["verify", "--plan", str(manifest), "--out", str(output)])
    assert result.exit_code == 0
    assert "All verifications passed" in result.stdout


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
