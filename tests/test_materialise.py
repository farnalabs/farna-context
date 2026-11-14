"""Materialisation destination safety tests."""

import json
from pathlib import Path

import pytest
from git import Repo
from typer.testing import CliRunner

from src.farna_context.audit import AuditResult
from src.farna_context.cli import app
from src.farna_context.config import LocalConfig
from src.farna_context.constants import ExitCode
from src.farna_context.materialise import materialise_files


def _audit(repo_root: Path) -> AuditResult:
    result = AuditResult()
    source = repo_root / "AGENTS.md"
    result.instruction_files = [source]
    return result


def _symlink_or_skip(link: Path, target: Path, *, target_is_directory: bool = True) -> None:
    try:
        link.symlink_to(target, target_is_directory=target_is_directory)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"platform cannot create symlink: {exc}")


def test_materialise_rejects_symlinked_output_directory(tmp_path: Path) -> None:
    """A symlinked output root cannot redirect generated files to a victim."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "AGENTS.md").write_text("instructions\n", encoding="utf-8")
    victim = tmp_path / "victim"
    victim.mkdir()
    output = tmp_path / "output"
    _symlink_or_skip(output, victim)

    with pytest.raises(ValueError, match="Unsafe output path"):
        materialise_files(LocalConfig(), _audit(repo), repo, output)

    assert not (victim / "AGENTS.md").exists()
    assert not (victim / "manifest.yaml").exists()


def test_materialise_cli_fails_on_symlinked_output_component(tmp_path: Path) -> None:
    """A symlinked output component fails closed without touching its victim."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "AGENTS.md").write_text("instructions\n", encoding="utf-8")
    git_repo = Repo.init(repo)
    git_repo.index.add(["AGENTS.md"])
    git_repo.index.commit("fixture")
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "repo_root": str(repo),
                "source_scope": {"explicit_instruction_files": ["AGENTS.md"]},
                "output_files": {"manifest": "nested/manifest.yaml"},
            }
        ),
        encoding="utf-8",
    )
    output_root = tmp_path / "output"
    output_root.mkdir()
    victim = tmp_path / "victim"
    victim.mkdir()
    _symlink_or_skip(output_root / "nested", victim)

    result = CliRunner().invoke(
        app,
        [
            "materialise",
            "--config",
            str(config_path),
            "--output-dir",
            str(output_root),
        ],
    )

    assert result.exit_code == int(ExitCode.WRITE_ERROR)
    assert not (victim / "AGENTS.md").exists()
    assert not (victim / "manifest.yaml").exists()


def test_materialise_cli_rejects_symlinked_output_directory(tmp_path: Path) -> None:
    """The CLI returns the stable destination-safety exit code before writing."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "AGENTS.md").write_text("instructions\n", encoding="utf-8")
    git_repo = Repo.init(repo)
    git_repo.index.add(["AGENTS.md"])
    git_repo.index.commit("fixture")
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "repo_root": str(repo),
                "source_scope": {"explicit_instruction_files": ["AGENTS.md"]},
            }
        ),
        encoding="utf-8",
    )
    victim = tmp_path / "victim"
    victim.mkdir()
    output = tmp_path / "output"
    _symlink_or_skip(output, victim)

    result = CliRunner().invoke(
        app,
        ["materialise", "--config", str(config_path), "--output-dir", str(output)],
    )

    assert result.exit_code == int(ExitCode.DESTINATION_ERROR)
    assert "Unsafe output path" in result.stdout
    assert not (victim / "AGENTS.md").exists()
    assert not (victim / "manifest.yaml").exists()
