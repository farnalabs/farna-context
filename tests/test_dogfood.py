"""Dogfood preparation command tests."""

import json
from pathlib import Path

from git import Repo
from typer.testing import CliRunner

from src.farna_context.cli import app

_EXPECTED_CONTEXT_ITEMS = 4


def test_dogfood_prepare_writes_pack_materialisation_receipt_and_launch(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "AGENTS.md").write_text("repository guidance\n", encoding="utf-8")
    (repo / "CLAUDE.md").write_text("repository instructions\n", encoding="utf-8")
    task = tmp_path / "task.txt"
    task.write_text("Improve internal docs.\n", encoding="utf-8")
    private = tmp_path / "private.md"
    private.write_text("private overlay guidance\n", encoding="utf-8")
    Repo.init(repo)
    out = tmp_path / "out"
    result = CliRunner().invoke(
        app,
        [
            "dogfood-prepare",
            "--repo-root",
            str(repo),
            "--task",
            str(task),
            "--profile",
            "internal-docs",
            "--pipeline",
            "improve-internal-docs",
            "--harness",
            "opencode",
            "--private-paths",
            str(private),
            "--out",
            str(out),
            "--staging-parent",
            str(tmp_path / "staging"),
        ],
    )

    assert result.exit_code == 0
    receipt = json.loads((out / "receipt.json").read_text(encoding="utf-8"))
    launch = json.loads((out / "launch.json").read_text(encoding="utf-8"))
    pack = json.loads((out / "pack.json").read_text(encoding="utf-8"))
    assert receipt["status"] == "prepared"
    assert receipt["private_overlay_provided"] is True
    assert launch["provenance"]["harness_consumption"] == "unobserved"
    assert "< /dev/null" in launch["command"]
    assert len(pack["items"]) == _EXPECTED_CONTEXT_ITEMS
    assert (out / "materialisation.json").is_file()


def test_dogfood_prepare_works_without_private_overlay(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
    task = tmp_path / "task.txt"
    task.write_text("task\n", encoding="utf-8")
    Repo.init(repo)
    out = tmp_path / "out"

    result = CliRunner().invoke(
        app,
        [
            "dogfood-prepare",
            "--repo-root",
            str(repo),
            "--task",
            str(task),
            "--out",
            str(out),
            "--staging-parent",
            str(tmp_path / "staging"),
        ],
    )

    assert result.exit_code == 0
    receipt = json.loads((out / "receipt.json").read_text(encoding="utf-8"))
    assert receipt["private_overlay_provided"] is False


def test_dogfood_prepare_fails_closed_for_secret_overlay(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    task = tmp_path / "task.txt"
    task.write_text("task\n", encoding="utf-8")
    private = tmp_path / "private.md"
    private.write_text("api_key = leaked\n", encoding="utf-8")
    Repo.init(repo)
    result = CliRunner().invoke(
        app,
        [
            "dogfood-prepare",
            "--repo-root",
            str(repo),
            "--task",
            str(task),
            "--private-paths",
            str(private),
            "--out",
            str(tmp_path / "out"),
            "--staging-parent",
            str(tmp_path / "staging"),
        ],
    )

    assert result.exit_code != 0
    assert not (tmp_path / "out" / "pack.json").exists()
