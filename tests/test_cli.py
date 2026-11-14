"""CLI compile command smoke tests."""

from pathlib import Path

from typer.testing import CliRunner

from src.farna_context.cli import app


def test_compile_command_writes_pack(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "AGENTS.md").write_text("safe\n", encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        '{"repo_root": "' + str(repo) + '", "sources": [{"path": "AGENTS.md", "included": true}]}',
        encoding="utf-8",
    )
    output = tmp_path / "pack.json"
    result = CliRunner().invoke(app, ["compile", "--manifest", str(manifest), "--out", str(output)])
    assert result.exit_code == 0
    assert output.is_file()
    assert "Pack hash:" in result.stdout
