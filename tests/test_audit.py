"""Source audit safety tests."""

import json
from pathlib import Path

import pytest

from src.farna_context.audit import audit_sources
from src.farna_context.config import LocalConfig


def _symlink_or_skip(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"platform cannot create symlink: {exc}")


def test_audit_excludes_source_symlink_without_reading_target(tmp_path: Path) -> None:
    """Configured source links are unsafe and never become included sources."""
    repo = tmp_path / "repo"
    repo.mkdir()
    victim = tmp_path / "victim.md"
    victim.write_text("outside\n", encoding="utf-8")
    link = repo / "configured.md"
    _symlink_or_skip(link, victim)
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "repo_root": str(repo),
                "source_scope": {"explicit_instruction_files": ["configured.md"]},
            }
        ),
        encoding="utf-8",
    )

    sources = audit_sources(LocalConfig.model_validate_json(config_path.read_text()), repo)

    assert len(sources) == 1
    source = sources[0]
    assert source.path == link
    assert source.readable is False
    assert source.included is False
    assert source.read_error is not None
    assert "Unsafe source path" in source.read_error
