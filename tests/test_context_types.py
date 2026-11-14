"""Tests for alpha context type validation and safe shadow delivery."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from pydantic import ValidationError

from src.farna_context.context_types import (
    ArtefactMetadata,
    ContextItem,
    ContextType,
    ResolvedDelivery,
    RuleScope,
    ShadowFilePolicy,
    decide_shadow_file_cleanup,
    shadow_file_preflight,
)


def test_all_four_context_types_enforce_instruction_semantics() -> None:
    rule = ContextItem(
        item_id="rule-1",
        context_type=ContextType.RULE,
        source_path="rules/python.md",
        rule_scope=RuleScope(path_glob="src/**/*.py"),
        instructional=True,
    )
    general = ContextItem(
        item_id="general-1",
        context_type=ContextType.GENERAL,
        source_path="profiles/team.md",
    )
    artefact = ContextItem(
        item_id="artefact-1",
        context_type=ContextType.ARTEFACT,
        source_path="references/spec.pdf",
        artefact_metadata=ArtefactMetadata(
            mime_type="application/pdf", extension=".pdf", size_bytes=10
        ),
    )
    shadow = ContextItem(
        item_id="shadow-1",
        context_type=ContextType.SHADOW_FILE,
        source_path="generated/AGENTS.md",
        shadow_file_policy=ShadowFilePolicy(destination="generated/AGENTS.md"),
    )

    assert rule.instructional
    assert not general.instructional
    assert not artefact.instructional
    assert not shadow.instructional

    with pytest.raises(ValidationError, match="instructional"):
        ContextItem(
            item_id="bad",
            context_type=ContextType.ARTEFACT,
            source_path="reference.txt",
            artefact_metadata=ArtefactMetadata(mime_type="text/plain", size_bytes=1),
            instructional=True,
        )


def test_glob_and_path_validation_rejects_escape_and_absolute_paths() -> None:
    with pytest.raises(ValidationError, match="unsafe path"):
        RuleScope(path_glob="../secret/**")
    with pytest.raises(ValidationError, match="repository-relative"):
        ContextItem(item_id="bad", context_type=ContextType.GENERAL, source_path="/tmp/file")
    with pytest.raises(ValidationError, match="AGENTS.md"):
        ShadowFilePolicy(destination="generated/notes.txt")


def test_artefact_metadata_validates_mime_extension_and_size() -> None:
    metadata = ArtefactMetadata(mime_type="TEXT/PLAIN", extension=".TXT", size_bytes=12)

    assert metadata.mime_type == "text/plain"
    assert metadata.extension == ".txt"

    with pytest.raises(ValidationError, match="application/pdf"):
        ArtefactMetadata(mime_type="text/plain", extension=".pdf", size_bytes=1)
    with pytest.raises(ValidationError):
        ArtefactMetadata(mime_type="text/plain", size_bytes=10 * 1024 * 1024 + 1)


def test_shadow_preflight_accepts_ignored_destination_without_mutating_gitignore(
    tmp_path: Path,
) -> None:
    gitignore = tmp_path / ".gitignore"
    gitignore.write_text("generated/AGENTS.md\n")
    before = gitignore.read_bytes()

    decision = shadow_file_preflight(
        tmp_path,
        "generated/AGENTS.md",
        ignore_checker=lambda _root, _destination: True,
    )

    assert decision.safe
    assert decision.ignored
    assert gitignore.read_bytes() == before


def test_shadow_preflight_refuses_unignored_destination(tmp_path: Path) -> None:
    decision = shadow_file_preflight(
        tmp_path,
        "generated/AGENTS.md",
        ignore_checker=lambda _root, _destination: False,
    )

    assert not decision.safe
    assert not decision.ignored
    assert "not ignored" in decision.reason


def test_changed_shadow_file_is_not_deleted(tmp_path: Path) -> None:
    destination = tmp_path / "generated" / "AGENTS.md"
    destination.parent.mkdir()
    destination.write_bytes(b"changed")
    delivery = ResolvedDelivery(
        delivery_id="delivery-1",
        item_id="shadow-1",
        destination="generated/AGENTS.md",
        sha256=hashlib.sha256(b"original").hexdigest(),
    )

    decision = decide_shadow_file_cleanup(tmp_path, delivery)

    assert not decision.safe
    assert not decision.should_delete
    assert destination.exists()
    assert "changed" in decision.reason


def test_matching_shadow_file_is_safe_to_delete(tmp_path: Path) -> None:
    destination = tmp_path / "generated" / "CLAUDE.md"
    destination.parent.mkdir()
    destination.write_bytes(b"generated")
    delivery = ResolvedDelivery(
        delivery_id="delivery-2",
        item_id="shadow-2",
        destination="generated/CLAUDE.md",
        sha256=hashlib.sha256(b"generated").hexdigest(),
    )

    decision = decide_shadow_file_cleanup(tmp_path, delivery)

    assert decision.safe
    assert decision.should_delete
