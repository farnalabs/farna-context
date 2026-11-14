"""Tests for the alpha named-secret delivery contract."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import pytest

from src.farna_context.secrets_broker import (
    AgentProfile,
    ExpiredLeaseError,
    FakeVaultProvider,
    InvalidCredentialError,
    InvalidProfileError,
    ProfileCredential,
    SecretBroker,
    SecretRequest,
    UndeclaredSecretError,
    UnknownSecretError,
)

TEST_SECRET_VALUE = "TEST_SECRET_VALUE"


def _broker(*, now: datetime | None = None) -> tuple[SecretBroker, ProfileCredential]:
    profile = AgentProfile.create("builder", "profile-1", ["API_TOKEN"])
    credential = ProfileCredential.from_value("credential-1", "harmless-credential")
    clock_value = now or datetime.now(UTC)
    broker = SecretBroker(
        FakeVaultProvider({"API_TOKEN": TEST_SECRET_VALUE, "OTHER": "other-value"}),
        {profile.name: (profile, credential)},
        clock=lambda: clock_value,
    )
    return broker, credential


def test_declared_secret_is_delivered_only_in_overlay() -> None:
    broker, credential = _broker()
    request = SecretRequest("builder", "API_TOKEN", "task-1", "run-1")

    lease = broker.issue_lease(request, credential)
    overlay, receipt = broker.deliver(lease, credential)

    assert overlay == {"API_TOKEN": TEST_SECRET_VALUE}
    assert receipt.to_dict() == {
        "secret_name": "API_TOKEN",
        "profile": "builder",
        "mechanism": "environment",
        "status": "delivered",
        "evidence_origin": "fake-provider",
    }
    assert TEST_SECRET_VALUE not in str(receipt.to_dict())


def test_parent_environment_is_unchanged() -> None:
    before = os.environ.get("API_TOKEN")
    broker, credential = _broker()

    lease = broker.issue_lease(SecretRequest("builder", "API_TOKEN", "task-1", "run-1"), credential)
    broker.deliver(lease, credential)

    assert os.environ.get("API_TOKEN") == before


def test_invalid_credential_fails_closed_without_value_in_error() -> None:
    broker, credential = _broker()
    invalid = ProfileCredential.from_value("credential-1", "wrong-credential")

    with pytest.raises(InvalidCredentialError) as error:
        broker.issue_lease(SecretRequest("builder", "API_TOKEN", "task-1", "run-1"), invalid)

    assert TEST_SECRET_VALUE not in str(error.value)
    assert credential != invalid


def test_undeclared_secret_fails_closed() -> None:
    broker, credential = _broker()

    with pytest.raises(UndeclaredSecretError):
        broker.issue_lease(SecretRequest("builder", "OTHER", "task-1", "run-1"), credential)


def test_unknown_secret_fails_closed_without_enumeration() -> None:
    profile = AgentProfile.create("builder", "profile-1", ["MISSING"])
    credential = ProfileCredential.from_value("credential-1", "harmless-credential")
    broker = SecretBroker(
        FakeVaultProvider({"API_TOKEN": TEST_SECRET_VALUE}),
        {profile.name: (profile, credential)},
    )

    with pytest.raises(UnknownSecretError):
        broker.issue_lease(SecretRequest("builder", "MISSING", "task-1", "run-1"), credential)

    assert not hasattr(FakeVaultProvider, "list_secrets")
    assert not hasattr(FakeVaultProvider, "enumerate")


def test_expired_lease_cannot_deliver() -> None:
    now = datetime.now(UTC)
    profile = AgentProfile.create("builder", "profile-1", ["API_TOKEN"])
    credential = ProfileCredential.from_value("credential-1", "harmless-credential")
    current_time = now
    broker = SecretBroker(
        FakeVaultProvider({"API_TOKEN": TEST_SECRET_VALUE}),
        {profile.name: (profile, credential)},
        lease_seconds=1,
        clock=lambda: current_time,
    )
    lease = broker.issue_lease(SecretRequest("builder", "API_TOKEN", "task-1", "run-1"), credential)
    current_time = now + timedelta(seconds=2)

    with pytest.raises(ExpiredLeaseError):
        broker.deliver(lease, credential)


def test_only_named_requested_secret_is_returned() -> None:
    broker, credential = _broker()
    profile = AgentProfile.create("builder", "profile-1", ["API_TOKEN", "OTHER"])
    broker = SecretBroker(
        FakeVaultProvider({"API_TOKEN": TEST_SECRET_VALUE, "OTHER": "other-value"}),
        {profile.name: (profile, credential)},
    )

    lease = broker.issue_lease(SecretRequest("builder", "API_TOKEN", "task-1", "run-1"), credential)
    overlay, _receipt = broker.deliver(lease, credential)

    assert list(overlay) == ["API_TOKEN"]
    assert "OTHER" not in overlay


def test_profile_grants_are_immutable_and_duplicate_names_are_rejected() -> None:
    with pytest.raises(InvalidProfileError, match="unique"):
        AgentProfile.create("builder", "profile-1", ["API_TOKEN", "API_TOKEN"])

    names = ["API_TOKEN"]
    profile = AgentProfile.create("builder", "profile-1", names)
    names.append("OTHER")

    assert profile.allowed_secret_names == ("API_TOKEN",)
