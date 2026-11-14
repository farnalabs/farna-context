"""Alpha named-secret delivery contract.

This module is a small contract, not a complete secrets manager. It models the
alpha boundary where a predeclared named secret is delivered to a child process
through an environment overlay. Values stay inside the provider and delivery
boundary; they are never placed in packs, manifests, receipts, or exception
messages. Environment delivery cannot guarantee that an agent will not disclose
a value after receiving it.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum


class SecretBrokerError(ValueError):
    """Base error for fail-closed secret broker operations."""


class InvalidCredentialError(SecretBrokerError):
    """The supplied profile credential is invalid."""


class UnknownSecretError(SecretBrokerError):
    """The named secret is not present in the provider."""


class UndeclaredSecretError(SecretBrokerError):
    """The profile has not predeclared the requested secret."""


class ExpiredLeaseError(SecretBrokerError):
    """The lease is expired or no longer usable."""


class InvalidProfileError(SecretBrokerError):
    """The profile definition is invalid."""


class LeaseStatus(StrEnum):
    ACTIVE = "active"
    DELIVERED = "delivered"
    EXPIRED = "expired"


@dataclass(frozen=True, slots=True)
class AgentProfile:
    """An agent identity and its immutable allowlist of named secrets."""

    name: str
    profile_id: str
    allowed_secret_names: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise InvalidProfileError(  # noqa: TRY003
                "Agent profile name must not be empty"
            )
        if not self.profile_id.strip():
            raise InvalidProfileError(  # noqa: TRY003
                "Agent profile id must not be empty"
            )
        if any(not secret_name.strip() for secret_name in self.allowed_secret_names):
            raise InvalidProfileError(  # noqa: TRY003
                "Allowed secret names must not be empty"
            )
        if len(set(self.allowed_secret_names)) != len(self.allowed_secret_names):
            raise InvalidProfileError(  # noqa: TRY003
                "Allowed secret names must be unique"
            )

    @classmethod
    def create(
        cls,
        name: str,
        profile_id: str,
        allowed_secret_names: tuple[str, ...] | list[str] = (),
    ) -> AgentProfile:
        """Build a profile while copying its grant list into an immutable tuple."""
        return cls(name, profile_id, tuple(allowed_secret_names))


@dataclass(frozen=True, slots=True)
class ProfileCredential:
    """Opaque credential metadata; raw credential values are never retained."""

    credential_id: str
    credential_hash: str

    def __post_init__(self) -> None:
        if not self.credential_id.strip() or not self.credential_hash.strip():
            raise SecretBrokerError(  # noqa: TRY003
                "Credential identifier and hash must not be empty"
            )

    @classmethod
    def from_value(cls, credential_id: str, value: str) -> ProfileCredential:
        """Hash a raw setup value without storing or exposing that value."""
        if not value:
            raise SecretBrokerError(  # noqa: TRY003
                "Credential value must not be empty"
            )
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
        return cls(credential_id, digest)

    def to_dict(self) -> dict[str, str]:
        """Serialize only opaque credential metadata."""
        return {"credential_id": self.credential_id, "credential_hash": self.credential_hash}


@dataclass(frozen=True, slots=True)
class SecretRequest:
    """A request for one exact named secret in a task/run scope."""

    profile: str
    secret_name: str
    task_scope: str
    run_scope: str

    def __post_init__(self) -> None:
        if not self.profile.strip() or not self.secret_name.strip():
            raise SecretBrokerError(  # noqa: TRY003
                "Secret request profile and name must not be empty"
            )
        if not self.task_scope.strip() or not self.run_scope.strip():
            raise SecretBrokerError(  # noqa: TRY003
                "Secret request scopes must not be empty"
            )


@dataclass(frozen=True, slots=True)
class SecretLease:
    """A short-lived capability to deliver one named secret."""

    secret_name: str
    profile: str
    mechanism: str
    lease_id: str
    expires_at: datetime
    status: LeaseStatus = LeaseStatus.ACTIVE

    def to_dict(self) -> dict[str, str]:
        """Serialize lease metadata without a secret value."""
        return {
            "secret_name": self.secret_name,
            "profile": self.profile,
            "mechanism": self.mechanism,
            "lease_id": self.lease_id,
            "expires_at": self.expires_at.isoformat(),
            "status": self.status.value,
        }


@dataclass(frozen=True, slots=True)
class SecretDeliveryReceipt:
    """Non-sensitive evidence that a named secret delivery occurred."""

    secret_name: str
    profile: str
    mechanism: str
    status: str
    evidence_origin: str

    def to_dict(self) -> dict[str, str]:
        """Serialize receipt metadata; the value is intentionally absent."""
        return {
            "secret_name": self.secret_name,
            "profile": self.profile,
            "mechanism": self.mechanism,
            "status": self.status,
            "evidence_origin": self.evidence_origin,
        }


class FakeVaultProvider:
    """In-memory provider for tests only; it deliberately has no enumeration API."""

    def __init__(self, secrets_by_name: Mapping[str, str]) -> None:
        self._secrets_by_name = dict(secrets_by_name)

    def resolve(self, secret_name: str) -> str:
        """Resolve one exact name, failing without revealing the stored value."""
        if secret_name not in self._secrets_by_name:
            raise UnknownSecretError(  # noqa: TRY003
                "Unknown named secret"
            )
        return self._secrets_by_name[secret_name]


@dataclass(frozen=True, slots=True)
class _LeaseRecord:
    lease: SecretLease
    request: SecretRequest
    value: str


class SecretBroker:
    """Fail-closed alpha broker for named environment delivery."""

    mechanism = "environment"
    evidence_origin = "fake-provider"

    def __init__(
        self,
        provider: FakeVaultProvider,
        profiles: Mapping[str, tuple[AgentProfile, ProfileCredential]],
        *,
        lease_seconds: int = 60,
        clock: Callable[[], datetime] = datetime.now,
    ) -> None:
        if lease_seconds <= 0:
            raise SecretBrokerError(  # noqa: TRY003
                "Lease duration must be positive"
            )
        self._provider = provider
        self._profiles = dict(profiles)
        self._lease_seconds = lease_seconds
        self._clock = clock
        self._leases: dict[str, _LeaseRecord] = {}

    def issue_lease(self, request: SecretRequest, credential: ProfileCredential) -> SecretLease:
        """Authenticate, enforce the allowlist, and issue one short-lived lease."""
        profile, expected_credential = self._profile_for(request.profile)
        self._validate_credential(credential, expected_credential)
        if request.secret_name not in profile.allowed_secret_names:
            raise UndeclaredSecretError(  # noqa: TRY003
                "Requested secret is not declared for this profile"
            )
        value = self._provider.resolve(request.secret_name)
        now = self._now()
        lease = SecretLease(
            secret_name=request.secret_name,
            profile=profile.name,
            mechanism=self.mechanism,
            lease_id=secrets.token_urlsafe(18),
            expires_at=now + timedelta(seconds=self._lease_seconds),
        )
        self._leases[lease.lease_id] = _LeaseRecord(lease, request, value)
        return lease

    def deliver(
        self,
        lease: SecretLease,
        credential: ProfileCredential,
    ) -> tuple[dict[str, str], SecretDeliveryReceipt]:
        """Return a child-process overlay and non-sensitive delivery receipt."""
        record = self._leases.get(lease.lease_id)
        if record is None or record.lease != lease:
            raise ExpiredLeaseError(  # noqa: TRY003
                "Secret lease is invalid or expired"
            )
        _profile, expected_credential = self._profile_for(record.request.profile)
        self._validate_credential(credential, expected_credential)
        if lease.status is not LeaseStatus.ACTIVE or self._now() >= lease.expires_at:
            raise ExpiredLeaseError(  # noqa: TRY003
                "Secret lease is invalid or expired"
            )
        delivered_lease = SecretLease(
            secret_name=lease.secret_name,
            profile=lease.profile,
            mechanism=lease.mechanism,
            lease_id=lease.lease_id,
            expires_at=lease.expires_at,
            status=LeaseStatus.DELIVERED,
        )
        self._leases[lease.lease_id] = _LeaseRecord(delivered_lease, record.request, record.value)
        receipt = SecretDeliveryReceipt(
            secret_name=lease.secret_name,
            profile=lease.profile,
            mechanism=lease.mechanism,
            status="delivered",
            evidence_origin=self.evidence_origin,
        )
        return {lease.secret_name: record.value}, receipt

    def _profile_for(self, profile_name: str) -> tuple[AgentProfile, ProfileCredential]:
        try:
            return self._profiles[profile_name]
        except KeyError as exc:
            raise InvalidCredentialError(  # noqa: TRY003
                "Profile credential is invalid"
            ) from exc

    @staticmethod
    def _validate_credential(credential: ProfileCredential, expected: ProfileCredential) -> None:
        if credential.credential_id != expected.credential_id or not hmac.compare_digest(
            credential.credential_hash, expected.credential_hash
        ):
            raise InvalidCredentialError(  # noqa: TRY003
                "Profile credential is invalid"
            )

    def _now(self) -> datetime:
        current = self._clock()
        if current.tzinfo is None:
            return current.replace(tzinfo=UTC)
        return current
