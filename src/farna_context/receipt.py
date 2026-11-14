"""Receipt generation for Farna Context."""

import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .audit import AuditResult
from .config import LocalConfig
from .constants import (
    HARNESS_FIXTURE,
    EvidenceOrigin,
    HarnessLoadMode,
    MaterialisationMode,
    ModelUseMode,
    OutcomeStatus,
    RequestedBy,
)
from .manifest import Manifest


@dataclass
class ReceiptOptions:
    """Options for receipt generation."""

    requested_by: RequestedBy = RequestedBy.HUMAN
    materialisation: MaterialisationMode = MaterialisationMode.FILES
    harness_load: HarnessLoadMode = HarnessLoadMode.CLI
    model_use: ModelUseMode = ModelUseMode.SYNC
    outcome: OutcomeStatus = OutcomeStatus.SUCCESS
    evidence_origin: EvidenceOrigin = EvidenceOrigin.DIRECT
    error_message: str | None = None


class Receipt:
    """Operation receipt."""

    def __init__(
        self,
        config: LocalConfig,
        audit: AuditResult,
        revision: str,
        options: ReceiptOptions | None = None,
    ) -> None:
        options = options or ReceiptOptions()

        self.id = str(uuid.uuid4())
        self.timestamp = datetime.now(UTC).isoformat()
        self.revision = revision
        self.requested_by = options.requested_by.value
        self.materialisation = options.materialisation.value
        self.harness_load = options.harness_load.value
        self.model_use = options.model_use.value
        self.outcome = options.outcome.value
        self.evidence_origin = options.evidence_origin.value
        self.harness_fixture = HARNESS_FIXTURE
        self.error_message = options.error_message

        # Source summary
        all_files = (
            list(audit.instruction_files)
            + list(audit.explicit_files)
            + list(audit.skills_files)
            + list(audit.scoped_files)
        )
        self.file_count = len(set(all_files))
        self.missing_required = audit.missing_required
        self.audit_errors = audit.errors

        # Config snapshot (non-sensitive)
        self.config_snapshot = {
            "repo_root": config.repo_root,
            "harness_fixture": config.harness_fixture,
            "source_scope": config.source_scope.model_dump(),
            "task_overlay": config.task_overlay.model_dump(),
        }

    def to_dict(self) -> dict[str, Any]:
        """Convert receipt to dictionary."""
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "revision": self.revision,
            "requested_by": self.requested_by,
            "materialisation": self.materialisation,
            "harness_load": self.harness_load,
            "model_use": self.model_use,
            "outcome": self.outcome,
            "evidence_origin": self.evidence_origin,
            "harness_fixture": self.harness_fixture,
            "error_message": self.error_message,
            "file_count": self.file_count,
            "missing_required": self.missing_required,
            "audit_errors": self.audit_errors,
            "config_snapshot": self.config_snapshot,
        }

    def to_json(self) -> str:
        """Convert receipt to JSON string."""
        return json.dumps(self.to_dict(), indent=2)

    def save(self, output_path: Path) -> None:
        """Save receipt to file."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w") as f:
            f.write(self.to_json())


def generate_receipt(
    config: LocalConfig,
    audit: AuditResult,
    manifest: Manifest,
    revision: str,
    **kwargs: Any,
) -> Receipt:
    """Generate a receipt for the operation.

    Args:
        config: Local configuration.
        audit: Audit results.
        manifest: Generated manifest (unused, kept for API compatibility).
        revision: Git revision.
        **kwargs: Additional receipt fields.

    Returns:
        Receipt object.
    """
    _ = manifest  # Unused, kept for API compatibility
    options = ReceiptOptions(**kwargs)
    return Receipt(config, audit, revision, options)
