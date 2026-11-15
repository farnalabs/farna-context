"""Typed context compilation for the alpha delivery contract."""

from __future__ import annotations

import base64
import mimetypes
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .compile import _load_json
from .config import SecretPatterns
from .context_types import MAX_GENERAL_SIZE_BYTES, ContextType, RuleScope, ShadowFilePolicy
from .secrets import scan_bytes
from .utils import canonical_json_bytes, safe_source_path, sha256_bytes, validate_relative_path


class DeliveryMode(StrEnum):
    REFERENCE_ONLY = "reference_only"
    COPY_TO_STAGING = "copy_to_staging"
    MOUNT_IF_SUPPORTED = "mount_if_supported"


class TypedContextItem(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    item_id: str = Field(min_length=1)
    context_type: ContextType
    source_path: str = Field(min_length=1)
    scope: RuleScope | None = None
    authority_status: str = "observed"
    evidence_status: str = "observed"
    delivery_mode: DeliveryMode | None = None
    selected: bool = True
    required: bool = False
    shadow_file_policy: ShadowFilePolicy | None = None

    @model_validator(mode="after")
    def validate_shadow_policy(self) -> TypedContextItem:
        if self.context_type is ContextType.SHADOW_FILE and self.shadow_file_policy is None:
            raise ValueError("shadow_file items require shadow_file_policy")  # noqa: TRY003
        if self.context_type is not ContextType.SHADOW_FILE and self.shadow_file_policy is not None:
            raise ValueError("only shadow_file items may have shadow_file_policy")  # noqa: TRY003
        return self


class TypedContextManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    repo_root: str
    items: list[TypedContextItem]


@dataclass(frozen=True)
class TypedContextPack:
    payload: dict[str, Any]
    pack_hash: str

    @staticmethod
    def canonical_hash(payload: dict[str, Any]) -> str:
        unsigned = {k: v for k, v in payload.items() if k != "pack_hash"}
        return sha256_bytes(canonical_json_bytes(unsigned))

    def validate_integrity(self) -> None:
        expected = self.canonical_hash(self.payload)
        if self.pack_hash != expected or self.payload.get("pack_hash") != self.pack_hash:
            raise ValueError("Typed context pack hash mismatch")  # noqa: TRY003

    def to_json(self) -> bytes:
        self.validate_integrity()
        return canonical_json_bytes(self.payload)


def _default_delivery(context_type: ContextType) -> DeliveryMode | None:
    return DeliveryMode.REFERENCE_ONLY if context_type is ContextType.ARTEFACT else None


def _typed_manifest(data: dict[str, Any]) -> TypedContextManifest:
    value = data.get("typed_context", data)
    if not isinstance(value, dict):
        raise TypeError("Typed context input must be an object")  # noqa: TRY003, TRY004
    items = value.get("items")
    if not isinstance(items, list):
        raise TypeError("Typed context input must contain items")  # noqa: TRY003, TRY004
    normalised: list[dict[str, Any]] = []
    for raw in items:
        if not isinstance(raw, dict):
            raise TypeError("Typed context item must be an object")  # noqa: TRY003, TRY004
        item = dict(raw)
        item["context_type"] = item.get("context_type", item.get("type"))
        item["scope"] = item.get("scope", item.get("rule_scope"))
        normalised.append(item)
    return TypedContextManifest.model_validate(
        {"repo_root": value.get("repo_root", data.get("repo_root")), "items": normalised}
    )


def _metadata(path: Path, data: bytes, delivery_mode: DeliveryMode) -> dict[str, Any]:
    mime_type, _ = mimetypes.guess_type(path.name)
    return {
        "mime_type": mime_type or "application/octet-stream",
        "extension": path.suffix.lower() or None,
        "size_bytes": len(data),
        "sha256": sha256_bytes(data),
        "source_path": path.as_posix(),
        "delivery_mode": delivery_mode.value,
    }


def compile_typed_context_data(
    manifest_data: dict[str, Any],
    *,
    repo_root: Path | None = None,
    secret_patterns: SecretPatterns | None = None,
) -> dict[str, Any]:
    """Compile typed items without writing a pack file."""
    manifest = _typed_manifest(manifest_data)
    root = (repo_root or Path(manifest.repo_root)).resolve(strict=True)
    patterns = secret_patterns or SecretPatterns()
    selected: list[dict[str, Any]] = []
    omitted: list[dict[str, Any]] = []

    for item in sorted(manifest.items, key=lambda value: value.item_id):
        path = validate_relative_path(item.source_path)
        delivery = item.delivery_mode or _default_delivery(item.context_type)
        if not item.selected:
            omitted.append(
                {
                    "item_id": item.item_id,
                    "context_type": item.context_type.value,
                    "reason": "policy_excluded",
                }
            )
            continue
        try:
            source = safe_source_path(root, path)
            data = source.read_bytes()
        except (OSError, ValueError) as exc:
            omission: dict[str, Any] = {
                "item_id": item.item_id,
                "context_type": item.context_type.value,
                "reason": "source_unavailable",
            }
            if item.required:
                raise ValueError(f"Required typed source unavailable: {path}") from exc  # noqa: TRY003
            omitted.append(omission)
            continue
        findings = scan_bytes(data, path, patterns)
        if findings:
            omission = {
                "item_id": item.item_id,
                "context_type": item.context_type.value,
                "reason": "secret_pattern_match",
                "detectors": sorted({finding.detector for finding in findings}),
            }
            if item.required:
                raise ValueError(f"Secret detected in required typed source: {path}")  # noqa: TRY003
            omitted.append(omission)
            continue
        if item.context_type is ContextType.GENERAL and len(data) > MAX_GENERAL_SIZE_BYTES:
            omission = {
                "item_id": item.item_id,
                "context_type": item.context_type.value,
                "reason": "general_context_too_large",
            }
            if item.required:
                raise ValueError("Required general context exceeds size limit")  # noqa: TRY003
            omitted.append(omission)
            continue
        record: dict[str, Any] = {
            "item_id": item.item_id,
            "context_type": item.context_type.value,
            "source_path": path,
            "source_sha256": sha256_bytes(data),
            "authority_status": item.authority_status,
            "evidence_status": item.evidence_status,
            "delivery_mode": delivery.value if delivery else None,
            "content_base64": base64.b64encode(data).decode("ascii"),
        }
        if item.scope is not None:
            record["scope"] = item.scope.model_dump(mode="json")
        if item.context_type is ContextType.ARTEFACT:
            record["artefact_metadata"] = _metadata(
                source, data, delivery or DeliveryMode.REFERENCE_ONLY
            )
        if item.context_type is ContextType.SHADOW_FILE:
            if item.shadow_file_policy is None:
                raise ValueError("Shadow file items require a shadow file policy")  # noqa: TRY003
            record["shadow_destination"] = item.shadow_file_policy.destination
            record["shadow_policy"] = item.shadow_file_policy.model_dump(mode="json")
        selected.append(record)

    return {
        "schema_version": "typed-context-alpha-1",
        "items": selected,
        "omitted": omitted,
        "secret_detector_names": sorted(patterns.named_detectors),
    }


def compile_typed_context(
    manifest_path: Path,
    output_path: Path,
    *,
    config_path: Path | None = None,
) -> TypedContextPack:
    """Compile a typed manifest to a deterministic JSON pack."""
    data, manifest_bytes = _load_json(manifest_path)
    config_data: dict[str, Any] = {}
    if config_path is not None:
        config_data, _ = _load_json(config_path)
    secret_data = config_data.get("secret_patterns", {})
    patterns = SecretPatterns.model_validate(secret_data if isinstance(secret_data, dict) else {})
    typed = compile_typed_context_data(data, secret_patterns=patterns)
    identity = {"manifest": typed, "manifest_sha256": sha256_bytes(canonical_json_bytes(data))}
    payload = {**typed, "identity": identity}
    pack_hash = TypedContextPack.canonical_hash(payload)
    payload["pack_hash"] = pack_hash
    if manifest_path.read_bytes() != manifest_bytes:
        raise ValueError("Typed context manifest changed during compilation")  # noqa: TRY003
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(canonical_json_bytes(payload))
    return TypedContextPack(payload, pack_hash)


__all__ = [
    "DeliveryMode",
    "TypedContextItem",
    "TypedContextManifest",
    "TypedContextPack",
    "compile_typed_context",
    "compile_typed_context_data",
]
