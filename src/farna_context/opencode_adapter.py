"""Deterministic adapter for the installed OpenCode scoped-rules plugin.

OpenCode core does not expose a proven path-glob rule API.  The installed
``opencode-rules`` plugin does: it discovers Markdown rules and evaluates their
YAML-frontmatter ``globs`` against observed file paths.  This module targets
that explicit plugin contract only.  It never turns a scoped rule into
unscoped general context.
"""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from pathlib import Path
from typing import Any

from .context_types import RuleScope
from .utils import atomic_write_bytes, canonical_json_bytes, sha256_bytes

ADAPTER_ID = "farna-context.opencode-rules"
ADAPTER_VERSION = "1"
PLUGIN_ID = "opencode-rules"
PLUGIN_CAPABILITY = "scoped_rules.path_glob"
RULES_DIRECTORY = "opencode-rules"
MANIFEST_FILENAME = "manifest.json"


class AdapterStatus(StrEnum):
    MATERIALISED = "materialised"
    ADAPTER_REQUIRED = "adapter_required"


class CapabilityDiscovery:
    """Observed capability contract for the installed OpenCode integration."""

    def __init__(self, **values: Any) -> None:
        self.harness = str(values["harness"])
        self.adapter_id = str(values["adapter_id"])
        self.adapter_version = str(values["adapter_version"])
        self.native_path_glob_rules = bool(values["native_path_glob_rules"])
        self.plugin_scoped_rules = bool(values["plugin_scoped_rules"])
        plugin_id = values["plugin_id"]
        self.plugin_id = str(plugin_id) if plugin_id is not None else None
        self.supported_scope_fields = tuple(
            str(value) for value in values["supported_scope_fields"]
        )
        self.evidence = str(values["evidence"])

    def to_dict(self) -> dict[str, Any]:
        return {
            "harness": self.harness,
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "native_path_glob_rules": self.native_path_glob_rules,
            "plugin_scoped_rules": self.plugin_scoped_rules,
            "plugin_id": self.plugin_id,
            "supported_scope_fields": list(self.supported_scope_fields),
            "evidence": self.evidence,
        }


class AdapterResult:
    """Result for one rule or a deterministic adapter manifest."""

    def __init__(
        self,
        *,
        status: AdapterStatus,
        reason: str,
        capability: CapabilityDiscovery,
        artifact_path: str | None = None,
        rule_ids: tuple[str, ...] = (),
    ) -> None:
        self.status = status
        self.reason = reason
        self.capability = capability
        self.artifact_path = artifact_path
        self.rule_ids = rule_ids

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "status": self.status.value,
            "reason": self.reason,
            "capability": self.capability.to_dict(),
        }
        if self.artifact_path is not None:
            result["artifact_path"] = self.artifact_path
        if self.rule_ids:
            result["rule_ids"] = list(self.rule_ids)
        return result


def discover_opencode_capabilities() -> CapabilityDiscovery:
    """Return the capability proven by the installed local integration.

    The capability is deliberately attributed to the plugin, not OpenCode
    core.  The plugin source was inspected without starting an OpenCode
    process: it discovers ``.md``/``.mdc`` rules and matches frontmatter
    ``globs`` with minimatch.  No operation-scope matcher was found.
    """

    return CapabilityDiscovery(
        harness="opencode",
        adapter_id=ADAPTER_ID,
        adapter_version=ADAPTER_VERSION,
        native_path_glob_rules=False,
        plugin_scoped_rules=True,
        plugin_id=PLUGIN_ID,
        supported_scope_fields=("path_glob",),
        evidence=(
            "Installed opencode-rules discovery/filter source supports Markdown "
            "frontmatter globs; OpenCode core scoped-rule support was not proven."
        ),
    )


def _rule_filename(item_id: str, source_path: str) -> str:
    digest = hashlib.sha256(f"{item_id}\0{source_path}".encode()).hexdigest()[:16]
    return f"rule-{digest}.md"


def _render_rule(
    *,
    item_id: str,
    source_path: str,
    scope: RuleScope,
    content: bytes,
) -> str:
    if scope.path_glob is None:
        raise ValueError("OpenCode adapter requires a path_glob scope")  # noqa: TRY003
    frontmatter = [
        "---",
        f"# generated-by: {ADAPTER_ID}@{ADAPTER_VERSION}",
        f"# capability: {PLUGIN_CAPABILITY}",
        f"# item-id: {json.dumps(item_id)}",
        f"# source-path: {json.dumps(source_path)}",
        f"# source-sha256: {sha256_bytes(content)}",
        "globs:",
        f"  - {json.dumps(scope.path_glob)}",
        "---",
        "",
    ]
    try:
        body = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("OpenCode scoped rules must be valid UTF-8") from exc  # noqa: TRY003
    return "\n".join(frontmatter) + body.rstrip("\n") + "\n"


def _unsupported_reason(scope: RuleScope) -> str | None:
    if scope.operation_scope is not None:
        return (
            "OpenCode plugin adapter supports path_glob only; operation_scope has no proven matcher"
        )
    if scope.path_glob is None:
        return "OpenCode plugin adapter requires a path_glob scope"
    return None


def materialise_opencode_rules(
    rules: list[tuple[dict[str, Any], bytes]],
    output_dir: Path,
) -> AdapterResult:
    """Write scoped rules as plugin files and a deterministic manifest.

    Files are written beneath the operation directory, never into the target
    repository.  Unsupported scopes produce no rule file and are reported as
    ``adapter_required`` by the caller.
    """

    capability = discover_opencode_capabilities()
    supported: list[tuple[dict[str, Any], bytes, RuleScope, str]] = []
    unsupported: list[str] = []
    unsupported_reasons: list[str] = []
    for item, content in rules:
        scope_data = item.get("scope")
        if not isinstance(scope_data, dict):
            item_id = str(item["item_id"])
            unsupported.append(item_id)
            unsupported_reasons.append(f"{item_id}: missing rule scope")
            continue
        scope = RuleScope.model_validate(scope_data)
        reason = _unsupported_reason(scope)
        if reason is not None:
            item_id = str(item["item_id"])
            unsupported.append(item_id)
            unsupported_reasons.append(f"{item_id}: {reason}")
            continue
        filename = _rule_filename(str(item["item_id"]), str(item["source_path"]))
        supported.append((item, content, scope, filename))

    if unsupported:
        return AdapterResult(
            status=AdapterStatus.ADAPTER_REQUIRED,
            reason="unsupported OpenCode rule scope: " + "; ".join(sorted(unsupported_reasons)),
            capability=capability,
            rule_ids=tuple(sorted(unsupported)),
        )

    rules_dir = output_dir / RULES_DIRECTORY
    rules_dir.mkdir(parents=True, exist_ok=True)
    manifest_rules: list[dict[str, Any]] = []
    for item, content, scope, filename in supported:
        rendered = _render_rule(
            item_id=str(item["item_id"]),
            source_path=str(item["source_path"]),
            scope=scope,
            content=content,
        ).encode("utf-8")
        atomic_write_bytes(rules_dir / filename, rendered)
        manifest_rules.append(
            {
                "item_id": str(item["item_id"]),
                "source_path": str(item["source_path"]),
                "scope": scope.model_dump(mode="json"),
                "filename": f"{RULES_DIRECTORY}/{filename}",
                "sha256": sha256_bytes(rendered),
            }
        )

    manifest = {
        "schema_version": "farna-context-opencode-rules-1",
        "adapter": capability.to_dict(),
        "plugin": {"id": PLUGIN_ID, "capability": PLUGIN_CAPABILITY},
        "rules": manifest_rules,
    }
    manifest_path = output_dir / MANIFEST_FILENAME
    atomic_write_bytes(manifest_path, canonical_json_bytes(manifest))
    return AdapterResult(
        status=AdapterStatus.MATERIALISED,
        reason="materialised through the installed opencode-rules plugin contract",
        capability=capability,
        artifact_path=MANIFEST_FILENAME,
        rule_ids=tuple(rule["item_id"] for rule in manifest_rules),
    )


__all__ = [
    "ADAPTER_ID",
    "AdapterResult",
    "AdapterStatus",
    "CapabilityDiscovery",
    "discover_opencode_capabilities",
    "materialise_opencode_rules",
]
