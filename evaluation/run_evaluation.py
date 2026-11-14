"""Run the controlled OpenCode usefulness evaluation."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

try:
    from .scoring import DECISION_THRESHOLDS, classify_attempt, score_task
except ImportError:
    from scoring import DECISION_THRESHOLDS, classify_attempt, score_task

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL_PATH = ROOT / "evaluation" / "protocol.json"
DEFAULT_TIMEOUT = 900
ASSIGNMENT_SEED = 20261114
_OUTPUT_LIMIT = 8000
_ALLOWED_CHANGED_FILES = {"src/slugify.py", "tests/test_slugify.py"}
_IGNORED_TREE_PARTS = {
    ".git",
    ".agents",
    ".farna-context",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "__pycache__",
    ".venv",
    "venv",
    "cache",
    "node_modules",
    ".tox",
    ".nox",
    ".coverage",
    "htmlcov",
    "dist",
    "build",
}
_IGNORED_TREE_NAMES = {
    ".evaluation-prompt.md",
    ".evaluation-pack",
    ".evaluation-output",
    ".evaluation-runs",
    "evaluation-pack",
    "evaluation-output",
    "evaluation-runs",
    "runs",
    "context-pack.json",
}
_MAX_SNAPSHOT_ERRORS = 20
_PARENT_SENTINEL_VERSION = "parent-sentinel-v1"


@dataclass(frozen=True)
class TreeSnapshot:
    hashes: dict[str, str]
    errors: tuple[str, ...] = ()


_SECRET_PATTERNS = {
    "github_token": re.compile(rb"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    "private_key": re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "aws_key": re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),
    "api_key": re.compile(rb"(?i)\bapi[_-]?key\s*[:=]\s*[^\s,}\]]+"),
}


@dataclass(frozen=True)
class Fixture:
    name: str
    root: Path
    task: Path


@dataclass(frozen=True)
class ExecutionResult:
    process_status: str
    returncode: int | None
    stdout_summary: str
    stderr_summary: str
    elapsed_seconds: float
    provider_ok: bool
    provider_failure_class: str | None
    oracle_passed: bool | None
    oracle_summary: str
    changed_files: list[str]
    scope_ok: bool
    test_deletion_ok: bool
    secret_output_ok: bool
    contamination_ok: bool
    contamination_evidence: dict[str, Any]
    prompt_sha256: str
    setup_ok: bool
    harness_ok: bool
    guard_error: str | None
    launch_manifest: dict[str, Any]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def _is_ignored_relative(relative: Path) -> bool:
    return any(part in _IGNORED_TREE_PARTS for part in relative.parts) or any(
        part in _IGNORED_TREE_NAMES for part in relative.parts
    )


def _tracked_tree_paths(root: Path) -> list[Path]:
    paths: list[Path] = []
    for directory, directory_names, file_names in os.walk(root, followlinks=False):
        directory_path = Path(directory)
        relative_directory = directory_path.relative_to(root)
        directory_names[:] = [
            name
            for name in directory_names
            if not _is_ignored_relative(relative_directory / name)
            and not (directory_path / name).is_symlink()
        ]
        for name in file_names:
            path = directory_path / name
            relative = path.relative_to(root)
            if not _is_ignored_relative(relative) and not path.is_symlink():
                paths.append(path)
    return paths


def _snapshot_tree(root: Path) -> TreeSnapshot:
    hashes: dict[str, str] = {}
    errors: list[str] = []
    for path in sorted(_tracked_tree_paths(root)):
        relative_name = path.relative_to(root).as_posix()
        try:
            hashes[relative_name] = sha256_file(path)
        except (OSError, ValueError) as exc:
            if len(errors) < _MAX_SNAPSHOT_ERRORS:
                errors.append(f"{relative_name}:{type(exc).__name__}")
    return TreeSnapshot(hashes=hashes, errors=tuple(errors))


def tree_hash(root: Path) -> str:
    snapshot = _snapshot_tree(root)
    if snapshot.errors:
        raise OSError("unstable tree snapshot")  # noqa: TRY003
    digest = hashlib.sha256()
    for path in sorted(_tracked_tree_paths(root)):
        relative = path.relative_to(root).as_posix().encode()
        try:
            content = path.read_bytes()
        except OSError as exc:
            raise OSError("unstable tree snapshot") from exc  # noqa: TRY003
        digest.update(relative)
        digest.update(b"\0")
        digest.update(content)
        digest.update(b"\0")
    return digest.hexdigest()


def file_hashes(root: Path) -> dict[str, str]:
    snapshot = _snapshot_tree(root)
    if snapshot.errors:
        raise OSError("unstable file snapshot")  # noqa: TRY003
    return snapshot.hashes


def _snapshot_digest(snapshot: TreeSnapshot) -> str:
    digest = hashlib.sha256()
    for relative_name, file_hash in sorted(snapshot.hashes.items()):
        digest.update(relative_name.encode())
        digest.update(b"\0")
        digest.update(file_hash.encode())
        digest.update(b"\0")
    return digest.hexdigest()


def _git_output(root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), *arguments],
        capture_output=True,
        text=True,
        check=True,
    )
    return completed.stdout


def _parent_sentinel_snapshot(root: Path) -> tuple[TreeSnapshot, str]:
    """Hash parent product files without traversing evaluation worktrees/caches.

    Git supplies the bounded candidate set: tracked files plus ordinary untracked
    files. The status digest catches deletions and metadata changes; file hashes
    catch in-place edits that status alone cannot distinguish. Non-git roots use
    the same explicit transient-directory exclusions as a test-only fallback.
    """
    errors: list[str] = []
    hashes: dict[str, str] = {}
    try:
        status = _git_output(root, "status", "--short", "--untracked-files=all")
        candidates = _git_output(
            root, "ls-files", "--cached", "--others", "--exclude-standard"
        ).splitlines()
        candidate_paths = [
            root / relative for relative in candidates if not _is_ignored_relative(Path(relative))
        ]
    except (OSError, subprocess.CalledProcessError):
        status = ""
        candidate_paths = _tracked_tree_paths(root)
    for path in sorted(candidate_paths):
        relative_name = path.relative_to(root).as_posix()
        try:
            if path.is_symlink():
                hashes[relative_name] = sha256_bytes(path.readlink().as_posix().encode())
            elif path.is_file():
                hashes[relative_name] = sha256_file(path)
        except (OSError, ValueError) as exc:
            if len(errors) < _MAX_SNAPSHOT_ERRORS:
                errors.append(f"{relative_name}:{type(exc).__name__}")
    status_hash = sha256_bytes(status.encode())
    return TreeSnapshot(hashes=hashes, errors=tuple(errors)), status_hash


def _parent_evidence(root: Path) -> dict[str, Any]:
    snapshot, status_hash = _parent_sentinel_snapshot(root)
    evidence: dict[str, Any] = {
        "path": str(root),
        "accessible": not snapshot.errors,
        "tree_hash": None,
        "sentinel_version": _PARENT_SENTINEL_VERSION,
        "status_sha256": status_hash,
        "file_count": len(snapshot.hashes),
        "excluded_tree_parts": sorted(_IGNORED_TREE_PARTS),
        "excluded_tree_names": sorted(_IGNORED_TREE_NAMES),
    }
    if snapshot.errors:
        evidence["error"] = "unstable_snapshot"
        evidence["unstable_paths"] = list(snapshot.errors)
    else:
        digest = hashlib.sha256(status_hash.encode())
        digest.update(_snapshot_digest(snapshot).encode())
        evidence["tree_hash"] = digest.hexdigest()
    return evidence


def _changed_paths(before: dict[str, str], after: dict[str, str]) -> list[str]:
    return sorted(path for path in set(before) | set(after) if before.get(path) != after.get(path))


def load_protocol() -> dict[str, Any]:
    return json.loads(PROTOCOL_PATH.read_text(encoding="utf-8"))


def parent_repository_root() -> Path | None:
    try:
        common_dir = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "--git-common-dir"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None
    common_path = Path(common_dir)
    if not common_path.is_absolute():
        common_path = (ROOT / common_path).resolve()
    return common_path.parent


def synthetic_fixture() -> Fixture:
    root = ROOT / "evaluation" / "fixtures" / "synthetic-repo"
    return Fixture("synthetic", root, root / "TASK.md")


def copy_fixture(fixture: Fixture, destination: Path) -> None:
    shutil.copytree(fixture.root, destination, dirs_exist_ok=True)


def materialise_pack(checkout: Path, destination: Path) -> tuple[str, str]:
    source_paths = [
        path for path in _tracked_tree_paths(checkout) if destination not in path.parents
    ]
    destination.mkdir(parents=True, exist_ok=True)
    source_hash = tree_hash(checkout)
    pack = {
        "pack_version": "evaluation-0.1",
        "source_tree_sha256": source_hash,
        "selected_files": [],
        "evidence_origin": "derived_from_local_fixture",
    }
    for path in sorted(source_paths):
        relative = path.relative_to(checkout)
        if relative.parts[0] == ".git":
            continue
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
        pack["selected_files"].append({"path": relative.as_posix(), "sha256": sha256_file(path)})
    pack_bytes = json.dumps(pack, sort_keys=True, separators=(",", ":")).encode()
    pack_hash = sha256_bytes(pack_bytes)
    pack["pack_sha256"] = pack_hash
    pack_path = destination / "context-pack.json"
    pack_path.write_text(json.dumps(pack, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return pack_hash, sha256_file(pack_path)


def command_version(executable: str) -> str:
    try:
        completed = subprocess.run(
            [executable, "--version"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"unavailable:{type(exc).__name__}"
    version = _bounded_summary(completed.stdout.strip())
    return version[:200] or f"exit:{completed.returncode}"


def frozen_protocol_hash() -> str:
    return sha256_file(PROTOCOL_PATH)


def assignment_order(repetitions: int) -> list[tuple[str, int]]:
    assignments = [(arm, attempt) for attempt in range(1, repetitions + 1) for arm in ("A", "B")]
    random.Random(ASSIGNMENT_SEED).shuffle(assignments)
    return assignments


def _bounded_summary(data: str) -> str:
    clean = re.sub(
        r"(?i)(token|password|secret|api[_-]?key)\s*[=:]\s*[^\s,;]+", r"\1=[REDACTED]", data
    )
    clean = re.sub(r"https?://[^\s/@]+:[^\s/@]+@", "https://[REDACTED]@", clean)
    return clean[:_OUTPUT_LIMIT]


def _isolated_environment(root: Path) -> dict[str, str]:
    home = root / "home"
    config = root / "config"
    cache = root / "cache"
    data = root / "data"
    for path in (home, config, cache, data):
        path.mkdir(parents=True, exist_ok=True)
    environment = os.environ.copy()
    environment.update(
        {
            "HOME": str(home),
            "USERPROFILE": str(home),
            "XDG_CONFIG_HOME": str(config),
            "XDG_CACHE_HOME": str(cache),
            "XDG_DATA_HOME": str(data),
            "OPENCODE_CONFIG_DIR": str(config / "opencode"),
            "OPENCODE_DISABLE_PROJECT_CONFIG": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
    )
    return environment


def _validate_project_argument(checkout: Path, project: Path) -> str | None:
    checkout_resolved = checkout.resolve()
    if project.is_symlink():
        return "project_argument_symlink"
    try:
        project_resolved = project.resolve(strict=True)
    except OSError:
        return "project_argument_unresolvable"
    try:
        project_resolved.relative_to(checkout_resolved)
    except ValueError:
        return "project_argument_outside_checkout"
    return None


def _launch_manifest(
    *, command: list[str], environment: dict[str, str], executable_version: str
) -> dict[str, Any]:
    project_argument = command[1] if len(command) > 1 else None
    normalized_command = [
        "<executable>"
        if index == 0
        else ("<checkout>" if index == 1 and project_argument else value)
        for index, value in enumerate(command)
    ]
    return {
        "argv": normalized_command,
        "cwd": "<checkout>",
        "project_argument": "<checkout>" if project_argument else None,
        "project_argument_is_explicit": bool(project_argument),
        "environment": {
            "OPENCODE_DISABLE_PROJECT_CONFIG": environment.get("OPENCODE_DISABLE_PROJECT_CONFIG"),
            "OPENCODE_CONFIG_DIR": "<checkout>/config/opencode",
            "FARNA_CONTEXT_EVALUATION_CHECKOUT": "<checkout>",
        },
        "executable_version": executable_version,
    }


def _prompt_for(arm: str, task: bytes, pack_path: Path | None, checkout: Path) -> bytes:
    instruction = (
        b"\n\nWork only inside this isolated checkout. "
        b"Do not access or modify any parent repository."
    )
    if arm == "A":
        return task + instruction
    if pack_path is None:
        raise ValueError("Arm B requires a materialised pack")  # noqa: TRY003
    relative_pack = pack_path.relative_to(checkout).as_posix()
    return (
        task
        + b"\n\nThe generated context pack is available at: "
        + relative_pack.encode()
        + instruction
        + b"\n"
    )


def _changed_files(before: dict[str, str], checkout: Path) -> list[str]:
    return _changed_paths(before, file_hashes(checkout))


def _guardrail_results(
    before: dict[str, str], checkout: Path, output: bytes, error: bytes
) -> tuple[list[str], bool, bool, bool, str | None]:
    try:
        after = file_hashes(checkout)
    except OSError:
        return [], False, False, False, "checkout_snapshot_unstable"
    changed = sorted(
        path for path in set(before) | set(after) if before.get(path) != after.get(path)
    )
    scope_ok = set(changed).issubset(_ALLOWED_CHANGED_FILES)
    deletion_ok = all(path in after for path in before if path.startswith("tests/"))
    if deletion_ok:
        for path in sorted(path for path in after if path.startswith("tests/")):
            content = (checkout / path).read_bytes()
            if re.search(
                rb"(?i)(pytest\.mark\.skip|pytest\.mark\.xfail|unittest\.skip|@skip)", content
            ):
                deletion_ok = False
                break
    combined = output + b"\n" + error
    secret_ok = not any(pattern.search(combined) for pattern in _SECRET_PATTERNS.values())
    if secret_ok:
        for path in changed:
            if any(
                pattern.search((checkout / path).read_bytes())
                for pattern in _SECRET_PATTERNS.values()
            ):
                secret_ok = False
                break
    return changed, scope_ok, deletion_ok, secret_ok, None


def _run_oracle(checkout: Path, environment: dict[str, str]) -> tuple[bool, str]:
    try:
        completed = subprocess.run(
            [sys.executable, "-m", "pytest", "tests/test_slugify.py", "-q"],
            cwd=checkout,
            env=environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"oracle:{type(exc).__name__}"
    summary = _bounded_summary(completed.stdout + "\n" + completed.stderr)
    return completed.returncode == 0, summary


def execute_attempt(  # noqa: PLR0913, PLR0915
    *,
    arm: str,
    checkout: Path,
    task: bytes,
    pack_path: Path | None,
    command: list[str],
    timeout: int,
) -> ExecutionResult:
    try:
        before = file_hashes(checkout)
    except OSError:
        return ExecutionResult(
            process_status="setup_error",
            returncode=None,
            stdout_summary="",
            stderr_summary="",
            elapsed_seconds=0.0,
            provider_ok=False,
            provider_failure_class=None,
            oracle_passed=None,
            oracle_summary="not_run:setup_invalidity",
            changed_files=[],
            scope_ok=False,
            test_deletion_ok=False,
            secret_output_ok=True,
            contamination_ok=True,
            contamination_evidence={"error": "checkout_snapshot_unstable"},
            prompt_sha256="",
            setup_ok=False,
            harness_ok=True,
            guard_error="checkout_snapshot_unstable",
            launch_manifest={},
        )
    project_argument = Path(command[1]) if len(command) > 1 else Path()
    project_error = _validate_project_argument(checkout, project_argument)
    if project_error:
        return ExecutionResult(
            process_status="setup_error",
            returncode=None,
            stdout_summary="",
            stderr_summary="",
            elapsed_seconds=0.0,
            provider_ok=False,
            provider_failure_class=None,
            oracle_passed=None,
            oracle_summary="not_run:setup_invalidity",
            changed_files=[],
            scope_ok=False,
            test_deletion_ok=False,
            secret_output_ok=True,
            contamination_ok=True,
            contamination_evidence={"error": project_error},
            prompt_sha256="",
            setup_ok=False,
            harness_ok=True,
            guard_error=project_error,
            launch_manifest={"project_argument": str(project_argument), "error": project_error},
        )
    parent_root = parent_repository_root()
    parent_before = _parent_evidence(parent_root) if parent_root else {"accessible": False}
    prompt = _prompt_for(arm, task, pack_path, checkout)
    prompt_path = checkout / ".evaluation-prompt.md"
    prompt_path.write_bytes(prompt)
    environment = _isolated_environment(checkout)
    environment["OPENCODE_PROJECT_DIR"] = str(checkout)
    environment["FARNA_CONTEXT_EVALUATION_CHECKOUT"] = str(checkout)
    command = [*command]
    executable_version = command_version(command[0])
    launch_manifest = _launch_manifest(
        command=command,
        environment=environment,
        executable_version=executable_version,
    )
    started = time.monotonic()
    output = b""
    error = b""
    process_status = "completed"
    returncode: int | None = None
    provider_ok = False
    provider_failure_class: str | None = None
    try:
        with prompt_path.open("rb") as prompt_file:
            completed = subprocess.run(
                command,
                cwd=checkout,
                env=environment,
                stdin=prompt_file,
                capture_output=True,
                timeout=timeout,
                check=False,
            )
        output = completed.stdout
        error = completed.stderr
        returncode = completed.returncode
        provider_ok = returncode == 0
        if not provider_ok:
            provider_failure_class = "provider_or_process_error"
    except FileNotFoundError:
        process_status = "executable_unavailable"
        provider_failure_class = "executable_unavailable"
    except subprocess.TimeoutExpired as exc:
        process_status = "timeout"
        provider_failure_class = "execution_timeout"
        output = exc.stdout or b""
        error = exc.stderr or b""
    except OSError as exc:
        process_status = "process_error"
        provider_failure_class = type(exc).__name__
    elapsed = time.monotonic() - started
    changed, scope_ok, deletion_ok, secret_ok, guard_error = _guardrail_results(
        before, checkout, output, error
    )
    parent_after = _parent_evidence(parent_root) if parent_root else {"accessible": False}
    contamination_ok = parent_before == parent_after and parent_after.get("accessible", False)
    setup_ok = guard_error is None
    harness_ok = True
    try:
        checkout_before_hash = tree_hash(checkout)
    except OSError:
        checkout_before_hash = None
        guard_error = guard_error or "checkout_snapshot_unstable"
        setup_ok = False
        harness_ok = False
    contamination_evidence = {
        "parent_before": parent_before,
        "parent_after": parent_after,
        "checkout_before_tree_sha256": checkout_before_hash,
        "checkout_changed_files": changed,
        "checkout_root": str(checkout),
    }
    launch_manifest["project_argument_validation"] = "passed"

    oracle_passed: bool | None = None
    oracle_summary = "not_run:provider_failure"
    if provider_ok and contamination_ok:
        oracle_passed, oracle_summary = _run_oracle(checkout, environment)
    elif provider_ok:
        oracle_summary = "not_run:contamination_invalidity"
    return ExecutionResult(
        process_status=process_status,
        returncode=returncode,
        stdout_summary=_bounded_summary(output.decode("utf-8", errors="replace")),
        stderr_summary=_bounded_summary(error.decode("utf-8", errors="replace")),
        elapsed_seconds=round(elapsed, 6),
        provider_ok=provider_ok,
        provider_failure_class=provider_failure_class,
        oracle_passed=oracle_passed,
        oracle_summary=oracle_summary,
        changed_files=changed,
        scope_ok=scope_ok,
        test_deletion_ok=deletion_ok,
        secret_output_ok=secret_ok,
        contamination_ok=contamination_ok,
        contamination_evidence=contamination_evidence,
        prompt_sha256=sha256_bytes(prompt),
        setup_ok=setup_ok,
        harness_ok=harness_ok,
        guard_error=guard_error,
        launch_manifest=launch_manifest,
    )


def build_record(  # noqa: PLR0913
    *,
    experiment_id: str,
    task_id: str,
    fixture: Fixture,
    arm: str,
    attempt: int,
    assignment_index: int,
    pack_hash: str | None,
    post_pack_hash: str | None,
    pack_path: Path | None,
    dry_run: bool,
    model: str,
    executable: str,
    protocol: dict[str, Any],
    execution: ExecutionResult | None,
) -> dict[str, Any]:
    task_bytes = fixture.task.read_bytes()
    task_hash = sha256_bytes(task_bytes)
    if dry_run or execution is None:
        outcome = "not_run" if dry_run else "unobserved"
        validity = classify_attempt(
            setup_ok=True,
            harness_ok=True,
            contamination_ok=True,
            provider_ok=dry_run,
            outcome=outcome,
        )
        checks: dict[str, bool] = {}
    else:
        checks = {
            "oracle": execution.oracle_passed is True,
            "changed_file_scope": execution.scope_ok,
            "test_deletion_or_disablement": execution.test_deletion_ok,
            "secret_output": execution.secret_output_ok,
            "contamination": execution.contamination_ok,
        }
        guardrails_ok = all(checks.values())
        outcome = "success" if execution.oracle_passed and guardrails_ok else "failure"
        validity = classify_attempt(
            setup_ok=execution.setup_ok,
            harness_ok=execution.harness_ok,
            contamination_ok=execution.contamination_ok,
            provider_ok=execution.provider_ok,
            outcome=outcome,
        )
        if not execution.provider_ok:
            outcome = "provider_failure"
        elif not execution.contamination_ok:
            outcome = "failure"
    return {
        "experiment_id": experiment_id,
        "protocol_version": protocol["protocol_version"],
        "protocol_sha256": frozen_protocol_hash(),
        "task_id": task_id,
        "repo_revision": protocol["frozen_inputs"]["fixture_revision"],
        "arm": arm,
        "arm_label": protocol["arms"][arm]["label"],
        "assignment": {
            "seed": ASSIGNMENT_SEED,
            "order_index": assignment_index,
            "strategy": protocol["assignment"]["arm_order"],
        },
        "harness_version": "evaluation-0.2.0",
        "model_version": model,
        "tool_versions": {
            "python": sys.version.split()[0],
            "opencode": "not_run" if dry_run else command_version(executable),
        },
        "permission_policy": protocol["isolation"]["permission_policy"],
        "network_policy": protocol["isolation"]["network_policy"],
        "cache_policy": protocol["isolation"]["fresh_cache_policy"],
        "run_id": f"{experiment_id}:{arm}:{attempt}",
        "attempt": attempt,
        "validity": validity,
        "scores": score_task(outcome=outcome, rubric_frozen=True, checks=checks),
        "input_hashes": {
            "task_sha256": task_hash,
            "fixture_tree_sha256": tree_hash(fixture.root),
            "task_bytes_sha256": sha256_bytes(task_bytes),
        },
        "frozen_task": {
            "path": protocol["frozen_inputs"]["task_path"],
            "sha256": protocol["frozen_inputs"]["task_input_sha256"],
        },
        "pre_pack_sha256": pack_hash,
        "post_pack_sha256": post_pack_hash,
        "pack_materialisation": {
            "boundary": protocol["arms"]["B"].get("materialisation_boundary"),
            "path": str(pack_path) if pack_path else None,
        },
        "delivery_evidence": {
            "observed": execution is not None and execution.provider_ok if not dry_run else False,
            "oracle_passed": execution.oracle_passed if execution else None,
            "oracle_summary": execution.oracle_summary if execution else "not_run",
            "changed_files": execution.changed_files if execution else [],
            "process_status": execution.process_status if execution else "not_run",
            "returncode": execution.returncode if execution else None,
            "provider_failure_class": execution.provider_failure_class if execution else None,
            "guard_error": execution.guard_error if execution else None,
            "stdout_summary": execution.stdout_summary if execution else "",
            "stderr_summary": execution.stderr_summary if execution else "",
            "launch_manifest": execution.launch_manifest if execution else {},
        },
        "secondary_metrics": {
            "task_completion_status": "completed"
            if execution and execution.provider_ok
            else "not_run",
            "changed_file_scope": execution.scope_ok if execution else "not_observed",
            "preparation_cost": None,
            "pack_size_bytes": pack_path.stat().st_size if pack_path else 0,
            "elapsed_wall_time_seconds": execution.elapsed_seconds if execution else None,
            "tool_call_count": None,
        },
        "guardrails": {
            "status": "not_run"
            if dry_run
            else (
                "passed"
                if execution and all(checks.values())
                else "failed"
                if execution
                else "unobserved"
            ),
            "rules": protocol["guardrails"],
            "checks": checks,
        },
        "contamination_check": {
            "status": "passed"
            if dry_run
            else ("passed" if execution and execution.contamination_ok else "failed"),
            "cross_arm_outputs": False,
            "fresh_checkout": True,
            "fresh_session": True,
            "fresh_cache": True,
            "evidence": execution.contamination_evidence if execution else {},
        },
        "harness_load_status": "not_applicable" if arm == "A" else "observed",
        "model_use_status": "not_run"
        if dry_run
        else ("observed" if execution and execution.provider_ok else "provider_failure"),
        "outcome_status": outcome,
        "prompt_sha256": execution.prompt_sha256 if execution else None,
    }


def run_evaluation(  # noqa: PLR0913
    *,
    fixture: Fixture,
    output_dir: Path,
    repetitions: int,
    dry_run: bool,
    model: str,
    executable: str,
) -> tuple[Path, Path]:
    protocol = load_protocol()
    experiment_id = f"exp-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"
    experiment_dir = output_dir / experiment_id
    experiment_dir.mkdir(parents=True, exist_ok=False)
    result_path = experiment_dir / "results.jsonl"
    records: list[dict[str, Any]] = []
    task_id = protocol["frozen_inputs"]["task_id"]
    for assignment_index, (arm, attempt) in enumerate(assignment_order(repetitions), start=1):
        with tempfile.TemporaryDirectory(prefix=f"evaluation-{arm}-{attempt}-") as temporary:
            temporary_path = Path(temporary)
            checkout = temporary_path / "checkout"
            copy_fixture(fixture, checkout)
            pack_hash: str | None = None
            post_pack_hash: str | None = None
            pack_path: Path | None = None
            if arm == "B":
                pack_path = checkout / ".evaluation-pack"
                pack_hash, post_pack_hash = materialise_pack(checkout, pack_path)
            command = [executable, str(checkout), "run", "--auto", "--format", "json"]

            if model != "UNSPECIFIED":
                command.extend(["--model", model])
            execution = (
                None
                if dry_run
                else execute_attempt(
                    arm=arm,
                    checkout=checkout,
                    task=fixture.task.read_bytes(),
                    pack_path=pack_path,
                    command=command,
                    timeout=int(protocol["runner"]["timeout_seconds"]),
                )
            )
            records.append(
                build_record(
                    experiment_id=experiment_id,
                    task_id=task_id,
                    fixture=fixture,
                    arm=arm,
                    attempt=attempt,
                    assignment_index=assignment_index,
                    pack_hash=pack_hash,
                    post_pack_hash=post_pack_hash,
                    pack_path=pack_path,
                    dry_run=dry_run,
                    model=model,
                    executable=executable,
                    protocol=protocol,
                    execution=execution,
                )
            )
    result_path.write_text(
        "\n".join(json.dumps(record, sort_keys=True) for record in records) + "\n", encoding="utf-8"
    )
    summary = {
        "experiment_id": experiment_id,
        "protocol_version": protocol["protocol_version"],
        "protocol_sha256": frozen_protocol_hash(),
        "fixture": fixture.name,
        "fixture_revision": protocol["frozen_inputs"]["fixture_revision"],
        "fixture_tree_sha256": protocol["frozen_inputs"]["fixture_tree_sha256"],
        "task_id": task_id,
        "task_sha256": protocol["frozen_inputs"]["task_input_sha256"],
        "repetitions_per_arm": repetitions,
        "assignment_seed": ASSIGNMENT_SEED,
        "arm_order": [record["arm"] for record in records],
        "dry_run": dry_run,
        "thresholds": DECISION_THRESHOLDS,
        "records": len(records),
        "validity_counts": {
            value: sum(record["validity"] == value for record in records)
            for value in (
                "valid_task_success",
                "valid_task_failure",
                "setup_invalidity",
                "harness_invalidity",
                "provider_failure",
                "contamination_invalidity",
                "unobserved",
            )
        },
        "result_jsonl": str(result_path),
    }
    summary_path = experiment_dir / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result_path, summary_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", choices=("synthetic",), default="synthetic")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "evaluation" / "runs")
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument(
        "--dry-run", action="store_true", help="Plan records without invoking OpenCode"
    )
    parser.add_argument("--model", default="UNSPECIFIED")
    parser.add_argument("--opencode", default="opencode")
    args = parser.parse_args()
    if args.repetitions < 1:
        parser.error("--repetitions must be positive")
    result_path, summary_path = run_evaluation(
        fixture=synthetic_fixture(),
        output_dir=args.output_dir,
        repetitions=args.repetitions,
        dry_run=args.dry_run,
        model=args.model,
        executable=args.opencode,
    )
    sys.stdout.write(json.dumps({"results": str(result_path), "summary": str(summary_path)}) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
