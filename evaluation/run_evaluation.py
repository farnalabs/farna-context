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
    prompt_sha256: str


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def tree_hash(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        relative = path.relative_to(root).as_posix().encode()
        digest.update(relative)
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def file_hashes(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): sha256_file(path)
        for path in root.rglob("*")
        if path.is_file()
    }


def load_protocol() -> dict[str, Any]:
    return json.loads(PROTOCOL_PATH.read_text(encoding="utf-8"))


def synthetic_fixture() -> Fixture:
    root = ROOT / "evaluation" / "fixtures" / "synthetic-repo"
    return Fixture("synthetic", root, root / "TASK.md")


def copy_fixture(fixture: Fixture, destination: Path) -> None:
    shutil.copytree(fixture.root, destination, dirs_exist_ok=True)


def materialise_pack(checkout: Path, destination: Path) -> tuple[str, str]:
    destination.mkdir(parents=True, exist_ok=True)
    source_hash = tree_hash(checkout)
    pack = {
        "pack_version": "evaluation-0.1",
        "source_tree_sha256": source_hash,
        "selected_files": [],
        "evidence_origin": "derived_from_local_fixture",
    }
    for path in sorted(item for item in checkout.rglob("*") if item.is_file()):
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
            "OPENCODE_DISABLE_PROJECT_CONFIG": "0",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
    )
    return environment


def _prompt_for(arm: str, task: bytes, pack_path: Path | None) -> bytes:
    if arm == "A":
        return task
    if pack_path is None:
        raise ValueError("Arm B requires a materialised pack")  # noqa: TRY003
    return (
        task + b"\n\nThe generated context pack is available at: " + str(pack_path).encode() + b"\n"
    )


def _changed_files(before: dict[str, str], checkout: Path) -> list[str]:
    after = file_hashes(checkout)
    return sorted(
        set(before) | set(after) - {path for path in before if before[path] == after.get(path)}
    )


def _guardrail_results(
    before: dict[str, str], checkout: Path, output: bytes, error: bytes
) -> tuple[list[str], bool, bool, bool]:
    after = file_hashes(checkout)
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
    return changed, scope_ok, deletion_ok, secret_ok


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


def execute_attempt(  # noqa: PLR0913
    *,
    arm: str,
    checkout: Path,
    task: bytes,
    pack_path: Path | None,
    command: list[str],
    timeout: int,
) -> ExecutionResult:
    before = file_hashes(checkout)
    prompt = _prompt_for(arm, task, pack_path)
    prompt_path = checkout.parent / "prompt.md"
    prompt_path.write_bytes(prompt)
    environment = _isolated_environment(checkout.parent)
    command = [*command]
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
    changed, scope_ok, deletion_ok, secret_ok = _guardrail_results(before, checkout, output, error)
    oracle_passed: bool | None = None
    oracle_summary = "not_run:provider_failure"
    if provider_ok:
        oracle_passed, oracle_summary = _run_oracle(checkout, environment)
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
        prompt_sha256=sha256_bytes(prompt),
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
        }
        guardrails_ok = all(checks.values())
        outcome = "success" if execution.oracle_passed and guardrails_ok else "failure"
        validity = classify_attempt(
            setup_ok=True,
            harness_ok=True,
            contamination_ok=True,
            provider_ok=execution.provider_ok,
            outcome=outcome,
        )
        if not execution.provider_ok:
            outcome = "provider_failure"
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
            "opencode": command_version(executable),
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
            "stdout_summary": execution.stdout_summary if execution else "",
            "stderr_summary": execution.stderr_summary if execution else "",
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
            "status": "passed",
            "cross_arm_outputs": False,
            "fresh_checkout": True,
            "fresh_session": True,
            "fresh_cache": True,
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
                pack_path = temporary_path / "pack"
                pack_hash, post_pack_hash = materialise_pack(checkout, pack_path)
            command = [executable, "run", "--auto", "--format", "json"]
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
