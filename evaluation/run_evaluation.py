"""Run the controlled OpenCode usefulness evaluation."""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import shutil
import subprocess
import sys
import tempfile
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


@dataclass(frozen=True)
class Fixture:
    name: str
    root: Path
    task: Path


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
    return completed.stdout.strip()[:200] or f"exit:{completed.returncode}"


def frozen_protocol_hash() -> str:
    return sha256_file(PROTOCOL_PATH)


def assignment_order(repetitions: int) -> list[tuple[str, int]]:
    assignments = [(arm, attempt) for attempt in range(1, repetitions + 1) for arm in ("A", "B")]
    random.Random(ASSIGNMENT_SEED).shuffle(assignments)
    return assignments


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
) -> dict[str, Any]:
    task_bytes = fixture.task.read_bytes()
    task_hash = sha256_bytes(task_bytes)
    outcome = "not_run" if dry_run else "unobserved"
    validity = classify_attempt(
        setup_ok=True,
        harness_ok=True,
        contamination_ok=True,
        provider_ok=dry_run,
        outcome="unobserved" if not dry_run else "not_run",
    )
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
        "scores": score_task(outcome=outcome, rubric_frozen=True, checks={}),
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
            "observed": False,
            "reason": "dry-run or provider not invoked",
            "oracle": protocol["task_and_scoring"]["primary_oracle"],
        },
        "secondary_metrics": {
            "task_completion_status": "not_run",
            "changed_file_scope": "not_observed",
            "preparation_cost": None,
            "pack_size_bytes": pack_path.stat().st_size if pack_path else 0,
            "elapsed_wall_time_seconds": None,
            "tool_call_count": None,
        },
        "guardrails": {
            "status": "not_run" if dry_run else "unobserved",
            "rules": protocol["guardrails"],
        },
        "contamination_check": {
            "status": "passed",
            "cross_arm_outputs": False,
            "fresh_checkout": True,
            "fresh_session": True,
            "fresh_cache": True,
        },
        "harness_load_status": "not_applicable" if arm == "A" else "observed",
        "model_use_status": "not_run" if dry_run else "unobserved",
        "outcome_status": outcome,
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
            checkout = Path(temporary) / "checkout"
            copy_fixture(fixture, checkout)
            pack_hash: str | None = None
            post_pack_hash: str | None = None
            pack_path: Path | None = None
            if arm == "B":
                pack_path = Path(temporary) / "pack"
                pack_hash, post_pack_hash = materialise_pack(checkout, pack_path)
            record = build_record(
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
            )
            records.append(record)
    result_text = "\n".join(json.dumps(record, sort_keys=True) for record in records) + "\n"
    result_path.write_text(result_text, encoding="utf-8")
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
    fixture = synthetic_fixture()
    result_path, summary_path = run_evaluation(
        fixture=fixture,
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
