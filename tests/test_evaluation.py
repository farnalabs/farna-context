from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from evaluation.run_evaluation import load_protocol, run_evaluation, synthetic_fixture
from evaluation.scoring import classify_attempt, score_task

ROOT = Path(__file__).resolve().parents[1]


def test_protocol_has_required_boundaries() -> None:
    protocol = load_protocol()
    assert protocol["arms"]["A"]["additional_materialisation"] is False
    assert protocol["arms"]["B"]["additional_materialisation"] is True
    assert protocol["isolation"]["cross_arm_outputs_allowed"] is False
    assert protocol["runner"]["stdin"] == (
        "always closed with subprocess.DEVNULL unless an explicit prompt file redirect is used"
    )
    required = set(protocol["required_record_fields"])
    assert {"experiment_id", "arm", "validity", "contamination_check"}.issubset(required)


def test_scoring_stays_unfrozen() -> None:
    result = score_task(outcome="success", rubric_frozen=False, checks={"tests": True})
    assert result["status"] == "unfrozen"
    assert result["value"] is None


def test_classification_prioritises_contamination() -> None:
    result = classify_attempt(
        setup_ok=True,
        harness_ok=True,
        contamination_ok=False,
        provider_ok=True,
        outcome="failure",
    )
    assert result == "contamination_invalidity"


def test_dry_run_writes_two_arms_and_summary(tmp_path: Path) -> None:
    results_path, summary_path = run_evaluation(
        fixture=synthetic_fixture(),
        output_dir=tmp_path,
        repetitions=2,
        dry_run=True,
        model="UNSPECIFIED",
        executable="opencode",
    )
    records = [json.loads(line) for line in results_path.read_text(encoding="utf-8").splitlines()]
    expected_records = 4
    assert len(records) == expected_records
    assert {record["arm"] for record in records} == {"A", "B"}
    assert all(record["outcome_status"] == "not_run" for record in records)
    assert all(record["scores"]["status"] == "unfrozen" for record in records)
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert summary["records"] == expected_records
    assert summary["dry_run"] is True


def test_cli_dry_run_emits_json_paths(tmp_path: Path) -> None:
    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "evaluation" / "run_evaluation.py"),
            "--fixture",
            "synthetic",
            "--dry-run",
            "--repetitions",
            "1",
            "--output-dir",
            str(tmp_path),
        ],
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0
    output = json.loads(completed.stdout)
    assert Path(output["results"]).is_file()
    assert Path(output["summary"]).is_file()
