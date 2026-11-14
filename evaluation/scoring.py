"""Frozen-rubric scoring helpers for the controlled evaluation."""

from __future__ import annotations

from typing import Any

VALID_OUTCOMES = {"success", "failure", "provider_failure", "unobserved", "not_run"}
DECISION_THRESHOLDS = {
    "absolute_correctness_difference_points": 20,
    "maximum_overhead_ratio": 2.0,
    "minimum_valid_runs_per_arm": 4,
    "maximum_invalidity_asymmetry": 0.10,
}


def score_task(*, outcome: str, rubric_frozen: bool, checks: dict[str, bool]) -> dict[str, Any]:
    """Return a conservative score; never score an unfrozen task."""
    if outcome not in VALID_OUTCOMES:
        raise ValueError("unsupported outcome")  # noqa: TRY003
    if not rubric_frozen:
        return {"status": "unfrozen", "value": None, "checks": {}}
    if outcome not in {"success", "failure"}:
        return {"status": "not_scored", "value": None, "checks": checks}
    passed = outcome == "success" and all(checks.values())
    return {"status": "scored", "value": 1 if passed else 0, "checks": checks}


def classify_attempt(
    *,
    setup_ok: bool,
    harness_ok: bool,
    contamination_ok: bool,
    provider_ok: bool,
    outcome: str,
) -> str:
    """Classify an attempt before any task score is considered."""
    if not setup_ok:
        classification = "setup_invalidity"
    elif not harness_ok:
        classification = "harness_invalidity"
    elif not contamination_ok:
        classification = "contamination_invalidity"
    elif not provider_ok:
        classification = "provider_failure"
    elif outcome == "success":
        classification = "valid_task_success"
    elif outcome == "failure":
        classification = "valid_task_failure"
    else:
        classification = "unobserved"
    return classification
