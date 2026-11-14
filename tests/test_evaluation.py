from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import evaluation.run_evaluation as evaluation_runner
from evaluation.run_evaluation import load_protocol, run_evaluation, synthetic_fixture
from evaluation.scoring import DECISION_THRESHOLDS, classify_attempt, score_task

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_TASK_HASH = "bb6900332ee84e9330e5f2c91658b40cce35710b37dc1295768bf94934387c26"
EXPECTED_FIXTURE_TREE_HASH = "1b5c29a6c8be7e41a724b657c2944d58a356dae6dd5b5b0fbb3740cc3ac9fcb7"
EXPECTED_REPETITIONS = 5
EXPECTED_ASSIGNMENT_SEED = 20261114
EXPECTED_INVALIDITY_ASYMMETRY = 0.10
EXPECTED_THRESHOLD_POINTS = 20
EXPECTED_OVERHEAD_RATIO = 2.0
EXPECTED_MINIMUM_VALID_RUNS = 4
EXPECTED_EXECUTION_RECORDS = 2


def test_protocol_has_required_boundaries_and_thresholds() -> None:
    protocol = load_protocol()
    assert protocol["protocol_version"] == "0.2.0"
    assert protocol["frozen_inputs"]["fixture"] == "synthetic"
    assert protocol["frozen_inputs"]["fixture_tree_sha256"] == EXPECTED_FIXTURE_TREE_HASH
    assert protocol["frozen_inputs"]["task_input_sha256"] == EXPECTED_TASK_HASH
    assert protocol["frozen_inputs"]["task_bytes"]
    assert protocol["arms"]["A"]["generated_pack"] is False
    assert protocol["arms"]["B"]["generated_pack"] is True
    assert protocol["arms"]["B"]["materialisation_boundary"]
    assert protocol["assignment"]["repetitions_per_arm"] == EXPECTED_REPETITIONS
    assert protocol["isolation"]["fresh_cache_per_attempt"] is True
    assert protocol["validity"]["asymmetric_invalidity_limit"] == EXPECTED_INVALIDITY_ASYMMETRY
    thresholds = protocol["exploratory_decision_thresholds"]
    assert thresholds["absolute_correctness_difference_points"] == EXPECTED_THRESHOLD_POINTS
    assert thresholds["maximum_overhead_ratio"] == EXPECTED_OVERHEAD_RATIO
    assert thresholds["minimum_valid_runs_per_arm"] == EXPECTED_MINIMUM_VALID_RUNS
    assert thresholds["thresholds_are_product_guarantees"] is False
    assert protocol["causal_interpretation"].startswith("Do not claim")
    assert protocol["runner"]["stdin"].startswith("always closed")
    assert (
        DECISION_THRESHOLDS["absolute_correctness_difference_points"] == EXPECTED_THRESHOLD_POINTS
    )
    required = set(protocol["required_record_fields"])
    assert {"experiment_id", "arm", "validity", "contamination_check"}.issubset(required)


def test_scoring_stays_frozen_and_valid_failures_are_scored() -> None:
    result = score_task(outcome="success", rubric_frozen=False, checks={"tests": True})
    assert result["status"] == "unfrozen"
    assert result["value"] is None
    failure = score_task(outcome="failure", rubric_frozen=True, checks={"tests": False})
    assert failure["status"] == "scored"
    assert failure["value"] == 0


def test_classification_prioritises_contamination() -> None:
    result = classify_attempt(
        setup_ok=True,
        harness_ok=True,
        contamination_ok=False,
        provider_ok=True,
        outcome="failure",
    )
    assert result == "contamination_invalidity"


def test_dry_run_writes_five_counterbalanced_records_per_arm(tmp_path: Path) -> None:
    executable = tmp_path / "must-not-run"
    executable.write_text(
        f"#!{sys.executable}\n{(tmp_path / 'invoked').as_posix()}\n", encoding="utf-8"
    )
    executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
    results_path, summary_path = run_evaluation(
        fixture=synthetic_fixture(),
        output_dir=tmp_path,
        repetitions=EXPECTED_REPETITIONS,
        dry_run=True,
        model="UNSPECIFIED",
        executable=str(executable),
    )
    records = [json.loads(line) for line in results_path.read_text(encoding="utf-8").splitlines()]
    expected_records = 10
    assert len(records) == expected_records
    assert {record["arm"] for record in records} == {"A", "B"}
    assert all(record["outcome_status"] == "not_run" for record in records)
    assert all(record["scores"]["status"] == "not_scored" for record in records)
    assert all(record["input_hashes"]["task_sha256"] == EXPECTED_TASK_HASH for record in records)
    assert all(
        record["input_hashes"]["fixture_tree_sha256"] == EXPECTED_FIXTURE_TREE_HASH
        for record in records
    )
    assert all(record["assignment"]["seed"] == EXPECTED_ASSIGNMENT_SEED for record in records)
    assert all(record["contamination_check"]["status"] == "passed" for record in records)
    assert all(record["guardrails"]["status"] == "not_run" for record in records)
    assert all(record["tool_versions"]["opencode"] == "not_run" for record in records)
    assert all(record["delivery_evidence"]["launch_manifest"] == {} for record in records)
    assert not (tmp_path / "invoked").exists()
    assert all(record["arm"] == "A" or record["pre_pack_sha256"] for record in records)
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert summary["records"] == expected_records
    assert summary["dry_run"] is True
    assert (
        summary["thresholds"]["absolute_correctness_difference_points"] == EXPECTED_THRESHOLD_POINTS
    )
    assert summary["validity_counts"]["unobserved"] == expected_records


def _fake_executable(tmp_path: Path, body: str) -> Path:
    executable = tmp_path / "fake-opencode.py"
    executable.write_text(f"#!{sys.executable}\n{body}", encoding="utf-8")
    executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
    return executable


def test_fake_execution_closes_stdin_scores_oracle_and_isolates_arms(tmp_path: Path) -> None:
    executable = _fake_executable(
        tmp_path,
        """
import json
import os
import sys
from pathlib import Path

if sys.argv[1:7] != ['run', '--auto', '--format', 'json', '--dir', str(Path.cwd())]:
    raise SystemExit('argv or cwd is not isolated')
if os.environ.get('OPENCODE_DISABLE_PROJECT_CONFIG') != '1':
    raise SystemExit('project config was not disabled')
prompt = sys.stdin.read()
if not prompt:
    raise SystemExit('prompt missing')
for runtime_path in (
    Path('config/opencode/state.json'),
    Path('data/opencode/run.db'),
    Path('home/.npm/_cacache/index-v5/entry'),
    Path('cache/provider.json'),
):
    runtime_path.parent.mkdir(parents=True, exist_ok=True)
    runtime_path.write_text('runtime', encoding='utf-8')
Path('src/slugify.py').write_text(
    'import re\\n\\ndef slugify(value: str) -> str:\\n'
    '    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")\\n',
    encoding='utf-8',
)
Path('tests/test_slugify.py').write_text(
    'from src.slugify import slugify\\n\\n'
    'def test_slugify() -> None:\\n'
    '    assert slugify("Hello, world!") == "hello-world"\\n'
    '    assert slugify("---") == ""\\n',
    encoding='utf-8',
)
print(json.dumps({'prompt_sha256': len(prompt)}))
""",
    )
    results_path, summary_path = run_evaluation(
        fixture=synthetic_fixture(),
        output_dir=tmp_path / "runs",
        repetitions=1,
        dry_run=False,
        model="UNSPECIFIED",
        executable=str(executable),
    )
    records = [json.loads(line) for line in results_path.read_text(encoding="utf-8").splitlines()]
    assert len(records) == EXPECTED_EXECUTION_RECORDS
    assert all(record["validity"] == "valid_task_success" for record in records)
    assert all(record["outcome_status"] == "success" for record in records)
    assert all(record["delivery_evidence"]["oracle_passed"] is True for record in records)
    assert all(
        record["delivery_evidence"]["changed_files"] == ["src/slugify.py", "tests/test_slugify.py"]
        for record in records
    )
    assert all(record["delivery_evidence"]["runtime_artifacts"] for record in records)
    assert all(record["secondary_metrics"]["changed_file_scope"] is True for record in records)
    assert all(record["guardrails"]["status"] == "passed" for record in records)
    assert all(record["delivery_evidence"]["stderr_summary"] == "" for record in records)
    assert all(
        record["delivery_evidence"]["launch_manifest"]["argv"]
        == ["<executable>", "run", "--auto", "--format", "json", "--dir", "<checkout>"]
        for record in records
    )
    assert all(
        record["delivery_evidence"]["launch_manifest"]["directory_argument_option"] == "--dir"
        for record in records
    )
    assert all(
        record["delivery_evidence"]["launch_manifest"]["environment"][
            "OPENCODE_DISABLE_PROJECT_CONFIG"
        ]
        == "1"
        for record in records
    )
    assert len({record["prompt_sha256"] for record in records}) == EXPECTED_EXECUTION_RECORDS
    assert (
        json.loads(summary_path.read_text(encoding="utf-8"))["records"]
        == EXPECTED_EXECUTION_RECORDS
    )


def test_unexpected_file_scope_fails_even_with_passing_oracle(tmp_path: Path) -> None:
    executable = _fake_executable(
        tmp_path,
        """
from pathlib import Path
Path('src/slugify.py').write_text(
    'import re\\n\\n\\ndef slugify(value: str) -> str:\\n'
    '    if value == "Already stable":\\n'
    '        return value\\n'
    '    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")\\n',
    encoding='utf-8',
)
Path('tests/test_slugify.py').write_text(
    'from src.slugify import slugify\\n\\n\\n'
    'def test_slugify_placeholder() -> None:\\n'
    '    assert slugify("Already stable") == "Already stable"\\n\\n\\n'
    'def test_slugify_task_acceptance() -> None:\\n'
    '    assert slugify("Hello, world!") == "hello-world"\\n'
    '    assert slugify("---") == ""\\n',
    encoding='utf-8',
)
Path('unexpected.py').write_text('unexpected', encoding='utf-8')
""",
    )
    results_path, _ = run_evaluation(
        fixture=synthetic_fixture(),
        output_dir=tmp_path / "runs",
        repetitions=1,
        dry_run=False,
        model="UNSPECIFIED",
        executable=str(executable),
    )
    records = [json.loads(line) for line in results_path.read_text(encoding="utf-8").splitlines()]
    assert all(record["delivery_evidence"]["oracle_passed"] is True for record in records)
    assert all(
        record["delivery_evidence"]["changed_files"]
        == ["src/slugify.py", "tests/test_slugify.py", "unexpected.py"]
        for record in records
    )
    assert all(record["secondary_metrics"]["changed_file_scope"] is False for record in records)
    assert all(record["outcome_status"] == "failure" for record in records)


def test_transient_cache_disappearance_returns_records(tmp_path: Path) -> None:
    executable = _fake_executable(
        tmp_path,
        """
import threading
import time
from pathlib import Path

cache_file = Path('.transient-cache-marker')
cache_file.write_text('transient', encoding='utf-8')
def remove_cache() -> None:
    time.sleep(0.01)
    cache_file.unlink(missing_ok=True)
threading.Thread(target=remove_cache).start()
while cache_file.exists():
    time.sleep(0.001)
""",
    )
    results_path, summary_path = run_evaluation(
        fixture=synthetic_fixture(),
        output_dir=tmp_path / "runs",
        repetitions=1,
        dry_run=False,
        model="UNSPECIFIED",
        executable=str(executable),
    )
    records = [json.loads(line) for line in results_path.read_text(encoding="utf-8").splitlines()]
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert len(records) == EXPECTED_EXECUTION_RECORDS
    assert summary["records"] == EXPECTED_EXECUTION_RECORDS
    assert all("validity" in record for record in records)


def test_parent_sentinel_excludes_nested_worktrees_and_hashes_product_files(tmp_path: Path) -> None:
    parent = tmp_path / "parent"
    (parent / "src").mkdir(parents=True)
    (parent / "src" / "slugify.py").write_text("original", encoding="utf-8")
    (parent / ".agents" / "worktrees" / "deep" / "nested").mkdir(parents=True)
    (parent / ".agents" / "worktrees" / "deep" / "nested" / "large.bin").write_bytes(b"x" * 1000)
    before = evaluation_runner._parent_evidence(parent)
    assert before["file_count"] == 1
    assert before["sentinel_version"] == "parent-sentinel-v1"
    assert ".agents" in before["excluded_tree_parts"]
    (parent / "src" / "slugify.py").write_text("changed", encoding="utf-8")
    after = evaluation_runner._parent_evidence(parent)
    assert before["tree_hash"] != after["tree_hash"]


def test_fake_process_cannot_contaminate_parent_checkout(tmp_path: Path, monkeypatch) -> None:
    sentinel_parent = tmp_path / "sentinel-parent"
    sentinel_parent.mkdir()
    marker = sentinel_parent / "parent-marker.txt"
    marker.write_text("before", encoding="utf-8")
    checkout = tmp_path / "isolated-checkout"
    checkout.mkdir()
    attempted_parent_write = sentinel_parent / "unexpected.txt"
    repository_marker = ROOT / "cwd-marker.txt"
    assert not repository_marker.exists()
    executable = _fake_executable(
        tmp_path,
        f"""
from pathlib import Path
import os
if "--version" not in os.sys.argv:
    Path('cwd-marker.txt').write_text(os.getcwd(), encoding='utf-8')
    Path({str(attempted_parent_write)!r}).write_text('bad', encoding='utf-8')
""",
    )
    monkeypatch.setattr(evaluation_runner, "parent_repository_root", lambda: sentinel_parent)
    result = evaluation_runner.execute_attempt(
        arm="A",
        checkout=checkout,
        task=b"work",
        pack_path=None,
        command=[str(executable), "run", "--auto", "--format", "json", "--dir", str(checkout)],
        timeout=30,
    )
    assert (checkout / "cwd-marker.txt").read_text(encoding="utf-8") == str(checkout)
    assert attempted_parent_write.read_text(encoding="utf-8") == "bad"
    assert result.contamination_ok is False
    assert (
        classify_attempt(
            setup_ok=result.setup_ok,
            harness_ok=result.harness_ok,
            contamination_ok=result.contamination_ok,
            provider_ok=result.provider_ok,
            outcome="failure",
        )
        == "contamination_invalidity"
    )
    assert not repository_marker.exists()
    assert result.launch_manifest["argv"] == [
        "<executable>",
        "run",
        "--auto",
        "--format",
        "json",
        "--dir",
        "<checkout>",
    ]
    assert result.launch_manifest["cwd"] == "<checkout>"
    assert result.launch_manifest["environment"]["OPENCODE_DISABLE_PROJECT_CONFIG"] == "1"
    assert (
        result.contamination_evidence["parent_before"]["tree_hash"]
        != result.contamination_evidence["parent_after"]["tree_hash"]
    )


def test_directory_argument_outside_checkout_is_setup_invalidity(tmp_path: Path) -> None:
    executable = _fake_executable(tmp_path, "raise SystemExit('must not run')")
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    result = evaluation_runner.execute_attempt(
        arm="A",
        checkout=checkout,
        task=b"work",
        pack_path=None,
        command=[str(executable), "run", "--dir", str(tmp_path)],
        timeout=30,
    )
    assert result.setup_ok is False
    assert result.guard_error == "directory_argument_outside_checkout"
    assert result.process_status == "setup_error"


def test_directory_argument_symlink_is_setup_invalidity(tmp_path: Path) -> None:
    executable = _fake_executable(tmp_path, "raise SystemExit('must not run')")
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    directory_link = checkout / "directory-link"
    directory_link.symlink_to(checkout, target_is_directory=True)
    result = evaluation_runner.execute_attempt(
        arm="A",
        checkout=checkout,
        task=b"work",
        pack_path=None,
        command=[str(executable), "run", "--dir", str(directory_link)],
        timeout=30,
    )
    assert result.setup_ok is False
    assert result.guard_error == "directory_argument_symlink"
    assert result.process_status == "setup_error"


def test_provider_failure_is_recorded_without_fabricated_task_result(tmp_path: Path) -> None:
    executable = _fake_executable(
        tmp_path,
        """
import sys
sys.stderr.write('provider authentication failed: token=should-not-be-recorded\\n')
raise SystemExit(17)
""",
    )
    results_path, _ = run_evaluation(
        fixture=synthetic_fixture(),
        output_dir=tmp_path / "runs",
        repetitions=1,
        dry_run=False,
        model="UNSPECIFIED",
        executable=str(executable),
    )
    records = [json.loads(line) for line in results_path.read_text(encoding="utf-8").splitlines()]
    assert all(record["validity"] == "provider_failure" for record in records)
    assert all(record["outcome_status"] == "provider_failure" for record in records)
    assert all(record["scores"]["status"] == "not_scored" for record in records)
    assert all("should-not-be-recorded" not in json.dumps(record) for record in records)


def test_cli_dry_run_emits_json_paths(tmp_path: Path) -> None:
    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "evaluation" / "run_evaluation.py"),
            "--fixture",
            "synthetic",
            "--dry-run",
            "--output-dir",
            str(tmp_path),
        ],
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
    )
    assert completed.returncode == 0
    output = json.loads(completed.stdout)
    assert Path(output["results"]).is_file()
    assert Path(output["summary"]).is_file()
