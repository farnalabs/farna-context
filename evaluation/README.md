# Controlled OpenCode usefulness evaluation

This harness freezes a low-generality exploratory comparison of two explicitly bounded arms on the committed synthetic fixture:

- **Arm A:** the fixture-native `AGENTS.md` plus normal repository/tool context, with no generated pack.
- **Arm B:** identical to Arm A, plus generated pack materialisation at the harness file-emitter boundary recorded in each result.

The frozen task is the bounded `slugify` task in `evaluation/fixtures/synthetic-repo/TASK.md`. The protocol records the fixture revision, fixture tree hash, exact task bytes, and task hash. `evaluation/protocol.json` is the protocol source of truth; do not change the task, scoring oracle, metrics, thresholds, or guardrails after runs begin.

## Run the dry-run planning pass

From this repository root:

```bash
uv run python evaluation/run_evaluation.py --fixture synthetic --dry-run --output-dir /tmp/farna-context-evaluation
```

The command emits a JSON object naming `results.jsonl` and `summary.json`. The default is five repetitions per arm, with randomized arm order and a recorded assignment seed. Each JSONL record is immutable evidence for one arm/attempt. Dry-run records satisfy the frozen protocol without invoking OpenCode.

## Frozen execution rules

Use one local OpenCode command/model/harness path when it is available. The runner must close stdin, use fresh checkout/session/cache state for every attempt, record the exact permission and network policies, and run the fixed task acceptance oracle after the agent run. If OpenCode/provider execution is unavailable, retain a `provider_failure` or `unobserved` record and never invent a result.

A valid task failure remains a valid scored failure. Setup, provider, harness, and contamination failures are retained but excluded from the primary outcome denominator. Invalidity asymmetry above 10 percentage points, provider failure preventing comparable runs, or fewer than four valid runs per arm makes the experiment inconclusive.

## Outcomes and guardrails

The primary outcome is task acceptance correctness from the fixed command/test oracle. Secondary outcomes are task completion status, changed-file scope, preparation cost, pack size, elapsed wall time, and tool-call count when observable. Guardrails prohibit unsafe or out-of-scope changes, test deletion/disablement, secret output, protocol violations, and contamination.

The exploratory decision thresholds are deliberately not product guarantees:

- Continue/positive signal: Arm B is at least 20 percentage points better than Arm A across valid runs, has no safety guardrail violation, and median preparation plus execution overhead is no more than 2x Arm A.
- No signal: the difference is within +/-20 points and there is no guardrail regression.
- Negative signal: Arm B is at least 20 points worse, or pack delivery causes a safety guardrail violation.
- Inconclusive: invalidity asymmetry is above 10%, provider failure prevents comparable runs, or either arm has fewer than four valid runs.

Do not claim that OpenCode consumed the pack unless that is independently observed. Otherwise report only the association between arm assignment and outcomes.

## Evidence fields

Every record includes the experiment and protocol identifiers, frozen task and fixture hashes, arm and assignment metadata, tool/model metadata, policies, run/attempt identity, validity, score object, pack hashes, delivery evidence, preparation/elapsed metrics, contamination check, guardrail status, and the three status enums (`harness_load_status`, `model_use_status`, and `outcome_status`). The summary is derived from JSONL and cannot rewrite past records.

## Fixture boundary

The synthetic fixture is intentionally small: a native guidance file, a bounded task, a target module, and a test file. It is a harness fixture, not evidence that the real Modulo dogfood task generalises. Modulo support is not part of this frozen experiment because it would require a caller-supplied clean detached checkout and must never mutate the parent Modulo checkout.
