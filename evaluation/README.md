# Controlled OpenCode usefulness evaluation

This harness compares two explicitly bounded arms:

- **Arm A:** the frozen repository-native context visible in an isolated checkout.
- **Arm B:** the same checkout and task plus a Farna Context materialisation.

The harness measures what it can observe. It does not claim that OpenCode loaded or used the materialised pack unless a later, independently instrumented run proves that state. The initial implementation therefore supports a safe synthetic fixture and a dry-run/planning mode only. A real provider run may be added only when the caller supplies a clean detached checkout and an explicit model/provider policy.

## Run the planning pass

From this repository root:

```bash
uv run python evaluation/run_evaluation.py --fixture synthetic --dry-run --output-dir /tmp/farna-context-evaluation
```

The command emits a JSON object naming `results.jsonl` and `summary.json`. Each JSONL record is immutable evidence for one arm/attempt. No secret values are written. The default is five repetitions per arm, which is exploratory and supports only low-generality conclusions.

## Protocol boundaries

`protocol.json` is the protocol source of truth. Before making any usefulness claim, the founder must freeze the repository revision, task input, and scoring rubric. Until then, records contain null/unfrozen scores and no ranking is valid. The protocol also requires fresh checkout/session/cache isolation, no cross-arm outputs or conversations, explicit permission/network/cache policies, bounded commands, and a classification separating valid task outcomes from setup, harness, provider, and contamination invalidity.

The runner's future OpenCode command path must use `subprocess.DEVNULL` or an explicit prompt-file redirect. It must not hard-code credentials or API keys. If OpenCode/provider execution is unavailable, the result must say `provider_failure` or `unobserved`; the harness must never invent an outcome.

## Evidence fields

Every record includes the experiment and protocol identifiers, task and repository hashes, arm, tool/model metadata, policies, run/attempt identity, validity, score object, pack hashes, delivery evidence, contamination check, and the three status enums (`harness_load_status`, `model_use_status`, and `outcome_status`). The summary is derived from JSONL and cannot rewrite past records.

## Fixture

The synthetic fixture is intentionally small: a native guidance file, a bounded task, a target module, and a test file. It is a harness fixture, not evidence that the real Modulo dogfood task generalises. Modulo support is intentionally not enabled in this first pass because it must use a caller-supplied clean detached checkout and must never mutate the parent Modulo checkout.
