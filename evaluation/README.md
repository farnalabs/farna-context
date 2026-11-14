# Controlled OpenCode usefulness evaluation

This harness compares two explicitly bounded arms on the frozen synthetic fixture:

- **Arm A:** the fixture-native `AGENTS.md` plus the task, with no generated pack.
- **Arm B:** the same task and isolated checkout, plus the exact generated pack materialisation at the harness file-emitter boundary.

The task and oracle are frozen in `evaluation/protocol.json` and `evaluation/fixtures/synthetic-repo/TASK.md`. The harness does not claim that OpenCode consumed the pack unless that is independently observed.

## Plan without invoking OpenCode

```bash
uv run python evaluation/run_evaluation.py --fixture synthetic --dry-run --output-dir /tmp/farna-context-evaluation
```

The default remains five repetitions per arm, ten JSONL records total, with the frozen randomized assignment seed. Dry-run records are planning records and are not task outcomes.

## Execute the bounded evaluation

```bash
uv run python evaluation/run_evaluation.py \
  --fixture synthetic \
  --opencode opencode \
  --model UNSPECIFIED \
  --output-dir /tmp/farna-context-evaluation
```

`--opencode` is the local OpenCode executable and `--model` is passed through only when it is not `UNSPECIFIED`; no key or credential is embedded in the harness. Each attempt gets a new temporary checkout, an in-checkout prompt and pack, isolated HOME/XDG config/cache/data directories, and process. Every OpenCode subprocess is launched with that checkout as its working directory, and the prompt names only relative paths inside it; the parent Farna Context checkout is never supplied as the project directory. The task is supplied through an explicitly opened prompt-file stdin; stdin is never inherited. Before and after each subprocess, the runner records a bounded parent sentinel: git status plus content hashes for tracked and ordinary untracked files in the parent worktree. It explicitly excludes `.agents` (including `.agents/worktrees`), `.venv`, caches, `node_modules`, generated outputs, pycache, evaluation runs and other transient names, and never follows symlinks. This detects tracked content edits, additions, deletions and unexpected untracked files in the parent product/source trees, but does not claim OS-level sandboxing or detect changes outside the declared parent boundary. Any parent change is retained as evidence, classified as `contamination_invalidity`, prevents the oracle from running, and makes the experiment inconclusive. The runner never deletes parent files. The runner enforces the protocol timeout (900 seconds by default), runs the fixed pytest oracle only after a clean provider attempt, records changed-file scope while excluding `.git`, caches, and evaluation metadata, and stores only bounded redacted output summaries and hashes.

The previously executed real run `exp-20261114T143459Z-bd1b8cd7` is invalid and must not be used as evidence: OpenCode wrote untracked product files into the parent checkout because the old run did not guard the actual process workspace. Quarantine those files outside the parent checkout before any further real run.

If the executable, provider, model, or authentication is unavailable, the record is retained as `provider_failure` (or `unobserved` when the state cannot be established). The harness returns a completed JSONL/summary report and never fabricates a task result. Real OpenCode execution is therefore optional for producing a report, but provider failures make the frozen comparison inconclusive under the protocol thresholds.

## Frozen interpretation rules

A valid task failure is retained and scored as a failure. Setup, provider, harness, and contamination failures are retained but excluded from the primary outcome denominator. Invalidity asymmetry above 10 percentage points, provider failure preventing comparable runs, or fewer than four valid runs per arm makes the experiment inconclusive. The exploratory thresholds are not product guarantees.

Do not claim that the model consumed the generated pack from arm assignment alone. Report only the association between arm assignment and observed outcomes unless pack consumption is independently observed.

## Evidence and safety

Every record includes protocol/task/fixture hashes, arm and assignment metadata, policy strings, run identity, validity, score, pack hashes, bounded execution evidence, elapsed wall time, changed-file scope, guardrail results, and contamination status. Records never contain full prompts, source contents, environment dumps, credentials, tokens, or raw unbounded stdout/stderr.

The fixture is intentionally small and safe for local execution. Modulo support is not part of this frozen experiment: a real Modulo run would require a caller-supplied clean detached checkout and must never mutate the parent checkout.
