# Controlled OpenCode usefulness evaluation

This harness defines a low-generality experiment around explicit context types and delivery modes:

- **Arm A:** incumbent synthetic repository guidance only.
- **Arm B:** incumbent guidance plus a native shadow `AGENTS.md` at `.farna-context/shadow/AGENTS.md`, after `git check-ignore` preflight. The shadow carries the private Unicode constraint.
- **Arm C:** recorded as unsupported/adapter-needed unless native scoped path-glob consumption is observed; it is not run or faked.
- **Artefact:** future/reference-only; never injected into the prompt automatically.

The task and oracle are frozen in `evaluation/protocol.json` and `evaluation/fixtures/synthetic-repo/TASK.md`. Baseline is valid but less safe: it may implement ASCII-only slugification. A successful Arm B outcome must preserve Unicode letters. The harness records context type, delivery mode, destination, ignore evidence and consumption status; it does not infer consumption from assignment.

## Plan without invoking OpenCode

```bash
uv run python evaluation/run_evaluation.py --fixture synthetic --dry-run --output-dir /tmp/farna-context-evaluation
```

The default remains five repetitions per valid arm, ten JSONL records total, with the frozen randomized assignment seed. Dry-run records include exact A/B context-delivery records and never invoke an executable. The ignored shadow file is treated as allowed runtime/context materialisation, recorded separately, and removed only when its hash matches. Dry-run records are planning records and are not task outcomes.

## Execute the bounded evaluation

```bash
uv run python evaluation/run_evaluation.py \
  --fixture synthetic \
  --opencode opencode \
  --model UNSPECIFIED \
  --output-dir /tmp/farna-context-evaluation
```

`--opencode` is the local OpenCode executable and `--model` is passed through only when it is not `UNSPECIFIED`; no key or credential is embedded in the harness. Each attempt gets a new temporary checkout, an in-checkout prompt and pack, isolated HOME/XDG config/cache/data directories, and process. Every OpenCode subprocess is launched with that checkout as its working directory, and the prompt names only relative paths inside it; the parent Farna Context checkout is never supplied as the project directory. The task is supplied through an explicitly opened prompt-file stdin; stdin is never inherited. Before and after each subprocess, the runner records a bounded parent sentinel: git status plus content hashes for tracked and ordinary untracked files in the parent worktree. It explicitly excludes `.agents` (including `.agents/worktrees`), `.venv`, caches, `node_modules`, generated outputs, pycache, evaluation runs and other transient names, and never follows symlinks. This detects tracked content edits, additions, deletions and unexpected untracked files in the parent product/source trees, but does not claim OS-level sandboxing or detect changes outside the declared parent boundary. Any parent change is retained as evidence, classified as `contamination_invalidity`, prevents the oracle from running, and makes the experiment inconclusive. The runner never deletes parent files. The runner enforces the protocol timeout (900 seconds by default), runs the fixed pytest oracle only after a clean provider attempt, and stores only bounded redacted output summaries and hashes. Checkout changes are split into task changes and runtime artefacts. Runtime artefacts include harness/provider state under `config/opencode`, `data/opencode`, and `home/.npm`, plus the explicit transient names `cache`, `caches`, `data`, `config`, `.evaluation-pack`, `.evaluation-output`, evaluation run/output directories, `__pycache__`, virtual environments, build/cache directories, and similar tool caches. They remain observable and are recorded in `delivery_evidence.runtime_artifacts` and the launch manifest; they are not allowed to hide an unexpected `src/**`, `tests/**`, or other task-relevant file. `changed_files` contains only non-artefact task changes, and `changed_file_scope` is true only when those changes are in the frozen task allowlist.

The previously executed real run `exp-20261114T143459Z-bd1b8cd7` is invalid and must not be used as evidence: OpenCode wrote untracked product files into the parent checkout because the old run did not guard the actual process workspace. Quarantine those files outside the parent checkout before any further real run. The evaluation harness invokes OpenCode with its directory option: `[executable, "run", "--auto", "--format", "json", "--dir", <checkout>, ...]`. `cwd=<checkout>` remains required, but is not sufficient. The harness also sets `OPENCODE_DISABLE_PROJECT_CONFIG=1`, uses isolated HOME/XDG paths, validates that the `--dir` path is a non-symlink directory inside the checkout, and records a redacted launch manifest in each observed result.

If the executable, provider, model, or authentication is unavailable, the record is retained as `provider_failure` (or `unobserved` when the state cannot be established). The harness returns a completed JSONL/summary report and never fabricates a task result. Real OpenCode execution is therefore optional for producing a report, but provider failures make the frozen comparison inconclusive under the protocol thresholds.

## Frozen interpretation rules

A valid task failure is retained and scored as a failure. Setup, provider, harness, and contamination failures are retained but excluded from the primary outcome denominator. Invalidity asymmetry above 10 percentage points, provider failure preventing comparable runs, or fewer than four valid runs per arm makes the experiment inconclusive. The exploratory thresholds are not product guarantees.

Do not claim that the model consumed the generated pack from arm assignment alone. Report only the association between arm assignment and observed outcomes unless pack consumption is independently observed.

## Evidence and safety

Every record includes protocol/task/fixture hashes, arm and assignment metadata, policy strings, run identity, validity, score, pack hashes, bounded execution evidence, elapsed wall time, changed-file scope, guardrail results, and contamination status. Records never contain full prompts, source contents, environment dumps, credentials, tokens, or raw unbounded stdout/stderr.

The fixture is intentionally small and safe for local execution. Modulo support is not part of this frozen experiment: a real Modulo run would require a caller-supplied clean detached checkout and must never mutate the parent checkout.
