# Farna Context

Context Pack compilation and verification for agentic workflows.

## Installation

```bash
uv sync --dev
```

## Commands

- `farna-context init` - Initialize configuration
- `farna-context audit` - Audit source files
- `farna-context manifest` - Generate manifest
- `farna-context compile` - Compile context pack
- `farna-context materialise` - Materialise source files
- `farna-context verify` - Verify integrity
- `farna-context receipt` - Generate receipt
- `farna-context secrets` - Scan for secrets
- `farna-context dogfood-prepare` - Prepare an inspectable dogfood pack, materialisation receipt, and OpenCode launch manifest without launching OpenCode

## Alpha context types

Context items are explicitly typed as `rule`, `general`, `artefact`, or `shadow_file`. Rules are scoped instructions; general context is bounded and unscoped; artefacts are opaque references rather than instructions; and shadow files are generated runtime materialisations, never authority sources. Shadow delivery requires the destination to already be ignored by Git, and cleanup is hash-aware: changed files are left untouched. The typed library API is `compile_typed_context(manifest_path, output_path, config_path=...)` and `compile_typed_context_data(...)`; it emits deterministic item records with scopes, source hashes, authority/evidence status, delivery modes, artefact MIME/extension/size/hash metadata, and omission reasons. `materialise_typed_context(pack, repo_root=..., staging_parent=..., harness="opencode")` emits general context, copies only explicit `copy_to_staging` artefacts, keeps `reference_only` artefacts out of staging, and reports `adapter_required` for unsupported scoped rules or mount delivery. Shadow files still require an ignored destination and hash-aware cleanup; `.gitignore` is never edited. Artefact bytes are scanned by the existing secret detectors before entering a pack or staging directory. PDF, image, audio, and other binary artefacts remain opaque and are never treated as instructions. OpenCode scoped rules are materialised by the explicit `farna-context.opencode-rules@1` adapter artifact. OpenCode core has no proven native path-glob rule API; the installed `opencode-rules` plugin does support Markdown frontmatter `globs`, so the adapter records that plugin identity and capability in a deterministic `manifest.json` and emits one generated rule file per scoped item. Operation scopes are not silently flattened: they return `adapter_required` with a precise reason and no rule file. The artifact is written to the operation staging directory, never into the target repository. General context, opaque artefacts, and hash-aware ignored shadow files retain their existing behavior.

### Typed context CLI

Use the typed commands separately from the legacy lifecycle commands:

```bash
farna-context context-preview --input typed-context.json --repo-root . --policy secret-policy.json --json
farna-context context-compile --input typed-context.json --config secret-policy.json --out .farna-context/typed-pack.json --json
farna-context context-materialise --pack .farna-context/typed-pack.json --policy secret-policy.json --repo-root . --staging-parent .farna-context/staging --out .farna-context/materialisation.json --harness opencode --json
```

`context-preview` validates each item and reports `selected`, `omitted`, `blocked`, or `adapter_required` without emitting source content. `context-compile` writes the canonical pack atomically and keeps literal secret values out of the pack; a policy with literal detectors remains required for later materialisation. `context-materialise` requires an explicit trusted policy file, a fresh staging parent, a repository root, and an explicit receipt path. Its result contains decisions and hashes only, never secret values. Invalid input exits `2`, secret policy/content failures exit `12`, unsafe destinations exit `13`, and write failures exit `14`.

## Alpha named-secret delivery contract

The standalone `farna_context.secrets_broker` module defines the alpha contract for
predeclared named secrets. A profile may request only its declared names, and the
fake provider used by tests delivers a short-lived value only at the child-process
environment boundary. Values are deliberately excluded from Context Packs,
manifests, receipts, and errors. This is not a complete secrets manager: alpha
uses an environment overlay and cannot guarantee that an agent will not disclose a
secret after receiving it.
