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

## Alpha context types

Context items are explicitly typed as `rule`, `general`, `artefact`, or `shadow_file`. Rules are scoped instructions; general context is bounded and unscoped; artefacts are opaque references rather than instructions; and shadow files are generated runtime materialisations, never authority sources. Shadow delivery requires the destination to already be ignored by Git, and cleanup is hash-aware: changed files are left untouched. This alpha model performs validation and preflight only; it does not write files, edit `.gitignore`, or store secret values.

## Alpha named-secret delivery contract

The standalone `farna_context.secrets_broker` module defines the alpha contract for
predeclared named secrets. A profile may request only its declared names, and the
fake provider used by tests delivers a short-lived value only at the child-process
environment boundary. Values are deliberately excluded from Context Packs,
manifests, receipts, and errors. This is not a complete secrets manager: alpha
uses an environment overlay and cannot guarantee that an agent will not disclose a
secret after receiving it.
