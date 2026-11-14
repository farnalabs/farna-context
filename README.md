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

## Alpha named-secret delivery contract

The standalone `farna_context.secrets_broker` module defines the alpha contract for
predeclared named secrets. A profile may request only its declared names, and the
fake provider used by tests delivers a short-lived value only at the child-process
environment boundary. Values are deliberately excluded from Context Packs,
manifests, receipts, and errors. This is not a complete secrets manager: alpha
uses an environment overlay and cannot guarantee that an agent will not disclose a
secret after receiving it.
