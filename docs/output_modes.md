# Output Modes

This document defines Forge's shared output-mode paradigm for interactive and scripted usage.

## Goal

- Keep interactive command output easy to read.
- Keep script/integration output deterministic and stable.
- Make command behavior consistent across tools.

## Standard Modes

Commands that emit structured results should support:

- `-output auto`
- `-output pretty`
- `-output kv`
- `-output json`

Mode semantics:

- `auto`
  - `pretty` when stdout is a terminal.
  - script-safe mode for non-interactive stdout (normally `kv`).
- `pretty`
  - human-focused summaries and ASCII tables.
  - intended for direct terminal use.
- `kv`
  - line-based `key=value` fields plus stable tabular row sections where needed.
  - intended for shell scripting and text tooling.
- `json`
  - structured JSON with stable keys.
  - intended for programmatic consumers.

## Tool-Specific Extensions

Some tools can expose additional modes when they serve a specific scripting workflow.

Example:

- `forge dupes` supports `paths` and `paths0` in addition to `auto|pretty|table|json`.

Extensions should be additive and should not break existing machine consumers.

## Compatibility Rules

- Keep machine-facing field names stable where practical.
- Prefer additive changes over renaming/removing fields.
- Document output contract changes in `README.md`.
- Add tests for any new mode or machine-facing output shape.
