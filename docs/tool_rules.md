# Tool Rules

These rules define how Forge tools should behave so commands can be composed reliably.

## Command Shape

- Top-level pattern: `forge <tool> <subcommand> [flags] [args]`.
- Each tool should provide a concise `Short` description and useful help text.
- Keep command names stable once released.

## Path Handling

- Resolve user-provided filesystem paths to absolute paths before persistence.
- Output canonical paths in command results.
- Avoid implicit CWD-dependent state in persisted data.

## Output Conventions

- Commands that return structured data should expose an `-output` flag.
- Standard output modes:
  - `auto`: choose human-friendly output when attached to a terminal, script-friendly output otherwise.
  - `pretty`: human-friendly summaries/tables for interactive use.
  - `kv`: stable `key=value` fields for scripting.
  - `json`: stable structured JSON for scripting/integration.
- `auto` should resolve to:
  - `pretty` when stdout is a terminal.
  - `kv` for non-interactive stdout (pipes/redirection).
- Keep machine-facing field names stable across versions when possible.
- Use tabular sections for repeated rows in human-facing modes.
- If a command already has stable script modes (for example `paths`/`paths0`), keep them additive and backward-compatible.

## Error Behavior

- Return structured, actionable errors.
- Avoid partial writes when an operation fails mid-run.
- If fallbacks are used, keep them explicit and deterministic.

## Data and Hashing

- Use deterministic serialization for hashed objects.
- Include an explicit schema/version marker in hash input formats.
- Record hash algorithm alongside stored hashes.
- Document hash input contracts whenever schema-affecting fields are added.

## Database Practices

- Use schema migrations or idempotent schema init.
- Add indexes for expected lookup paths.
- Keep writes transactional for multi-step operations.

## Compatibility

- Preserve existing stable command behavior unless intentionally versioned.
- Additive changes are preferred over breaking changes.
- Document incompatible changes in `README.md` and release notes.
