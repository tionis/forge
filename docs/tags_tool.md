# Tags Tool

`forge tags` manages normalized `user.xdg.tags` metadata directly on filesystem paths.

## Commands

- `forge tags get [flags] [path]`
- `forge tags set -tags tag1,tag2 [flags] [path]`
- `forge tags add -tags tag3 [flags] [path]`
- `forge tags remove -tags tag2 [flags] [path]`
- `forge tags clear [flags] [path]`

If `path` is omitted, current directory (`.`) is used.

## Flags

- `-output`: `auto|pretty|kv|json` (default `auto`)
- `-tags`: comma/semicolon-separated tag list (required for `set` / `add` / `remove`)

## Tag Normalization

Input tags are normalized using the same rules as snapshot ingestion:

1. Replace `;` with `,`.
2. Split by `,`.
3. Trim whitespace.
4. Drop empty values.
5. Deduplicate exact matches.
6. Sort ascending.

Serialized storage format in xattr is comma-separated normalized tags.

## Output

All subcommands return a structured result:

- `operation`
- `path`
- `xattr` (`user.xdg.tags`)
- `count`
- `tags`

Mutating operations (`set`, `add`, `remove`, `clear`) also include:

- `changed`
- `before`
- `after`

## Behavior Notes

- `clear` removes the xattr when present.
- Missing xattr is treated as empty tag set.
- On filesystems without xattr support, commands return actionable errors.
