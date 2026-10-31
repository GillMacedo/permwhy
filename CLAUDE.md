# permwhy

Claude Code plugin that explains Bash permission decisions and lints permission rules.

## Architecture
`scripts/permwhy.py` holds all the logic: split the command, match rules, decide, lint. `skills/explaining-permissions/SKILL.md` tells Claude when and how to run it. See `docs/architecture.md`.

## Commands
- `make test`: unit tests and project checks
- `make lint`: manifest validation
- `make demo`: run both subcommands on the example settings

## Conventions
- Python 3.10+, standard library only.
- Every behavior claim follows Claude Code's docs. Link the doc in the PR when adding one.
- Each lint finding has a stable `PWnnn` code and a test. Don't reuse codes.

## Do and don't
- Do keep the skill body under 500 lines, and its description in the third person.
- Don't add network calls or telemetry.
- Don't claim this is a security boundary or that it matches Claude Code exactly.

## Definition of done
`make test` and `make lint` pass, and `CHANGELOG.md`, `ROADMAP.md` and docs are updated when relevant.
