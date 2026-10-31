---
name: explaining-permissions
description: Explains why Claude Code prompted for, allowed or denied a Bash command, and finds ineffective or risky permission rules. Use when the user asks why a permission prompt appeared, why an allow rule doesn't work, or wants their permission settings audited.
---

# Explaining permissions

Run the bundled script. Don't work the answer out by hand, because compound commands, wrappers and rule order are easy to get wrong.

## Why did this command prompt?

Run:

    python3 "${CLAUDE_PLUGIN_ROOT}/scripts/permwhy.py" explain "<the exact command>"

Report the decision, the reason and which subcommand caused it. If the decision is `prompt`, suggest the narrowest rule that would allow that subcommand. Only suggest a rule the user would be comfortable running unattended.

## Audit the rules

Run:

    python3 "${CLAUDE_PLUGIN_ROOT}/scripts/permwhy.py" lint

It exits 1 when it has findings. Summarize them most serious first, and ask before editing any settings file.

## Reading another settings file

Pass `--settings <path>` before the subcommand. Repeat it for several files. Without it, the script reads the user file and the project's two files.

## What to tell the user

- The result is an approximation of Claude Code's documented behavior, and Claude Code has the final say.
- Permission rules match command text, so they are not a security boundary. A sandbox is.
