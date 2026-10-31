# permwhy

**Find out why Claude Code asked for permission, and which of your rules don't do what you think.**

Claude Code splits compound commands, strips some wrappers, and checks deny, then ask, then allow. When a prompt appears anyway, the reason is hard to see, and a long allow list can hide rules that never apply. `permwhy` shows the decision for each subcommand and flags rules that are ineffective or risky. It runs locally, needs no network, and has no dependencies beyond Python 3.10.

## Install

As a Claude Code plugin:

    claude plugin marketplace add GillMacedo/permwhy
    claude plugin install permwhy@permwhy-marketplace

Then ask Claude "why did you ask permission for that?" or "audit my permission rules."

Or run the script directly:

    git clone https://github.com/GillMacedo/permwhy
    python3 permwhy/plugin/scripts/permwhy.py lint

## Usage

Try both commands on the rules in `examples/settings.json`.

**Why did this prompt?**

    $ python3 plugin/scripts/permwhy.py --settings examples/settings.json explain 'git status && npm test'
    Decision: PROMPT
    Why: No allow rule matches: `npm test`. Claude Code may still approve read-only commands without a rule.
      allow    git status  <- Bash(git *) in examples/settings.json
      no rule  npm test

**Which rules have problems?** (excerpt)

    $ python3 plugin/scripts/permwhy.py --settings examples/settings.json lint
    PW004 Bash(python *) (examples/settings.json)
      Wildcarded interpreter: allows any code to run and is dropped when entering auto mode.
    PW007 Bash(aws s3 ls) (examples/settings.json)
      Shadowed by deny rule Bash(aws *). An allow rule can't carve an exception out of a deny rule.

`lint` exits 1 when it has findings, so it can run in CI. Add `--json` before the subcommand for machine-readable output. Without `--settings`, it reads `~/.claude/settings.json`, `.claude/settings.json` and `.claude/settings.local.json`.

| Code | Finding |
|---|---|
| PW001 | Not a valid rule |
| PW002 | Duplicate rule |
| PW003 | Blanket Bash allow |
| PW004 | Wildcarded interpreter |
| PW005 | Wildcarded package-manager run |
| PW006 | Runner that matches whatever runs inside it |
| PW007 | Allow rule shadowed by a deny rule |
| PW008 | Deny or ask rule that only matches command text |
| PW009 | Fragile URL pattern |

## Limits

`permwhy` follows [Claude Code's documented permission behavior](https://code.claude.com/docs/en/permissions), but it is a separate approximation, so Claude Code has the final say. It doesn't know Claude Code's built-in read-only list, managed settings, or auto mode's classifier decisions. Permission rules also aren't a security boundary: use a sandbox for that.

## Contributing

Contributions are welcome, from people and from people working with AI agents. See [CONTRIBUTING.md](CONTRIBUTING.md). Good first issues:

- Handle `FOO=bar command` environment prefixes
- Explain `Read` and `Edit` rules as well as `Bash`
- Add SARIF output so `lint` can report in GitHub code scanning
- Support `PowerShell(...)` rules
- Add a plugin icon

## AI disclosure

This project was largely generated with Claude Code and reviewed by its maintainer.

## Credits

Rule behavior comes from Anthropic's public Claude Code documentation. This is an independent project, not affiliated with or endorsed by Anthropic.

## About me

I'm Giulliano Macedo, and I build developer tools at GoTech Solutions. Follow along or get in touch:

- GitHub: [GillMacedo](https://github.com/GillMacedo)
- LinkedIn: [giulliano](https://www.linkedin.com/in/giulliano/)
- X: [@giumacedo](https://x.com/giumacedo)

If `permwhy` saved you some prompts, a star helps others find it.

---

Built by [Giulliano Macedo](https://github.com/GillMacedo), GoTech Solutions · [LinkedIn](https://www.linkedin.com/in/giulliano/) · [X](https://x.com/giumacedo)
