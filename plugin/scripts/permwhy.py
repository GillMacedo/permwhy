#!/usr/bin/env python3
"""Explain Claude Code Bash permission decisions and lint permission rules.

This approximates Claude Code's documented behavior. It is a diagnostic aid,
not a security boundary, and Claude Code itself always has the final say.
"""

import argparse
import fnmatch
import json
import posixpath
import re
import shlex
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import quote

SEPARATORS = ("&&", "||", "|&", ";", "|", "&", "\n")
LEADING_KEYWORDS = {"if", "then", "else", "elif", "while", "until", "do", "!", "{"}
TRAILING_ONLY = {"fi", "done", "esac", "}"}
# Wrappers Claude Code's docs say are stripped before matching.
SIMPLE_WRAPPERS = {"time", "nohup", "command", "builtin", "noglob"}
INTERPRETERS = {"python", "python3", "node", "ruby", "perl", "bash", "sh", "zsh", "deno", "bun"}
RUNNERS = ("npx", "docker exec", "docker run", "devbox run", "uv run", "pnpm dlx", "uvx")
PACKAGE_RUNS = ("npm run", "pnpm run", "yarn run", "bun run", "make")
RULE_PATTERN = re.compile(r"^([A-Za-z][A-Za-z0-9_]*)(?:\((.*)\))?$", re.DOTALL)
ENV_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
# Claude Code does not publish the full list of "known-safe" variables.
# These are the ones its docs name in examples; extend only with evidence.
SAFE_ENV_VARS = frozenset({"NODE_ENV", "LANG", "NO_COLOR"})
# One shell word: plain characters, backslash-escaped characters (so `a\ b`
# stays one word), quoted strings, and a lone trailing backslash.
_WORD = r"(?:\\.|[^\s'\"\\]+|'[^']*'|\"(?:[^\"\\]|\\.)*\"|\\)+"
RAW_WORD = re.compile(_WORD, re.DOTALL)
WORD_AND_SPACE = re.compile(_WORD + r"\s*", re.DOTALL)


@dataclass
class Rule:
    kind: str
    text: str
    source: str
    pattern: str | None = None
    tool: str = "Bash"


@dataclass
class Subcommand:
    command: str
    nested: bool = False
    decision: str = "no rule"
    rule: str | None = None
    source: str | None = None


@dataclass
class Explanation:
    command: str
    decision: str
    reason: str
    subcommands: list[Subcommand] = field(default_factory=list)


@dataclass
class Finding:
    code: str
    rule: str
    source: str
    message: str


SARIF_RULES = {
    "PW001": "Invalid permission rule",
    "PW002": "Duplicate permission rule",
    "PW003": "Blanket Bash allow",
    "PW004": "Wildcarded interpreter allow",
    "PW005": "Wildcarded package-manager run allow",
    "PW006": "Wildcarded command runner allow",
    "PW007": "Allow rule shadowed by a deny rule",
    "PW008": "Deny or ask rule matches command text only",
    "PW009": "Fragile URL permission pattern",
}


def split_command(command):
    """Return ([top-level subcommands], [nested subcommands], parseable)."""
    top, nested = [], []
    current = []
    quote = None
    index = 0
    parseable = True
    ended_with_operator = False

    def flush():
        text = "".join(current).strip()
        current.clear()
        if text:
            top.append(text)

    while index < len(command):
        char = command[index]
        if quote == "'":
            current.append(char)
            if char == "'":
                quote = None
            index += 1
            continue
        if char == "\\" and index + 1 < len(command):
            current.append(command[index : index + 2])
            index += 2
            continue
        if char == '"':
            quote = None if quote == '"' else '"'
            current.append(char)
            index += 1
            continue
        if char == "'" and quote is None:
            quote = "'"
            current.append(char)
            index += 1
            continue
        if command.startswith("$(", index) or (char == "(" and quote is None):
            start = index + (2 if char == "$" else 1)
            end = _matching_paren(command, start)
            if end is None:
                parseable = False
                current.append(command[index:])
                break
            _collect_nested(command[start:end], nested)
            if char == "$":
                current.append(command[index : end + 1])
            index = end + 1
            continue
        if char == "`":
            end = command.find("`", index + 1)
            if end == -1:
                parseable = False
                current.append(command[index:])
                break
            _collect_nested(command[index + 1 : end], nested)
            current.append(command[index : end + 1])
            index = end + 1
            continue
        if quote is None:
            separator = next((s for s in SEPARATORS if command.startswith(s, index)), None)
            is_redirect = separator == "&" and (
                (index > 0 and command[index - 1] in "<>") or command.startswith("&>", index)
            )
            if separator and not is_redirect:
                flush()
                index += len(separator)
                ended_with_operator = separator in ("&&", "||")
                continue
        if not char.isspace():
            ended_with_operator = False
        current.append(char)
        index += 1

    flush()
    if quote is not None or ended_with_operator:
        parseable = False
    return [c for c in map(_normalize, top) if c], [c for c in map(_normalize, nested) if c], parseable


def _matching_paren(text, start):
    depth = 1
    quote = None
    index = start
    while index < len(text):
        char = text[index]
        if quote:
            if char == quote:
                quote = None
        elif char in "'\"":
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return None


def _collect_nested(text, nested):
    inner_top, inner_nested, _ = split_command(text)
    nested.extend(inner_top)
    nested.extend(inner_nested)


def _normalize(subcommand):
    """Drop control-flow keywords and wrappers so the rule sees the real command."""
    words = subcommand.split()
    while words and words[0] in LEADING_KEYWORDS:
        words.pop(0)
    if not words or words[0] in TRAILING_ONLY or words[0] in ("for", "case"):
        return ""
    return strip_wrappers(" ".join(words), env="none")


def _strip_env_prefix(command, env):
    """Drop leading NAME=value words. env: "safe" (allow rules), "all" (deny/ask), "none"."""
    if env == "none":
        return command
    count = 0
    for word in RAW_WORD.findall(command):
        match = ENV_ASSIGNMENT.match(word)
        if not match:
            break
        name, value = word[: match.end() - 1], word[match.end() :]
        if env == "safe" and any(char in value for char in "$`(<>"):
            break  # allow side: dynamic values and redirections can't be judged statically
        if env == "safe" and name not in SAFE_ENV_VARS:
            break
        count += 1
    if count == 0:
        return command
    rest = _drop_words(command, count).strip()
    return rest or command  # a bare assignment stays as written


def strip_wrappers(command, env="safe"):
    command = _strip_env_prefix(command, env)
    while True:
        try:
            words = shlex.split(command)
        except ValueError:
            return command
        if not words:
            return command
        head = words[0]
        skip = 0
        if head in SIMPLE_WRAPPERS:
            skip = 1
        elif head == "timeout":
            skip = 1
            while skip < len(words) and words[skip].startswith("-"):
                # -k and -s take their value as the next word.
                skip += 2 if words[skip] in ("-k", "-s", "--kill-after", "--signal") else 1
            skip += 1
        elif head == "nice":
            skip = 1
            if skip < len(words) and words[skip] == "-n":
                skip += 2
            elif skip < len(words) and words[skip].startswith("-"):
                skip += 1
        elif head == "stdbuf":
            skip = 1
            while skip < len(words) and words[skip].startswith("-"):
                skip += 1
        if skip == 0 or skip >= len(words):
            return command
        command = _drop_words(command, skip)


def _drop_words(command, count):
    rest = command.lstrip()
    for _ in range(count):
        match = WORD_AND_SPACE.match(rest)
        if not match:
            return rest
        rest = rest[match.end() :]
    return rest


def parse_rule(kind, text, source):
    match = RULE_PATTERN.match(text.strip())
    if not match:
        return None

    tool = match.group(1)
    pattern = match.group(2) if match.group(2) is not None else "*"

    return Rule(
        kind,
        text,
        source,
        pattern=pattern,
        tool=tool,
    )


def pattern_matches(pattern, command):
    """Match a rule's text against one subcommand."""
    if pattern.endswith(":*"):
        prefix = pattern[:-2]
        return command == prefix or command.startswith(prefix + " ")
    # "npm *" also matches a bare "npm". The docs don't settle this, so this
    # errs toward showing that a rule could apply.
    if pattern.endswith(" *") and command == pattern[:-2]:
        return True
    translated = pattern.replace("[", "[[]").replace("?", "[?]")
    return fnmatch.fnmatchcase(command, translated)




def _is_windows_path(path):
    """Return whether a path uses Windows drive or UNC syntax."""
    value = str(path)
    return (
        re.match(r"^[A-Za-z]:[\\/]", value) is not None
        or value.startswith("\\\\")
        or value.startswith("//")
    )


def _path_to_posix(path):
    """Normalize Windows and POSIX paths to a comparable POSIX form."""
    original = str(path)
    value = original.replace("\\", "/")

    # Windows drive paths: C:/foo -> /c/foo.
    drive_match = re.match(r"^([A-Za-z]):/", value)
    if drive_match:
        return "/" + drive_match.group(1).lower() + value[2:]

    # UNC paths: \\server\share\foo -> /unc/server/share/foo.
    if value.startswith("//"):
        unc_parts = [part for part in value[2:].split("/") if part]
        if len(unc_parts) >= 2:
            return posixpath.normpath(
                posixpath.join("/unc", *unc_parts)
            )

    return value


def _absolute_posix_path(path, cwd):
    """Resolve a path against cwd and return its normalized POSIX form."""
    value = _path_to_posix(path)

    if not value.startswith("/"):
        value = posixpath.join(cwd, value)

    return posixpath.normpath(value)


def _settings_source_root(source, cwd, home):
    """Return the base directory used by source-relative permission patterns."""
    source_path = _absolute_posix_path(
        Path(source).expanduser(),
        cwd,
    )

    home_claude = posixpath.join(home, ".claude")
    user_settings = posixpath.join(home_claude, "settings.json")

    if source_path == user_settings:
        return home_claude

    source_dir = posixpath.dirname(source_path)
    source_name = posixpath.basename(source_path)

    if (
        posixpath.basename(source_dir) == ".claude"
        and source_name in {"settings.json", "settings.local.json"}
    ):
        return posixpath.dirname(source_dir)

    return source_dir


def path_pattern_matches(pattern, path, kind, source=None, cwd=None):
    """Match Read/Edit paths using normalized glob-style path semantics."""
    raw_pattern = str(pattern)
    raw_path = str(path)

    cwd_value = cwd if cwd is not None else Path.cwd()
    cwd_posix = _absolute_posix_path(cwd_value, "/")
    home = _absolute_posix_path(Path.home(), cwd_posix)

    windows_semantics = (
        _is_windows_path(raw_path)
        or _is_windows_path(raw_pattern)
        or _is_windows_path(cwd_value)
    )

    target = _absolute_posix_path(raw_path, cwd_posix)

    # Expand home-relative paths.
    if raw_path.replace("\\", "/").startswith("~/"):
        target = posixpath.normpath(
            posixpath.join(home, raw_path.replace("\\", "/")[2:])
        )

    pattern_slashes = raw_pattern.replace("\\", "/")

    if pattern_slashes.startswith("~/"):
        resolved_pattern = posixpath.join(
            home,
            pattern_slashes[2:],
        )

    # A pattern beginning with // is the explicit filesystem-absolute
    # pattern syntax. A Windows UNC pattern is written with backslashes.
    elif raw_pattern.startswith("\\\\"):
        resolved_pattern = _path_to_posix(raw_pattern)

    elif pattern_slashes.startswith("//"):
        resolved_pattern = "/" + pattern_slashes.lstrip("/")

    elif pattern_slashes.startswith("/"):
        source_root = (
            _settings_source_root(source, cwd_posix, home)
            if source is not None
            else cwd_posix
        )
        resolved_pattern = posixpath.join(
            source_root,
            pattern_slashes.lstrip("/"),
        )

    elif re.match(r"^[A-Za-z]:/", pattern_slashes):
        resolved_pattern = _path_to_posix(pattern_slashes)

    else:
        relative_pattern = pattern_slashes.removeprefix("./")
        resolved_pattern = posixpath.join(
            cwd_posix,
            relative_pattern,
        )

    # A pattern without a slash matches a filename at any depth
    # beneath its selected base directory.
    if (
        "/" not in pattern_slashes
        and not pattern_slashes.startswith("/")
        and not pattern_slashes.startswith("~/")
    ):
        resolved_pattern = posixpath.join(
            cwd_posix,
            "**",
            pattern_slashes,
        )

    # Windows paths are case-insensitive. POSIX paths remain case-sensitive.
    if windows_semantics:
        target = target.casefold()
        resolved_pattern = resolved_pattern.casefold()

    regex = []
    i = 0

    while i < len(resolved_pattern):
        if resolved_pattern.startswith("**/", i):
            # **/ matches zero or more directory levels.
            regex.append("(?:.*/)?")
            i += 3
        elif resolved_pattern.startswith("**", i):
            regex.append(".*")
            i += 2
        elif resolved_pattern[i] == "*":
            regex.append("[^/]*")
            i += 1
        elif resolved_pattern[i] == "?":
            regex.append("[^/]")
            i += 1
        else:
            regex.append(re.escape(resolved_pattern[i]))
            i += 1

    return re.fullmatch("".join(regex), target) is not None


def load_rules(paths):
    rules, errors = [], []
    for path in paths:
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except FileNotFoundError:
            continue
        except (OSError, json.JSONDecodeError) as error:
            errors.append(f"{path}: {error}")
            continue
        permissions = data.get("permissions", {}) if isinstance(data, dict) else {}
        for kind in ("deny", "ask", "allow"):
            for text in permissions.get(kind, []) or []:
                rule = parse_rule(kind, text, str(path)) if isinstance(text, str) else None
                rules.append(rule or Rule(kind, str(text), str(path), pattern="\0invalid"))
    return rules, errors


def default_settings_paths():
    return [
        Path.home() / ".claude" / "settings.json",
        Path(".claude") / "settings.json",
        Path(".claude") / "settings.local.json",
    ]


def _first_match(rules, kind, command, tool="Bash"):
    for rule in rules:
        if rule.kind != kind or rule.tool != tool or rule.pattern is None:
            continue

        if tool == "Bash":
            matched = pattern_matches(rule.pattern, command)
        else:
            matched = path_pattern_matches(
                          rule.pattern,
                          command,
                          kind,
                          source=rule.source,
                        )

        if matched:
            return rule

    return None


def _match_with_env_forms(rules, kind, text, tool="Bash"):
    """Check the command as written first, then with its env prefix stripped.

    A rule can name a prefix itself, so stripping may only add matches.
    """
    stripped = strip_wrappers(
        text,
        env="safe" if kind == "allow" else "all",
    )

    for form in dict.fromkeys((text, stripped)):
        rule = _first_match(rules, kind, form, tool=tool)
        if rule:
            return rule

    return None


def explain(command, rules, tool="Bash"):
    if tool not in {"Bash", "Read", "Edit"}:
        raise ValueError(
            f"Unsupported tool: {tool!r}. Expected Bash, Read, or Edit."
        )

    if tool != "Bash":
        item = Subcommand(command)

        for kind, label in (
            ("deny", "deny"),
            ("ask", "ask"),
            ("allow", "allow"),
        ):
            rule = _first_match(
                rules,
                kind,
                command,
                tool=tool,
            )

            if rule:
                item.decision = label
                item.rule = rule.text
                item.source = rule.source
                break

        if item.decision == "deny":
            return Explanation(
                command,
                "deny",
                "A subcommand matches a deny rule.",
                [item],
            )

        if item.decision == "ask":
            return Explanation(
                command,
                "ask",
                "A subcommand matches an ask rule.",
                [item],
            )

        if item.decision == "allow":
            return Explanation(
                command,
                "allow",
                "Every subcommand matches an allow rule.",
                [item],
            )

        return Explanation(
            command,
            "prompt",
            "No allow rule matches the file path.",
            [item],
        )

    top, nested, parseable = split_command(command)
    subcommands = []
    for text, is_nested in [(c, False) for c in top] + [(c, True) for c in nested]:
        item = Subcommand(text, nested=is_nested)
        # Docs: deny, then ask, then allow. Rule specificity doesn't change the order.
        for kind, label in (("deny", "deny"), ("ask", "ask"), ("allow", "allow")):
            rule = _match_with_env_forms(rules, kind, text)
            if rule:
                item.decision, item.rule, item.source = label, rule.text, rule.source
                break
        subcommands.append(item)

    decisions = [item.decision for item in subcommands]
    needing_allow = [item for item in subcommands if not item.nested]
    if "deny" in decisions:
        return Explanation(command, "deny", "A subcommand matches a deny rule.", subcommands)
    if "ask" in decisions:
        return Explanation(command, "ask", "A subcommand matches an ask rule, which prompts even in auto mode.", subcommands)
    if not parseable:
        return Explanation(command, "prompt", "The command can't be split reliably, so allow rules can't approve it.", subcommands)
    unmatched = [item.command for item in needing_allow if item.decision != "allow"]
    if unmatched:
        return Explanation(
            command,
            "prompt",
            "No allow rule matches: " + ", ".join(f"`{c}`" for c in unmatched)
            + ". Claude Code may still approve read-only commands without a rule.",
            subcommands,
        )
    return Explanation(command, "allow", "Every subcommand matches an allow rule.", subcommands)


def lint(rules):
    findings = []
    seen = {}
    for rule in rules:
        add = lambda code, message: findings.append(Finding(code, rule.text, rule.source, message))

        if rule.pattern == "\0invalid":
            add("PW001", "This is not a valid permission rule.")
            continue
        key = (rule.kind, rule.text)
        if key in seen:
            add("PW002", f"Duplicate of the same rule in {seen[key]}.")
        seen.setdefault(key, rule.source)
        if rule.tool != "Bash" or rule.pattern is None:
            continue

        pattern = rule.pattern
        program = pattern.split()[0].rstrip(":*") if pattern.split() else ""
        if rule.kind == "allow":
            if pattern in ("*", ""):
                add("PW003", "Blanket Bash allow: approves everything and is dropped when entering auto mode.")
            elif program in INTERPRETERS and "*" in pattern:
                add("PW004", "Wildcarded interpreter: allows any code to run and is dropped when entering auto mode.")
            elif pattern.startswith(PACKAGE_RUNS) and "*" in pattern:
                add("PW005", "Wildcarded package-manager run: approves any script and is dropped when entering auto mode.")
            elif pattern.startswith(RUNNERS) and "*" in pattern:
                add("PW006", "The runner isn't stripped, so this matches whatever runs inside it.")
            for other in rules:
                if other.kind == "deny" and other.pattern and pattern_matches(other.pattern, pattern.replace(" *", "").replace(":*", "")):
                    add("PW007", f"Shadowed by deny rule {other.text}. An allow rule can't carve an exception out of a deny rule.")
                    break
        if rule.kind in ("deny", "ask") and pattern not in ("*", "") and program:
            add("PW008", f"Matches command text only: it won't stop `/bin/{program} ...` or `bash -c '{program} ...'`. Use a sandbox for a real boundary.")
        if re.search(r"https?://", pattern):
            add("PW009", "Argument patterns on URLs are fragile: other flags, schemes, redirects and variables get past them.")
    return findings


def _print_explanation(result):
    print(f"Decision: {result.decision.upper()}")
    print(f"Why: {result.reason}")
    for item in result.subcommands:
        where = " (nested)" if item.nested else ""
        suffix = f"  <- {item.rule} in {item.source}" if item.rule else ""
        print(f"  {item.decision:8} {item.command}{where}{suffix}")


def _sarif_report(findings):
    """Return lint findings as a SARIF 2.1.0 log."""
    rules = [
        {"id": code, "shortDescription": {"text": description}}
        for code, description in SARIF_RULES.items()
    ]
    results = []
    for finding in findings:
        source_path = Path(finding.source)
        if source_path.is_absolute():
            artifact_location = {"uri": source_path.as_uri()}
        else:
            artifact_location = {
                "uri": quote(source_path.as_posix(), safe="/:@-._~"),
                "uriBaseId": "%SRCROOT%",
            }
        result = {
            "ruleId": finding.code,
            "level": "warning",
            "message": {"text": finding.message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": artifact_location
                }
            }],
        }
        results.append(result)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "permwhy", "rules": rules}},
            "originalUriBaseIds": {
                "%SRCROOT%": {"uri": Path.cwd().as_uri() + "/"}
            },
            "results": results,
        }],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(prog="permwhy", description="Explain and lint Claude Code Bash permission rules.")
    parser.add_argument("--settings", action="append", help="settings file to read (repeatable); defaults to the user and project files")
    output = parser.add_mutually_exclusive_group()
    output.add_argument("--json", action="store_true", help="print JSON")
    output.add_argument("--sarif", action="store_true", help="print SARIF 2.1.0 (lint only)")
    commands = parser.add_subparsers(dest="action", required=True)
    explain_parser = commands.add_parser(
        "explain",
        help="explain the decision for a command",
    )
    explain_parser.add_argument(
        "--tool",
        choices=("Bash", "Read", "Edit"),
        default="Bash",
        help="permission tool to evaluate (default: Bash)",
    )
    explain_parser.add_argument("shell_command")
    commands.add_parser("lint", help="find ineffective or risky rules")
    args = parser.parse_args(argv)

    if args.sarif and args.action != "lint":
        parser.error("--sarif is only available with lint")

    rules, errors = load_rules(args.settings or default_settings_paths())
    for error in errors:
        print(f"permwhy: {error}", file=sys.stderr)
    if errors:
        return 2

    if args.action == "explain":
        result = explain(
            args.shell_command,
            rules,
            tool=args.tool,
        )
        if args.json:
            print(json.dumps(asdict(result), indent=2))
        else:
            _print_explanation(result)
        return 0

    findings = lint(rules)
    if args.sarif:
        print(json.dumps(_sarif_report(findings), indent=2))
        return 1 if findings else 0
    if args.json:
        print(json.dumps([asdict(f) for f in findings], indent=2))
    else:
        for finding in findings:
            print(f"{finding.code} {finding.rule} ({finding.source})\n  {finding.message}")
        print(f"{len(findings)} finding(s) in {len(rules)} rule(s).")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
