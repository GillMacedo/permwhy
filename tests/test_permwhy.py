import io
import json
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "plugin" / "scripts"))

import permwhy  # noqa: E402


def rules(allow=(), ask=(), deny=()):
    result = []
    for kind, texts in (("deny", deny), ("ask", ask), ("allow", allow)):
        result.extend(permwhy.parse_rule(kind, text, "test.json") for text in texts)
    return result


class SplitCommandTest(unittest.TestCase):
    def test_every_documented_separator(self):
        top, _, parseable = permwhy.split_command("a && b || c ; d | e |& f & g\nh")
        self.assertEqual(top, list("abcdefgh"))
        self.assertTrue(parseable)

    def test_quoted_separators_are_text(self):
        top, _, _ = permwhy.split_command("""echo "a && b" 'c; d'""")
        self.assertEqual(len(top), 1)

    def test_redirects_are_not_separators(self):
        top, _, _ = permwhy.split_command("make test 2>&1")
        self.assertEqual(top, ["make test 2>&1"])

    def test_nested_commands_are_found(self):
        _, nested, _ = permwhy.split_command('echo "$(git clean -f)" && (rm x) && echo `whoami`')
        self.assertEqual(sorted(nested), ["git clean -f", "rm x", "whoami"])

    def test_control_flow_body_is_found(self):
        top, _, _ = permwhy.split_command("for f in a b; do rm $f; done")
        self.assertEqual(top, ["rm $f"])

    def test_trailing_operator_is_unparseable(self):
        self.assertFalse(permwhy.split_command("npm test &&")[2])

    def test_unclosed_input_is_unparseable(self):
        self.assertFalse(permwhy.split_command("echo $(oops")[2])
        self.assertFalse(permwhy.split_command('echo "oops')[2])


class WrapperTest(unittest.TestCase):
    def test_documented_wrappers_are_stripped(self):
        cases = {
            "timeout 30 npm test": "npm test",
            "timeout -k 5 30 npm test": "npm test",
            "timeout --signal=KILL 30 npm test": "npm test",
            "nice -n 5 npm test": "npm test",
            "nohup npm test": "npm test",
            "stdbuf -oL npm test": "npm test",
            "command npm test": "npm test",
            "time nohup npm test": "npm test",
        }
        for given, want in cases.items():
            self.assertEqual(permwhy.strip_wrappers(given), want, given)

    def test_runners_are_not_stripped(self):
        self.assertEqual(permwhy.strip_wrappers("npx rm -rf x"), "npx rm -rf x")


class MatchTest(unittest.TestCase):
    def test_word_boundary(self):
        self.assertTrue(permwhy.pattern_matches("ls *", "ls -la"))
        self.assertFalse(permwhy.pattern_matches("ls *", "lsof"))
        self.assertTrue(permwhy.pattern_matches("ls*", "lsof"))

    def test_legacy_prefix(self):
        self.assertTrue(permwhy.pattern_matches("npm:*", "npm test"))
        self.assertFalse(permwhy.pattern_matches("npm:*", "npmx test"))

    def test_brackets_are_literal(self):
        self.assertTrue(permwhy.pattern_matches("echo [a]", "echo [a]"))
        self.assertFalse(permwhy.pattern_matches("echo [a]", "echo a"))


class ExplainTest(unittest.TestCase):
    def test_all_subcommands_allowed(self):
        result = permwhy.explain("git status && npm test", rules(allow=["Bash(git *)", "Bash(npm *)"]))
        self.assertEqual(result.decision, "allow")

    def test_docs_example_safe_cmd_does_not_cover_other_cmd(self):
        result = permwhy.explain("safe-cmd && other-cmd", rules(allow=["Bash(safe-cmd *)"]))
        self.assertEqual(result.decision, "prompt")
        self.assertIn("other-cmd", result.reason)

    def test_docs_example_ask_rule_reaches_compound_and_nested(self):
        ask = rules(ask=["Bash(git clean *)"])
        self.assertEqual(permwhy.explain("cd /tmp && git clean -f", ask).decision, "ask")
        self.assertEqual(permwhy.explain('echo "$(git clean -f)"', ask).decision, "ask")

    def test_deny_beats_ask_and_allow(self):
        result = permwhy.explain("aws s3 ls", rules(allow=["Bash(aws s3 ls)"], ask=["Bash(aws s3 *)"], deny=["Bash(aws *)"]))
        self.assertEqual(result.decision, "deny")

    def test_docs_example_trailing_operator_is_not_approved(self):
        self.assertEqual(permwhy.explain("npm test &&", rules(allow=["Bash(npm *)"])).decision, "prompt")

    def test_docs_example_deny_misses_other_invocations(self):
        deny = rules(deny=["Bash(rm *)"])
        self.assertEqual(permwhy.explain("rm -rf build", deny).decision, "deny")
        self.assertNotEqual(permwhy.explain("/bin/rm -rf build", deny).decision, "deny")

    def test_wrapper_is_stripped_before_matching(self):
        self.assertEqual(permwhy.explain("timeout 30 npm test", rules(allow=["Bash(npm test)"])).decision, "allow")

    def test_non_bash_rules_are_ignored(self):
        self.assertEqual(permwhy.explain("ls", rules(allow=["Read(./*)"])).decision, "prompt")


class LintTest(unittest.TestCase):
    def codes(self, **kwargs):
        return {finding.code for finding in permwhy.lint(rules(**kwargs))}

    def test_broad_allows(self):
        self.assertIn("PW003", self.codes(allow=["Bash(*)"]))
        self.assertIn("PW003", self.codes(allow=["Bash"]))
        self.assertIn("PW004", self.codes(allow=["Bash(python *)"]))
        self.assertIn("PW005", self.codes(allow=["Bash(npm run *)"]))
        self.assertIn("PW006", self.codes(allow=["Bash(devbox run *)"]))

    def test_shadowed_allow(self):
        self.assertIn("PW007", self.codes(allow=["Bash(aws s3 ls)"], deny=["Bash(aws *)"]))

    def test_deny_is_not_a_boundary(self):
        self.assertIn("PW008", self.codes(deny=["Bash(rm *)"]))

    def test_url_pattern(self):
        self.assertIn("PW009", self.codes(allow=["Bash(curl http://github.com/ *)"]))

    def test_narrow_rule_is_clean(self):
        self.assertEqual(self.codes(allow=["Bash(npm test)", "Bash(git status)"]), set())

    def test_duplicate_and_invalid(self):
        duplicate = rules(allow=["Bash(npm test)", "Bash(npm test)"])
        self.assertIn("PW002", {f.code for f in permwhy.lint(duplicate)})
        invalid = [permwhy.Rule("allow", "not a rule!", "x", pattern="\0invalid")]
        self.assertEqual([f.code for f in permwhy.lint(invalid)], ["PW001"])


class CliTest(unittest.TestCase):
    def run_cli(self, settings, *args):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "settings.json"
            path.write_text(settings, encoding="utf-8")
            output = io.StringIO()
            with redirect_stdout(output):
                code = permwhy.main(["--settings", str(path), *args])
            return code, output.getvalue()

    def test_explain_json(self):
        code, output = self.run_cli('{"permissions":{"allow":["Bash(ls *)"]}}', "--json", "explain", "ls -la")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output)["decision"], "allow")

    def test_lint_exit_codes(self):
        self.assertEqual(self.run_cli('{"permissions":{"allow":["Bash(*)"]}}', "lint")[0], 1)
        self.assertEqual(self.run_cli('{"permissions":{"allow":["Bash(ls)"]}}', "lint")[0], 0)

    def test_broken_settings_file(self):
        self.assertEqual(self.run_cli("{oops", "lint")[0], 2)


class ProjectTest(unittest.TestCase):
    def test_skill_follows_published_limits(self):
        text = (ROOT / "plugin" / "skills" / "explaining-permissions" / "SKILL.md").read_text(encoding="utf-8")
        match = re.match(r"---\n(.*?)\n---\n(.*)", text, re.DOTALL)
        self.assertIsNotNone(match)
        front = dict(line.split(": ", 1) for line in match.group(1).splitlines())
        self.assertRegex(front["name"], r"^[a-z0-9-]{1,64}$")
        self.assertNotRegex(front["name"], "anthropic|claude")
        self.assertLessEqual(len(front["description"]), 1024)
        self.assertLess(len(match.group(2).splitlines()), 500)

    def test_at_least_three_evals(self):
        evals = json.loads((ROOT / "evals" / "evals.json").read_text(encoding="utf-8"))
        self.assertGreaterEqual(len(evals), 3)

    def test_no_real_tokens_in_repo(self):
        pattern = re.compile(r"(github_pat_[A-Za-z0-9_]{20,}|gh[opusr]_[A-Za-z0-9]{30,}|sk-ant-[A-Za-z0-9_-]{20,})")
        for path in ROOT.rglob("*"):
            if path.is_file() and ".git" not in path.parts and "__pycache__" not in path.parts:
                self.assertIsNone(pattern.search(path.read_text(encoding="utf-8", errors="ignore")), path)


if __name__ == "__main__":
    unittest.main()
