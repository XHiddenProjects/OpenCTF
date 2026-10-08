"""Proves the bundled challenges are internally consistent and solvable.

    python -m unittest tests.test_seed_challenges -v

Coding challenges are run through the real code runner with the reference
solutions in seed_challenges_extra.REFERENCE_SOLUTIONS (languages whose
toolchain isn't installed are skipped). The crypto/terminal puzzles are
checked by decoding them the way a player would.
"""
import os
import re
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_db.close()
os.environ.update(DATABASE_URL=f"sqlite:///{_db.name}", SECRET_KEY="t" * 24, JWT_SECRET_KEY="t" * 40,
                  FLAG_PEPPER="t" * 24, ADMIN_PASSWORD="test-pass-123")

import code_runner  # noqa: E402
import seed_challenges as seed  # noqa: E402
import seed_challenges_extra as extra  # noqa: E402

seed._finalize_challenges()
BY_TITLE = {c["title"]: c for c in seed.CHALLENGES}
FLAG_RE = re.compile(r"OCTF\{[0-9a-f]{32}\}")


class Catalogue(unittest.TestCase):
    def test_titles_unique_and_flags_well_formed(self):
        titles = [c["title"] for c in seed.CHALLENGES]
        self.assertEqual(len(titles), len(set(titles)), "duplicate challenge titles")
        for c in seed.CHALLENGES:
            self.assertRegex(c["flag"], FLAG_RE, c["title"])

    def test_every_new_challenge_is_present(self):
        for c in extra.EXTRA_CHALLENGES:
            self.assertIn(c["title"], BY_TITLE)
            self.assertTrue(BY_TITLE[c["title"]].get("description"), c["title"])


class CodingChallenges(unittest.TestCase):
    def test_every_coding_challenge_has_reference_solutions_that_pass(self):
        installed = set(code_runner.available_languages())
        coding = [c for c in extra.EXTRA_CHALLENGES if c["type"] == "code"]
        self.assertEqual(len(coding), len(extra.REFERENCE_SOLUTIONS))
        for c in coding:
            cfg = c["code_config"]
            solutions = extra.REFERENCE_SOLUTIONS[c["title"]]
            self.assertIn("javascript", solutions, c["title"])
            self.assertIn("python", solutions, c["title"])
            for language, code in solutions.items():
                self.assertIn(language, cfg["languages"], f"{c['title']}: {language} not enabled")
                if language not in installed:
                    continue
                with self.subTest(challenge=c["title"], language=language):
                    results = code_runner.run_coding_task(
                        language=language, player_code=code, function_name=cfg["function_name"],
                        tests=cfg["tests"], parameter_types=cfg.get("parameter_types"),
                        return_type=cfg.get("return_type"))
                    failed = [(i, r["status"], r["expected"], r["actual"], r["stderr"], r["compile_output"])
                              for i, r in enumerate(results) if not r["passed"]]
                    self.assertEqual(failed, [], "reference solution fails its own tests")

    def test_wrong_solution_does_not_pass_hidden_tests(self):
        """A solution that hard-codes the visible answers must still fail."""
        cfg = BY_TITLE["Count Set Bits"]["code_config"]
        visible = {tuple(t["args"]): t["expect"] for t in cfg["tests"] if not t.get("hidden")}
        cheat = "def countSetBits(n):\n    return %r.get(n, -1)\n" % ({k[0]: v for k, v in visible.items()},)
        results = code_runner.run_coding_task(language="python", player_code=cheat,
                                              function_name="countSetBits", tests=cfg["tests"])
        self.assertFalse(all(r["passed"] for r in results))
        self.assertTrue(any(t.get("hidden") for t in cfg["tests"]))

    def test_configs_pass_server_validation(self):
        import app
        for c in extra.EXTRA_CHALLENGES:
            if c["type"] == "code":
                task, error = app._validate_code_task(c["code_config"])
                self.assertIsNone(error, f"{c['title']}: {error}")


class Puzzles(unittest.TestCase):
    def test_atbash_decodes_to_flag(self):
        text = BY_TITLE["Atbash Whisper"]["description"]
        cipher = re.search(r"^    (\S+)$", text, re.M).group(1)
        self.assertEqual(extra.atbash(cipher), BY_TITLE["Atbash Whisper"]["flag"])
        self.assertNotIn(BY_TITLE["Atbash Whisper"]["flag"], text)

    def test_binary_decodes_to_flag(self):
        text = BY_TITLE["Binary Beacon"]["description"]
        bits = re.search(r"^    ([01 ]+)$", text, re.M).group(1).split()
        self.assertEqual("".join(chr(int(b, 2)) for b in bits), BY_TITLE["Binary Beacon"]["flag"])

    def test_morse_decodes_to_flag(self):
        text = BY_TITLE["Morse Dispatch"]["description"]
        code = re.search(r"^    ([.\- ]+)$", text, re.M).group(1).split(" ")
        reverse = {v: k for k, v in extra._MORSE.items()}
        self.assertEqual("OCTF{" + "".join(reverse[c] for c in code) + "}", BY_TITLE["Morse Dispatch"]["flag"])

    def test_rail_fence_decodes_to_flag(self):
        text = BY_TITLE["Rail Fence Rails"]["description"]
        cipher = re.search(r"^    (\S+)$", text, re.M).group(1)
        self.assertEqual(extra.rail_fence_decrypt(cipher, 3), BY_TITLE["Rail Fence Rails"]["flag"])
        self.assertEqual(sorted(cipher), sorted(BY_TITLE["Rail Fence Rails"]["flag"]))

    def test_terminal_flags_are_reachable(self):
        import app
        cases = {
            "Cron Trail": ["cat /etc/crontab", "cat /opt/scripts/nightly_sync.sh", "cat /var/backups/.vault/archive_token"],
            "Config Hunt": ["grep -r -i api /srv"],
            "Shell History": ["cat /home/admin/.bash_history"],
        }
        for title, commands in cases.items():
            tree = BY_TITLE[title]["terminal_fs"]
            outputs, cwd = [], "/"
            for command in commands:
                out, cwd = app.run_terminal_command(tree, cwd, command)
                outputs.append(out)
            self.assertIn(BY_TITLE[title]["flag"], "\n".join(outputs), title)


if __name__ == "__main__":
    unittest.main()
