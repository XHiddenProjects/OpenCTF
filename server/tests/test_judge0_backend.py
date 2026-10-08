"""The optional Judge0 backend, exercised against a stub `judge0` package
(no network, no Judge0 server needed).   python -m unittest tests.test_judge0_backend
"""
import os
import sys
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import code_harness as harness  # noqa: E402


def install_stub(stdout_for):
    """Fake `judge0` module. stdout_for(source, stdin) -> (status, stdout)."""
    mod = types.ModuleType("judge0")

    class Status:
        ACCEPTED, WRONG_ANSWER, RUNTIME = "Accepted", "Wrong Answer", "Runtime Error (NZEC)"

    class LanguageAlias:
        JAVASCRIPT = PYTHON3 = PHP = RUBY = C = CPP = JAVA = object()

    class Submission:
        def __init__(self, source_code=None, language=None, stdin="", **kw):
            self.source_code, self.language, self.stdin, self.kw = source_code, language, stdin, kw
            self.status = self.stdout = self.stderr = self.compile_output = None

    class Client:
        def __init__(self, endpoint=None, headers=None):
            self.endpoint = endpoint

    def sync_execute(client=None, submissions=None, source_code=None, language=None, test_cases=None, **kw):
        if submissions is None:
            submissions = []
            for case in test_cases:
                s = Submission(source_code=source_code, language=language, stdin=case["input"], **kw)
                submissions.append(s)
        for s in submissions:
            s.status, s.stdout = stdout_for(s.source_code, s.stdin)
        return submissions

    mod.Status, mod.LanguageAlias, mod.Submission, mod.Client, mod.sync_execute = (
        Status, LanguageAlias, Submission, Client, sync_execute)
    sys.modules["judge0"] = mod
    return mod


class Judge0Backend(unittest.TestCase):
    def setUp(self):
        os.environ["CODE_RUNNER"] = "judge0"
        os.environ["JUDGE0_CE_ENDPOINT"] = "http://judge0.invalid"
        import importlib
        import judge0_runner
        importlib.reload(judge0_runner)
        judge0_runner._client = None
        self.judge0_runner = judge0_runner
        import code_runner
        importlib.reload(code_runner)
        self.code_runner = code_runner

    def tearDown(self):
        os.environ.pop("CODE_RUNNER", None)
        os.environ.pop("JUDGE0_CE_ENDPOINT", None)
        sys.modules.pop("judge0", None)

    def test_results_use_the_marker_protocol(self):
        install_stub(lambda src, stdin: ("Accepted", "debug line\n" + harness.RESULT_MARK + "42"))
        r = self.code_runner.run_coding_task(
            language="python", player_code="def f(x): return 42", function_name="f",
            tests=[{"args": [1], "expect": 42}, {"args": [2], "expect": 41}])
        self.assertTrue(r[0]["passed"]);  self.assertEqual(r[0]["stdout"], "debug line")
        self.assertFalse(r[1]["passed"]); self.assertEqual(r[1]["status"], "Wrong Answer")

    def test_static_languages_get_one_submission_per_test(self):
        seen = []
        def fake(src, stdin):
            seen.append(src)
            return "Accepted", harness.RESULT_MARK + "3"
        install_stub(fake)
        r = self.code_runner.run_coding_task(
            language="cpp", player_code="int add(int a, int b) { return a + b; }", function_name="add",
            tests=[{"args": [1, 2], "expect": 3}, {"args": [2, 1], "expect": 3}],
            parameter_types=["int", "int"], return_type="int")
        self.assertEqual(len(seen), 2)
        self.assertTrue(all("case 0:" in s and "case 1:" not in s for s in seen), "each submission holds only its own test")
        self.assertTrue(all(x["passed"] for x in r))

    def test_runtime_error_status_passes_through(self):
        install_stub(lambda src, stdin: ("Runtime Error (NZEC)", ""))
        r = self.code_runner.run_coding_task(language="python", player_code="x", function_name="f", tests=[{"args": [], "expect": 1}])
        self.assertEqual(r[0]["status"], "Runtime Error (NZEC)"); self.assertFalse(r[0]["passed"])

    def test_missing_package_is_a_clean_error(self):
        sys.modules["judge0"] = None  # makes `import judge0` raise ImportError
        with self.assertRaises(self.code_runner.CodeRunnerUnavailable) as ctx:
            self.code_runner.run_coding_task(language="python", player_code="x", function_name="f", tests=[{"args": [], "expect": 1}])
        self.assertIn("requirements-judge0.txt", str(ctx.exception))

    def test_status_describes_judge0_and_warns(self):
        s = self.code_runner.status()
        self.assertEqual((s["backend"], s["offline"]), ("judge0", False))
        self.assertTrue(any("judge0.invalid" in w for w in s["warnings"]))


class DefaultIsOffline(unittest.TestCase):
    def test_default_backend_is_local_even_if_judge0_url_is_set(self):
        os.environ.pop("CODE_RUNNER", None)
        os.environ["JUDGE0_CE_ENDPOINT"] = "https://ce.judge0.com"
        try:
            import code_runner
            self.assertEqual(code_runner.backend(), "local")
            self.assertTrue(any("ignored" in w for w in code_runner.status()["warnings"]))
        finally:
            os.environ.pop("JUDGE0_CE_ENDPOINT", None)


if __name__ == "__main__":
    unittest.main()
