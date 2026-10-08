"""Tests for the offline code runner.  Run from the server/ directory:

    python -m unittest tests.test_code_runner -v

Languages whose interpreter/compiler isn't installed are skipped, not failed.
Isolation tests only run when a sandbox is available.
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("CODE_RUNNER", "local")

import code_harness as harness  # noqa: E402
import code_runner  # noqa: E402
import local_runner  # noqa: E402

SUM_TESTS = [
    {"args": [[1, 2, 3]], "expect": 6},
    {"args": [[]], "expect": 0},
    {"args": [[-5, 5, 10]], "expect": 10},
]
SIG = dict(parameter_types=["int[]"], return_type="int")

GOOD = {
    "javascript": "function sumArray(nums) { let s = 0; for (const n of nums) s += n; return s; }",
    "python": "def sumArray(nums):\n    return sum(nums)\n",
    "php": "function sumArray($nums) { return array_sum($nums); }",
    "ruby": "def sumArray(nums)\n  nums.sum\nend\n",
    "c": "int sumArray(const int *nums, size_t n) { int s = 0; for (size_t i = 0; i < n; i++) s += nums[i]; return s; }",
    "cpp": "int sumArray(std::vector<int> nums) { int s = 0; for (int n : nums) s += n; return s; }",
    "java": "public static int sumArray(int[] nums) { int s = 0; for (int n : nums) s += n; return s; }",
}


def run(language, code, tests=SUM_TESTS, name="sumArray", **kw):
    return code_runner.run_coding_task(language=language, player_code=code, function_name=name,
                                       tests=tests, **(SIG if kw.get("sig", True) else {}))


def installed(language):
    return language in code_runner.available_languages()


class Languages(unittest.TestCase):
    def test_every_installed_language_passes(self):
        for language, code in GOOD.items():
            if not installed(language):
                continue
            with self.subTest(language=language):
                results = run(language, code)
                self.assertEqual([r["status"] for r in results], ["Accepted"] * 3, results)
                self.assertTrue(all(r["passed"] for r in results))

    def test_wrong_answer(self):
        bad = {
            "javascript": "function sumArray(n) { return 1; }",
            "python": "def sumArray(n):\n    return 1\n",
            "cpp": "int sumArray(std::vector<int> n) { return 1; }",
        }
        for language, code in bad.items():
            if not installed(language):
                continue
            with self.subTest(language=language):
                results = run(language, code)
                self.assertFalse(results[0]["passed"])
                self.assertEqual(results[0]["status"], "Wrong Answer")
                self.assertEqual(results[0]["actual"], 1)

    def test_compile_error_reported_for_every_test(self):
        for language in ("c", "cpp", "java"):
            if not installed(language):
                continue
            with self.subTest(language=language):
                results = run(language, "this is not valid code")
                self.assertTrue(all(r["status"] == "Compilation Error" for r in results))
                self.assertTrue(results[0]["compile_output"])

    def test_runtime_error_has_stderr(self):
        for language, code in {"python": "def sumArray(n):\n    raise ValueError('boom')\n",
                               "javascript": "function sumArray(n) { throw new Error('boom'); }"}.items():
            if not installed(language):
                continue
            with self.subTest(language=language):
                r = run(language, code)[0]
                self.assertEqual(r["status"], "Runtime Error (NZEC)")
                self.assertIn("boom", r["stderr"])

    def test_missing_function(self):
        r = run("python", "x = 1\n")[0]
        self.assertFalse(r["passed"])

    def test_print_debugging_does_not_break_result(self):
        cases = {
            "python": "def sumArray(n):\n    print('debug', n)\n    return sum(n)\n",
            "javascript": "function sumArray(n) { console.log('debug', n); return n.reduce((a,b)=>a+b,0); }",
            "cpp": '#include <cstdio>\nint sumArray(std::vector<int> n) { printf("dbg"); int s=0; for(int x:n) s+=x; return s; }',
        }
        for language, code in cases.items():
            if not installed(language):
                continue
            with self.subTest(language=language):
                results = run(language, code)
                self.assertTrue(all(r["passed"] for r in results), results)
                self.assertIn("dbg" if language == "cpp" else "debug", results[0]["stdout"])

    def test_infinite_loop_times_out(self):
        old = local_runner.WALL_LIMIT_S, local_runner.CPU_LIMIT_S
        local_runner.WALL_LIMIT_S, local_runner.CPU_LIMIT_S = 2, 1
        try:
            r = run("python", "def sumArray(n):\n    while True: pass\n", tests=SUM_TESTS[:1])[0]
        finally:
            local_runner.WALL_LIMIT_S, local_runner.CPU_LIMIT_S = old
        self.assertEqual(r["status"], "Time Limit Exceeded")

    def test_runaway_output_is_capped(self):
        r = run("python", "def sumArray(n):\n    while True: print('x' * 1000)\n", tests=SUM_TESTS[:1])[0]
        self.assertFalse(r["passed"])
        self.assertLessEqual(len(r["stdout"] or ""), local_runner.CONSOLE_RETURN_CAP + 50)


class Harness(unittest.TestCase):
    def test_split_output(self):
        console, found, value = harness.split_output("hello\n" + harness.RESULT_MARK + "[1,2]")
        self.assertEqual((console, found, value), ("hello", True, [1, 2]))
        self.assertEqual(harness.split_output("only noise")[1], False)
        self.assertEqual(harness.split_output(harness.RESULT_MARK + "not json")[1], False)

    def test_json_equal_distinguishes_bool_and_int(self):
        self.assertFalse(harness.json_values_equal(True, 1))
        self.assertTrue(harness.json_values_equal(1, 1.0))
        self.assertTrue(harness.json_values_equal({"a": [1]}, {"a": [1]}))

    def test_bad_function_name_rejected(self):
        with self.assertRaises(ValueError):
            code_runner.run_coding_task(language="python", player_code="", function_name="a;b", tests=[])

    def test_typed_signature_required_for_static(self):
        with self.assertRaises(ValueError):
            code_runner.run_coding_task(language="cpp", player_code="", function_name="f",
                                        tests=[{"args": [], "expect": 0}])


@unittest.skipUnless(sys.platform.startswith("linux") and local_runner.sandbox_info()["mode"] == "bwrap",
                     "bubblewrap sandbox not available")
class Isolation(unittest.TestCase):
    """What the sandbox is actually for: player code must not see server files."""

    def test_cannot_read_server_files_or_env(self):
        secret = tempfile.NamedTemporaryFile("w", delete=False, suffix=".env")
        secret.write("FLAG_PEPPER=top-secret")
        secret.close()
        os.environ["OCTF_TEST_SECRET"] = "env-secret"
        try:
            code = (
                "def sumArray(n):\n"
                "    import os\n"
                f"    leaked = []\n"
                f"    try: leaked.append(open({secret.name!r}).read())\n"
                "    except Exception as e: leaked.append('blocked')\n"
                "    leaked.append(os.environ.get('OCTF_TEST_SECRET', 'no-env'))\n"
                "    return leaked\n"
            )
            r = run("python", code, tests=[{"args": [[1]], "expect": ["blocked", "no-env"]}])[0]
            self.assertTrue(r["passed"], r)
        finally:
            os.unlink(secret.name)
            del os.environ["OCTF_TEST_SECRET"]

    def test_no_network(self):
        code = (
            "def sumArray(n):\n"
            "    import socket\n"
            "    try:\n"
            "        s = socket.create_connection(('1.1.1.1', 80), timeout=2); return 'connected'\n"
            "    except Exception: return 'blocked'\n"
        )
        r = run("python", code, tests=[{"args": [[1]], "expect": "blocked"}])[0]
        self.assertTrue(r["passed"], r)

    def test_cannot_write_outside_workdir(self):
        target = os.path.join(tempfile.gettempdir(), "octf-escape-test.txt")
        code = (
            "def sumArray(n):\n"
            f"    try:\n        open({target!r}, 'w').write('x'); return 'wrote'\n"
            "    except Exception: return 'blocked'\n"
        )
        run("python", code, tests=[{"args": [[1]], "expect": "wrote"}])
        self.assertFalse(os.path.exists(target), "player code escaped the sandbox")


if __name__ == "__main__":
    unittest.main()
