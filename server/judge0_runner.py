"""Optional Judge0 backend for the Code Challenge Editor.

Only used when `CODE_RUNNER=judge0`. The default backend is the offline local
runner (`local_runner.py`). Point this at a Judge0 you host yourself (on your
LAN it needs no internet either) for stronger isolation than a plain local
subprocess; see https://github.com/judge0/judge0.

The `judge0` Python package is imported lazily, so installations that never use
this backend don't need it (`pip install -r requirements-judge0.txt`).

  JUDGE0_CE_ENDPOINT       base URL, e.g. http://localhost:2358
  JUDGE0_CE_AUTH_HEADERS   optional JSON object of auth headers
"""

from __future__ import annotations

import json
import os
import threading

try:
    import code_harness as harness
except ImportError:  # installed as the `openctf-server` package
    from . import code_harness as harness


class Judge0Unavailable(Exception):
    """Judge0 isn't configured, installed, or reachable."""


_CPU_TIME_LIMIT_S = 5
_WALL_TIME_LIMIT_S = 10
_MEMORY_LIMIT_KB = 128_000

_client_lock = threading.Lock()
_client = None


def _import_judge0():
    try:
        import judge0  # noqa: PLC0415
    except ImportError as exc:
        raise Judge0Unavailable(
            "CODE_RUNNER=judge0 needs the 'judge0' package: pip install -r requirements-judge0.txt"
        ) from exc
    return judge0


def configured() -> bool:
    return bool(os.environ.get("JUDGE0_CE_ENDPOINT"))


def _get_client():
    global _client
    if _client is not None:
        return _client
    with _client_lock:
        if _client is not None:
            return _client
        judge0 = _import_judge0()
        endpoint = os.environ.get("JUDGE0_CE_ENDPOINT")
        if not endpoint:
            raise Judge0Unavailable(
                "CODE_RUNNER=judge0 but JUDGE0_CE_ENDPOINT isn't set. Set it to your Judge0 base URL, "
                "or remove CODE_RUNNER to use the offline local runner."
            )
        headers = {}
        raw = os.environ.get("JUDGE0_CE_AUTH_HEADERS")
        if raw:
            try:
                headers = json.loads(raw)
            except ValueError as exc:
                raise Judge0Unavailable("JUDGE0_CE_AUTH_HEADERS is set but isn't valid JSON.") from exc
        try:
            _client = judge0.Client(endpoint=endpoint, headers=headers)
        except Exception as exc:  # Client() fetches API metadata immediately.
            cause = exc.__cause__ or exc
            raise Judge0Unavailable(
                f"Couldn't reach Judge0 at {endpoint}: {type(cause).__name__}: {cause}"
            ) from exc
        return _client


def run_tests(*, language, player_code, function_name, tests, parameter_types=None, return_type=None):
    judge0 = _import_judge0()
    aliases = {
        "javascript": judge0.LanguageAlias.JAVASCRIPT, "python": judge0.LanguageAlias.PYTHON3,
        "php": judge0.LanguageAlias.PHP, "ruby": judge0.LanguageAlias.RUBY,
        "c": judge0.LanguageAlias.C, "cpp": judge0.LanguageAlias.CPP, "java": judge0.LanguageAlias.JAVA,
    }
    static = language in harness.STATIC_LANGUAGES
    limits = dict(cpu_time_limit=_CPU_TIME_LIMIT_S, wall_time_limit=_WALL_TIME_LIMIT_S,
                  memory_limit=_MEMORY_LIMIT_KB, enable_network=False)

    if static:
        # One submission per test; each program runs its only case (index 0).
        submissions_to_run = [
            judge0.Submission(
                source_code=harness.static_source(language, player_code, function_name, [test],
                                                  parameter_types, return_type),
                language=aliases[language], stdin="", **limits,
            )
            for test in tests
        ]
    else:
        source = harness.dynamic_source(language, player_code, function_name)
        test_cases = [{"input": harness.stdin_for(test)} for test in tests]

    client = _get_client()
    try:
        if static:
            submissions = judge0.sync_execute(client=client, submissions=submissions_to_run)
        else:
            submissions = judge0.sync_execute(
                client=client, source_code=source, language=aliases[language],
                test_cases=test_cases, **limits,
            )
    except Exception as exc:
        raise Judge0Unavailable(f"Judge0 request failed: {exc}") from exc

    if isinstance(submissions, judge0.Submission):
        submissions = [submissions]
    if len(submissions) != len(tests):
        raise Judge0Unavailable(f"Judge0 returned {len(submissions)} results for {len(tests)} tests.")

    results = []
    for test, submission in zip(tests, submissions, strict=True):
        status = str(submission.status) if submission.status is not None else "Unknown"
        executed = submission.status in (judge0.Status.ACCEPTED, judge0.Status.WRONG_ANSWER)
        console, found, actual = harness.split_output(submission.stdout or "")
        expected = test.get("expect")
        passed = bool(executed and found and harness.json_values_equal(actual, expected))
        results.append({
            "passed": passed, "expected": expected, "actual": actual if found else None,
            "status": ("Accepted" if passed else "Wrong Answer") if executed else status,
            "stderr": (submission.stderr or "").strip()[:2000] or None,
            "compile_output": (submission.compile_output or "").strip()[:4000] or None,
            "stdout": console.strip()[:4000] or None,
        })
    return results
