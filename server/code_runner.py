"""Code execution for the Code Challenge Editor: one entry point, two backends.

  CODE_RUNNER=local   (default) run on this machine with the installed
                      interpreters/compilers. Works with no internet at all.
                      See local_runner.py for the security model.
  CODE_RUNNER=judge0  send the code to a Judge0 server (JUDGE0_CE_ENDPOINT).

`app.py` only imports this module.
"""

from __future__ import annotations

import os

try:
    import code_harness as harness
    import judge0_runner
    import local_runner
except ImportError:  # installed as the `openctf-server` package
    from . import code_harness as harness
    from . import judge0_runner, local_runner
SUPPORTED_DYNAMIC_LANGUAGES = harness.SUPPORTED_DYNAMIC_LANGUAGES  # re-exported for app.py
SUPPORTED_LANGUAGES = harness.SUPPORTED_LANGUAGES
UnsupportedLanguage = harness.UnsupportedLanguage
normalize_language = harness.normalize_language

__all__ = [
    "CodeRunnerUnavailable", "UnsupportedLanguage", "SUPPORTED_LANGUAGES",
    "SUPPORTED_DYNAMIC_LANGUAGES", "normalize_language", "run_coding_task",
    "available_languages", "status",
]


class CodeRunnerUnavailable(Exception):
    """The configured backend can't run code right now (shown to the player)."""


def backend() -> str:
    value = (os.environ.get("CODE_RUNNER") or "local").strip().lower()
    return value if value in ("local", "judge0") else "local"


def available_languages() -> list[str]:
    """Languages the server can actually run right now."""
    if backend() == "judge0":
        return list(SUPPORTED_LANGUAGES)  # Judge0 hosts the toolchains
    return local_runner.available_languages()


def run_coding_task(
    *, language: str, player_code: str, function_name: str, tests: list[dict],
    parameter_types: list[str] | None = None, return_type: str | None = None,
) -> list[dict]:
    """Run every test and return one result dict per test:

      {"passed": bool, "expected": ..., "actual": ..., "status": str,
       "stderr": str|None, "compile_output": str|None, "stdout": str|None}

    Raises CodeRunnerUnavailable, UnsupportedLanguage or ValueError (bad task).
    """
    language = normalize_language(language)
    if language not in SUPPORTED_LANGUAGES:
        raise UnsupportedLanguage(
            f"'{language}' isn't supported for server-side execution. "
            f"Supported: {', '.join(SUPPORTED_LANGUAGES)}."
        )
    harness.validate_function_name(function_name)
    if language in harness.STATIC_LANGUAGES:
        harness.validate_signature(language, parameter_types, return_type)

    kwargs = dict(language=language, player_code=player_code, function_name=function_name,
                  tests=tests, parameter_types=parameter_types, return_type=return_type)
    try:
        if backend() == "judge0":
            return judge0_runner.run_tests(**kwargs)
        return local_runner.run_tests(**kwargs)
    except (judge0_runner.Judge0Unavailable, local_runner.LocalRunnerError) as exc:
        raise CodeRunnerUnavailable(str(exc)) from exc


def status() -> dict:
    """Describe the current setup (admin screen + startup log)."""
    chosen = backend()
    warnings = []
    if chosen == "local":
        sandbox = local_runner.sandbox_info()
        info = local_runner.toolchains()
        languages = {
            lang: {"available": d["available"], "missing": d["missing"]} for lang, d in sorted(info.items())
        }
        if sandbox["mode"] == "none":
            warnings.append(
                "No OS-level sandbox is active: player code runs with this server's own file access. "
                "Fine for a trusted classroom; for a competition install bubblewrap (Linux) or use "
                "CODE_RUNNER=judge0 with a self-hosted Judge0."
            )
        elif sandbox["mode"] == "netns":
            warnings.append(
                "Only the network is isolated; player code can still read files this server can read. "
                "Install bubblewrap (bwrap) for filesystem isolation."
            )
        if judge0_runner.configured():
            warnings.append(
                "JUDGE0_CE_ENDPOINT is set but CODE_RUNNER is not 'judge0', so it is being ignored "
                "(code runs locally and offline)."
            )
        return {"backend": "local", "offline": True, "sandbox": sandbox["mode"],
                "sandbox_detail": sandbox["detail"], "languages": languages, "warnings": warnings}

    languages = {lang: {"available": True, "missing": []} for lang in SUPPORTED_LANGUAGES}
    warnings.append(
        "CODE_RUNNER=judge0: submitted code is sent to "
        f"{os.environ.get('JUDGE0_CE_ENDPOINT') or '(JUDGE0_CE_ENDPOINT not set)'}."
    )
    return {"backend": "judge0", "offline": False, "sandbox": "judge0",
            "sandbox_detail": "isolation provided by the Judge0 server",
            "languages": languages, "warnings": warnings}
