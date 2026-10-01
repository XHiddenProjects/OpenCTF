"""Server-side code execution for the Code Challenge Editor addon, via Judge0.

The addon's "Run" button hands the player's code to Judge0
(https://github.com/judge0/judge0) - a real,
purpose-built sandboxed execution judge (it uses `isolate` under the hood,
the same sandboxing technology many competitive-programming judges use) -
rather than shelling out to a local interpreter/compiler directly, which
would mean running arbitrary player-submitted code on this server's own
host with nothing standing in the way of it.

This module does NOT stand up a Judge0 instance - you need one already
running, self-hosted (see https://github.com/judge0/judge0#get-started,
Docker Compose is the fastest path) or via a hosted plan, and pointed to
via the JUDGE0_CE_ENDPOINT / JUDGE0_CE_AUTH_HEADERS environment variables
(same names the `judge0` PyPI client itself already looks for - see
Client.__init__/_get_custom_client in that package). Nothing here works
without one; every call below fails closed with a clear error rather than
silently no-opping if it's unreachable or unconfigured.

The registered harnesses support dynamically typed languages that decode
the JSON-native test format (arrays, objects, numbers, strings, booleans)
and invoke `function_name` with positional arguments. Statically typed
languages require a per-task function signature and are not offered as
runnable until that authoring contract exists.
"""

from __future__ import annotations

import json
import os
import re
import threading

from judge0 import Client, LanguageAlias, Status, Submission, sync_execute


class Judge0Unavailable(Exception):
    """Judge0 isn't configured, or isn't reachable right now."""


class UnsupportedLanguage(Exception):
    """No harness registered for this language (see _HARNESSES)."""


# --- Per-language harness templates ----------------------------------
# Each harness wraps the player's own source with a small driver that:
# reads one test's args as a JSON array from stdin, calls their function
# with those args spread as positional arguments, and prints the result
# as compact JSON. Judge0 runs this combined program once per test case;
# the runner parses its output and compares JSON values so object key order
# doesn't cause false failures. Whatever the player's code raises (a real bug, a bad
# function name, a syntax error) surfaces as a Runtime/Compilation Error
# status rather than a Python traceback leaking server internals, since
# it's Judge0's own sandboxed process producing that output, not ours.
_HARNESSES = {
    "javascript": {
        "language_id": LanguageAlias.JAVASCRIPT,
        "wrap": lambda code, function_name: (
            "const _fs = require('fs');\n"
            "const _args = JSON.parse(_fs.readFileSync(0, 'utf8') || '[]');\n"
            "console.log = (..._values) => console.error(..._values);\n"
            "const _fn = new Function("
            + json.dumps(
                f"{code}\nreturn typeof {function_name} === 'function' ? {function_name} : null;"
            )
            + ")();\n"
            "if (typeof _fn !== 'function') throw new Error('Function not defined');\n"
            "process.stdout.write(JSON.stringify(_fn(..._args)));\n"
        ),
    },
    "python": {
        "language_id": LanguageAlias.PYTHON3,
        "wrap": lambda code, function_name: (
            f"{code}\n\n"
            "if __name__ == '__main__':\n"
            "    import json as _json, sys as _sys\n"
            "    _args = _json.loads(_sys.stdin.read() or '[]')\n"
            f"    _result = {function_name}(*_args)\n"
            "    _sys.stdout.write(_json.dumps(_result, separators=(',', ':')))\n"
        ),
    },
    "php": {
        "language_id": LanguageAlias.PHP,
        "wrap": lambda code, function_name: (
            "<?php\n"
            f"{code}\n"
            "$_args = json_decode(stream_get_contents(STDIN), true, 512, JSON_THROW_ON_ERROR);\n"
            f"$_result = {function_name}(...$_args);\n"
            "echo json_encode($_result, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);\n"
        ),
    },
    "ruby": {
        "language_id": LanguageAlias.RUBY,
        "wrap": lambda code, function_name: (
            "require 'json'\n"
            f"{code}\n"
            "_args = JSON.parse(STDIN.read)\n"
            f"_result = send(:{function_name}, *_args)\n"
            "STDOUT.write(JSON.generate(_result))\n"
        ),
    },
}

_STATIC_LANGUAGES = {
    "c": LanguageAlias.C,
    "cpp": LanguageAlias.CPP,
    "java": LanguageAlias.JAVA,
}
_STATIC_TYPES = {"int", "double", "bool", "string", "int[]", "int[][]"}
SUPPORTED_DYNAMIC_LANGUAGES = sorted(_HARNESSES)
SUPPORTED_LANGUAGES = sorted({*SUPPORTED_DYNAMIC_LANGUAGES, *_STATIC_LANGUAGES})
_LANGUAGE_ALIASES = {
    "js": "javascript", "py": "python", "py3": "python",
    "c++": "cpp", "cplusplus": "cpp", "cxx": "cpp",
}
_FUNCTION_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


def normalize_language(language: str) -> str:
    language = str(language or "").strip().lower()
    return _LANGUAGE_ALIASES.get(language, language)


def _json_values_equal(actual, expected):
    if isinstance(actual, bool) or isinstance(expected, bool):
        return type(actual) is type(expected) and actual == expected
    if isinstance(actual, (int, float)) and isinstance(expected, (int, float)):
        return actual == expected
    if isinstance(actual, dict) and isinstance(expected, dict):
        return actual.keys() == expected.keys() and all(
            _json_values_equal(actual[key], expected[key]) for key in actual
        )
    if isinstance(actual, list) and isinstance(expected, list):
        return len(actual) == len(expected) and all(
            _json_values_equal(left, right) for left, right in zip(actual, expected, strict=True)
        )
    return type(actual) is type(expected) and actual == expected


def _c_string_literal(value: str) -> str:
    escaped = []
    for byte in value.encode("utf-8"):
        if byte == 34:
            escaped.append(r'\"')
        elif byte == 92:
            escaped.append(r"\\")
        elif byte == 10:
            escaped.append(r"\n")
        elif byte == 13:
            escaped.append(r"\r")
        elif byte == 9:
            escaped.append(r"\t")
        elif 32 <= byte < 127:
            escaped.append(chr(byte))
        else:
            escaped.append(f"\\{byte:03o}")
    return '"' + "".join(escaped) + '"'


def _typed_literal(value, value_type: str, language: str) -> str:
    if value_type == "string":
        return _c_string_literal(value) if language == "c" else json.dumps(value, ensure_ascii=True)
    if value_type == "bool":
        if language == "java":
            return "true" if value else "false"
        return "true" if value else "false"
    if value_type == "int[][]":
        values = ", ".join(_typed_literal(item, "int[]", language) for item in value)
        if language == "cpp":
            return f"std::vector<std::vector<int>>{{{values}}}"
        if language == "java":
            return f"new int[][]{{{values}}}"
        raise ValueError("nested arrays are not supported for this language")
    if value_type == "int[]":
        values = ", ".join(_typed_literal(item, "int", language) for item in value)
        if language == "cpp":
            return f"std::vector<int>{{{values}}}"
        if language == "java":
            return f"new int[]{{{values}}}"
        raise ValueError("C array literals are declared separately")
    if value_type == "int":
        return str(int(value))
    if value_type == "double":
        return repr(float(value))
    raise ValueError(f"unsupported static-language type: {value_type}")


def _static_source(language, player_code, function_name, test, parameter_types, return_type):
    args = test.get("args", [])
    if len(args) != len(parameter_types):
        raise ValueError("test arguments do not match the declared function signature")
    if any(value_type not in _STATIC_TYPES for value_type in parameter_types):
        raise ValueError("parameter_types contains an unsupported static-language type")
    if return_type not in _STATIC_TYPES:
        raise ValueError("return_type is not a supported static-language type")
    if language == "c" and return_type.endswith("[]"):
        raise ValueError("C challenges cannot return arrays; use C++ or Java for array results")

    call_args = []
    declarations = []
    for index, (value, value_type) in enumerate(zip(args, parameter_types, strict=True)):
        name = f"_arg{index}"
        if language == "c" and value_type.endswith("[]"):
            if value_type != "int[]":
                raise ValueError("C currently supports int[] parameters only")
            values = ", ".join(str(int(item)) for item in value) or "0"
            declarations.append(
                f"int {name}_data[{max(1, len(value))}] = {{{values}}};"
            )
            call_args.extend((f"{name}_data", str(len(value))))
        else:
            literal = _typed_literal(value, value_type, language)
            if language == "c":
                c_type = {"int": "int", "double": "double", "bool": "bool", "string": "const char *"}[value_type]
                declarations.append(f"{c_type} {name} = {literal};")
            else:
                declarations.append(f"auto {name} = {literal};" if language == "cpp" else f"var {name} = {literal};")
            call_args.append(name)

    call = f"{function_name}({', '.join(call_args)})"
    if language == "c":
        prefix = "#include <stdbool.h>\n#include <stddef.h>\n#include <stdio.h>\n"
        c_return = {"int": "int", "double": "double", "bool": "bool", "string": "const char *"}[return_type]
        if return_type == "string":
            prefix += (
                "static void _print_json_string(const char *s) {\n"
                "  if (!s) { fputs(\"null\", stdout); return; }\n"
                "  putchar('\\\"');\n"
                "  for (const unsigned char *p = (const unsigned char *)s; *p; ++p) {\n"
                "    if (*p == '\\\"' || *p == '\\\\') { putchar('\\\\'); putchar(*p); }\n"
                "    else if (*p == '\\n') fputs(\"\\\\n\", stdout);\n"
                "    else if (*p == '\\r') fputs(\"\\\\r\", stdout);\n"
                "    else if (*p == '\\t') fputs(\"\\\\t\", stdout);\n"
                "    else putchar(*p);\n"
                "  }\n"
                "  putchar('\\\"');\n"
                "}\n"
            )
        printer = {
            "int": 'printf("%d", _result);',
            "double": 'printf("%.17g", _result);',
            "bool": 'fputs(_result ? "true" : "false", stdout);',
            "string": "_print_json_string(_result);",
        }[return_type]
        body = "\n".join(declarations)
        return f"{prefix}\n{player_code}\nint main(void) {{\n{body}\n  {c_return} _result = {call};\n  {printer}\n  return 0;\n}}\n"

    if language == "cpp":
        prefix = r'''#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <type_traits>
#include <vector>
using namespace std;
static string _quote(const string& s) {
    string o = "\"";
    for (unsigned char c : s) {
        if (c == '"' || c == '\\') { o += '\\'; o += c; }
        else if (c == '\n') o += "\\n";
        else if (c == '\r') o += "\\r";
        else if (c == '\t') o += "\\t";
        else o += c;
    }
    return o + "\"";
}
static string _json(bool v) { return v ? "true" : "false"; }
static string _json(const string& v) { return _quote(v); }
static string _json(const char* v) { return _quote(v ? string(v) : string()); }
template<class T, enable_if_t<is_arithmetic_v<T> && !is_same_v<T, bool>, int> = 0>
static string _json(T v) { ostringstream s; s << setprecision(17) << v; return s.str(); }
template<class T> static string _json(const vector<T>& v) {
    string s = "[";
    for (size_t i = 0; i < v.size(); ++i) { if (i) s += ","; s += _json(v[i]); }
    return s + "]";
}
'''
        body = "\n".join(declarations)
        return f"{prefix}\n{player_code}\nint main() {{\n{body}\n  auto _result = {call};\n  cout << _json(_result);\n}}\n"

    java_types = {"int": "int", "double": "double", "bool": "boolean", "string": "String", "int[]": "int[]", "int[][]": "int[][]"}
    java_args = []
    for value, value_type in zip(args, parameter_types, strict=True):
        literal = _typed_literal(value, value_type, language)
        java_args.append(literal)
    java_call = f"{function_name}({', '.join(java_args)})"
    helpers = r'''static String _json(String v) {
    StringBuilder s = new StringBuilder("\"");
    for (char c : v.toCharArray()) {
        if (c == '"' || c == '\\') { s.append('\\').append(c); }
        else if (c == '\n') s.append("\\n");
        else if (c == '\r') s.append("\\r");
        else if (c == '\t') s.append("\\t");
        else s.append(c);
    }
    return s.append('"').toString();
}
static String _json(boolean v) { return v ? "true" : "false"; }
static String _json(int v) { return Integer.toString(v); }
static String _json(double v) { return Double.toString(v); }
static String _json(int[] v) { StringJoiner j = new StringJoiner(",", "[", "]"); for (int x : v) j.add(_json(x)); return j.toString(); }
static String _json(int[][] v) { StringJoiner j = new StringJoiner(",", "[", "]"); for (int[] x : v) j.add(_json(x)); return j.toString(); }
'''
    body = "\n".join(declarations)
    return (
        "import java.util.*;\npublic class Main {\n"
        f"{player_code}\n{helpers}public static void main(String[] args) {{\n{body}\n"
        f"System.out.print(_json({java_call}));\n}}\n}}\n"
    )

_JSON_SEPARATORS = (",", ":")

# A real per-language, per-run cap, independent of whatever the Judge0
# instance's own operator-side defaults happen to be - defense in depth,
# not a substitute for those.
_CPU_TIME_LIMIT_S = 5
_WALL_TIME_LIMIT_S = 10
_MEMORY_LIMIT_KB = 128_000

_client_lock = threading.Lock()
_client: Client | None = None


def _get_client() -> Client:
    global _client
    if _client is not None:
        return _client
    with _client_lock:
        if _client is not None:
            return _client
        endpoint = os.environ.get("JUDGE0_CE_ENDPOINT")
        if not endpoint:
            raise Judge0Unavailable(
                "JUDGE0_CE_ENDPOINT isn't set - server-side execution for "
                "coding tasks requires a running Judge0 "
                "instance. Set JUDGE0_CE_ENDPOINT to its base URL (and "
                "JUDGE0_CE_AUTH_HEADERS to a JSON object of auth headers, "
                "if it needs any) and restart the server."
            )
        headers_raw = os.environ.get("JUDGE0_CE_AUTH_HEADERS")
        headers = {}
        if headers_raw:
            try:
                headers = json.loads(headers_raw)
            except ValueError as exc:
                raise Judge0Unavailable(
                    "JUDGE0_CE_AUTH_HEADERS is set but isn't valid JSON."
                ) from exc
        try:
            client = Client(endpoint=endpoint, headers=headers)
        except Exception as exc:  # Client() fetches API metadata immediately.
            cause = exc.__cause__ or exc
            raise Judge0Unavailable(
                f"Couldn't initialize Judge0 at {endpoint}: "
                f"{type(cause).__name__}: {cause}"
            ) from exc
        _client = client
        return _client


def run_coding_task(
    *, language: str, player_code: str, function_name: str, tests: list[dict],
    parameter_types: list[str] | None = None, return_type: str | None = None,
) -> list[dict]:
    """Run every test case for one submission and report pass/fail per test.

    Returns a list, same order and length as `tests`, of:
      {"passed": bool, "expected": <value>, "actual": <value or None>,
       "status": "Accepted" | "Wrong Answer" | "Compilation Error" | ...,
       "stderr": str | None, "compile_output": str | None}
    `actual`/`stderr`/`compile_output` are omitted/None where Judge0
    didn't produce them (e.g. a clean Accepted has no stderr).

    Raises Judge0Unavailable if Judge0 isn't configured/reachable, and
    UnsupportedLanguage if there's no harness for `language`.
    """
    language = normalize_language(language)
    harness = _HARNESSES.get(language)
    static_language_id = _STATIC_LANGUAGES.get(language)
    if harness is None and static_language_id is None:
        raise UnsupportedLanguage(
            f"'{language}' isn't supported for server-side execution. "
            f"Supported: {', '.join(SUPPORTED_LANGUAGES)}."
        )
    if not _FUNCTION_NAME_RE.fullmatch(function_name):
        raise ValueError("function_name must be a valid identifier")
    if static_language_id is not None:
        if not isinstance(parameter_types, list) or not isinstance(return_type, str):
            raise ValueError("static-language tasks need parameter_types and return_type")
        submissions_to_run = [
            Submission(
                source_code=_static_source(
                    language, player_code, function_name, test, parameter_types, return_type
                ),
                language=static_language_id,
                stdin="",
                expected_output=json.dumps(test.get("expect"), separators=_JSON_SEPARATORS),
                cpu_time_limit=_CPU_TIME_LIMIT_S,
                wall_time_limit=_WALL_TIME_LIMIT_S,
                memory_limit=_MEMORY_LIMIT_KB,
                enable_network=False,
            )
            for test in tests
        ]
    else:
        source = harness["wrap"](player_code, function_name)
        test_cases = [
            {
                "input": json.dumps(test.get("args", []), separators=_JSON_SEPARATORS),
                "expected_output": json.dumps(
                    test.get("expect"), separators=_JSON_SEPARATORS
                ),
            }
            for test in tests
        ]
    client = _get_client()

    try:
        if static_language_id is not None:
            submissions = sync_execute(client=client, submissions=submissions_to_run)
        else:
            submissions = sync_execute(
                client=client,
                source_code=source,
                language=harness["language_id"],
                test_cases=test_cases,
                cpu_time_limit=_CPU_TIME_LIMIT_S,
                wall_time_limit=_WALL_TIME_LIMIT_S,
                memory_limit=_MEMORY_LIMIT_KB,
                enable_network=False,
            )
    except Exception as exc:
        raise Judge0Unavailable(f"Judge0 request failed: {exc}") from exc

    if isinstance(submissions, Submission):
        submissions = [submissions]
    if len(submissions) != len(tests):
        raise Judge0Unavailable(
            f"Judge0 returned {len(submissions)} results for {len(tests)} tests."
        )

    results = []
    for test, submission in zip(tests, submissions, strict=True):
        status = submission.status
        stdout = (submission.stdout or "").strip()
        actual = None
        if stdout:
            try:
                actual = json.loads(stdout)
            except ValueError:
                actual = None
        executed = status in (Status.ACCEPTED, Status.WRONG_ANSWER)
        passed = executed and _json_values_equal(actual, test.get("expect"))
        results.append(
            {
                "passed": passed,
                "expected": test.get("expect"),
                "actual": actual,
                "status": str(status) if status is not None else "Unknown",
                "stderr": (submission.stderr or "").strip() or None,
                "compile_output": (submission.compile_output or "").strip() or None,
            }
        )
    return results
