"""Language-agnostic pieces of the Code Challenge runner.

Everything here is pure (no I/O, no network, no subprocesses), so it is shared
by both execution backends - `local_runner.py` (offline, default) and
`judge0_runner.py` (optional Judge0 server) - and is easy to unit test.

A harness wraps the player's own source with a tiny driver that reads one
test's arguments as a JSON array from stdin, calls `function_name` with them
as positional arguments and prints the return value as compact JSON.

The JSON result is printed after a marker (`RESULT_MARK`) rather than being
the whole of stdout. That means a player's own `print()` / `console.log()` /
`echo` debugging output can't corrupt the result - it simply becomes the
"console output" shown next to the test. The runner parses the *last* marker.
"""

from __future__ import annotations

import json
import re

RESULT_MARK = "@@OCTF-RESULT@@"

_JSON_SEPARATORS = (",", ":")

DYNAMIC_LANGUAGES = ("javascript", "python", "php", "ruby")
STATIC_LANGUAGES = ("c", "cpp", "java")
SUPPORTED_DYNAMIC_LANGUAGES = sorted(DYNAMIC_LANGUAGES)
SUPPORTED_LANGUAGES = sorted({*DYNAMIC_LANGUAGES, *STATIC_LANGUAGES})

STATIC_TYPES = {"int", "double", "bool", "string", "int[]", "int[][]"}

_LANGUAGE_ALIASES = {
    "js": "javascript", "py": "python", "py3": "python",
    "c++": "cpp", "cplusplus": "cpp", "cxx": "cpp",
}
_FUNCTION_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


class UnsupportedLanguage(Exception):
    """No harness registered for this language."""


def normalize_language(language) -> str:
    language = str(language or "").strip().lower()
    return _LANGUAGE_ALIASES.get(language, language)


def validate_function_name(function_name) -> None:
    if not isinstance(function_name, str) or not _FUNCTION_NAME_RE.fullmatch(function_name):
        raise ValueError("function_name must be a valid identifier")


# --- Dynamic-language harnesses ---------------------------------------------

def _wrap_javascript(code: str, function_name: str) -> str:
    body = json.dumps(f"{code}\nreturn typeof {function_name} === 'function' ? {function_name} : null;")
    return (
        "const _fs = require('fs');\n"
        "const _args = JSON.parse(_fs.readFileSync(0, 'utf8') || '[]');\n"
        f"const _fn = new Function({body})();\n"
        "if (typeof _fn !== 'function') throw new Error('Function not defined');\n"
        f"process.stdout.write('\\n{RESULT_MARK}' + JSON.stringify(_fn(..._args)));\n"
    )


def _wrap_python(code: str, function_name: str) -> str:
    return (
        f"{code}\n\n"
        "if __name__ == '__main__':\n"
        "    import json as _json, sys as _sys\n"
        "    _args = _json.loads(_sys.stdin.read() or '[]')\n"
        f"    _result = {function_name}(*_args)\n"
        f"    _sys.stdout.write('\\n{RESULT_MARK}' + _json.dumps(_result, separators=(',', ':')))\n"
    )


def _wrap_php(code: str, function_name: str) -> str:
    return (
        "<?php\n"
        f"{code}\n"
        "$_args = json_decode(stream_get_contents(STDIN), true, 512, JSON_THROW_ON_ERROR);\n"
        f"$_result = {function_name}(...$_args);\n"
        f"echo \"\\n{RESULT_MARK}\" . json_encode($_result, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);\n"
    )


def _wrap_ruby(code: str, function_name: str) -> str:
    return (
        "require 'json'\n"
        f"{code}\n"
        "_args = JSON.parse(STDIN.read)\n"
        f"_result = send(:{function_name}, *_args)\n"
        f"STDOUT.write(\"\\n{RESULT_MARK}\" + JSON.generate(_result))\n"
    )


_WRAPPERS = {
    "javascript": _wrap_javascript,
    "python": _wrap_python,
    "php": _wrap_php,
    "ruby": _wrap_ruby,
}

# File extension used for the generated source file (local backend).
SOURCE_FILENAMES = {
    "javascript": "main.js", "python": "main.py", "php": "main.php", "ruby": "main.rb",
    "c": "main.c", "cpp": "main.cpp", "java": "Main.java",
}


def dynamic_source(language: str, player_code: str, function_name: str) -> str:
    return _WRAPPERS[language](player_code, function_name)


# --- Static-language (C / C++ / Java) harness --------------------------------

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


_C_TYPES = {"int": "int", "double": "double", "bool": "bool", "string": "const char *"}
_JAVA_TYPES = {"int": "int", "double": "double", "bool": "boolean", "string": "String",
               "int[]": "int[]", "int[][]": "int[][]"}

_C_PREFIX = (
    "#include <stdbool.h>\n#include <stddef.h>\n#include <stdio.h>\n#include <stdlib.h>\n"
)
_C_JSON_STRING = (
    "static void _print_json_string(const char *s) {\n"
    "  if (!s) { fputs(\"null\", stdout); return; }\n"
    "  putchar('\"');\n"
    "  for (const unsigned char *p = (const unsigned char *)s; *p; ++p) {\n"
    "    if (*p == '\"' || *p == '\\\\') { putchar('\\\\'); putchar(*p); }\n"
    "    else if (*p == '\\n') fputs(\"\\\\n\", stdout);\n"
    "    else if (*p == '\\r') fputs(\"\\\\r\", stdout);\n"
    "    else if (*p == '\\t') fputs(\"\\\\t\", stdout);\n"
    "    else putchar(*p);\n"
    "  }\n"
    "  putchar('\"');\n"
    "}\n"
)
_CPP_PREFIX = r'''#include <cstdlib>
#include <iomanip>
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
_JAVA_HELPERS = r'''static String _json(String v) {
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


def validate_signature(language, parameter_types, return_type) -> None:
    if not isinstance(parameter_types, list) or not isinstance(return_type, str):
        raise ValueError("static-language tasks need parameter_types and return_type")
    if any(t not in STATIC_TYPES for t in parameter_types):
        raise ValueError("parameter_types contains an unsupported static-language type")
    if return_type not in STATIC_TYPES:
        raise ValueError("return_type is not a supported static-language type")
    if language == "c":
        if return_type.endswith("[]"):
            raise ValueError("C challenges cannot return arrays; use C++ or Java for array results")
        if any(t.endswith("[]") and t != "int[]" for t in parameter_types):
            raise ValueError("C currently supports int[] parameters only")


def static_source(language, player_code, function_name, tests, parameter_types, return_type) -> str:
    """One program that can run any of `tests`, chosen by its first command-line
    argument (the test's index; defaults to 0). This lets the local backend
    compile once and run N times instead of compiling per test."""
    validate_signature(language, parameter_types, return_type)
    cases = []
    for index, test in enumerate(tests):
        args = test.get("args", [])
        if len(args) != len(parameter_types):
            raise ValueError("test arguments do not match the declared function signature")
        cases.append(_case_block(language, index, function_name, args, parameter_types, return_type))
    body = "\n".join(cases)

    if language == "c":
        string_helper = _C_JSON_STRING if return_type == "string" else ""
        return (
            f"{_C_PREFIX}{string_helper}\n{player_code}\n"
            "int main(int argc, char **argv) {\n"
            "  int _idx = argc > 1 ? atoi(argv[1]) : 0;\n"
            f"  switch (_idx) {{\n{body}\n  }}\n  return 0;\n}}\n"
        )
    if language == "cpp":
        return (
            f"{_CPP_PREFIX}\n{player_code}\n"
            "int main(int argc, char **argv) {\n"
            "  int _idx = argc > 1 ? atoi(argv[1]) : 0;\n"
            f"  switch (_idx) {{\n{body}\n  }}\n  return 0;\n}}\n"
        )
    return (
        "import java.util.*;\npublic class Main {\n"
        f"{player_code}\n{_JAVA_HELPERS}"
        "public static void main(String[] args) {\n"
        "  int _idx = args.length > 0 ? Integer.parseInt(args[0]) : 0;\n"
        f"  switch (_idx) {{\n{body}\n  }}\n}}\n}}\n"
    )


def _case_block(language, index, function_name, args, parameter_types, return_type) -> str:
    mark = f"\\n{RESULT_MARK}"
    if language == "java":
        literals = ", ".join(
            _typed_literal(v, t, "java") for v, t in zip(args, parameter_types, strict=True)
        )
        return (
            f"  case {index}: {{ System.out.print(\"{mark}\" + _json({function_name}({literals}))); break; }}"
        )

    declarations, call_args = [], []
    for i, (value, value_type) in enumerate(zip(args, parameter_types, strict=True)):
        name = f"_arg{i}"
        if language == "c" and value_type == "int[]":
            values = ", ".join(str(int(item)) for item in value) or "0"
            declarations.append(f"int {name}_data[{max(1, len(value))}] = {{{values}}};")
            call_args.extend((f"{name}_data", str(len(value))))
        else:
            literal = _typed_literal(value, value_type, language)
            if language == "c":
                declarations.append(f"{_C_TYPES[value_type]} {name} = {literal};")
            else:
                declarations.append(f"auto {name} = {literal};")
            call_args.append(name)
    call = f"{function_name}({', '.join(call_args)})"
    decl = "\n    ".join(declarations)
    if language == "c":
        printer = {
            "int": 'printf("%d", _result);',
            "double": 'printf("%.17g", _result);',
            "bool": 'fputs(_result ? "true" : "false", stdout);',
            "string": "_print_json_string(_result);",
        }[return_type]
        return (
            f"  case {index}: {{\n    {decl}\n    {_C_TYPES[return_type]} _result = {call};\n"
            f"    fputs(\"{mark}\", stdout);\n    {printer}\n    break;\n  }}"
        )
    return (
        f"  case {index}: {{\n    {decl}\n    auto _result = {call};\n"
        f"    cout << \"{mark}\" << _json(_result);\n    break;\n  }}"
    )


# --- Result parsing / comparison ---------------------------------------------

def split_output(stdout: str):
    """Split raw stdout into (console_text, found, value).

    `found` is False when the harness never printed its marker (the program
    exited early, crashed, or the output wasn't valid JSON after the marker).
    """
    stdout = stdout or ""
    index = stdout.rfind(RESULT_MARK)
    if index < 0:
        return stdout.strip("\n"), False, None
    console = stdout[:index]
    if console.endswith("\n"):
        console = console[:-1]
    raw = stdout[index + len(RESULT_MARK):].strip()
    try:
        return console, True, json.loads(raw)
    except ValueError:
        return console, False, None


def json_values_equal(actual, expected) -> bool:
    if isinstance(actual, bool) or isinstance(expected, bool):
        return type(actual) is type(expected) and actual == expected
    if isinstance(actual, (int, float)) and isinstance(expected, (int, float)):
        return actual == expected
    if isinstance(actual, dict) and isinstance(expected, dict):
        return actual.keys() == expected.keys() and all(
            json_values_equal(actual[key], expected[key]) for key in actual
        )
    if isinstance(actual, list) and isinstance(expected, list):
        return len(actual) == len(expected) and all(
            json_values_equal(left, right) for left, right in zip(actual, expected, strict=True)
        )
    return type(actual) is type(expected) and actual == expected


def stdin_for(test: dict) -> str:
    return json.dumps(test.get("args", []), separators=_JSON_SEPARATORS)
