# Authoring a coding challenge

There are two ways to make one. **Use the builder** unless you're scripting
challenges in bulk.

## 1. The builder (recommended)

**Admin -> Challenges -> New challenge**, then pick **Code challenge** as the
Type (or choose the *Code challenge (function + tests)* template to start from a
working example). The form asks for:

| Field | What it does |
| --- | --- |
| Function name | The name players' code must define. |
| Signature | A name and type for each parameter, and the return type. Give every one a type to allow C, C++ and Java; choose **any** if the function takes objects or mixed values (then only JavaScript, Python, PHP and Ruby are offered). |
| Languages players can use | Which languages appear in the editor. C/C++/Java are greyed out until the signature is fully typed. |
| Instructions | Shown above the editor. |
| Starter code | Optional. Left empty, each language gets a stub generated from the signature (so the editor is never blank and the parameter names match your tests). |
| Tests | One row per test: the arguments as comma-separated JSON values (`[1, 2, 3]`, or `"abc", 5` for two parameters) and the expected result as JSON. Tick **Hidden** to show players only pass/fail for that test. |

The usual Flag, Points, Difficulty and Hint fields work exactly as for any other
challenge, and **the flag players receive is always the challenge's own flag**:
changing it later in the Flag field is enough, there's nothing else to keep in sync.

**Check your tests before publishing.** Open *Check your tests with a reference
solution*, paste a working solution, and press *Run check*. It runs your
(unsaved) tests against it and shows every result, including hidden tests. A
failing test almost always means a wrong expected value. Nothing is saved by the check.

**Hidden tests.** Players see the visible tests' arguments and expected values,
so a determined player can hard-code those answers. Add a couple of hidden
tests (the template includes one) and a solution that special-cases the visible
examples will still fail. For hidden tests players never see the arguments,
expected value, actual value or program output, only pass/fail.

Challenges still using the older `[[coding-task]]` block (below) open in the
same builder; saving converts them to the new storage and removes the block
from the description.

## 2. The `[[coding-task]]` block (older format, still supported)

This addon works off the free-text **Description** field of an ordinary
challenge. Paste this into a challenge's Description, anywhere - text before
and after it is shown to the player as normal, the block itself is detected,
parsed, and then stripped back out before the description is displayed, so
players never see the raw JSON. Challenges created in the builder store the
exact same JSON in the `code_config` column instead (the format below is the
same, minus `flag`, which isn't needed there):

```
Implement a function that reverses a string, without using .reverse().

[[coding-task]]
{
  "function_name": "reverseString",
  "starter_code": "function reverseString(s) {\n  // your code here\n}\n",
  "instructions": "Return the reversed string. No built-in .reverse().",
  "tests": [
    { "args": ["hello"], "expect": "olleh" },
    { "args": ["OpenCTF"], "expect": "FTCnepO" },
    { "args": [""], "expect": "" },
    { "args": ["abc"], "expect": "cba", "hidden": true }
  ],
  "flag": "OCTF{r3v3rs3_th3_str1ng}"
}
[[/coding-task]]
```

| Field | Required | Notes |
| --- | --- | --- |
| `function_name` | yes | The exact name the player's code must define. |
| `tests` | yes | Array of `{ "args": [...], "expect": ..., "hidden": false }`. `args` is spread as positional arguments into a call to `function_name`; `expect` is compared with the return value structurally (objects compare regardless of key order, `true` is not equal to `1`). Every test needs the same number of arguments. |
| `flag` | block format only | Kept server-side and returned only after every test passes. For builder challenges the challenge's own flag is used. |
| `starter_code` | no | Pre-filled into the editor for the default `language`. If omitted a stub is generated per language from the signature. |
| `instructions` | no | Short extra guidance shown above the editor. |
| `language` | no | Initial runnable language. Defaults to the first of `languages`. |
| `languages` | no | Runnable languages offered in the dropdown. Defaults to the runtimes supported by the task signature. |
| `parameter_names` | no | Argument names used in generated starter code, in the same order as the test `args`. |
| `parameter_types` | for C/C++/Java | Types: `int`, `double`, `bool`, `string`, `int[]`, `int[][]`. |
| `return_type` | for C/C++/Java | The result type, using the same names. |
| `starter_code_by_language` | no | Custom starter code per language. |

## Syntax highlighting

The editor colors comments, strings, numbers, keywords, and called
function names as the player types, via a small built-in tokenizer (no
external library, same "no network calls" rule as the rest of this
addon). `language` accepts:

`javascript` (default), `typescript`, `python`, `java`, `c`, `cpp`,
`csharp`, `go`, `rust`, `ruby`, `php`, `bash`, `sql`, `json`, `html`,
`css`, plus common aliases (`js`, `ts`, `py`, `c++`, `c#`, `sh`, ...).
Anything else (or `plaintext`) falls back to plain, uncolored text rather
than erroring.

The selected runnable language controls both syntax highlighting and which
test harness runs the code. The runnable languages are JavaScript, Python,
PHP, Ruby, C, C++ and Java. C, C++ and Java require an explicit typed
signature (`parameter_types` and `return_type`).

The actual colors (and the editor's background/border/gutter/caret) are
themeable - see the `--cc-*` custom properties documented at the top of
`style.css`'s token-color rules and in the "Themes" section of
`docs/ADDON_DEVELOPMENT.md`. Nothing to do here as a challenge author;
this is for anyone writing a `server/themes/<id>/theme.css`.

## How it runs

By default every language runs **on the platform's own machine, offline**:
no internet, no Judge0. The server uses the interpreters/compilers installed on
it (JavaScript needs Node, Python is always available, PHP/Ruby need `php`/`ruby`,
C/C++ need `gcc`/`g++`, Java needs the JDK `javac`). The editor only offers
languages the server can actually run, and says so if none of a challenge's
languages is installed. Each run has CPU, wall-clock, memory and output limits,
and on Linux with `bubblewrap` installed it also runs in a sandbox with no
network and no access to the server's files.

**Read `docs/CODE_RUNNER.md` before running a real competition** - it explains the
isolation levels, how to install the runtimes, and the self-hosted Judge0 option
(`CODE_RUNNER=judge0`).

Anything the player's code prints (`print`, `console.log`, `echo`, `printf`...)
shows up in the editor's **Console output** panel; it no longer corrupts the result.

## Runnable languages

For typed runtimes (C, C++, Java), declare the function signature; arrays map
to C pointer/length pairs, `std::vector` in C++, and native arrays in Java:

```json
{
  "languages": ["javascript", "python", "php", "ruby", "c", "cpp", "java"],
  "parameter_names": ["nums"],
  "parameter_types": ["int[]"],
  "return_type": "int"
}
```

C supports primitive results and `int[]` parameters only; C++ and Java also
support `int[]` / `int[][]` results and `int[][]` parameters. A challenge that
returns objects or mixed values is JavaScript/Python/PHP/Ruby only. Runs go to
`POST /api/challenges/<id>/code-run` and are rejected unless the language is
enabled for that task.

## Where the flag actually lives

The task is removed from the ordinary challenge listing. Task metadata is
fetched separately without the flag (and with hidden tests reduced to
`{"hidden": true}`), and the run endpoint returns the flag only when every test
passes. Keep starter code as a stub; do not put a working solution in it.

## Matching a challenge to its open modal

The addon matches the open modal to its challenge record, then loads task
metadata from the authenticated coding-task endpoint using the challenge ID.
