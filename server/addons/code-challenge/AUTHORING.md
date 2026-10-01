# Authoring a coding challenge

This addon needs **no backend or database changes** - it works entirely off
the free-text **Description** field every ordinary (`type: "standard"`)
challenge already has, the same field you fill in from **Admin -> New
Challenge** today. Nothing about the challenge type changes; you're just
putting a specially-marked block inside the description.

## The `[[coding-task]]` block

Paste this into a challenge's Description, anywhere - text before and after
it is shown to the player as normal, the block itself is detected, parsed,
and then stripped back out before the description is displayed, so players
never see the raw JSON:

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
    { "args": [""], "expect": "" }
  ],
  "flag": "OCTF{r3v3rs3_th3_str1ng}"
}
[[/coding-task]]
```

| Field | Required | Notes |
| --- | --- | --- |
| `function_name` | yes | The exact name the player's code must define. |
| `starter_code` | yes | Pre-filled into the editor. Should at least declare the function so the editor isn't blank. |
| `tests` | yes | Array of `{ "args": [...], "expect": ... }`. `args` is spread as positional arguments into a call to `function_name`; `expect` is compared against the return value with a structural (`JSON.stringify`) comparison, so arrays/objects/numbers/strings/booleans all work, but key **order** in an expected object must match what your reference solution actually produces. |
| `flag` | yes | Kept server-side and returned only after every test passes; it is not included in the challenge listing or task metadata. |
| `instructions` | no | Short extra guidance shown above the editor. Falls back to nothing. |
| `language` | no | Initial runnable language. Defaults to `"javascript"`. |
| `languages` | no | Runnable languages offered in the editor dropdown. Defaults to the runtimes supported by the task signature. |
| `parameter_names` | for C/C++/Java | Argument names used in generated starter signatures, in the same order as test `args`. |
| `parameter_types` | for C/C++/Java | Typed signature values such as `int`, `double`, `bool`, `string`, `int[]`, and `int[][]`. |
| `return_type` | for C/C++/Java | The result type, using the same type names as `parameter_types`. |

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

The selected runnable language controls both syntax highlighting and the
Judge0 runtime. Supported backends are JavaScript, Python, PHP, Ruby, C,
C++, and Java. C, C++, and Java require explicit typed signatures; their
function stubs are generated from `parameter_names`, `parameter_types`,
and `return_type`.

The actual colors (and the editor's background/border/gutter/caret) are
themeable - see the `--cc-*` custom properties documented at the top of
`style.css`'s token-color rules and in the "Themes" section of
`docs/ADDON_DEVELOPMENT.md`. Nothing to do here as a challenge author;
this is for anyone writing a `server/themes/<id>/theme.css`.

## How it runs

Every language executes on the server through Judge0, which runs the
submission in its isolated sandbox and executes every test case. The
server requires `JUDGE0_CE_ENDPOINT` and, when needed,
`JUDGE0_CE_AUTH_HEADERS`; see `.env.example`. The Judge0 runner enforces
CPU, wall-time, and memory limits for each test.

## Runnable languages

Set `languages` to restrict the runtime dropdown. For typed runtimes,
declare the function signature; arrays map to C pointer/length pairs,
`std::vector` in C++, and native arrays in Java:

```json
{
  "languages": ["javascript", "python", "php", "ruby", "c", "cpp", "java"],
  "parameter_names": ["nums"],
  "parameter_types": ["int[]"],
  "return_type": "int",
  "starter_code_by_language": {
    "python": "def sumArray(nums):\n    pass\n",
    "php": "function sumArray($nums) {\n    // implement the sum\n}\n",
    "ruby": "def sumArray(nums)\n  # implement the sum\nend\n"
  }
}
```

`languages` may contain any subset of the supported runtimes. C supports
primitive results and `int[]` inputs; C++ and Java also support `int[][]`
results. `starter_code_by_language` lets each dynamic language start with
custom code; typed-language function stubs are generated from the signature.
Runs go to
`POST /api/challenges/<id>/code-run` and are rejected unless the language
is enabled for that task. A missing or unreachable Judge0 instance returns
a clear error. Runs are networked and do not produce local console output.

## Where the flag actually lives

The coding-task block is removed from the ordinary challenge listing.
Task metadata is fetched separately without the flag, and the Judge0 run
endpoint returns the flag only when every test passes. Keep starter code as
a stub; do not put a working solution in `starter_code`.

## Matching a challenge to its open modal

The addon matches the open modal to its challenge record, then loads task
metadata from the authenticated coding-task endpoint using the challenge ID.
