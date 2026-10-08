# Running player code (Code Challenge Editor)

When a player presses **Run** in a coding challenge, the server executes their
code against the challenge's tests. As of v1.3.1 this happens **on your own
machine, offline** by default. No internet connection and no Judge0 are needed.

```text
CODE_RUNNER=local    (default)  run here, with the interpreters/compilers you have installed
CODE_RUNNER=judge0              send the code to a Judge0 server instead
```

Set these in `server/.env` (see `server/.env.example`).

## What you need installed

The local runner uses what's already on the server. Players only see the
languages that are actually available, and the challenge editor says so if none
of a challenge's languages can run. **Admin -> Addons & Themes -> Code Challenge
Editor -> gear icon** shows the live status: backend, isolation level and which
languages were found. The same summary is printed when the server starts.

| Language | Needs | Notes |
| --- | --- | --- |
| Python | nothing | Uses the Python the server itself runs on. |
| JavaScript | `node` | Any recent Node.js. |
| PHP | `php` (CLI) | |
| Ruby | `ruby` | |
| C | `gcc` (or `cc`, `clang`) | |
| C++ | `g++` (or `c++`, `clang++`) | C++17. |
| Java | JDK (`javac` **and** `java`) | A JRE alone is not enough. |

Tools not on `PATH` can be pointed at explicitly:
`OPENCTF_NODE`, `OPENCTF_PYTHON`, `OPENCTF_PHP`, `OPENCTF_RUBY`, `OPENCTF_CC`,
`OPENCTF_CXX`, `OPENCTF_JAVAC`, `OPENCTF_JAVA`.

Typical installs: Debian/Ubuntu `apt install nodejs php-cli ruby gcc g++ default-jdk-headless`;
Windows: install the languages you want and make sure they are on `PATH`
(MinGW-w64 provides `gcc`/`g++`).

## Limits applied to every run

* A private temporary directory per run, deleted afterwards.
* The server's environment variables are **not** passed on (your `SECRET_KEY`,
  `FLAG_PEPPER`, `ADMIN_PASSWORD`... never reach player code).
* 10 s wall-clock and 5 s CPU time per test (30 s to compile), the whole process
  tree is killed on timeout.
* Output is capped, so `while True: print(...)` can't fill memory or disk.
* On Linux and other POSIX systems: file-size, open-file and (Python/PHP/Ruby/C/C++) memory limits.
  Node and Java get heap limits (`--max-old-space-size`, `-Xmx`) instead.
* At most 2 runs at once (`CODE_RUNNER_MAX_CONCURRENT`); others wait up to 30 s.
* Players are limited to 15 runs per 5 minutes.

## Isolation - read this before a real competition

Running other people's code on your machine is only as safe as the walls around
it. The runner uses the strongest it can find, and tells you which:

| `sandbox` | What it is | Can player code read your server's files? | Can it reach the network? |
| --- | --- | --- | --- |
| `bwrap` | [bubblewrap](https://github.com/containers/bubblewrap): a minimal read-only filesystem containing only system libraries, own PID namespace | **No** | **No** |
| `netns` | `unshare` network namespace only | **Yes** | No |
| `none` | limits and a scrubbed environment only | **Yes** | **Yes** |

This table is not theoretical; it is what the test suite measures. With
`sandbox: none`, a player can submit code that reads `server/.env` or
`instance/ctf.db` (which stores every flag) and returns the contents, and can open
network connections. Players in a CTF are exactly the people likely to try.

**Recommendations**

* Trusted classroom or lab (everyone is a student you know): `none` is fine.
* A competition with people you don't know: use **Linux with bubblewrap**
  (`apt install bubblewrap`) and set `CODE_RUNNER_REQUIRE_SANDBOX=1`, so the
  server refuses to run code at all if the strong sandbox disappears.
* Windows has no equivalent of bubblewrap, so it always runs as `none`. For an
  untrusted audience, run the server on Linux (or WSL2), or use Judge0.
* Inside Docker, bubblewrap normally can't start (Docker's default seccomp profile
  blocks user namespaces), so a stock container reports `none`.

Related settings:

```text
CODE_RUNNER_SANDBOX=auto      auto | bwrap | netns | none
CODE_RUNNER_REQUIRE_SANDBOX=1 refuse to run unless the strong (bwrap) sandbox is active
CODE_RUNNER_EXTRA_RO_BINDS=/opt/node,/opt/jdk   extra directories to expose read-only
                                                 inside bwrap (for tools installed outside /usr)
```

## Using Judge0 instead

[Judge0](https://github.com/judge0/judge0) is a dedicated code-execution service
with its own sandbox. It is the better choice for hostile audiences. Hosted on your
own LAN it needs no internet either.

```text
pip install -r requirements-judge0.txt
CODE_RUNNER=judge0
JUDGE0_CE_ENDPOINT=http://your-judge0-host:2358
JUDGE0_CE_AUTH_HEADERS={"X-Auth-Token": "..."}      # optional
```

`CODE_RUNNER` must be `judge0` to use it: a stray `JUDGE0_CE_ENDPOINT` alone is
ignored (and a warning is printed), so a leftover setting can never silently send
player code to the internet. The public `https://ce.judge0.com` is for
development only; it receives everything players submit.

## Docker

The image contains Python only. To add languages at build time:

```bash
docker compose build --build-arg CODE_RUNTIMES="nodejs php-cli ruby gcc g++ default-jdk-headless"
```

(or set `CODE_RUNTIMES` in `.env`). Because player code then runs inside the API
container, next to your secrets and database, prefer Judge0 for untrusted players.
The container runs gunicorn with several threads (one process), so a slow compile
doesn't freeze other players.

## Verifying your setup

```bash
cd server
python -m unittest tests.test_code_runner -v        # all installed languages, limits, isolation
python -m unittest tests.test_seed_challenges -v    # every bundled coding challenge is solvable
python -m unittest tests.test_judge0_backend -v     # the optional Judge0 path (stubbed)
```

Languages that aren't installed are skipped, not failed, and the isolation tests
only run when `bwrap` is available.

## How a run works (for the curious)

The platform wraps the player's function with a tiny driver that reads one test's
arguments as JSON from stdin, calls the function, and prints the result as JSON
after a marker line. Everything the player's own code prints appears before the
marker and is shown in the **Console output** panel. C, C++ and Java compile once
per run and execute each test as a separate process.
