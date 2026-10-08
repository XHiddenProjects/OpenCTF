"""Offline code execution for the Code Challenge Editor.

Runs player code with the interpreters/compilers already installed on this
machine - no internet, no Judge0. Nothing here ever talks to the network.

SECURITY MODEL - read this before running a real competition
------------------------------------------------------------
Executing player-submitted code on the server's own machine is only as safe as
the isolation around it. This module layers what the platform offers:

  always      scrubbed environment (the server's secrets are NOT inherited),
              a private temp directory per run, wall-clock timeout with
              process-tree kill, output size caps, a concurrency cap.
  POSIX       + CPU-time, file-size, open-file and (where it works) address
              space limits, applied via a tiny launcher shim.
  Linux       + bubblewrap ("bwrap") when installed: a read-only minimal
              filesystem that does NOT contain the server's files, no network,
              its own PID namespace. This is the level that actually stops a
              hostile player from reading .env / ctf.db. (`sandbox: bwrap`)
              Without bwrap, `unshare` can still cut off the network
              (`sandbox: netns`).
  otherwise   `sandbox: none` - fine for a trusted classroom, NOT for a hostile
              audience. Use bubblewrap, or point CODE_RUNNER=judge0 at a
              self-hosted Judge0 on your LAN (also offline).

Windows has no equivalent of these tools, so it runs with `sandbox: none` plus
the timeout / output limits.
"""

from __future__ import annotations

import glob
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time

try:
    import code_harness as harness
except ImportError:  # installed as the `openctf-server` package
    from . import code_harness as harness

IS_WINDOWS = os.name == "nt"

CPU_LIMIT_S = 5
WALL_LIMIT_S = 10
COMPILE_WALL_LIMIT_S = 30
FILE_SIZE_LIMIT_BYTES = 1_048_576          # per output file
NOFILE_LIMIT = 256
ADDRESS_SPACE_LIMIT_BYTES = 1_024 * 1024 * 1024
OUTPUT_READ_CAP = 262_144
STDERR_RETURN_CAP = 2_000
CONSOLE_RETURN_CAP = 4_000
COMPILE_OUTPUT_RETURN_CAP = 4_000

MAX_CONCURRENT = max(1, int(os.environ.get("CODE_RUNNER_MAX_CONCURRENT", "2") or 2))
QUEUE_WAIT_S = 30
_slots = threading.BoundedSemaphore(MAX_CONCURRENT)


class LocalRunnerError(Exception):
    """The local runner can't run this right now (missing toolchain, busy, ...)."""


# --- Toolchain discovery ------------------------------------------------------

def _which(env_name, *names):
    override = os.environ.get(env_name)
    if override:
        return shutil.which(override)
    for name in names:
        found = shutil.which(name)
        if found:
            return found
    return None


def _python_executable():
    override = os.environ.get("OPENCTF_PYTHON")
    if override:
        return shutil.which(override)
    exe = sys.executable
    # Resolve a venv's python symlink to the base interpreter: with -I/-S we
    # don't want the server's site-packages, and the base interpreter lives in
    # a system location that is easy to expose inside a sandbox.
    return exe if IS_WINDOWS or not exe else os.path.realpath(exe)


def toolchains() -> dict:
    """{language: {"available": bool, "tools": {role: path}, "missing": [...]}}"""
    spec = {
        "javascript": {"run": _which("OPENCTF_NODE", "node", "nodejs")},
        "python": {"run": _python_executable()},
        "php": {"run": _which("OPENCTF_PHP", "php")},
        "ruby": {"run": _which("OPENCTF_RUBY", "ruby")},
        "c": {"compile": _which("OPENCTF_CC", "gcc", "cc", "clang")},
        "cpp": {"compile": _which("OPENCTF_CXX", "g++", "c++", "clang++")},
        "java": {"compile": _which("OPENCTF_JAVAC", "javac"), "run": _which("OPENCTF_JAVA", "java")},
    }
    out = {}
    for language, tools in spec.items():
        missing = [role for role, path in tools.items() if not path]
        out[language] = {
            "available": not missing,
            "tools": {role: path for role, path in tools.items() if path},
            "missing": missing,
        }
    return out


def available_languages() -> list[str]:
    return sorted(lang for lang, info in toolchains().items() if info["available"])


# --- Sandbox detection ----------------------------------------------------------

_sandbox_lock = threading.Lock()
_sandbox_cache: dict | None = None


def _probe(cmd) -> bool:
    try:
        return subprocess.run(
            cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=10,
        ).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _detect_sandbox() -> dict:
    requested = (os.environ.get("CODE_RUNNER_SANDBOX") or "auto").strip().lower()
    if requested not in ("auto", "bwrap", "netns", "none"):
        requested = "auto"
    info = {"mode": "none", "requested": requested, "detail": "no OS-level isolation available"}
    if IS_WINDOWS or requested == "none":
        if requested == "none":
            info["detail"] = "disabled by CODE_RUNNER_SANDBOX=none"
        return info

    true_bin = shutil.which("true") or "/bin/true"
    bwrap = shutil.which("bwrap")
    if requested in ("auto", "bwrap") and bwrap:
        if _probe([bwrap, "--unshare-all", "--ro-bind", "/", "/", "--", true_bin]):
            return {"mode": "bwrap", "requested": requested, "bwrap": bwrap,
                    "detail": "bubblewrap: private filesystem, no network, own PID namespace"}
    unshare = shutil.which("unshare")
    if requested in ("auto", "netns") and unshare:
        if _probe([unshare, "--user", "--map-root-user", "--net", "--", true_bin]):
            return {"mode": "netns", "requested": requested, "unshare": unshare,
                    "detail": "network namespace only (files are NOT hidden from player code)"}
    if requested in ("bwrap", "netns"):
        info["detail"] = f"CODE_RUNNER_SANDBOX={requested} requested but unavailable on this host"
    return info


def sandbox_info() -> dict:
    global _sandbox_cache
    with _sandbox_lock:
        if _sandbox_cache is None:
            _sandbox_cache = _detect_sandbox()
        return dict(_sandbox_cache)


def reset_sandbox_cache() -> None:
    global _sandbox_cache
    with _sandbox_lock:
        _sandbox_cache = None


def require_sandbox() -> bool:
    return (os.environ.get("CODE_RUNNER_REQUIRE_SANDBOX") or "").strip().lower() in ("1", "true", "yes")


# --- Process launching ----------------------------------------------------------

# Applies rlimits then replaces itself with the real command. Used instead of
# subprocess's preexec_fn, which is documented as unsafe with threads.
_SHIM = (
    "import os, sys, json, resource\n"
    "lim = json.loads(sys.argv[1])\n"
    "def setl(r, soft, hard=None):\n"
    "    try: resource.setrlimit(r, (soft, soft if hard is None else hard))\n"
    "    except (ValueError, OSError): pass\n"
    "setl(resource.RLIMIT_CORE, 0)\n"
    "if 'cpu' in lim: setl(resource.RLIMIT_CPU, lim['cpu'], lim['cpu'] + 1)\n"
    "if 'fsize' in lim: setl(resource.RLIMIT_FSIZE, lim['fsize'])\n"
    "if 'nofile' in lim: setl(resource.RLIMIT_NOFILE, lim['nofile'])\n"
    "if 'as' in lim: setl(resource.RLIMIT_AS, lim['as'])\n"
    "os.execv(sys.argv[2], sys.argv[2:])\n"
)

_SYSTEM_DIRS = ("/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/opt")
_SYSTEM_ETC = (
    "/etc/ld.so.cache", "/etc/ld.so.conf", "/etc/ld.so.conf.d", "/etc/alternatives",
    "/etc/localtime", "/etc/passwd", "/etc/group", "/etc/nsswitch.conf",
)
_SYSTEM_ETC_GLOBS = ("/etc/java-*", "/etc/php", "/etc/ruby", "/etc/gcc*")
_UNDER_SYSTEM = tuple(d + os.sep for d in _SYSTEM_DIRS)


def _extra_ro_binds(executables) -> list[str]:
    """Directories outside the standard system paths that an executable needs
    (e.g. a Node installed under ~/.nvm). Bound read-only into the sandbox."""
    extra = []
    for path in executables:
        real = os.path.realpath(path)
        if real.startswith(_UNDER_SYSTEM):
            continue
        # Bind the install prefix (parent of the bin directory) when it looks like one.
        parent = os.path.dirname(real)
        prefix = os.path.dirname(parent) if os.path.basename(parent) in ("bin", "sbin") else parent
        if prefix not in extra and prefix not in ("/", ""):
            extra.append(prefix)
    for item in (os.environ.get("CODE_RUNNER_EXTRA_RO_BINDS") or "").split(","):
        item = item.strip()
        if item and os.path.exists(item) and item not in extra:
            extra.append(item)
    return extra


def _bwrap_prefix(info, workdir, executables) -> list[str]:
    cmd = [info["bwrap"], "--die-with-parent", "--new-session", "--unshare-all",
           "--uid", "65534", "--gid", "65534", "--cap-drop", "ALL"]
    seen = set()

    def bind(path):
        if path in seen or not os.path.lexists(path):
            return
        seen.add(path)
        if os.path.islink(path):
            cmd.extend(["--symlink", os.readlink(path), path])
        else:
            cmd.extend(["--ro-bind", path, path])

    for path in _SYSTEM_DIRS + _SYSTEM_ETC:
        bind(path)
    for pattern in _SYSTEM_ETC_GLOBS:
        for path in sorted(glob.glob(pattern)):
            bind(path)
    for path in _extra_ro_binds(executables):
        bind(path)
    cmd.extend(["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
                "--bind", workdir, "/work", "--chdir", "/work"])
    return cmd


def _child_env(workdir: str, sandboxed: bool) -> dict:
    home = "/work" if sandboxed else workdir
    env = {"HOME": home, "TMPDIR": "/tmp" if sandboxed else workdir, "LANG": "C.UTF-8",
           "LC_ALL": "C.UTF-8", "PYTHONIOENCODING": "utf-8", "PYTHONDONTWRITEBYTECODE": "1"}
    if IS_WINDOWS:
        for key in ("SystemRoot", "windir", "PATH", "PATHEXT", "COMSPEC"):
            if key in os.environ:
                env[key] = os.environ[key]
        env["TEMP"] = env["TMP"] = workdir
    else:
        env["PATH"] = "/usr/local/bin:/usr/bin:/bin"
    return env


def _kill_tree(proc: subprocess.Popen) -> None:
    try:
        if IS_WINDOWS:
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        else:
            os.killpg(proc.pid, signal.SIGKILL)
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        proc.kill()
    except OSError:
        pass


class _Run:
    """Outcome of one process."""
    def __init__(self):
        self.returncode = 0
        self.stdout = ""
        self.stderr = ""
        self.timed_out = False
        self.signal = None
        self.elapsed = 0.0


def _read_capped(handle) -> str:
    handle.seek(0)
    return handle.read(OUTPUT_READ_CAP).decode("utf-8", "replace")


def _execute(cmd, *, workdir, stdin_text, wall_s, cpu_s, limit_memory, sandbox, executables) -> _Run:
    """Run `cmd` (relative paths resolve inside `workdir`) and collect results."""
    sandboxed = sandbox["mode"] == "bwrap"
    env = _child_env(workdir, sandboxed)
    full = list(cmd)

    if not IS_WINDOWS:
        limits = {"cpu": cpu_s, "fsize": FILE_SIZE_LIMIT_BYTES, "nofile": NOFILE_LIMIT}
        if limit_memory:
            limits["as"] = ADDRESS_SPACE_LIMIT_BYTES
        full = [_python_executable() or sys.executable, "-I", "-S", "-c", _SHIM, json.dumps(limits)] + full
        executables = list(executables) + [full[0]]
        if sandbox["mode"] == "bwrap":
            full = _bwrap_prefix(sandbox, workdir, executables) + ["--"] + full
        elif sandbox["mode"] == "netns":
            full = [sandbox["unshare"], "--user", "--map-root-user", "--net", "--"] + full

    run = _Run()
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err, tempfile.TemporaryFile() as inp:
        inp.write(stdin_text.encode("utf-8"))
        inp.seek(0)
        popen_kwargs = {"cwd": workdir, "env": env, "stdin": inp, "stdout": out, "stderr": err}
        if IS_WINDOWS:
            popen_kwargs["creationflags"] = (
                getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | getattr(subprocess, "CREATE_NO_WINDOW", 0)
            )
        else:
            popen_kwargs["start_new_session"] = True
        started = time.monotonic()
        try:
            proc = subprocess.Popen(full, **popen_kwargs)
        except OSError as exc:
            raise LocalRunnerError(f"couldn't start {os.path.basename(str(cmd[0]))}: {exc}") from exc
        try:
            proc.wait(timeout=wall_s)
        except subprocess.TimeoutExpired:
            run.timed_out = True
            _kill_tree(proc)
            proc.wait()
        finally:
            if not IS_WINDOWS:
                try:  # clear stragglers the program may have left behind
                    os.killpg(proc.pid, signal.SIGKILL)
                except OSError:
                    pass
        run.elapsed = time.monotonic() - started
        run.returncode = proc.returncode
        run.stdout = _read_capped(out)
        run.stderr = _read_capped(err)

    rc = run.returncode
    if rc is not None and rc < 0:
        run.signal = -rc
    elif sandboxed and rc is not None and rc > 128:
        run.signal = rc - 128
    return run


# --- Language drivers -------------------------------------------------------------

def _runtime_command(language, tools, argument=None):
    if language == "javascript":
        return [tools["run"], "--max-old-space-size=96", "main.js"]
    if language == "python":
        return [tools["run"], "-I", "-S", "-B", "main.py"]
    if language == "php":
        return [tools["run"], "-d", "display_errors=stderr", "-d", "html_errors=0",
                "-d", "memory_limit=128M", "main.php"]
    if language == "ruby":
        return [tools["run"], "main.rb"]
    if language in ("c", "cpp"):
        return ["./main"] + ([str(argument)] if argument is not None else [])
    return [tools["run"], "-Xmx128m", "-Xss8m", "-XX:+UseSerialGC", "-XX:TieredStopAtLevel=1",
            "-XX:-UsePerfData", "-cp", ".", "Main"] + ([str(argument)] if argument is not None else [])


def _compile_command(language, tools):
    if language == "c":
        return [tools["compile"], "-O1", "-std=gnu11", "-o", "main", "main.c", "-lm"]
    if language == "cpp":
        return [tools["compile"], "-O1", "-std=gnu++17", "-o", "main", "main.cpp"]
    return [tools["compile"], "-J-Xmx256m", "-J-XX:TieredStopAtLevel=1", "-encoding", "UTF-8", "Main.java"]


def _clean(text: str, workdir: str, cap: int) -> str:
    text = (text or "").replace(workdir, ".").replace("/work/", "./").strip()
    return text if len(text) <= cap else text[:cap] + "\n... (output truncated)"


def _signal_status(run: _Run, cpu_limit: float) -> str:
    sig = run.signal
    xcpu = getattr(signal, "SIGXCPU", None)
    if run.timed_out or (xcpu is not None and sig == xcpu):
        return "Time Limit Exceeded"
    if sig == getattr(signal, "SIGKILL", 9) and run.elapsed >= cpu_limit:
        return "Time Limit Exceeded"
    names = {11: "SIGSEGV", 6: "SIGABRT", 8: "SIGFPE", 9: "SIGKILL", 25: "SIGXFSZ", 7: "SIGBUS"}
    if sig:
        return f"Runtime Error ({names.get(sig, f'SIG{sig}')})"
    return "Runtime Error (NZEC)"


def run_tests(*, language, player_code, function_name, tests, parameter_types=None, return_type=None):
    """Run every test; same result shape as the Judge0 backend."""
    tools_info = toolchains().get(language)
    if tools_info is None:
        raise harness.UnsupportedLanguage(f"'{language}' isn't supported for server-side execution.")
    if not tools_info["available"]:
        needed = ", ".join(tools_info["missing"])
        raise LocalRunnerError(
            f"{language} isn't installed on this server (missing: {needed}). "
            "Install it, or set OPENCTF_<TOOL> to its path - see docs/CODE_RUNNER.md."
        )
    tools = tools_info["tools"]
    sandbox = sandbox_info()
    if require_sandbox() and sandbox["mode"] != "bwrap":
        raise LocalRunnerError(
            "CODE_RUNNER_REQUIRE_SANDBOX is set but no strong sandbox (bubblewrap) is available."
        )

    static = language in harness.STATIC_LANGUAGES
    if static:
        source = harness.static_source(language, player_code, function_name, tests,
                                       parameter_types, return_type)
    else:
        source = harness.dynamic_source(language, player_code, function_name)

    if not _slots.acquire(timeout=QUEUE_WAIT_S):
        raise LocalRunnerError("the code runner is busy - try again in a few seconds")
    try:
        with tempfile.TemporaryDirectory(prefix="octf-run-", ignore_cleanup_errors=True) as workdir:
            if not IS_WINDOWS:
                os.chmod(workdir, 0o777)  # sandbox uid differs from ours
            with open(os.path.join(workdir, harness.SOURCE_FILENAMES[language]), "w",
                      encoding="utf-8", newline="\n") as handle:
                handle.write(source)

            executables = list(tools.values())
            compile_failure = None
            if "compile" in tools:
                built = _execute(_compile_command(language, tools), workdir=workdir, stdin_text="",
                                 wall_s=COMPILE_WALL_LIMIT_S, cpu_s=COMPILE_WALL_LIMIT_S,
                                 limit_memory=False, sandbox=sandbox, executables=executables)
                if built.timed_out or built.returncode != 0:
                    message = (built.stderr + "\n" + built.stdout).strip() or "compiler failed"
                    compile_failure = _clean(message, workdir, COMPILE_OUTPUT_RETURN_CAP)

            results = []
            for index, test in enumerate(tests):
                expected = test.get("expect")
                if compile_failure is not None:
                    results.append(_result(False, expected, None, "Compilation Error",
                                           compile_output=compile_failure))
                    continue
                argument = index if static else None
                run = _execute(
                    _runtime_command(language, tools, argument), workdir=workdir,
                    stdin_text="" if static else harness.stdin_for(test),
                    wall_s=WALL_LIMIT_S, cpu_s=CPU_LIMIT_S,
                    limit_memory=language not in ("javascript", "java"),
                    sandbox=sandbox, executables=executables,
                )
                console, found, actual = harness.split_output(run.stdout)
                stderr = _clean(run.stderr, workdir, STDERR_RETURN_CAP)
                console = _clean(console, workdir, CONSOLE_RETURN_CAP)
                if run.timed_out or run.signal or run.returncode != 0:
                    results.append(_result(False, expected, None, _signal_status(run, CPU_LIMIT_S),
                                           stderr=stderr, stdout=console))
                    continue
                passed = found and harness.json_values_equal(actual, expected)
                results.append(_result(passed, expected, actual if found else None,
                                       "Accepted" if passed else "Wrong Answer",
                                       stderr=stderr, stdout=console))
            return results
    finally:
        _slots.release()


def _result(passed, expected, actual, status, *, stderr="", stdout="", compile_output=None):
    return {
        "passed": bool(passed), "expected": expected, "actual": actual, "status": status,
        "stderr": stderr or None, "compile_output": compile_output, "stdout": stdout or None,
    }
