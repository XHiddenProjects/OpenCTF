#!/usr/bin/env node
// Launches the OpenCTF server's Python code from Node - this package
// bundles the Python source as plain files (see package.json "files"), it
// does not reimplement anything. npm cannot install Python itself, so a
// working `python3` (or `python`) with the requirements already installed
// (see postinstall.js) has to already be on the machine running this.
//
// Usage:
//   openctf-server            # main API (python app.py)
//   openctf-server --target   # sandboxed target-website service
//   openctf-server --seed     # load the starter challenges, then exit

const { spawnSync, spawn } = require("child_process");
const path = require("path");

const ROOT = path.join(__dirname, "..");

function findPython() {
  for (const candidate of ["python3", "python"]) {
    const result = spawnSync(candidate, ["--version"], { stdio: "ignore" });
    if (!result.error && result.status === 0) return candidate;
  }
  return null;
}

function main() {
  const python = findPython();
  if (!python) {
    console.error(
      "openctf-server: no working `python3` or `python` found on PATH.\n" +
      "This package bundles the server's Python source but can't install a Python runtime - " +
      "install Python 3.10+ yourself, then run `pip install -r " +
      path.join(ROOT, "requirements.txt") + "` and try again."
    );
    process.exit(1);
  }

  const args = process.argv.slice(2);
  let script = "app.py";
  if (args.includes("--target")) script = "target_app.py";
  else if (args.includes("--seed")) script = "seed_challenges.py";

  const child = spawn(python, [path.join(ROOT, script)], {
    cwd: ROOT,
    stdio: "inherit",
    env: process.env,
  });
  child.on("exit", (code) => process.exit(code ?? 1));
  child.on("error", (err) => {
    console.error("openctf-server: failed to start Python process:", err.message);
    process.exit(1);
  });
}

main();
