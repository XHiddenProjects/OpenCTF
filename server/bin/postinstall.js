#!/usr/bin/env node
// Best-effort convenience only: tries to `pip install` this package's
// bundled requirements.txt so `openctf-server` works right after `npm
// install` without an extra manual step. Never fails the npm install
// itself - if Python/pip aren't available, or the install fails, this just
// prints what to do manually and exits 0.

const { spawnSync } = require("child_process");
const path = require("path");

const ROOT = path.join(__dirname, "..");
const REQUIREMENTS = path.join(ROOT, "requirements.txt");

function findPip() {
  for (const candidate of [["pip3"], ["pip"], ["python3", "-m", "pip"], ["python", "-m", "pip"]]) {
    const result = spawnSync(candidate[0], [...candidate.slice(1), "--version"], { stdio: "ignore" });
    if (!result.error && result.status === 0) return candidate;
  }
  return null;
}

function manualInstructions() {
  console.warn(
    "openctf-server: couldn't find a working pip to auto-install Python dependencies.\n" +
    `Once Python 3.10+ and pip are available, run:\n  pip install -r ${REQUIREMENTS}\n`
  );
}

const pip = findPip();
if (!pip) {
  manualInstructions();
  process.exit(0);
}

console.log(`openctf-server: installing Python dependencies with \`${pip.join(" ")}\`...`);
const result = spawnSync(pip[0], [...pip.slice(1), "install", "-r", REQUIREMENTS], {
  cwd: ROOT,
  stdio: "inherit",
});

if (result.status !== 0) {
  console.warn(
    "openctf-server: automatic `pip install` failed (see output above).\n" +
    `Install manually with:\n  pip install -r ${REQUIREMENTS}\n`
  );
}
// Always exit 0 - a failed postinstall here shouldn't break `npm install`
// for anyone who doesn't even plan to run the server from this package.
process.exit(0);
