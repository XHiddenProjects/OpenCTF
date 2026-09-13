"""
Console-script entry points for the `openctf-server` PyPI package.

These are only meant to be invoked through the package namespace (the
installed `openctf-server` / `openctf-server-target` / `openctf-server-seed`
commands) - they are not a replacement for running app.py / target_app.py /
seed_challenges.py directly, which remains the documented way to run things
from a cloned copy of the repo.
"""

import os


def main():
    """Entry point for the `openctf-server` command: runs the main API.

    This does NOT also start the sandboxed target-website service - run
    `openctf-server-target` in a second process/terminal for that, same as
    the two-service split in docker-compose.yml.
    """
    from openctf_server.app import app  # import alone triggers DB bootstrap

    port = int(os.environ.get("PORT", "5000"))
    debug = os.environ.get("FLASK_DEBUG", "").strip().lower() in ("1", "true", "yes")
    print(f"OpenCTF API starting on http://0.0.0.0:{port}")
    print("This does not start the sandboxed target-website service - run `openctf-server-target` separately.")
    app.run(host="0.0.0.0", port=port, debug=debug, use_reloader=False)


def target():
    """Entry point for the `openctf-server-target` command: runs the
    sandboxed target-website service on its own."""
    from openctf_server.target_app import target_app, TARGET_PORT

    print(f"OpenCTF target-website service starting on http://0.0.0.0:{TARGET_PORT}")
    target_app.run(host="0.0.0.0", port=TARGET_PORT, debug=False, use_reloader=False)


def seed():
    """Entry point for the `openctf-server-seed` command: loads the starter
    set of preset challenges."""
    from openctf_server.seed_challenges import seed as _seed

    _seed()
