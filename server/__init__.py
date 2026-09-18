"""OpenCTF server - Flask API, sandboxed target-website service, and
challenge-seeding CLI for the OpenCTF lab platform.

This file exists so the flat `server/` directory (app.py, target_app.py,
seed_challenges.py) can also be published to PyPI as a proper namespaced
package (`openctf_server`), without moving any of those files - see
pyproject.toml's `[tool.setuptools] package-dir` mapping. Running things
directly from this directory (`python app.py`, `python target_app.py`,
`python seed_challenges.py`) is unaffected either way.
"""

__version__ = "1.1.0"
