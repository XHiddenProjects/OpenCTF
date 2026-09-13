# OpenCTF

OpenCTF is a lightweight, jeopardy-style capture-the-flag platform for classroom labs, private competitions, and security training sessions.

It consists of:

- A Flask API backed by SQLite for authentication, teams, challenges, submissions, and the scoreboard.
- An Electron desktop client for participants and administrators.
- An isolated target server for sandboxed web challenges.
- Optional Ollama integration for AI conversation challenges.

> **Project status:** OpenCTF is a lab-oriented platform. Review the security notes before exposing it to an untrusted network or using it for a production event.

## Features

- Username/password registration and JWT-based authentication
- Teams and team-scoped flag generation
- Standard flag-submission challenges
- Interactive terminal challenges with a server-side virtual filesystem
- Sandboxed web challenges served by a separate target process
- Optional AI challenges powered by a local Ollama model
- Admin panel for challenge and user management
- User profiles with display name, biography, and avatar
- Scoreboard, progress tracking, and submission limits
- Windows, macOS, and Linux Electron builds

## Repository Layout

```text
OpenCTF/
├── client/                 Electron desktop client
│   ├── src/                Main process, renderer, preload, and styles
│   └── package.json        Build and packaging configuration
├── server/                 Flask API and challenge services
│   ├── app.py              Main API, database models, and startup logic
│   ├── target_app.py       Isolated web-challenge server
│   ├── seed_challenges.py  Starter challenge data
│   ├── requirements.txt    Python dependencies
│   └── .env.example        Server configuration template
└── README.md
```

## Architecture

The API listens on port `5000`. When started with `python app.py`, it also launches the isolated web-target process on port `5001`. Participants communicate with the API through the Electron client; web challenge pages are loaded from the target service and receive signed, team-specific access parameters.

The default database is SQLite at `server/instance/ctf.db`. Flags are not stored as plaintext: the server stores an HMAC-SHA256 digest using `FLAG_PEPPER`, and team-specific flags are generated when required.

## Requirements

### Server

- Python 3.10 or newer
- A Linux host is recommended for a lab deployment
- Network access to ports `5000` and, when web challenges are enabled, `5001`
- Optional: [Ollama](https://ollama.com/) for AI challenges

### Client

- Node.js 18 or newer
- npm
- Electron is installed locally by `npm install`

## Installation

OpenCTF has two halves that install separately: the **client** (the Electron desktop app players and admins run) and the **server** (the Flask API + sandboxed target-website service someone has to host). Whichever way you install either one, the client still needs a running server to point at — see **Quick Start** below if you're standing one up yourself.

### Installing the client

**Option A: npm**

```bash
npm install -g openctf
openctf
```

**Option B: download a prebuilt release** — grab the build for your OS from the project's Releases page:

- **Windows:** portable `.exe` (no install needed) or the NSIS installer
- **macOS:** `.dmg` or `.zip`
- **Linux:** `.AppImage` or `.deb`

These are the same artifacts produced locally by `npm run dist` — see **Building the Client** below to build them yourself.

**Option C: build from source** — see **Quick Start** below for the full walkthrough.

### Installing the server

Three ways to get the server running, in order of how much they manage for you:

**Option A: Docker (recommended for self-hosting)**

```bash
cp .env.example .env    # fill in real secrets first
docker compose up --build
docker compose exec api python seed_challenges.py
```

Runs the API and the sandboxed target-website service as two containers sharing one database — see `docker-compose.yml` at the repo root. This is the only method here that doesn't require Python installed on your machine at all (just Docker).

**Option B: pip (once published)**

```bash
pip install openctf-server

export SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
export JWT_SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
export FLAG_PEPPER=$(python -c "import secrets; print(secrets.token_hex(32))")
export TARGET_ACCESS_SECRET=$(python -c "import secrets; print(secrets.token_hex(32))")
export ADMIN_PASSWORD=set-a-real-password

openctf-server            # main API on :5000
openctf-server-target     # sandboxed target-website service on :5001 (separate terminal)
openctf-server-seed       # load the starter challenges (one-off)
```

> **Not published yet.** Intended command once [pypi.org/project/openctf-server](https://pypi.org/project/openctf-server/) exists. See `server/pyproject.toml`.

**Option C: npm (bundled Python source, once published)**

```bash
npm install -g openctf-server
openctf-server              # main API
openctf-server --target     # sandboxed target-website service (separate terminal)
openctf-server --seed       # load the starter challenges
```

> **Not published yet.** This package bundles the server's Python source with a small Node launcher — npm still can't install a Python runtime for you, so Python 3.10+ needs to already be on the machine. Installing tries to `pip install` the server's dependencies automatically (see `server/bin/postinstall.js`); if that fails silently (no pip found, etc.) it prints the manual command to run instead. Prefer Option A or B over this one where you can — they're both more standard for their respective ecosystems.

**Option D: build from source** — see **Quick Start** below.

## Quick Start

### 1. Configure and start the server

From the repository root:

```bash
cd server
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Edit `.env` and replace every placeholder secret. Export the values before starting the server. For a shell session, this can be done with:

```bash
set -a
source .env
set +a
python app.py
```

The server starts at `http://<host>:5000`. The isolated web-target service starts at `http://<host>:5001`.

On first startup, OpenCTF creates the database and an administrator account using `ADMIN_PASSWORD`. If `ADMIN_PASSWORD` is not set, the development fallback is `changeme123`; change it immediately before allowing access to other users.

### 2. Load starter challenges

Keep the virtual environment active and run:

```bash
python seed_challenges.py
```

Seeding is idempotent by challenge title, so it is safe to run again after adding new entries to `seed_challenges.py`.

### 3. Start the desktop client

In a second terminal:

```bash
cd client
npm install
npm start
```

The client defaults to `http://localhost:5000`. Participants can change the server address from **Server settings**; the value is stored in the Electron user-data directory.

## Configuration

Copy `server/.env.example` to `server/.env` and configure these variables:

| Variable | Purpose |
| --- | --- |
| `SECRET_KEY` | Flask application secret |
| `JWT_SECRET_KEY` | Signs access tokens; use a separate random value |
| `FLAG_PEPPER` | HMAC key used to verify and generate flags |
| `DATABASE_URL` | SQLAlchemy database URL; SQLite is the default |
| `CORS_ORIGINS` | Allowed CORS origins; restrict this instead of using `*` where possible |
| `ADMIN_PASSWORD` | Password for the first administrator account |
| `TARGET_SERVER_URL` | Public URL of the isolated target service, normally `http://localhost:5001` |
| `TARGET_ACCESS_SECRET` | Signs target-service access parameters |
| `TARGET_PORT` | Port used by `target_app.py`, default `5001` |
| `OLLAMA_URL` | Ollama API URL, default `http://127.0.0.1:11434` |
| `OLLAMA_MODEL` | Ollama model name, default `llama3.2` |

Generate strong values for secrets rather than reusing passwords. Do not commit `.env`, database files, or access tokens.

## Building the Client

Install dependencies once:

```bash
cd client
npm install
```

Available commands:

```bash
npm start       # Run the client locally
npm run dist    # Build Windows, macOS, and Linux packages
npm run dist:win
npm run dist:mac
npm run dist:linux
```

Build artifacts are written to `client/dist/`. The Windows build includes a portable executable and an NSIS installer. The macOS build includes a DMG and ZIP archive; the Linux build includes an AppImage and Debian package.

The packaged application uses the icon files under `client/build/`. Replace those assets before distributing a branded build.

## Managing Challenges

Log in with an administrator account and open the **Admin** view in the client. Administrators can create, edit, activate, deactivate, and delete challenges, and promote or demote users.

Supported challenge types are:

- **Standard:** description, hints, optional files, and a submitted flag.
- **Terminal:** a server-side virtual filesystem explored with `ls`, `cd`, `cat`, and `pwd`.
- **Web:** an isolated target page served by `target_app.py`.
- **AI:** a conversation challenge backed by the configured Ollama model.

### Terminal filesystem format

Terminal challenge files are represented as nested JSON objects. Objects are directories and strings are file contents:

```json
{
  "home": {
    "user": {
      "notes.txt": "nothing to see here",
      ".secret": {
        "flag.txt": "flag{you_found_it}"
      }
    }
  }
}
```

The complete filesystem is kept on the server. The client receives command results, not the raw tree.

### Web challenge safety

Web challenges are intentionally vulnerable training targets. Keep `target_app.py` isolated from the public internet and from sensitive infrastructure. Players should only interact with the supplied target pages and should never be given access to the CTF host itself.

### AI challenge requirements

Install and start Ollama separately, then pull the configured model:

```bash
ollama pull llama3.2
```

Set `OLLAMA_URL` and `OLLAMA_MODEL` if your deployment uses a different endpoint or model. AI challenges require a working Ollama service and microphone permissions are only needed for voice input in the client.

## Operations

### Production-style server process

For a real lab session, run the API under Gunicorn rather than Flask's development server:

```bash
cd server
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

The isolated target process is currently started by `app.py`; plan its lifecycle and network policy accordingly when moving beyond a small lab deployment.

### Health check

```bash
curl http://localhost:5000/api/health
```

Expected response:

```json
{"status":"ok","time":"2026-01-01T00:00:00.000000"}
```

### Firewall

Expose only the ports required by participants. For a Linux host using UFW:

```bash
sudo ufw allow 5000/tcp
```

Port `5001` should remain restricted to the lab network or the API host unless your deployment specifically requires otherwise.

## Database and Upgrades

The default database is a local SQLite file. Stop the server before backing it up or replacing it:

```bash
cp server/instance/ctf.db server/instance/ctf.db.backup
```

The application performs a small amount of compatibility setup for some added challenge columns, but it is not a full migration system. For disposable development data, stop the server, remove `server/instance/ctf.db`, and restart it. This deletes accounts, teams, challenges, and submissions. For retained data, use a migration tool such as Flask-Migrate/Alembic and take a backup first.

## Security Checklist

Before a session:

- Replace all default secrets and the default admin password.
- Use HTTPS behind a reverse proxy; the development server uses plain HTTP.
- Restrict `CORS_ORIGINS` to known origins where possible.
- Keep `target_app.py` isolated and do not expose it to the public internet.
- Back up the database and test restoring it.
- Run the API behind Gunicorn or another production WSGI server.
- Treat challenge descriptions, uploaded files, and target behavior as untrusted training content.
- Add network and request rate limiting at the reverse proxy for larger events.

## Known Limitations

- SQLite is suitable for small lab sessions, not high-concurrency events.
- The target service is launched as a child process of `app.py`; a supervisor or containerized deployment is recommended for stronger isolation.
- There is no built-in HTTPS termination; use a reverse proxy with a trusted certificate.
- Challenge migrations are limited; use Flask-Migrate/Alembic for databases that must be preserved.
- AI challenge behavior depends on the availability, model, and configuration of the local Ollama service.

## Publishing

Reference commands for maintainers, once you've replaced the placeholder `OWNER/OpenCTF` repo URLs in `client/package.json`, `server/pyproject.toml`, `server/package.json`, and `server/PACKAGE_README.md`.

**Client to npm** (`openctf`):

```bash
cd client
npm publish
```

**Server to PyPI** (`openctf-server`):

```bash
cd server
python -m pip install --upgrade build twine
python -m build
twine upload dist/*
```

**Server to npm** (`openctf-server`, bundled Python source):

```bash
cd server
npm publish
```

Bump the version in all three manifests (`client/package.json`, `server/pyproject.toml`, `server/package.json`) together when cutting a release so the three packages stay in sync with each other.

## License

The Electron client declares the MIT license in `client/package.json`. Confirm the licensing terms for your complete distribution and any additional assets before publishing a release.
