# openctf-server

Flask API and sandboxed target-website service for [OpenCTF](https://github.com/XHIiddenProjects/OpenCTF), a self-hosted lab CTF platform. This package is the server half only - the desktop client is published separately on npm as `openctf`.

## Install
```bash
pip install openctf-server
```

## Quick start

```bash
export SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
export JWT_SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
export FLAG_PEPPER=$(python -c "import secrets; print(secrets.token_hex(32))")
export TARGET_ACCESS_SECRET=$(python -c "import secrets; print(secrets.token_hex(32))")
export ADMIN_PASSWORD=set-a-real-password

openctf-server           # main API on :5000
openctf-server-target     # sandboxed target-website service on :5001 (separate terminal)
openctf-server-seed       # load the starter set of preset challenges (one-off)
```

Both processes need the same `SECRET_KEY`, `TARGET_ACCESS_SECRET`, and `DATABASE_URL` (if you set one) to talk to each other correctly - they share one database and one signed-URL secret between the two services.

## Configuration

All configuration is via environment variables - there's no config file. See the main repository's `server/.env.example` for the full list (`DATABASE_URL`, `CORS_ORIGINS`, `TARGET_SERVER_URL`, `OLLAMA_URL`, `OLLAMA_MODEL`, and the secrets above).

## Docker

If you'd rather not manage two processes and env vars by hand, the main repository ships a `docker-compose.yml` that runs both services correctly out of the box - see the [repository README](https://github.com/XHIiddenProjects/OpenCTF#installation) for that path.

## Security

Read `SECURITY.md` in the main repository before exposing this to more than your own laptop - in particular, the target-website service is *intentionally* vulnerable (that's the point, it hosts the challenges) and should never be reachable from outside your lab's own network.
