# Single image, shared by two services (see docker-compose.yml):
#   - the main API, run under gunicorn
#   - the sandboxed target-website service (target_app.py), run standalone
#
# Which one a given container actually runs is set by `command:` in
# docker-compose.yml, not by this Dockerfile - that way there's only one
# image to build and keep in sync.

FROM python:3.13-slim

WORKDIR /app

# Install dependencies first so this layer is cached across rebuilds that
# only change application code.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

COPY app.py target_app.py seed_challenges.py seed_challenges_extra.py code_runner.py code_harness.py local_runner.py judge0_runner.py ./
# Code Challenge Editor: player code runs inside this container, offline. The
# image ships with Python only. Add more languages at build time, e.g.
#   docker compose build --build-arg CODE_RUNTIMES="nodejs php-cli ruby gcc g++ default-jdk-headless bubblewrap"
# Note: bubblewrap needs unprivileged user namespaces, which Docker's default
# seccomp profile blocks, so in a stock container the runner reports
# `sandbox: none` (limits + scrubbed environment only). For untrusted players
# prefer a self-hosted Judge0 (CODE_RUNNER=judge0) - see docs/CODE_RUNNER.md.
ARG CODE_RUNTIMES=""
RUN if [ -n "$CODE_RUNTIMES" ]; then \
      apt-get update && apt-get install -y --no-install-recommends $CODE_RUNTIMES \
      && rm -rf /var/lib/apt/lists/*; \
    fi

COPY addons ./addons
COPY themes ./themes

# Both services write to / read from the same SQLite file by default - see
# the `ctf-data` volume in docker-compose.yml.
RUN mkdir -p /app/instance

EXPOSE 5000 5001

# Default to the API; docker-compose.yml overrides this for the target
# service. Kept here so `docker build` + `docker run` alone still does
# something useful without compose.
CMD ["gunicorn", "-w", "1", "--threads", "8", "--timeout", "120", "-b", "0.0.0.0:5000", "app:app"]
