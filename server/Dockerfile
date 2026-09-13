# Single image, shared by two services (see docker-compose.yml):
#   - the main API, run under gunicorn
#   - the sandboxed target-website service (target_app.py), run standalone
#
# Which one a given container actually runs is set by `command:` in
# docker-compose.yml, not by this Dockerfile - that way there's only one
# image to build and keep in sync.

FROM python:3.12-slim

WORKDIR /app

# Install dependencies first so this layer is cached across rebuilds that
# only change application code.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

COPY app.py target_app.py seed_challenges.py ./

# Both services write to / read from the same SQLite file by default - see
# the `ctf-data` volume in docker-compose.yml.
RUN mkdir -p /app/instance

EXPOSE 5000 5001

# Default to the API; docker-compose.yml overrides this for the target
# service. Kept here so `docker build` + `docker run` alone still does
# something useful without compose.
CMD ["gunicorn", "-w", "1", "-b", "0.0.0.0:5000", "app:app"]
