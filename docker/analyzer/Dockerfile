# WiFi-BLE Analyzer web UI container.
# Build context is the repo root (see docker-compose.yml) so it can copy both
# the app under app/ and the repo-root requirements.txt.
FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Application code.
COPY app /app

# Persistent state (analyzer.db, logs/, alerts/, whitelist/) lives here, backed
# by a named volume; config.py reads ANALYZER_DATA_DIR to relocate all paths.
ENV ANALYZER_DATA_DIR=/data

EXPOSE 8081
CMD ["python", "run_ui.py"]
