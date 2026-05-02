FROM python:3.12-slim

WORKDIR /app

# WARNING: This image intentionally keeps unsafe defaults for training:
# - dependencies are installed into the image without hardening
# - the container runs as root
# - the filesystem remains writable
# Do not copy these patterns into production services.
COPY requirements.txt pyproject.toml README.md ./
COPY vulnerable_mcp ./vulnerable_mcp
COPY lab-data ./lab-data
COPY secrets ./secrets

RUN pip install --no-cache-dir -r requirements.txt && pip install --no-cache-dir .

ENV APP_ENV=training \
    DEBUG=true \
    LOG_LEVEL=DEBUG \
    MCP_HOST=0.0.0.0 \
    MCP_PORT=8000 \
    MCP_TRANSPORT=streamable-http \
    DATABASE_PATH=/data/vulnerable_mcp.sqlite \
    TRAINING_SECRET=training_env_secret_exposed_by_system_info

RUN mkdir -p /data /lab-data /app/secrets && chmod -R 777 /data /lab-data /app/secrets

# VULNERABILITY: running as root is deliberate for the filesystem permission lab.
# Normal fix: create and switch to an unprivileged user, make the filesystem
# read-only, and mount only the directories the app truly needs.
USER root

EXPOSE 8000

CMD ["uvicorn", "vulnerable_mcp.http_app:app", "--host", "0.0.0.0", "--port", "8000", "--log-level", "debug"]
