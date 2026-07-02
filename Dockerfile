# syntax=docker/dockerfile:1
FROM python:3.12-slim

# Unbuffered stdout/stderr so audit logs stream in real time (they go to
# stderr); no .pyc files written into the image.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# curl is required by the container HEALTHCHECK below.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Install the package (and its runtime deps) from source. A modern pip is
# required for the src/ layout + pyproject build backend.
COPY pyproject.toml ./
COPY src/ ./src/
RUN pip install --upgrade pip \
    && pip install .

# Drop privileges: run as an unprivileged, fixed-UID user (least privilege).
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin wazuh
USER wazuh

# HTTP transport for Docker deployments.
# 0.0.0.0 is correct *inside* the container — Docker's host-side port mapping
# is the actual security boundary. The server still refuses to start unless
# MCP_API_KEY is provided at runtime (see docker-compose.yml / .env).
ENV MCP_TRANSPORT=http \
    MCP_HOST=0.0.0.0 \
    MCP_PORT=8000

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -sf "http://localhost:${MCP_PORT}/health" || exit 1

CMD ["wazuh-mcp"]
