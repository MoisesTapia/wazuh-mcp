FROM python:3.11-slim

WORKDIR /app

# Install curl for healthcheck inside container (optional)
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Install dependencies first (better layer caching)
COPY pyproject.toml .
RUN pip install --no-cache-dir -e "." 2>/dev/null || true

# Copy source
COPY src/ ./src/

# Install in editable mode with final source
RUN pip install --no-cache-dir -e "."

# Default: HTTP transport for Docker deployments
ENV MCP_TRANSPORT=http
ENV MCP_HOST=0.0.0.0
ENV MCP_PORT=8000

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -sf http://localhost:${MCP_PORT}/health || exit 1

CMD ["wazuh-mcp"]
