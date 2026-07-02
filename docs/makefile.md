# Makefile reference

Every project command is a `make` target. Run `make <target>` from the project
root.

## Setup

| Target | Description |
|--------|-------------|
| `make install` | Create `.venv` and install the package in editable mode with dev deps |

## Certificates

| Target | Description |
|--------|-------------|
| `make certs` | Generate SSL certificates for the Wazuh stack (run before the first `docker-up`) |

## Wazuh stack (Manager + Indexer + Dashboard)

| Target | Description |
|--------|-------------|
| `make docker-up` | Start the stack and wait until the API is healthy |
| `make docker-down` | Stop the containers (data preserved) |
| `make docker-status` | Status of the 3 containers |
| `make docker-logs` | Real-time logs from all services |
| `make docker-logs-manager` | Manager logs only |
| `make docker-logs-indexer` | Indexer logs only |
| `make docker-logs-dashboard` | Dashboard logs only |
| `make docker-reset` | **DESTRUCTIVE** — remove containers **and** volumes (all data); asks for confirmation |
| `make wait-for-wazuh` | Poll until the REST API responds |

## Full stack + MCP server in Docker

| Target | Description |
|--------|-------------|
| `make mcp-docker` | Start everything + MCP HTTP on `:8000` (rebuilds the image) |
| `make mcp-docker-down` | Stop the full stack including the MCP |

## Local MCP (development)

| Target | Description |
|--------|-------------|
| `make dev` | MCP with hot-reload and the FastMCP web inspector |
| `make run` | MCP in production mode (stdio) |

## Tests & quality

| Target | Description |
|--------|-------------|
| `make test` | Unit tests (~3 s, no Docker) |
| `make test-integration` | Tests against a live Wazuh instance (requires `make docker-up`) |
| `make test-all` | All tests |
| `make lint` | Check Python syntax for all source modules |
| `make check-tools` | Verify every registered tool has a docstring |

## Security (DevSecOps)

Same scans as the CI pipeline, run locally. See [DevSecOps](devsecops.md).

| Target | Description |
|--------|-------------|
| `make security` | Run all four scans (deps, licenses, SAST, Dockerfile) |
| `make security-deps` | Dependency vulnerability scan (`pip-audit`) |
| `make security-licenses` | License scan (`pip-licenses`) + copyleft/unknown check |
| `make security-sast` | Python SAST (`bandit`) |
| `make security-docker` | Dockerfile lint/SAST (`hadolint`, Docker fallback) |

## Claude Desktop

| Target | Description |
|--------|-------------|
| `make setup-claude-desktop` | Register the MCP in Claude Desktop automatically |

## Cleanup

| Target | Description |
|--------|-------------|
| `make clean` | Remove `__pycache__`, `*.pyc`, `*.egg-info` |

---

Next: [Development](development.md) · [Troubleshooting](troubleshooting.md)
