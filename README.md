# Wazuh MCP Server

**206 tools** that expose the [Wazuh](https://wazuh.com/) Security Platform as
[Model Context Protocol](https://modelcontextprotocol.io/) tools for Claude,
Claude Code and any MCP-compatible client.

The server covers the full **Wazuh Manager REST API** (agents, rules, cluster,
RBAC, FIM, SCA, MITRE…) plus a **SOC layer** that queries the Wazuh Indexer
directly for alerts, CVEs and threat analysis, and a **SOAR layer** for active
response (block IPs, isolate agents, kill processes, run YARA scans).

```
Claude Desktop / Claude Code
        │  stdio  (or HTTP + Bearer auth when MCP runs in Docker)
        ▼
┌─────────────────────┐    HTTPS :55000    ┌────────────────────────┐
│   wazuh-mcp server  │ ──────────────────► │   wazuh.manager        │
│   (FastMCP 2.0+)    │                     │   REST API + Filebeat  │
│                     │    HTTPS :9200      └────────────┬───────────┘
│  audit · circuit    │ ─────────────┐                   │
│  breaker · sanitize │              ▼                   │
└─────────────────────┘   ┌────────────────────────┐    │
                          │   wazuh.indexer        │◄───┘
                          │   OpenSearch (SOC data)│
                          └────────────┬───────────┘
                                       │
                          ┌────────────▼───────────┐
                          │   wazuh.dashboard       │
                          │   Web UI :443           │
                          └─────────────────────────┘
```

---

## Documentation

The full documentation lives in the [`docs/`](docs/) folder, organized by topic:

| Guide | What's inside |
|-------|---------------|
| [Installation](docs/installation.md) | Requirements, quick start, SSL certificates, Docker stack, first run |
| [Configuration](docs/configuration.md) | Environment variables, credentials, changing passwords, Indexer setup |
| [Claude integration](docs/claude-integration.md) | Claude Desktop and Claude Code setup (stdio and HTTP) |
| [Tools catalog](docs/tools.md) | All 206 tools by module, with real usage examples |
| [SOC & SOAR](docs/soc.md) | Alerts, CVEs, threat analysis and active response via the Indexer |
| [Security model](docs/security.md) | Audit log, circuit breaker, output sanitization, HTTP Bearer auth, TLS |
| [Architecture](docs/architecture.md) | Request flow, module layout, Docker dependencies |
| [Development](docs/development.md) | Running tests, adding modules, code conventions |
| [DevSecOps](docs/devsecops.md) | Security scanning in CI and locally: pip-audit, pip-licenses, bandit, hadolint |
| [Troubleshooting](docs/troubleshooting.md) | Common errors and fixes |
| [Makefile reference](docs/makefile.md) | Every `make` target explained |

---

## Quick start

```bash
git clone <repo-url>
cd wazuh-mcp

make install                 # create .venv and install the package
cp .env.example .env         # fill in WAZUH_USER / WAZUH_PASSWORD

make certs                   # generate SSL certificates (first time only)
make docker-up               # start manager + indexer + dashboard

source .venv/bin/activate
make setup-claude-desktop    # register the MCP in Claude Desktop
```

Restart Claude Desktop and try:

```
Call ping_wazuh and tell me the Wazuh version that is running.
```

> On Linux you must set `vm.max_map_count=262144` before `make docker-up`.
> See [Installation](docs/installation.md#linux-vmmax_map_count) for details.

Full walkthrough: **[docs/installation.md](docs/installation.md)**.

---

## Features

| Feature | Detail |
|---|---|
| **206 tools** in 23 modules | Full Wazuh 4.9 REST API + SOC + SOAR coverage |
| **SOC layer** | Alerts, CVEs and threat analysis queried directly from the Indexer |
| **SOAR layer** | Block/unblock IPs, isolate agents, kill processes, YARA scans, custom AR |
| **Full local stack** | Manager + Indexer (OpenSearch) + Dashboard in Docker |
| **Retry with backoff** | 429/502/503/504 and connection errors retried automatically |
| **Circuit breaker** | Fails fast when the Manager is down, recovers automatically |
| **JWT auto-refresh** | Token renewed transparently before expiry or on 401 |
| **Audit logging** | One structured JSON line per tool call, secrets auto-redacted |
| **Output sanitization** | Prompt-injection neutralization + secret redaction on tool output |
| **HTTP Bearer auth** | API key required in HTTP mode; loopback-only host by default |
| **Dual transport** | `stdio` for local use, `http` for Docker deployments |
| **278 unit tests** | No Docker or network required |

Details for each capability are in the [documentation](#documentation) above.

---

## Requirements

| Resource | Minimum | Recommended |
|---------|--------|-------------|
| CPU | 4 cores | 4+ cores |
| RAM | 8 GB | 16 GB |
| Disk | 20 GB free | 50 GB free |
| Python | 3.11+ | 3.12+ |
| Docker Desktop | 4.x+ | Latest |
| Docker Compose | v2 (`docker compose`) | Latest |

See [docs/installation.md](docs/installation.md#requirements) for platform notes.

---

## License

MIT — see [LICENSE](LICENSE) for details.
