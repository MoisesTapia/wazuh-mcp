# Wazuh MCP Server

**177 tools** that expose the [Wazuh](https://wazuh.com/) REST API as MCP tools
for Claude, Claude Code and any client compatible with the
[Model Context Protocol](https://modelcontextprotocol.io/).

```
Claude Desktop / Claude Code
        │  stdio  (or HTTP when MCP runs in Docker)
        ▼
┌─────────────────────┐    HTTPS :55000    ┌────────────────────────┐
│   wazuh-mcp server  │ ──────────────────► │   wazuh.manager        │
│   (FastMCP 3.4)     │                     │   REST API + Filebeat  │
└─────────────────────┘                     └────────────┬───────────┘
                                                         │ HTTPS :9200
                                            ┌────────────▼───────────┐
                                            │   wazuh.indexer        │
                                            │   OpenSearch           │
                                            └────────────┬───────────┘
                                                         │
                                            ┌────────────▼───────────┐
                                            │   wazuh.dashboard      │
                                            │   Web UI :443          │
                                            └────────────────────────┘
```

---

## Contents

- [Features](#features)
- [System requirements](#system-requirements)
- [Project structure](#project-structure)
- [Quick start](#quick-start)
- [Claude Desktop integration](#claude-desktop-integration)
- [Claude Code integration](#claude-code-integration)
- [Credentials and access](#credentials-and-access)
- [Environment variables](#environment-variables)
- [Makefile commands](#makefile-commands)
- [Available tools](#available-tools)
- [Technical architecture](#technical-architecture)
- [Development](#development)
- [Troubleshooting](#troubleshooting)

---

## Features

| Feature | Detail |
|---|---|
| **177 tools** in 19 modules | Full coverage of the Wazuh 4.9 REST API |
| **Full local stack** | Manager + Indexer (OpenSearch) + Dashboard in Docker |
| **Retry with exponential backoff** | 429, 502, 503, 504, ConnectError → automatic retries |
| **JWT auto-refresh** | Token transparently renewed before expiry or on 401 |
| **Clean parameters** | `None` values are never sent to the API (avoids 400 errors) |
| **Detailed errors** | `WazuhAPIError` with `status_code` and `response_body` |
| **Dual transport** | `stdio` for local, `http` for Docker |
| **165 unit tests** | No Docker or network required |

---

## System requirements

| Resource | Minimum | Recommended |
|---------|--------|-------------|
| CPU | 4 cores | 4+ cores |
| RAM | 8 GB | 16 GB |
| Disk | 20 GB free | 50 GB free |
| Python | 3.11+ | 3.12+ |
| Docker Desktop | 4.x+ | Latest version |
| Docker Compose | v2 (`docker compose`) | Latest version |

> **macOS:** Docker Desktop manages resources automatically.
> **Linux:** You must configure `vm.max_map_count` (see [Quick start](#linux-vm-max_map_count)).

---

## Project structure

```
wazuh-mcp/
├── docker-compose.yml              # Full stack: manager + indexer + dashboard + mcp (profile)
├── generate-indexer-certs.yml      # Generates SSL certificates (run once)
├── Dockerfile                      # MCP server image for Docker
├── Makefile                        # All project commands
├── pyproject.toml                  # Python dependencies
├── .env                            # Credentials (DO NOT commit)
├── .env.example                    # Configuration template
│
├── config/                         # Static Wazuh stack configuration
│   ├── certs.yml                   # Nodes for the certificate generator
│   ├── wazuh_indexer_ssl_certs/    # Generated SSL certificates (gitignored)
│   │   └── .gitkeep
│   ├── wazuh_cluster/
│   │   └── wazuh_manager.conf      # Wazuh Manager ossec.conf
│   ├── wazuh_indexer/
│   │   ├── wazuh.indexer.yml       # OpenSearch configuration
│   │   └── internal_users.yml      # Indexer users with password hashes
│   └── wazuh_dashboard/
│       ├── opensearch_dashboards.yml
│       └── wazuh.yml               # Dashboard → Manager API connection
│
├── src/wazuh_mcp/
│   ├── config.py                   # WazuhSettings (pydantic-settings, reads .env)
│   ├── auth.py                     # JWTManager — authentication and cache
│   ├── client.py                   # WazuhClient — HTTP with retry and clean_params
│   ├── server.py                   # FastMCP server, module registration
│   └── tools/                      # 19 modules (177 tools)
│       ├── agents.py               # 30 tools
│       ├── manager.py              # 18 tools
│       ├── security.py             # 31 tools
│       ├── rules.py                #  7 tools
│       ├── decoders.py             #  6 tools
│       ├── cluster.py              # 23 tools
│       ├── syscheck.py             #  4 tools
│       ├── syscollector.py         # 13 tools
│       ├── groups.py               #  8 tools
│       ├── mitre.py                #  7 tools
│       ├── sca.py                  #  2 tools
│       ├── rootcheck.py            #  4 tools
│       ├── lists.py                #  5 tools
│       ├── logtest.py              #  2 tools
│       ├── active_response.py      #  1 tool
│       ├── ciscat.py               #  1 tool
│       ├── events.py               #  1 tool
│       ├── overview.py             #  1 tool
│       └── experimental.py         # 12 tools
│
├── tests/
│   ├── conftest.py                 # Fixtures: mock_client, wazuh_api (respx)
│   ├── test_*.py                   # 165 unit tests (19 modules + client)
│   └── test_auth_live.py           # Integration tests (require Docker)
│
└── scripts/
    ├── wait-for-wazuh.sh           # Polls until the API is available
    └── setup-claude-desktop.sh     # Installs the MCP in Claude Desktop
```

---

## Quick start

### Step 0 — Clone and install

```bash
git clone <repo-url>
cd wazuh-mcp
make install
cp .env.example .env
```

The `.env.example` already includes the correct values for this repo's Docker setup.
**Do not edit `.env` if you are using the local stack.**

---

### Step 1 — Configure Linux (Linux only)

#### Linux: vm.max_map_count

The OpenSearch indexer requires the kernel to allow more VMAs:

```bash
# Temporary (lost on reboot)
sudo sysctl -w vm.max_map_count=262144

# Permanent (append to /etc/sysctl.conf)
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
```

On **macOS and Windows** with Docker Desktop this is **not necessary**.

---

### Step 2 — Generate SSL certificates

Only the first time (or if you want to regenerate the certificates):

```bash
make certs
```

This runs the official Wazuh certificate generator and creates certificates in
`config/wazuh_indexer_ssl_certs/`. The certificates are self-signed and used
for internal communication between containers.

---

### Step 3 — Start the Wazuh stack

```bash
make docker-up
```

This starts the three services and waits until the API is available:

```
Starting Wazuh stack (manager + indexer + dashboard)...
Note: first start takes ~3-4 minutes.
....................
✓ Wazuh API available (42 attempt(s)).

  Dashboard: https://localhost
  REST API:  https://localhost:55000
  User:      admin / SecretPassword  (dashboard)
  User:      wazuh-wui / MyS3cr37P450r.*-  (REST API / MCP)
```

> **First time:** Docker downloads ~2 GB of images and the indexer takes ~2-3 minutes
> to initialize. Subsequent runs are faster (~60-90 seconds).

---

### Step 4 — Install the MCP in Claude Desktop

```bash
source .venv/bin/activate
make setup-claude-desktop
```

Restart Claude Desktop. Type in the chat:
```
Call ping_wazuh and tell me the Wazuh version that is running.
```

---

### Step 5 (optional) — Development mode with hot-reload

```bash
source .venv/bin/activate
make dev
```

This opens the FastMCP web inspector where you can test tools manually.

---

### Alternative: Everything in Docker (MCP included)

If you prefer to run the MCP in Docker too and expose it over HTTP:

```bash
make certs          # if not done yet
make mcp-docker     # starts manager + indexer + dashboard + MCP (HTTP :8000)
```

You can then connect Claude Desktop directly to the HTTP URL:
```json
{
  "mcpServers": {
    "wazuh": { "url": "http://localhost:8000/mcp/" }
  }
}
```

---

## Claude Desktop integration

### Automatic installation (recommended)

```bash
source .venv/bin/activate
make setup-claude-desktop
# → Restart Claude Desktop
```

### Manual installation

Edit the Claude Desktop configuration file:
- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux:** `~/.config/Claude/claude_desktop_config.json`

**Option A — Local MCP (stdio):**

```json
{
  "mcpServers": {
    "wazuh": {
      "command": "/ABSOLUTE/PATH/wazuh-mcp/.venv/bin/fastmcp",
      "args": ["run", "src/wazuh_mcp/server.py"],
      "cwd": "/ABSOLUTE/PATH/wazuh-mcp",
      "env": {
        "WAZUH_HOST": "localhost",
        "WAZUH_PORT": "55000",
        "WAZUH_USER": "wazuh-wui",
        "WAZUH_PASSWORD": "MyS3cr37P450r.*-",
        "WAZUH_VERIFY_SSL": "false"
      }
    }
  }
}
```

**Option B — MCP in Docker (HTTP, requires `make mcp-docker`):**

```json
{
  "mcpServers": {
    "wazuh": {
      "url": "http://localhost:8000/mcp/"
    }
  }
}
```

---

## Claude Code integration

```bash
# From the project root, with the venv active:
source .venv/bin/activate

fastmcp install claude-code src/wazuh_mcp/server.py \
  --name wazuh \
  --env-file .env \
  --with-editable .
```

Or in MCP HTTP mode (if using `make mcp-docker`):
```bash
# In your project's .claude/settings.json:
# {
#   "mcpServers": {
#     "wazuh": { "url": "http://localhost:8000/mcp/" }
#   }
# }
```

---

## Credentials and access

| Service | URL | User | Password |
|----------|-----|---------|-----------|
| **Dashboard** (web UI) | `https://localhost` | `admin` | `SecretPassword` |
| **REST API** (MCP and tools) | `https://localhost:55000` | `wazuh-wui` | `MyS3cr37P450r.*-` |
| **Indexer** (OpenSearch) | `https://localhost:9200` | `admin` | `SecretPassword` |
| **MCP HTTP** (if `mcp` profile) | `http://localhost:8000/mcp/` | — | — |

> **Development** credentials — do not use in production.
> See [Changing passwords](#changing-passwords) to harden them.

### Changing passwords

To change `SecretPassword` (indexer) or `MyS3cr37P450r.*-` (API):

1. **Indexer** (`SecretPassword`): the hash in `config/wazuh_indexer/internal_users.yml`
   must be updated with `bcrypt`. Use the container tool:
   ```bash
   docker exec -it wazuh.indexer /bin/bash
   /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh
   ```
   Copy the generated hash into `internal_users.yml` for the `admin` user.
   Also update `INDEXER_PASSWORD` in `.env` and docker-compose.yml.

2. **REST API** (`MyS3cr37P450r.*-`): change `WAZUH_PASSWORD` in `.env`.
   The Manager applies it on startup via `API_PASSWORD`.

3. Restart the stack: `make docker-down && make docker-up`

---

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `WAZUH_HOST` | `localhost` | Wazuh Manager hostname |
| `WAZUH_PORT` | `55000` | REST API port |
| `WAZUH_USER` | `wazuh-wui` | REST API user |
| `WAZUH_PASSWORD` | `MyS3cr37P450r.*-` | REST API password |
| `WAZUH_VERIFY_SSL` | `false` | `false` for dev, `true` or CA bundle for prod |
| `JWT_REFRESH_MARGIN` | `60` | Seconds before expiry to renew JWT |
| `REQUEST_TIMEOUT` | `30` | HTTP timeout per request (seconds) |
| `MAX_RETRIES` | `3` | Retries with backoff on transient errors |
| `INDEXER_PASSWORD` | `SecretPassword` | Indexer admin password (OpenSearch) |
| `MCP_TRANSPORT` | `stdio` | `stdio` (local) or `http` (Docker) |
| `MCP_HOST` | `0.0.0.0` | Listening host when `MCP_TRANSPORT=http` |
| `MCP_PORT` | `8000` | Port when `MCP_TRANSPORT=http` |

---

## Makefile commands

```bash
# ── Setup ─────────────────────────────────────────────────────────────────────
make install               # Creates .venv and installs the package in editable mode

# ── Certificates (required before first docker-up) ────────────────────────────
make certs                 # Generates SSL certificates for the Wazuh stack

# ── Wazuh Stack (Manager + Indexer + Dashboard) ───────────────────────────────
make docker-up             # Starts the stack and waits for the API to be healthy
make docker-down           # Stops the containers (data preserved)
make docker-status         # Status of the 3 containers
make docker-logs           # Real-time logs from all services
make docker-logs-manager   # Manager logs only
make docker-logs-indexer   # Indexer logs only
make docker-logs-dashboard # Dashboard logs only
make docker-reset          # DESTRUCTIVE: removes containers AND volumes (data)

# ── Full stack + MCP Server in Docker ─────────────────────────────────────────
make mcp-docker            # Starts everything + MCP HTTP on :8000 (rebuilds image)
make mcp-docker-down       # Stops the full stack including MCP

# ── Local MCP (development) ───────────────────────────────────────────────────
make dev                   # MCP with hot-reload and web inspector (FastMCP dev)
make run                   # MCP in production mode (stdio)

# ── Tests ─────────────────────────────────────────────────────────────────────
make test                  # Unit tests (~2 seconds, no Docker)
make test-integration      # Tests against a live Wazuh instance (requires make docker-up)
make test-all              # All tests

# ── Quality ───────────────────────────────────────────────────────────────────
make lint                  # Check Python syntax for all modules

# ── Claude Desktop ────────────────────────────────────────────────────────────
make setup-claude-desktop  # Installs the MCP in Claude Desktop automatically

# ── Cleanup ───────────────────────────────────────────────────────────────────
make clean                 # Removes __pycache__, .pyc, .egg-info
```

---

## Available tools

**177 tools** in 19 modules + `ping_wazuh`.

| Module | Tools | Description | Main operations |
|--------|------:|-------------|------------------------|
| `agents` | 30 | Agent management | List, create, restart, update, delete, assign groups, upgrade |
| `manager` | 18 | Wazuh Manager | Configuration, logs, statistics, status, validate config, restart |
| `security` | 31 | RBAC and users | Users, roles, policies, RBAC rules, tokens, security config |
| `cluster` | 23 | Wazuh Cluster | Nodes, status, healthcheck, configuration, logs, statistics |
| `syscollector` | 13 | Per-agent inventory | OS, hardware, packages, processes, ports, network interfaces, hotfixes |
| `rules` | 7 | Detection rules | List, files, groups, requirements (PCI-DSS, HIPAA, GDPR, NIST…) |
| `mitre` | 7 | MITRE ATT&CK | Techniques, tactics, APT groups, software, mitigations, references |
| `groups` | 8 | Agent groups | Create, delete, configure, list agents and group files |
| `decoders` | 6 | Log decoders | List, files, parent decoders |
| `syscheck` | 4 | File Integrity Monitoring | FIM results, last scan, clear, run scan |
| `rootcheck` | 4 | Rootkit detection | Results, last scan, clear, run scan |
| `lists` | 5 | CDB lists | List, read, update and delete Constant Database lists |
| `sca` | 2 | Security Config Assessment | Evaluated CIS policies, individual checks (passed/failed) |
| `logtest` | 2 | Log testing | Test logs against rules/decoders, manage sessions |
| `experimental` | 12 | Multi-agent (experimental) | Hardware, OS, packages, processes, ports, network and hotfixes across all agents; bulk clear of rootcheck and syscheck |
| `active_response` | 1 | Active Response | Execute scripts on agents (firewall-drop, restart-wazuh…) |
| `ciscat` | 1 | CIS-CAT | CIS-CAT results per agent (requires CIS-CAT license) |
| `events` | 1 | Ingest | Send events directly to the Manager |
| `overview` | 1 | Dashboard | Executive summary of all agents |
| `(built-in)` | 1 | `ping_wazuh` | Check connectivity and Manager version |
| **Total** | **177** | | |

### Usage examples with Claude

<details>
<summary><strong>Infrastructure inventory and status</strong></summary>

```
"Give me a summary of all my agents' status"
→ get_agents_overview, list_agents

"What operating system versions do my agents have?"
→ get_all_agents_os, get_agents_summary_os

"Show me the installed packages on agent 001"
→ get_agent_packages(agent_id="001")

"What ports are open on my servers?"
→ get_all_agents_ports(protocol="tcp", state="listening")

"Are there any disconnected agents?"
→ list_agents(status="disconnected")
```

</details>

<details>
<summary><strong>Security and compliance</strong></summary>

```
"What is the CIS compliance score for my agents?"
→ get_sca_results(agent_id="001")

"Show me failed CIS checks on agent 001"
→ get_sca_policy_checks(agent_id="001", policy_id="cis_ubuntu20-04", result="failed")

"Are there any rootkits detected on any agent?"
→ get_rootcheck_results(agent_id="001", status="outstanding")

"What MITRE techniques are covered by Wazuh rules?"
→ list_mitre_techniques()
→ list_rules()
```

</details>

<details>
<summary><strong>Security operations (SOAR)</strong></summary>

```
"Test this syslog: 'Dec 25 10:00:00 host sshd: Failed password for root'"
→ run_logtest(event="...", log_format="syslog", location="/var/log/auth.log")

"Block IP 192.168.1.100 on agent 001"
→ run_active_response(command="firewall-drop", agents_list="001",
                       alert={"data": {"srcip": "192.168.1.100"}})

"Run a FIM scan on all agents in the 'production' group"
→ run_syscheck_scan(agents_list="001,002,003")
```

</details>

<details>
<summary><strong>Administration</strong></summary>

```
"Create a user called 'analyst' with the read-only policy"
→ create_user(username="analyst", password="...")
→ list_policies()
→ add_policies_to_role(...)

"What is the Manager's active configuration?"
→ get_manager_active_configuration()

"Show me the last Manager logs"
→ get_manager_logs(limit=50)

"Is the cluster synchronized?"
→ get_cluster_ruleset_sync_status()
```

</details>

---

## Technical architecture

### Request flow

```
Claude calls list_agents(status="active", limit=10)
    │
    ▼
tools/agents.py :: list_agents()
    │  params = {"status": "active", "limit": 10}
    ▼
WazuhClient.get("/agents", params=...)         ← client.py
    │  _clean_params() → removes None values
    │  get_token()     → JWTManager (cache 900s or re-auth)
    │  httpx.AsyncClient.request(GET /agents?status=active&limit=10)
    │
    │  Status 429/502/503/504? → sleep(2^attempt + jitter) → retry
    │  Status 401?             → invalidate() → retry with new token
    │  ConnectError/Timeout?   → sleep(2^attempt + jitter) → retry
    │
    ▼
Wazuh REST API https://localhost:55000/agents
    │
    ▼
dict {"data": {"affected_items": [...], "total_affected_items": N}, "error": 0}
    │
    ▼
Claude receives the result and presents it to the user
```

### Docker service dependencies

```
wazuh.indexer ──healthy──► wazuh.dashboard
wazuh.manager ──healthy──► wazuh.dashboard
wazuh.manager ──healthy──► wazuh-mcp       (mcp profile)
```

The Dashboard waits for both the indexer and manager to be healthy.
The MCP only needs the manager (it does not need the indexer or dashboard).

---

## Development

### Running tests

```bash
# Unit tests only (no Docker, ~2 seconds)
make test

# With integration tests (requires the stack running)
make docker-up
make test-integration

# All at once
make test-all

# A specific test
source .venv/bin/activate
PYTHONPATH=src pytest tests/test_sca.py -v
```

### Adding a new module

1. Create `src/wazuh_mcp/tools/my_module.py`:

```python
from __future__ import annotations
from typing import Optional
from fastmcp import FastMCP
from ..client import WazuhClient

def register(mcp: FastMCP, client: WazuhClient) -> None:

    @mcp.tool()
    async def my_tool(agent_id: str, limit: Optional[int] = None) -> dict:
        """
        Description of what the tool does.

        Args:
            agent_id: Agent ID with zero-padding (e.g. '001').
            limit: Maximum number of results to return.

        Returns:
            data.affected_items: List of items with their fields.
        """
        params = {"limit": limit} if limit is not None else None
        return await client.get(f"/my-endpoint/{agent_id}", params=params)
```

2. Register in `src/wazuh_mcp/server.py`:
```python
from .tools import ..., my_module
# Add my_module to the for loop at the end of the file
```

3. Create `tests/test_my_module.py` following the pattern of existing tests.

4. Verify:
```bash
make lint && make test
```

### Code conventions

- **Optional parameters**: always `Optional[type] = None`.
- **Never send `None` to the API**: use the dict comprehension pattern with `if v is not None`.
- **Docstrings**: `Args:` section for each parameter, `Returns:` with the actual structure.
- **Destructive operations**: prefix the docstring with `DESTRUCTIVE:` or `CAUTION:`.
- **No unnecessary comments**: only when the "why" is not obvious from the code.

---

## Troubleshooting

### Certificates not found when running `make docker-up`

```
ERROR: SSL certificates not found in config/wazuh_indexer_ssl_certs/
Run first: make certs
```

**Solution:**
```bash
make certs
make docker-up
```

### Indexer not starting / `unhealthy` status

The indexer (OpenSearch) is the most demanding service and requires:
1. At least 4 GB of RAM available for Docker
2. On Linux: `vm.max_map_count >= 262144`

```bash
# View indexer logs
docker compose logs wazuh.indexer

# Verify it responds (may take 2-3 min)
curl -sk -u admin:SecretPassword https://localhost:9200/_cluster/health

# On Linux, adjust vm.max_map_count
sudo sysctl -w vm.max_map_count=262144
```

If Docker Desktop has little RAM assigned: go to Settings → Resources → Memory and increase to at least 8 GB.

### Dashboard shows indexer connection error

The dashboard needs the indexer to be healthy. The first startup can take 3-4 minutes in total.

```bash
# Status of all services
make docker-status

# Wait actively
make wait-for-wazuh
```

### 401 error when calling tools from the MCP

The credentials in `.env` do not match those in docker-compose.

**With this repo's stack, `.env` must have:**
```env
WAZUH_USER=wazuh-wui
WAZUH_PASSWORD=MyS3cr37P450r.*-
```

Do not use `admin/SecretPassword` for the MCP — those are indexer credentials, not REST API credentials.

### Claude Desktop does not detect the MCP

1. Validate the configuration JSON (syntax errors are silent):
   ```bash
   cat "~/Library/Application Support/Claude/claude_desktop_config.json" | python3 -m json.tool
   ```

2. Check that the path to the venv is correct and absolute:
   ```bash
   ls /ABSOLUTE/PATH/wazuh-mcp/.venv/bin/fastmcp
   ```

3. Test the server manually:
   ```bash
   source .venv/bin/activate
   fastmcp run src/wazuh_mcp/server.py
   # Should start without errors
   ```

4. Fully restart Claude Desktop (Cmd+Q on macOS, don't just close the window).

### `make docker-reset` — delete everything and start fresh

```bash
make docker-reset       # asks for confirmation
make certs              # regenerate certificates (optional, previous ones still valid)
make docker-up
```

### Integration tests fail with `Connection refused`

```bash
# The stack must be running before the tests
make docker-up          # wait until it prints "✓ Wazuh API available"
make test-integration
```

### `make lint` fails with Xcode error (macOS)

```bash
# Direct alternative, without make
source .venv/bin/activate
python -m py_compile src/wazuh_mcp/server.py && echo OK
```

---

## License

MIT — see [LICENSE](LICENSE) for details.
