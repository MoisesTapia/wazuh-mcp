# Installation

This guide takes you from a fresh clone to a running Wazuh stack with the MCP
server wired into Claude.

- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Step 0 — Clone and install](#step-0--clone-and-install)
- [Step 1 — Linux kernel setup](#step-1--linux-kernel-setup)
- [Step 2 — Generate SSL certificates](#step-2--generate-ssl-certificates)
- [Step 3 — Start the Wazuh stack](#step-3--start-the-wazuh-stack)
- [Step 4 — Install the MCP in Claude Desktop](#step-4--install-the-mcp-in-claude-desktop)
- [Step 5 — Development mode (optional)](#step-5--development-mode-optional)
- [Alternative: everything in Docker](#alternative-everything-in-docker)

---

## Requirements

| Resource | Minimum | Recommended |
|---------|--------|-------------|
| CPU | 4 cores | 4+ cores |
| RAM | 8 GB | 16 GB |
| Disk | 20 GB free | 50 GB free |
| Python | 3.11+ | 3.12+ |
| Docker Desktop | 4.x+ | Latest version |
| Docker Compose | v2 (`docker compose`) | Latest version |

The Docker stack pins Wazuh **4.9.2** (manager, indexer, dashboard).

> **macOS / Windows:** Docker Desktop manages kernel resources automatically.
> **Linux:** you must set `vm.max_map_count` (see [Step 1](#step-1--linux-kernel-setup)).

---

## Quick start

```bash
git clone <repo-url>
cd wazuh-mcp

make install                 # create .venv and install the package
cp .env.example .env         # fill in credentials

make certs                   # generate SSL certificates (first time only)
make docker-up               # start manager + indexer + dashboard

source .venv/bin/activate
make setup-claude-desktop    # register the MCP in Claude Desktop
```

The steps below explain each command in detail.

---

## Step 0 — Clone and install

```bash
git clone <repo-url>
cd wazuh-mcp
make install
cp .env.example .env
```

`make install` creates a `.venv` and installs the package in editable mode with
its dev dependencies. Then edit `.env` and set at least `WAZUH_USER` and
`WAZUH_PASSWORD` — see [Configuration](configuration.md) for every variable and
the default credentials used by the Docker stack.

---

## Step 1 — Linux kernel setup

### Linux: vm.max_map_count

The OpenSearch indexer requires the kernel to allow more memory-mapped areas:

```bash
# Temporary (lost on reboot)
sudo sysctl -w vm.max_map_count=262144

# Permanent (append to /etc/sysctl.conf)
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
```

On **macOS and Windows** with Docker Desktop this is **not necessary**.

---

## Step 2 — Generate SSL certificates

Only the first time (or when you want to regenerate them):

```bash
make certs
```

This runs the official Wazuh certificate generator and writes self-signed
certificates to `config/wazuh_indexer_ssl_certs/`. They secure internal
communication between the containers (manager ↔ indexer ↔ dashboard).

---

## Step 3 — Start the Wazuh stack

```bash
make docker-up
```

This starts the three services and waits until the REST API is available:

```
Starting Wazuh stack (manager + indexer + dashboard)...
Note: first start takes ~3-4 minutes.
....................
✓ Wazuh API available (42 attempt(s)).

  Dashboard: https://localhost
  REST API:  https://localhost:55000
  User:      admin / SecretPassword       (dashboard)
  User:      wazuh-wui / MyS3cr37P450r.*-  (REST API / MCP)
```

> **First time:** Docker downloads ~2 GB of images and the indexer takes ~2-3
> minutes to initialize. Subsequent runs are faster (~60-90 seconds).

---

## Step 4 — Install the MCP in Claude Desktop

```bash
source .venv/bin/activate
make setup-claude-desktop
```

Restart Claude Desktop, then type in the chat:

```
Call ping_wazuh and tell me the Wazuh version that is running.
```

For manual installation and Claude Code, see
[Claude integration](claude-integration.md).

---

## Step 5 — Development mode (optional)

```bash
source .venv/bin/activate
make dev
```

This opens the FastMCP web inspector where you can test tools manually with
hot-reload. See [Development](development.md) for more.

---

## Alternative: everything in Docker

To run the MCP server inside Docker too and expose it over HTTP:

```bash
# 1. Generate a Bearer key and add it to .env (required — the container
#    refuses to start in HTTP mode without it):
echo "MCP_API_KEY=$(openssl rand -hex 32)" >> .env

make certs          # if not done yet
make mcp-docker     # manager + indexer + dashboard + MCP (HTTP :8000)
```

`docker-compose.yml` reads `MCP_API_KEY` from `.env`. See
[Configuration](configuration.md#mcp-transport) and
[Security model](security.md#http-transport-authentication) before exposing it.

Connect Claude Desktop to the HTTP endpoint:

```json
{
  "mcpServers": {
    "wazuh": {
      "url": "http://localhost:8000/mcp/",
      "headers": { "Authorization": "Bearer <your-mcp-api-key>" }
    }
  }
}
```

---

Next: [Configuration](configuration.md) · [Claude integration](claude-integration.md) · [Troubleshooting](troubleshooting.md)
