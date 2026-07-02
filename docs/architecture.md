# Architecture

- [Project structure](#project-structure)
- [Request flow](#request-flow)
- [Docker service dependencies](#docker-service-dependencies)

---

## Project structure

```
wazuh-mcp/
├── docker-compose.yml              # Full stack: manager + indexer + dashboard + mcp (profile)
├── generate-indexer-certs.yml      # Generates SSL certificates (run once)
├── Dockerfile                      # MCP server image for Docker
├── Makefile                        # All project commands
├── pyproject.toml                  # Python dependencies
├── .env / .env.example             # Credentials and configuration
│
├── docs/                           # This documentation
│
├── config/                         # Static Wazuh stack configuration
│   ├── certs.yml                   # Nodes for the certificate generator
│   ├── wazuh_indexer_ssl_certs/    # Generated SSL certificates (gitignored)
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
│   ├── client.py                   # WazuhClient — HTTP with retry + circuit breaker
│   ├── circuit_breaker.py          # CircuitBreaker — fail-fast on Manager outage
│   ├── audit.py                    # Structured JSON audit logging per tool call
│   ├── sanitize.py                 # Prompt-injection neutralization + secret redaction
│   ├── server.py                   # FastMCP server, auth middleware, module registration
│   ├── api/
│   │   └── wazuh_indexer.py        # WazuhIndexerClient — OpenSearch (SOC data)
│   └── tools/                      # 23 modules (206 tools)
│       ├── agents.py               # 30 tools    manager.py         # 18 tools
│       ├── security.py             # 31 tools    cluster.py         # 23 tools
│       ├── syscollector.py         # 13 tools    experimental.py    # 12 tools
│       ├── groups.py               #  8 tools    rules.py           #  7 tools
│       ├── mitre.py                #  7 tools    decoders.py        #  6 tools
│       ├── lists.py                #  5 tools    syscheck.py        #  4 tools
│       ├── rootcheck.py            #  4 tools    observability.py   #  3 tools
│       ├── sca.py                  #  2 tools    logtest.py         #  2 tools
│       ├── active_response.py      #  1 tool     ciscat.py          #  1 tool
│       ├── events.py               #  1 tool     overview.py        #  1 tool
│       ├── soc_alerts.py           #  7 tools  (Indexer)
│       ├── soc_vulnerabilities.py  #  5 tools  (Indexer)
│       └── active_response_soc.py  # 14 tools  (SOAR)
│
├── tests/
│   ├── conftest.py                 # Fixtures: mock_client, wazuh_api (respx)
│   ├── test_*.py                   # 278 unit tests
│   └── test_auth_live.py           # Integration tests (require Docker)
│
└── scripts/
    ├── wait-for-wazuh.sh           # Polls until the API is available
    ├── check_tools.py              # Verifies every registered tool has a docstring
    └── setup-claude-desktop.sh     # Installs the MCP in Claude Desktop
```

---

## Request flow

### Manager tool (REST API)

```
Claude calls list_agents(status="active", limit=10)
    │
    ▼
tools/agents.py :: list_agents()
    │  params = {"status": "active", "limit": 10}
    ▼
WazuhClient.get("/agents", params=...)          ← client.py
    │  audit_tool()   → log call (secrets redacted)
    │  _clean_params()→ drop None values
    │  get_token()    → JWTManager (cached ~900s, or re-auth)
    │  CircuitBreaker.call(...) → fail fast if Manager is down
    │  httpx GET /agents?status=active&limit=10
    │
    │  429/502/503/504? → sleep(2^attempt + jitter) → retry
    │  401?             → invalidate() → retry with new token
    │  ConnectError?    → sleep(backoff) → retry
    ▼
Wazuh REST API https://localhost:55000/agents
    ▼
{"data": {"affected_items": [...], "total_affected_items": N}, "error": 0}
    ▼
Claude receives the result
```

### SOC tool (Indexer)

```
Claude calls get_critical_alerts(hours=6)
    │
    ▼
tools/soc_alerts.py :: get_critical_alerts()
    │  builds Elasticsearch DSL via WazuhIndexerClient helpers
    ▼
WazuhIndexerClient.search(ALERT_INDEX, query, ...)   ← api/wazuh_indexer.py
    │  HTTP Basic Auth (no JWT)
    │  redact_alert() → strip secrets from each hit
    ▼
Wazuh Indexer https://localhost:9200/wazuh-alerts-4.x-*/_search
    ▼
sanitized alert documents → Claude
```

If the Indexer is not configured, SOC tools short-circuit with a
`not_configured` response — see [SOC & SOAR](soc.md#graceful-degradation).

---

## Docker service dependencies

```
wazuh.indexer ──healthy──► wazuh.dashboard
wazuh.manager ──healthy──► wazuh.dashboard
wazuh.manager ──healthy──► wazuh-mcp       (mcp profile)
```

- The **Dashboard** waits for both the indexer and manager to be healthy.
- The **MCP** only depends on the manager. When run in Docker it also connects
  to the indexer for SOC tools, but the indexer is not a hard dependency —
  SOC tools degrade gracefully if it is unreachable.

All images are pinned to Wazuh **4.9.2** in `docker-compose.yml`.

---

Next: [Security model](security.md) · [Development](development.md)
