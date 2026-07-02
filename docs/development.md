# Development

- [Running tests](#running-tests)
- [Adding a new module](#adding-a-new-module)
- [Code conventions](#code-conventions)

---

## Running tests

The suite has **278 unit tests** (no Docker or network) plus integration tests
that require a live stack.

```bash
# Unit tests only (no Docker, ~3 seconds)
make test

# Integration tests (require the stack running)
make docker-up
make test-integration

# Everything
make test-all

# A specific test
source .venv/bin/activate
PYTHONPATH=src pytest tests/test_sca.py -v
```

Verify every registered tool has a docstring (FastMCP uses it for the schema):

```bash
make check-tools
```

See the [Makefile reference](makefile.md) for all targets.

---

## Adding a new module

### 1. Create the tool module

`src/wazuh_mcp/tools/my_module.py`:

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

> A SOC module that queries the Indexer uses the signature
> `register(mcp, client, indexer)` instead — see `tools/soc_alerts.py`.

### 2. Register it in `server.py`

```python
from .tools import ..., my_module
# Add my_module to the registration loop near the end of the file.
```

Audit logging is injected automatically: `server.py` wraps `mcp.tool` so every
`@mcp.tool()` is transparently decorated with `audit_tool`. You do not need to
add it yourself.

### 3. Add tests

Create `tests/test_my_module.py` following the pattern of existing tests
(they use the `mock_client` / `wazuh_api` fixtures from `conftest.py`, backed by
`respx`).

### 4. Verify

```bash
make lint && make test && make check-tools
```

If you add a module to the source tree, also add it to the `lint` target's file
list in the `Makefile`.

---

## Code conventions

- **Optional parameters**: always `Optional[type] = None`.
- **Never send `None` to the API**: build params with `if v is not None` — the
  client's `_clean_params()` also strips them as a safety net.
- **Docstrings**: an `Args:` entry per parameter and a `Returns:` describing the
  real response structure. FastMCP turns these into the tool schema, so they are
  mandatory (`make check-tools` enforces their presence).
- **Destructive operations**: prefix the docstring with `DESTRUCTIVE:` or
  `CAUTION:`. The audit logger keys off these markers to flag and escalate the
  log level. See [Security model](security.md#audit-logging).
- **External content**: tools that return text ingested from monitored hosts
  should route it through `sanitize.py` (envelope + neutralization).
- **No unnecessary comments**: comment only when the "why" is not obvious.

---

Next: [Architecture](architecture.md) · [Makefile reference](makefile.md)
