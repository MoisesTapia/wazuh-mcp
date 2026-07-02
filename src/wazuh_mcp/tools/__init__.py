"""MCP tool modules for Wazuh endpoints."""

from . import soc_alerts, soc_vulnerabilities

# SOC modules tienen firma distinta: register(mcp, client, indexer)
SOC_MODULES = [soc_alerts, soc_vulnerabilities]

# Active Response SOC (firma: register(mcp, client))
from . import active_response_soc

AR_SOC_MODULE = active_response_soc
