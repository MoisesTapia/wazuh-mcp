import pytest
from fastmcp import FastMCP
from unittest.mock import AsyncMock

from wazuh_mcp.api.wazuh_indexer import WazuhIndexerClient
from wazuh_mcp.tools import soc_alerts


# ── Helpers ───────────────────────────────────────────────────────────────────

def make_alert(level=10, agent="agent-001", rule_id="5712"):
    return {
        "_source": {
            "@timestamp": "2024-01-15T10:30:00Z",
            "agent": {"id": "001", "name": agent},
            "rule": {
                "id": rule_id,
                "level": level,
                "description": "SSH brute force",
                "groups": ["authentication_failed", "sshd"],
                "mitre": {"id": ["T1110"], "tactic": ["Credential Access"]},
            },
            "data": {"srcip": "10.0.1.45"},
        }
    }


def make_es_response(hits, total=None):
    docs = [make_alert(**h) if isinstance(h, dict) else h for h in hits]
    return {
        "hits": {
            "total": {"value": total or len(docs)},
            "hits": docs,
        }
    }


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def mock_indexer():
    indexer = AsyncMock(spec=WazuhIndexerClient)
    # Bind the real redact_alert implementation to the mock object
    indexer.redact_alert = WazuhIndexerClient.redact_alert.__get__(
        indexer, WazuhIndexerClient
    )
    return indexer


@pytest.fixture
async def fns(mock_client, mock_indexer):
    mcp = FastMCP("test")
    soc_alerts.register(mcp, mock_client, mock_indexer)
    tools = await mcp.list_tools()
    result = {}
    for t in tools:
        tool = await mcp.local_provider.get_tool(t.name)
        result[t.name] = tool.fn
    return result


@pytest.fixture
async def fns_no_indexer(mock_client):
    mcp = FastMCP("test")
    soc_alerts.register(mcp, mock_client, None)
    tools = await mcp.list_tools()
    result = {}
    for t in tools:
        tool = await mcp.local_provider.get_tool(t.name)
        result[t.name] = tool.fn
    return result


# ── get_alerts ────────────────────────────────────────────────────────────────

async def test_get_alerts_returns_formatted_response(fns, mock_indexer):
    mock_indexer.search.return_value = make_es_response([{}, {}, {}])
    result = await fns["get_alerts"]()
    assert result["total"] == 3
    assert len(result["alerts"]) == 3
    for alert in result["alerts"]:
        assert "@timestamp" in alert
        assert "rule" in alert
        assert "agent" in alert


async def test_get_alerts_filter_by_level(fns, mock_indexer):
    mock_indexer.search.return_value = make_es_response([{"level": 12}])
    await fns["get_alerts"](level=12)
    call_args = mock_indexer.search.call_args
    query = call_args.args[1]
    # The bool filter should contain a range on rule.level
    query_str = str(query)
    assert "rule.level" in query_str
    assert "gte" in query_str


async def test_get_alerts_filter_by_agent(fns, mock_indexer):
    mock_indexer.search.return_value = make_es_response([{}])
    await fns["get_alerts"](agent_id="001")
    call_args = mock_indexer.search.call_args
    query = call_args.args[1]
    query_str = str(query)
    assert "agent.id" in query_str
    assert "001" in query_str


async def test_get_alerts_query_hours_in_response(fns, mock_indexer):
    mock_indexer.search.return_value = make_es_response([])
    result = await fns["get_alerts"](hours=48)
    assert result["query_hours"] == 48


# ── get_critical_alerts ───────────────────────────────────────────────────────

async def test_get_critical_alerts_uses_level_12(fns, mock_indexer):
    mock_indexer.search.return_value = make_es_response([{"level": 14}])
    await fns["get_critical_alerts"]()
    call_args = mock_indexer.search.call_args
    query = call_args.args[1]
    # Verify filter contains rule.level >= 12
    filter_clauses = query.get("bool", {}).get("filter", [])
    level_filters = [
        f for f in filter_clauses
        if "range" in f and "rule.level" in f["range"]
    ]
    assert len(level_filters) == 1
    assert level_filters[0]["range"]["rule.level"]["gte"] == 12


# ── get_alert_summary ─────────────────────────────────────────────────────────

async def test_get_alert_summary_returns_aggregations(fns, mock_indexer):
    mock_indexer.search.return_value = {
        "hits": {"total": {"value": 150}, "hits": []},
        "aggregations": {
            "levels_dist": {
                "buckets": [{"key": 10, "doc_count": 50}]
            },
            "top_agents": {
                "buckets": [{"key": "web-01", "doc_count": 100}]
            },
            "top_rules": {"buckets": []},
            "top_groups": {"buckets": []},
            "mitre_tactics": {"buckets": []},
        },
    }
    result = await fns["get_alert_summary"]()
    assert result["total_alerts"] == 150
    assert result["by_level"]["10"] == 50
    assert result["top_agents"][0]["agent"] == "web-01"
    assert result["top_agents"][0]["count"] == 100


async def test_get_alert_summary_uses_size_zero(fns, mock_indexer):
    mock_indexer.search.return_value = {
        "hits": {"total": {"value": 0}, "hits": []},
        "aggregations": {
            "levels_dist": {"buckets": []},
            "top_agents": {"buckets": []},
            "top_rules": {"buckets": []},
            "top_groups": {"buckets": []},
            "mitre_tactics": {"buckets": []},
        },
    }
    await fns["get_alert_summary"]()
    call_args = mock_indexer.search.call_args
    # size=0 is passed as keyword arg
    assert call_args.kwargs.get("size") == 0 or call_args.args[2:3] == (0,)


# ── search_alerts ─────────────────────────────────────────────────────────────

async def test_search_alerts_text_search(fns, mock_indexer):
    mock_indexer.search.return_value = make_es_response([])
    await fns["search_alerts"](query_string="ssh AND brute")
    call_args = mock_indexer.search.call_args
    query = call_args.args[1]
    # query_string clause should be in 'must'
    must_clauses = query.get("bool", {}).get("must", [])
    qs_clauses = [m for m in must_clauses if "query_string" in m]
    assert len(qs_clauses) == 1
    assert qs_clauses[0]["query_string"]["query"] == "ssh AND brute"


async def test_search_alerts_returns_query_string_in_response(fns, mock_indexer):
    mock_indexer.search.return_value = make_es_response([])
    result = await fns["search_alerts"](query_string="rule.level:>=10")
    assert result["query_string"] == "rule.level:>=10"


# ── redact_alert ──────────────────────────────────────────────────────────────

def test_redact_alert_removes_password(mock_indexer):
    alert = {"_source": {"full_log": "login password=secret123 failed"}}
    result = mock_indexer.redact_alert(alert)
    assert "secret123" not in result["_source"]["full_log"]
    assert "[REDACTED]" in result["_source"]["full_log"]


def test_redact_alert_removes_bearer_token(mock_indexer):
    alert = {"_source": {"full_log": "GET /api Authorization: Bearer eyJhbGc..."}}
    result = mock_indexer.redact_alert(alert)
    assert "eyJhbGc" not in result["_source"]["full_log"]


# ── degradación graceful sin Indexer ─────────────────────────────────────────

async def test_indexer_not_configured_returns_error(fns_no_indexer):
    result = await fns_no_indexer["get_alerts"]()
    assert "error" in result or "not_configured" in result


async def test_indexer_not_configured_critical_alerts(fns_no_indexer):
    result = await fns_no_indexer["get_critical_alerts"]()
    assert "error" in result or "not_configured" in result


# ── get_top_threats ───────────────────────────────────────────────────────────

async def test_get_top_threats_calculates_score(fns, mock_indexer):
    mock_indexer.search.return_value = {
        "hits": {"total": {"value": 60}, "hits": []},
        "aggregations": {
            "top_rules": {
                "buckets": [
                    {
                        "key": "rule_A",
                        "doc_count": 10,
                        "max_level": {"value": 12.0},
                        "sample_desc": {"buckets": [{"key": "Auth failure"}]},
                    },
                    {
                        "key": "rule_B",
                        "doc_count": 50,
                        "max_level": {"value": 5.0},
                        "sample_desc": {"buckets": [{"key": "Port scan"}]},
                    },
                ]
            }
        },
    }
    result = await fns["get_top_threats"]()
    assert isinstance(result, list)
    assert len(result) == 2
    # rule_A: 10*12=120, rule_B: 50*5=250 → B first
    assert result[0]["rule_id"] == "rule_B"
    assert result[0]["score"] == 250
    assert result[1]["rule_id"] == "rule_A"
    assert result[1]["score"] == 120


async def test_get_top_threats_respects_limit(fns, mock_indexer):
    buckets = [
        {
            "key": f"rule_{i}",
            "doc_count": 10 - i,
            "max_level": {"value": 10.0},
            "sample_desc": {"buckets": [{"key": "desc"}]},
        }
        for i in range(10)
    ]
    mock_indexer.search.return_value = {
        "hits": {"total": {"value": 100}, "hits": []},
        "aggregations": {"top_rules": {"buckets": buckets}},
    }
    result = await fns["get_top_threats"](limit=3)
    assert len(result) <= 3


# ── get_agent_alert_timeline ──────────────────────────────────────────────────

async def test_get_agent_alert_timeline_structure(fns, mock_indexer):
    mock_indexer.search.return_value = {
        "hits": {"total": {"value": 5}, "hits": []},
        "aggregations": {
            "timeline": {
                "buckets": [
                    {
                        "key_as_string": "2024-01-15T10:00:00.000Z",
                        "doc_count": 3,
                        "max_level": {"value": 10.0},
                    },
                    {
                        "key_as_string": "2024-01-15T11:00:00.000Z",
                        "doc_count": 2,
                        "max_level": {"value": 12.0},
                    },
                ]
            }
        },
    }
    result = await fns["get_agent_alert_timeline"](agent_id="001")
    assert result["agent_id"] == "001"
    assert result["total"] == 5
    assert len(result["timeline"]) == 2
    assert result["timeline"][0]["count"] == 3
    assert result["timeline"][1]["max_level"] == 12
