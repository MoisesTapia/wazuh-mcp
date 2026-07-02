import pytest

from wazuh_mcp.api import IndexerNotConfiguredError, WazuhIndexerClient
from wazuh_mcp.config import WazuhSettings


@pytest.fixture
def settings_no_indexer() -> WazuhSettings:
    return WazuhSettings(wazuh_user="x", wazuh_password="x")


@pytest.fixture
def idx(settings_no_indexer) -> WazuhIndexerClient:
    return WazuhIndexerClient(settings_no_indexer)


# ── redact_alert ──────────────────────────────────────────────────────────────

def test_redact_alert_does_not_modify_original(idx):
    original = {"_source": {"full_log": "login password=secret123 failed"}}
    original_copy = {"_source": {"full_log": "login password=secret123 failed"}}
    idx.redact_alert(original)
    assert original == original_copy


def test_redact_alert_removes_password(idx):
    alert = {"_source": {"full_log": "login password=secret123 failed"}}
    result = idx.redact_alert(alert)
    assert "secret123" not in result["_source"]["full_log"]
    assert "[REDACTED]" in result["_source"]["full_log"]


def test_redact_alert_removes_bearer_token(idx):
    alert = {"_source": {"full_log": "GET /api Authorization: Bearer eyJhbGc..."}}
    result = idx.redact_alert(alert)
    assert "eyJhbGc" not in result["_source"]["full_log"]


def test_redact_alert_handles_direct_doc(idx):
    """También funciona con un doc plano (sin _source wrapper)."""
    doc = {"full_log": "api_key=supersecret call"}
    result = idx.redact_alert(doc)
    assert "supersecret" not in result["full_log"]
    assert "[REDACTED]" in result["full_log"]


# ── query DSL helpers ─────────────────────────────────────────────────────────

def test_bool_query_helper_builds_correctly(idx):
    q = idx.bool_query(
        must=[idx.term_query("a", "b")],
        filter=[idx.time_range_query(24)],
    )
    assert "bool" in q
    assert q["bool"]["must"] == [{"term": {"a": "b"}}]
    assert q["bool"]["filter"] == [
        {"range": {"@timestamp": {"gte": "now-24h", "lte": "now"}}}
    ]


def test_bool_query_omits_empty_clauses():
    q = WazuhIndexerClient.bool_query(must=[{"term": {"x": "y"}}])
    assert "filter" not in q["bool"]
    assert "should" not in q["bool"]
    assert "must_not" not in q["bool"]


def test_time_range_query_uses_correct_field():
    q = WazuhIndexerClient.time_range_query(hours=48)
    assert "@timestamp" in q["range"]
    assert q["range"]["@timestamp"]["gte"] == "now-48h"
    assert q["range"]["@timestamp"]["lte"] == "now"


def test_time_range_query_custom_field():
    q = WazuhIndexerClient.time_range_query(hours=12, field="event.created")
    assert "event.created" in q["range"]


def test_term_query():
    assert WazuhIndexerClient.term_query("agent.id", "001") == {
        "term": {"agent.id": "001"}
    }


def test_terms_query():
    q = WazuhIndexerClient.terms_query("rule.level", [10, 11, 12])
    assert q == {"terms": {"rule.level": [10, 11, 12]}}


def test_wildcard_query():
    q = WazuhIndexerClient.wildcard_query("agent.name", "web-*")
    assert q["wildcard"]["agent.name"]["value"] == "web-*"
    assert q["wildcard"]["agent.name"]["case_insensitive"] is True


# ── initialize ────────────────────────────────────────────────────────────────

async def test_indexer_not_configured_raises_on_initialize(settings_no_indexer):
    idx = WazuhIndexerClient(settings_no_indexer)
    with pytest.raises(IndexerNotConfiguredError):
        await idx.initialize()


def test_indexer_configured_property():
    s_no = WazuhSettings(wazuh_user="x", wazuh_password="x")
    assert not s_no.indexer_configured
    assert s_no.indexer_url is None

    s_yes = WazuhSettings(
        wazuh_user="x",
        wazuh_password="x",
        wazuh_indexer_host="localhost",
    )
    assert s_yes.indexer_configured
    assert s_yes.indexer_url == "https://localhost:9200"
