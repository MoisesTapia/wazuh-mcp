"""
Cliente asíncrono para el Wazuh Indexer (OpenSearch/Elasticsearch).

Wazuh 4.8.0+ almacena alertas y vulnerabilidades exclusivamente en el
Indexer (puerto 9200). La Manager REST API (puerto 55000) ya no expone
estos datos.

Índices principales:
  wazuh-alerts-4.x-*              — alertas generadas por el manager
  wazuh-states-vulnerabilities-*  — CVEs detectados por agente
  wazuh-archives-4.x-*           — todos los eventos (sin filtrar)
  wazuh-monitoring-*             — estado histórico de agentes
  wazuh-statistics-*             — métricas de rendimiento
"""
from __future__ import annotations

import asyncio
import copy
import re
from typing import Any

import httpx

from ..config import WazuhSettings

ALERT_INDEX = "wazuh-alerts-4.x-*"
VULN_INDEX = "wazuh-states-vulnerabilities-*"
ARCHIVE_INDEX = "wazuh-archives-4.x-*"
MONITORING_INDEX = "wazuh-monitoring-*"


class IndexerNotConfiguredError(Exception):
    """Lanzada cuando se invoca una tool de Indexer sin WAZUH_INDEXER_HOST."""
    pass


class WazuhIndexerClient:
    """
    Cliente httpx async para el Wazuh Indexer.

    A diferencia del Manager (JWT), el Indexer usa HTTP Basic Auth
    en cada request — sin intercambio de tokens.

    Uso:
        client = WazuhIndexerClient(settings)
        await client.initialize()
        results = await client.search(ALERT_INDEX, query, size=10)
    """

    def __init__(self, settings: WazuhSettings) -> None:
        self._settings = settings
        self._client: httpx.AsyncClient | None = None
        self._lock = asyncio.Lock()

    async def _ensure_initialized(self) -> None:
        """Double-check pattern para inicialización lazy thread-safe."""
        if self._client is not None:
            return
        async with self._lock:
            if self._client is not None:
                return
            await self.initialize()

    async def initialize(self) -> None:
        if not self._settings.indexer_configured:
            raise IndexerNotConfiguredError(
                "WAZUH_INDEXER_HOST no configurado. "
                "Añade WAZUH_INDEXER_HOST=<host> al .env para "
                "habilitar tools de alertas y vulnerabilidades."
            )
        self._client = httpx.AsyncClient(
            base_url=self._settings.indexer_url,
            auth=(
                self._settings.wazuh_indexer_user,
                self._settings.wazuh_indexer_password,
            ),
            verify=self._settings.wazuh_indexer_verify_ssl,
            timeout=self._settings.request_timeout,
        )

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    async def search(
        self,
        index: str,
        query: dict,
        size: int = 10,
        sort: list | None = None,
        source: list | None = None,
        aggs: dict | None = None,
    ) -> dict:
        """
        Ejecuta un query Elasticsearch DSL contra el índice especificado.

        Args:
            index:  Patrón de índice (ej: "wazuh-alerts-4.x-*")
            query:  Query DSL completo (sin envolver en {"query": ...})
            size:   Máximo de hits a devolver (default 10, max 1000)
            sort:   Lista de criterios de ordenación
            source: Campos a incluir en _source (None = todos)
            aggs:   Agregaciones Elasticsearch

        Returns:
            {"hits": {"total": {"value": N}, "hits": [...]}, "aggregations": {...}}
        """
        await self._ensure_initialized()
        body: dict[str, Any] = {"query": query, "size": size}
        if sort:
            body["sort"] = sort
        if source:
            body["_source"] = source
        if aggs:
            body["aggs"] = aggs

        resp = await self._client.post(  # type: ignore[union-attr]
            f"/{index}/_search",
            json=body,
            headers={"Content-Type": "application/json"},
        )
        resp.raise_for_status()
        return resp.json()

    async def count(self, index: str, query: dict) -> int:
        """Devuelve el total de documentos que coinciden con el query."""
        await self._ensure_initialized()
        resp = await self._client.post(  # type: ignore[union-attr]
            f"/{index}/_count",
            json={"query": query},
            headers={"Content-Type": "application/json"},
        )
        resp.raise_for_status()
        return resp.json().get("count", 0)

    async def get_indices(self, pattern: str = "wazuh-*") -> list[dict]:
        """Lista índices disponibles que coinciden con el patrón."""
        await self._ensure_initialized()
        resp = await self._client.get(  # type: ignore[union-attr]
            f"/_cat/indices/{pattern}",
            params={"format": "json", "h": "index,health,status,docs.count,store.size"},
        )
        resp.raise_for_status()
        return resp.json()

    # ── Helpers de query DSL ─────────────────────────────────────────────────────

    @staticmethod
    def time_range_query(hours: int = 24, field: str = "@timestamp") -> dict:
        return {"range": {field: {"gte": f"now-{hours}h", "lte": "now"}}}

    @staticmethod
    def term_query(field: str, value: str | int) -> dict:
        return {"term": {field: value}}

    @staticmethod
    def terms_query(field: str, values: list) -> dict:
        return {"terms": {field: values}}

    @staticmethod
    def match_query(field: str, value: str) -> dict:
        return {"match": {field: value}}

    @staticmethod
    def wildcard_query(field: str, pattern: str) -> dict:
        return {"wildcard": {field: {"value": pattern, "case_insensitive": True}}}

    @staticmethod
    def bool_query(
        must: list | None = None,
        filter: list | None = None,
        should: list | None = None,
        must_not: list | None = None,
    ) -> dict:
        q: dict[str, Any] = {}
        if must:
            q["must"] = must
        if filter:
            q["filter"] = filter
        if should:
            q["should"] = should
        if must_not:
            q["must_not"] = must_not
        return {"bool": q}

    # ── Helpers de redacción de secrets ──────────────────────────────────────────

    _SECRET_FIELDS = frozenset({
        "full_log",
        "data.full_log",
        "data.win.eventdata.commandLine",
        "data.command",
        "data.audit.execve.a0",
    })
    _SECRET_PATTERNS = [
        # Bearer tokens first — must precede the generic 'authorization' pattern
        (r"(?i)Bearer\s+[A-Za-z0-9\-._~+/]+=*", "Bearer [REDACTED]"),
        # password=xxx, passwd=xxx, pwd=xxx
        (r"(?i)(password|passwd|pwd)\s*[=:]\s*\S+", r"\1=[REDACTED]"),
        # token=xxx, api_key=xxx, secret=xxx, authorization=xxx
        (
            r"(?i)(token|api[_-]?key|secret|authorization)\s*[=:]\s*\S+",
            r"\1=[REDACTED]",
        ),
    ]

    def redact_alert(self, alert: dict) -> dict:
        """
        Redacta credentials y tokens en un documento de alerta antes de
        devolverlo al LLM. Modifica una copia, no el original.

        Acepta tanto el hit completo {"_source": {...}} como el doc directo.
        """
        doc = copy.deepcopy(alert)
        # Si el dict tiene _source, procesar _source; si no, procesar el doc directamente
        target = doc.get("_source", doc) if isinstance(doc.get("_source"), dict) else doc
        for field in WazuhIndexerClient._SECRET_FIELDS:
            parts = field.split(".")
            obj = target
            for part in parts[:-1]:
                obj = obj.get(part, {}) if isinstance(obj, dict) else {}
            last = parts[-1]
            if isinstance(obj, dict) and last in obj and isinstance(obj[last], str):
                val = obj[last]
                for pattern, replacement in WazuhIndexerClient._SECRET_PATTERNS:
                    val = re.sub(pattern, replacement, val)
                obj[last] = val
        return doc
