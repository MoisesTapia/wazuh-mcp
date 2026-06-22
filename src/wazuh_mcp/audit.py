"""Structured audit logging for Wazuh MCP tool invocations."""
from __future__ import annotations

import functools
import inspect
import json
import logging
import logging.handlers
import re
import time
from typing import Any, Callable

# Matches parameter names that contain sensitive words (case-insensitive).
_SENSITIVE_RE = re.compile(r"password|token|secret|key|credential", re.IGNORECASE)

# Matches docstring markers used to flag destructive tools.
_DESTRUCTIVE_RE = re.compile(r"DESTRUCTIVE:|CAUTION:")

# Module-level singleton; set by configure_audit().
_audit_logger: AuditLogger | None = None


# ── Helpers ───────────────────────────────────────────────────────────────────


def _redact(value: Any, key: str = "") -> Any:
    """Recursively redact values whose parameter name matches the sensitive pattern."""
    if key and _SENSITIVE_RE.search(key):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {k: _redact(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


def _is_destructive(fn: Callable) -> bool:
    """Return True if the function's docstring contains DESTRUCTIVE: or CAUTION:."""
    doc = inspect.getdoc(fn) or ""
    return bool(_DESTRUCTIVE_RE.search(doc))


# ── AuditLogger ───────────────────────────────────────────────────────────────


class AuditLogger:
    """
    Thin wrapper around a stdlib logger that emits one JSON line per tool call.

    Handlers are rebuilt on every instantiation so that configure_audit() can be
    called multiple times (e.g. in tests) without accumulating duplicate handlers.
    """

    def __init__(self, log_level: str, log_file: str | None, enabled: bool) -> None:
        self.enabled = enabled
        self._logger = logging.getLogger("wazuh_mcp.audit")

        # Clear any previously installed handlers before reconfiguring.
        self._logger.handlers.clear()
        self._logger.propagate = False
        self._logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))

        fmt = logging.Formatter("%(message)s")

        stderr_handler = logging.StreamHandler()
        stderr_handler.setFormatter(fmt)
        self._logger.addHandler(stderr_handler)

        if log_file:
            file_handler = logging.handlers.RotatingFileHandler(
                log_file,
                maxBytes=10 * 1024 * 1024,  # 10 MB per file
                backupCount=5,
                encoding="utf-8",
            )
            file_handler.setFormatter(fmt)
            self._logger.addHandler(file_handler)

    def emit(self, record: dict[str, Any], level: int) -> None:
        """Serialize *record* as a single JSON line at *level*.

        Uses ``"%s"`` as the format string so that any ``%`` characters inside
        the serialized JSON are never interpreted as Python format specifiers.
        """
        if self.enabled:
            self._logger.log(level, "%s", json.dumps(record, default=str))


# ── Public API ────────────────────────────────────────────────────────────────


def configure_audit(settings: Any) -> None:
    """Initialize the global audit logger from *settings*. Call once at server startup."""
    global _audit_logger
    _audit_logger = AuditLogger(
        log_level=settings.log_level,
        log_file=settings.log_file,
        enabled=settings.audit_enabled,
    )


def audit_tool(fn: Callable) -> Callable:
    """Wrap an async tool function with structured audit logging.

    Behaviour:
    - Logs parameters (sensitive fields auto-redacted), outcome, and duration.
    - Emits at WARNING and sets ``"destructive": true`` for tools whose docstring
      contains ``DESTRUCTIVE:`` or ``CAUTION:``.
    - Emits at ERROR (and re-raises) when the tool raises an exception.
    - Is a transparent no-op when the audit logger is disabled or not yet configured.
    - Preserves the original function's ``__name__``, ``__doc__``, ``__annotations__``,
      and ``__signature__`` via ``functools.wraps`` so that FastMCP schema generation
      remains unaffected.
    """
    destructive = _is_destructive(fn)
    log_level = logging.WARNING if destructive else logging.INFO
    # Compute signature once at decoration time, not on every call.
    sig = inspect.signature(fn)

    @functools.wraps(fn)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        logger = _audit_logger
        if logger is None or not logger.enabled:
            return await fn(*args, **kwargs)

        # Bind arguments to parameter names for structured logging.
        try:
            bound = sig.bind(*args, **kwargs)
            bound.apply_defaults()
            params = _redact(dict(bound.arguments))
        except TypeError:
            # Fallback: log whatever kwargs arrived without crashing.
            params = _redact(kwargs)

        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        start = time.monotonic()

        try:
            result = await fn(*args, **kwargs)
            logger.emit(
                {
                    "ts": ts,
                    "tool": fn.__name__,
                    "params": params,
                    "outcome": "success",
                    "duration_ms": round((time.monotonic() - start) * 1000),
                    "destructive": destructive,
                },
                log_level,
            )
            return result

        except Exception as exc:
            logger.emit(
                {
                    "ts": ts,
                    "tool": fn.__name__,
                    "params": params,
                    "outcome": "error",
                    "duration_ms": round((time.monotonic() - start) * 1000),
                    "destructive": destructive,
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                },
                logging.ERROR,
            )
            raise

    return wrapper
