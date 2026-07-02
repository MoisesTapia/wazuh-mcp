"""
Circuit breaker para WazuhClient.

Estados:
  CLOSED  -> operacion normal, requests pasan
  OPEN    -> Wazuh caido, requests fallan inmediatamente sin intentar
  HALF    -> periodo de prueba, se deja pasar UNA request para probar

Transiciones:
  CLOSED -> OPEN:   cuando failure_threshold requests consecutivas fallan
  OPEN   -> HALF:   despues de recovery_timeout segundos
  HALF   -> CLOSED: si la request de prueba tiene exito
  HALF   -> OPEN:   si la request de prueba falla
"""
from __future__ import annotations

import asyncio
import time
import logging
from enum import Enum
from typing import Awaitable, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")


class CircuitState(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF = "half_open"


class CircuitBreakerOpen(Exception):
    """Lanzada cuando el circuit breaker esta OPEN."""

    def __init__(self, service: str, retry_after: float):
        self.service = service
        self.retry_after = retry_after
        super().__init__(
            f"Circuit breaker OPEN para {service}. "
            f"Reintenta en {retry_after:.0f}s. "
            f"Wazuh puede estar caido o sin conexion."
        )


class CircuitBreaker:
    """
    Circuit breaker thread-safe con asyncio.Lock.

    Args:
        name:               Nombre del servicio (para logs)
        failure_threshold:  Fallos consecutivos para abrir el circuito
        recovery_timeout:   Segundos en OPEN antes de probar HALF_OPEN
        half_open_timeout:  Segundos maximos en HALF_OPEN antes de volver a OPEN
    """

    def __init__(
        self,
        name: str = "wazuh",
        failure_threshold: int = 5,
        recovery_timeout: float = 60.0,
        half_open_timeout: float = 10.0,
    ):
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_timeout = half_open_timeout

        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._last_failure_time: float = 0.0
        self._half_open_since: float = 0.0
        self._lock = asyncio.Lock()

        # Metricas basicas
        self.total_requests = 0
        self.total_failures = 0
        self.total_circuit_opens = 0

    @property
    def state(self) -> CircuitState:
        return self._state

    @property
    def is_open(self) -> bool:
        return self._state == CircuitState.OPEN

    async def call(self, coro: Awaitable[T]) -> T:
        """
        Ejecuta un coroutine a traves del circuit breaker.

        Uso:
            result = await cb.call(client.get("/agents"))

        Raises:
            CircuitBreakerOpen: si el circuito esta OPEN
            Exception: cualquier excepcion del coro (registrada como fallo)
        """
        async with self._lock:
            await self._maybe_transition()

            if self._state == CircuitState.OPEN:
                retry_after = max(
                    0.0,
                    self.recovery_timeout - (time.monotonic() - self._last_failure_time),
                )
                raise CircuitBreakerOpen(self.name, retry_after)

            self.total_requests += 1

        try:
            result = await coro
            async with self._lock:
                await self._on_success()
            return result
        except Exception as exc:
            async with self._lock:
                await self._on_failure(exc)
            raise

    async def _maybe_transition(self) -> None:
        """Evalua si hay que cambiar de estado. Llamar con self._lock."""
        if self._state == CircuitState.OPEN:
            elapsed = time.monotonic() - self._last_failure_time
            if elapsed >= self.recovery_timeout:
                self._state = CircuitState.HALF
                self._half_open_since = time.monotonic()
                logger.info(
                    "Circuit breaker [%s] OPEN -> HALF_OPEN (elapsed %.0fs)",
                    self.name, elapsed,
                )

        elif self._state == CircuitState.HALF:
            elapsed = time.monotonic() - self._half_open_since
            if elapsed >= self.half_open_timeout:
                # Tardo demasiado en probar -> volver a OPEN
                self._state = CircuitState.OPEN
                self._last_failure_time = time.monotonic()
                logger.warning(
                    "Circuit breaker [%s] HALF_OPEN -> OPEN (timeout)",
                    self.name,
                )

    async def _on_success(self) -> None:
        """Llamar con self._lock."""
        if self._state == CircuitState.HALF:
            logger.info(
                "Circuit breaker [%s] HALF_OPEN -> CLOSED (recovery OK)",
                self.name,
            )
        self._state = CircuitState.CLOSED
        self._failure_count = 0

    async def _on_failure(self, exc: Exception) -> None:
        """Llamar con self._lock."""
        self.total_failures += 1
        self._failure_count += 1
        self._last_failure_time = time.monotonic()

        if self._state == CircuitState.HALF:
            self._state = CircuitState.OPEN
            self.total_circuit_opens += 1
            logger.warning(
                "Circuit breaker [%s] HALF_OPEN -> OPEN (probe failed: %s)",
                self.name, exc,
            )
        elif (
            self._state == CircuitState.CLOSED
            and self._failure_count >= self.failure_threshold
        ):
            self._state = CircuitState.OPEN
            self.total_circuit_opens += 1
            logger.error(
                "Circuit breaker [%s] CLOSED -> OPEN (%d fallos consecutivos, ultimo: %s)",
                self.name, self._failure_count, exc,
            )

    def get_status(self) -> dict:
        """Estado actual del circuit breaker para /health."""
        return {
            "state": self._state.value,
            "failure_count": self._failure_count,
            "total_requests": self.total_requests,
            "total_failures": self.total_failures,
            "total_circuit_opens": self.total_circuit_opens,
            "last_failure_ago": (
                round(time.monotonic() - self._last_failure_time, 1)
                if self._last_failure_time > 0 else None
            ),
        }

    def reset(self) -> None:
        """Resetea el circuito a CLOSED manualmente. Util para tests."""
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._last_failure_time = 0.0
