import asyncio
import time

import pytest

from wazuh_mcp.circuit_breaker import CircuitBreaker, CircuitBreakerOpen, CircuitState
from wazuh_mcp.client import WazuhAPIError


def test_circuit_breaker_starts_closed():
    cb = CircuitBreaker("test")
    assert cb.state == CircuitState.CLOSED
    assert cb.is_open is False


async def test_successful_call_passes_through():
    cb = CircuitBreaker("test")

    async def ok():
        return {"ok": True}

    result = await cb.call(ok())
    assert result == {"ok": True}
    assert cb.state == CircuitState.CLOSED


async def test_single_failure_stays_closed():
    cb = CircuitBreaker("test", failure_threshold=5)

    async def fail():
        raise ConnectionError("timeout")

    with pytest.raises(ConnectionError):
        await cb.call(fail())

    assert cb.state == CircuitState.CLOSED
    assert cb._failure_count == 1


async def test_threshold_failures_opens_circuit():
    cb = CircuitBreaker("test", failure_threshold=3)

    async def fail():
        raise ConnectionError("down")

    for _ in range(3):
        with pytest.raises(ConnectionError):
            await cb.call(fail())

    assert cb.state == CircuitState.OPEN
    assert cb.is_open is True
    assert cb.total_circuit_opens == 1


async def test_open_circuit_raises_immediately_without_calling():
    cb = CircuitBreaker("test", failure_threshold=2)
    call_count = 0

    async def counting_fail():
        nonlocal call_count
        call_count += 1
        raise ConnectionError("down")

    for _ in range(2):
        with pytest.raises(ConnectionError):
            await cb.call(counting_fail())

    # Ahora esta OPEN — la siguiente llamada debe fallar sin ejecutar el coro
    with pytest.raises(CircuitBreakerOpen):
        await cb.call(counting_fail())

    assert call_count == 2  # la 3a llamada nunca llego a ejecutarse


async def test_open_circuit_transitions_to_half_open_after_timeout():
    cb = CircuitBreaker("test", failure_threshold=2, recovery_timeout=0.1)

    async def fail():
        raise ConnectionError("down")

    for _ in range(2):
        with pytest.raises(ConnectionError):
            await cb.call(fail())

    assert cb.state == CircuitState.OPEN

    await asyncio.sleep(0.15)

    async with cb._lock:
        await cb._maybe_transition()

    assert cb.state == CircuitState.HALF


async def test_half_open_success_closes_circuit():
    cb = CircuitBreaker("test", failure_threshold=2, recovery_timeout=0.1)

    async def fail():
        raise ConnectionError("down")

    async def ok():
        return "success"

    for _ in range(2):
        with pytest.raises(ConnectionError):
            await cb.call(fail())

    await asyncio.sleep(0.15)

    result = await cb.call(ok())
    assert result == "success"
    assert cb.state == CircuitState.CLOSED
    assert cb._failure_count == 0


async def test_half_open_failure_reopens_circuit():
    cb = CircuitBreaker("test", failure_threshold=2, recovery_timeout=0.1)

    async def fail():
        raise ConnectionError("down")

    for _ in range(2):
        with pytest.raises(ConnectionError):
            await cb.call(fail())

    await asyncio.sleep(0.15)

    with pytest.raises(ConnectionError):
        await cb.call(fail())

    assert cb.state == CircuitState.OPEN
    assert cb.total_circuit_opens == 2


async def test_success_resets_failure_count():
    cb = CircuitBreaker("test", failure_threshold=5)

    async def fail():
        raise ConnectionError()

    async def ok():
        return "ok"

    for _ in range(3):
        with pytest.raises(ConnectionError):
            await cb.call(fail())

    assert cb._failure_count == 3

    await cb.call(ok())
    assert cb._failure_count == 0
    assert cb.state == CircuitState.CLOSED


def test_get_status_returns_correct_info():
    cb = CircuitBreaker("test-service")
    status = cb.get_status()
    assert status["state"] == "closed"
    assert status["failure_count"] == 0
    assert status["total_requests"] == 0


async def test_reset_closes_open_circuit():
    cb = CircuitBreaker("test", failure_threshold=1)

    async def fail():
        raise ConnectionError()

    with pytest.raises(ConnectionError):
        await cb.call(fail())

    assert cb.state == CircuitState.OPEN

    cb.reset()
    assert cb.state == CircuitState.CLOSED
    assert cb._failure_count == 0


async def test_circuit_breaker_open_exception_has_retry_after():
    cb = CircuitBreaker("test", failure_threshold=1, recovery_timeout=30.0)

    async def fail():
        raise ConnectionError()

    with pytest.raises(ConnectionError):
        await cb.call(fail())

    with pytest.raises(CircuitBreakerOpen) as exc_info:
        await cb.call(fail())

    assert exc_info.value.retry_after <= 30.0
    assert exc_info.value.service == "test"


async def test_client_raises_wazuh_api_error_503_when_cb_open(mock_client):
    mock_client._cb._state = CircuitState.OPEN
    mock_client._cb._last_failure_time = time.monotonic()

    with pytest.raises(WazuhAPIError) as exc_info:
        await mock_client.get("/agents")

    assert exc_info.value.status_code == 503
