import time
import asyncio
import httpx
from .config import WazuhSettings


class JWTManager:
    def __init__(self, settings: WazuhSettings) -> None:
        self._settings = settings
        self._token: str | None = None
        self._expires_at: float = 0.0
        self._lock = asyncio.Lock()

    async def get_token(self) -> str:
        async with self._lock:
            if self._token and time.time() < self._expires_at:
                return self._token
            await self._authenticate()
            return self._token  # type: ignore[return-value]

    async def _authenticate(self) -> None:
        async with httpx.AsyncClient(
            verify=self._settings.ssl_verify,
            timeout=self._settings.request_timeout,
        ) as client:
            resp = await client.post(
                f"{self._settings.base_url}/security/user/authenticate",
                auth=(self._settings.wazuh_user, self._settings.wazuh_password),
            )
            resp.raise_for_status()
            self._token = resp.json()["data"]["token"]
            self._expires_at = (
                time.time() + 900 - self._settings.jwt_refresh_margin
            )

    def invalidate(self) -> None:
        """Force re-authentication on the next get_token() call."""
        self._token = None
        self._expires_at = 0.0
