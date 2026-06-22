from __future__ import annotations

import asyncio
import random
from typing import Any

import httpx

from .auth import JWTManager
from .config import WazuhSettings

RETRYABLE_STATUS = (429, 502, 503, 504)


class WazuhAPIError(Exception):
    def __init__(
        self,
        message: str,
        status_code: int | None = None,
        response_body: dict | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.response_body = response_body


class WazuhClient:
    def __init__(self, settings: WazuhSettings, auth: JWTManager) -> None:
        self._settings = settings
        self._auth = auth

    @staticmethod
    def _clean_params(params: dict | None) -> dict | None:
        if params is None:
            return None
        cleaned = {k: v for k, v in params.items() if v is not None}
        return cleaned or None

    async def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json: Any = None,
        content: str | bytes | None = None,
        content_type: str | None = None,
    ) -> Any:
        params = self._clean_params(params)
        url = f"{self._settings.base_url}{path}"
        raw: bytes | None = None
        if content is not None:
            raw = content.encode() if isinstance(content, str) else content

        last_exc: Exception | None = None

        for attempt in range(self._settings.max_retries):
            token = await self._auth.get_token()
            headers: dict[str, str] = {"Authorization": f"Bearer {token}"}
            if content_type:
                headers["Content-Type"] = content_type

            try:
                async with httpx.AsyncClient(
                    verify=self._settings.ssl_verify,
                    timeout=self._settings.request_timeout,
                ) as http:
                    resp = await http.request(
                        method,
                        url,
                        headers=headers,
                        params=params,
                        json=json,
                        content=raw,
                    )

                    if resp.status_code == 401:
                        self._auth.invalidate()
                        if attempt < self._settings.max_retries - 1:
                            continue
                        raise WazuhAPIError(
                            "Invalid credentials or expired token",
                            status_code=401,
                            response_body=_safe_json(resp),
                        )

                    if resp.status_code in RETRYABLE_STATUS:
                        wait = (2 ** attempt) + random.uniform(0, 1)
                        await asyncio.sleep(wait)
                        last_exc = None
                        continue

                    try:
                        resp.raise_for_status()
                    except httpx.HTTPStatusError as exc:
                        code = exc.response.status_code
                        body = _safe_json(exc.response)
                        detail = (
                            body.get("detail") or body.get("message") or str(body)
                            if body
                            else exc.response.text
                        )
                        if code == 403:
                            raise WazuhAPIError(
                                f"Permission denied: {detail}",
                                status_code=code,
                                response_body=body,
                            ) from exc
                        if code == 400:
                            raise WazuhAPIError(
                                f"Invalid request: {detail}",
                                status_code=code,
                                response_body=body,
                            ) from exc
                        raise WazuhAPIError(
                            f"Wazuh API error {code}: {detail}",
                            status_code=code,
                            response_body=body,
                        ) from exc

                    return resp.json()

            except (httpx.ConnectError, httpx.TimeoutException) as exc:
                last_exc = exc
                wait = (2 ** attempt) + random.uniform(0, 1)
                await asyncio.sleep(wait)

        raise WazuhAPIError(
            f"Could not connect to Wazuh after {self._settings.max_retries} attempts: {last_exc}"
        )

    async def get(self, path: str, *, params: dict[str, Any] | None = None) -> Any:
        return await self.request("GET", path, params=params)

    async def post(
        self, path: str, *, json: Any = None, params: dict[str, Any] | None = None
    ) -> Any:
        return await self.request("POST", path, params=params, json=json)

    async def put(
        self,
        path: str,
        *,
        json: Any = None,
        params: dict[str, Any] | None = None,
        content: str | bytes | None = None,
        content_type: str | None = None,
    ) -> Any:
        return await self.request(
            "PUT", path, params=params, json=json,
            content=content, content_type=content_type,
        )

    async def delete(
        self, path: str, *, params: dict[str, Any] | None = None
    ) -> Any:
        return await self.request("DELETE", path, params=params)


def _safe_json(response: httpx.Response) -> dict | None:
    try:
        return response.json()
    except Exception:
        return None
