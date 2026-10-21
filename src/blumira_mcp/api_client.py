# Copyright 2026 MSPbots.ai
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Async client for the Blumira public API (OAuth 2.0 client credentials or JWT)."""

import asyncio
import logging
import time
from dataclasses import dataclass
from http.cookiejar import CookieJar, DefaultCookiePolicy
from typing import Any

import httpx

from ._json import error_envelope
from .config import API_BASE_URL, TOKEN_AUDIENCE, TOKEN_URL

logger = logging.getLogger("blumira_mcp.api")

_TIMEOUT = httpx.Timeout(connect=5.0, read=30.0, write=10.0, pool=5.0)
_RETRYABLE_STATUS = {429, 500, 502, 503, 504}
_MAX_RETRIES = 2
_MAX_BACKOFF_SECONDS = 20.0
# Whole-call budget including retries; the gateway times a tool call out at 120s.
_CALL_BUDGET_SECONDS = 100.0

# One connection pool for the process. It never holds credentials: the
# Authorization header is built per request from the caller's own
# credentials, so sharing the pool across tenants is safe.
_shared_http_client: httpx.AsyncClient | None = None


class _RejectAllCookies(DefaultCookiePolicy):
    """Never store or send a cookie: the HTTP client is shared by every tenant."""

    def set_ok(self, cookie, request) -> bool:  # noqa: ANN001 - stdlib signature
        return False

    def return_ok(self, cookie, request) -> bool:  # noqa: ANN001 - stdlib signature
        return False


def _no_cookies() -> CookieJar:
    # A plain CookieJar: httpx uses it as is (an httpx.Cookies would be copied into a default jar).
    return CookieJar(policy=_RejectAllCookies())


def _get_shared_http_client() -> httpx.AsyncClient:
    global _shared_http_client
    if _shared_http_client is None:
        _shared_http_client = httpx.AsyncClient(cookies=_no_cookies(), timeout=_TIMEOUT)
    return _shared_http_client


# status_code -> (error code, retryable). 0 means no HTTP response at all
# (connection error or timeout).
_STATUS_TO_CODE: dict[int, tuple[str, bool]] = {
    0: ("upstream_error", True),
    400: ("invalid_argument", False),
    401: ("unauthorized", False),
    403: ("unauthorized", False),
    404: ("not_found", False),
    422: ("invalid_argument", False),
    429: ("rate_limited", True),
}


def classify_status(status_code: int) -> tuple[str, bool]:
    if status_code in _STATUS_TO_CODE:
        return _STATUS_TO_CODE[status_code]
    if status_code >= 500:
        return "upstream_error", True
    if status_code >= 400:
        return "invalid_argument", False
    return "upstream_error", True


class BlumiraError(Exception):
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message
        super().__init__(f"Blumira API error {status_code}: {message}")

    def to_envelope(self) -> str:
        code, retryable = classify_status(self.status_code)
        return error_envelope(code, self.message, retryable)


@dataclass(frozen=True)
class BlumiraCredentials:
    client_id: str | None = None
    client_secret: str | None = None
    jwt_token: str | None = None  # pre-issued token, used instead of client id / secret

    def __repr__(self) -> str:  # never leak secrets into logs or tracebacks
        mode = "jwt" if self.jwt_token else "oauth"
        return f"BlumiraCredentials(mode={mode!r}, secrets=<redacted>)"


class BlumiraClient:
    """Blumira API wrapper for one caller's credentials.

    An OAuth access token is fetched lazily and kept only on this instance,
    which lives for a single MCP request; it is never cached across requests.
    """

    def __init__(self, credentials: BlumiraCredentials, http_client: httpx.AsyncClient | None = None):
        self._credentials = credentials
        self._http = http_client
        self._access_token: str | None = credentials.jwt_token
        self.base_url = API_BASE_URL

    @property
    def auth_mode(self) -> str:
        return "jwt" if self._credentials.jwt_token else "oauth"

    async def _token(self) -> str:
        if self._access_token is None:
            http = self._http or _get_shared_http_client()
            body = {
                "grant_type": "client_credentials",
                "client_id": self._credentials.client_id,
                "client_secret": self._credentials.client_secret,
                "audience": TOKEN_AUDIENCE,
            }
            try:
                resp = await http.post(TOKEN_URL, json=body, headers={"Accept": "application/json"})
            except httpx.RequestError as e:
                raise BlumiraError(0, f"Network error requesting a Blumira token: {type(e).__name__}") from e
            logger.info("blumira_api method=POST path=/oauth/token status=%s", resp.status_code)
            if resp.status_code in (400, 401, 403):
                raise BlumiraError(401, "Blumira rejected the client id / secret (token request failed)")
            if resp.status_code >= 400:
                raise BlumiraError(resp.status_code, _error_message(resp))
            token = (_parse_body(resp) or {}).get("access_token")
            if not token:
                raise BlumiraError(502, "Blumira token response had no access_token")
            self._access_token = token
        return self._access_token

    async def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {await self._token()}", "Accept": "application/json"}

    async def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        return await self.request("GET", path, params=params)

    async def post(self, path: str, params: dict[str, Any] | None = None, body: Any = None) -> Any:
        return await self.request("POST", path, params=params, body=body)

    async def request(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
        body: Any = None,
    ) -> Any:
        http = self._http or _get_shared_http_client()
        url = f"{self.base_url}{path}"
        query = {k: _param_value(v) for k, v in (params or {}).items() if v is not None}
        headers = await self._headers()
        if body is not None:
            headers["Content-Type"] = "application/json"

        started = time.monotonic()
        attempt = 0
        while True:
            t0 = time.monotonic()
            try:
                resp = await http.request(method, url, params=query, json=body, headers=headers)
            except httpx.TimeoutException as e:
                status, error = 0, BlumiraError(0, f"Timed out calling Blumira ({method} {path})")
                resp, exc = None, e
            except httpx.RequestError as e:
                status = 0
                error = BlumiraError(0, f"Network error calling Blumira ({method} {path}): {type(e).__name__}")
                resp, exc = None, e
            else:
                status, error, exc = resp.status_code, None, None

            logger.info(
                "blumira_api method=%s path=%s status=%s ms=%d attempt=%d",
                method,
                path,
                status,
                (time.monotonic() - t0) * 1000,
                attempt,
            )

            retryable = status == 0 or status in _RETRYABLE_STATUS
            if retryable and attempt < _MAX_RETRIES:
                delay = _retry_delay(resp, attempt)
                if time.monotonic() - started + delay < _CALL_BUDGET_SECONDS:
                    attempt += 1
                    await asyncio.sleep(delay)
                    continue

            if error is not None:
                raise error from exc
            assert resp is not None
            if resp.status_code >= 400:
                raise BlumiraError(resp.status_code, _error_message(resp))
            return _parse_body(resp)


def _param_value(value: Any) -> Any:
    if isinstance(value, bool):
        return "true" if value else "false"
    return value


def _retry_delay(resp: httpx.Response | None, attempt: int) -> float:
    if resp is not None:
        retry_after = resp.headers.get("Retry-After")
        if retry_after:
            try:
                return max(0.0, min(float(retry_after), _MAX_BACKOFF_SECONDS))
            except ValueError:
                pass
    return min(float(2**attempt), _MAX_BACKOFF_SECONDS)


def _parse_body(resp: httpx.Response) -> Any:
    if not resp.content:
        return None
    try:
        return resp.json()
    except ValueError:
        return {"raw_response": resp.text[:2000]}


def _error_message(resp: httpx.Response) -> str:
    """Short, credential-free description of a Blumira error response."""
    fallback = f"Blumira returned HTTP {resp.status_code}"
    try:
        payload = resp.json()
    except ValueError:
        return fallback
    if isinstance(payload, dict):
        errors = payload.get("errors")
        if isinstance(errors, list) and errors:
            parts = []
            for err in errors[:3]:
                if isinstance(err, dict):
                    text = err.get("detail") or err.get("title") or err.get("code")
                    if text:
                        parts.append(str(text))
            if parts:
                return f"{fallback}: " + "; ".join(parts)[:500]
        for key in ("message", "error", "detail"):
            if isinstance(payload.get(key), str):
                return f"{fallback}: {payload[key][:500]}"
    return fallback
