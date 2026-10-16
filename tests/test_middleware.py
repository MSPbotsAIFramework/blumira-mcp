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
"""Credential middleware: OAuth or JWT, 401 when neither, per-request isolation."""

import asyncio

import pytest
from starlette.testclient import TestClient

from blumira_mcp.__main__ import build_http_app
from blumira_mcp.server import (
    GatewayCredentialsMiddleware,
    _credentials_var,
    create_mcp_server,
    get_client_from_context,
)

MCP_HEADERS = {"Accept": "application/json, text/event-stream"}
LIST_TOOLS = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}


def _client() -> TestClient:
    return TestClient(build_http_app(create_mcp_server()))


def test_health_is_local():
    with _client() as client:
        resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


@pytest.mark.parametrize(
    "headers",
    [{}, {"X-Blumira-Client-Id": "id-only"}, {"X-Blumira-Client-Secret": "secret-only"}, {"X-Blumira-Jwt-Token": "Bearer "}],
)
def test_incomplete_credentials_return_401(headers):
    with _client() as client:
        resp = client.post("/mcp", json=LIST_TOOLS, headers=MCP_HEADERS | headers)
    assert resp.status_code == 401
    assert resp.json()["required_one_of"] == [
        ["X-Blumira-Client-Id", "X-Blumira-Client-Secret"],
        ["X-Blumira-Jwt-Token"],
    ]


@pytest.mark.parametrize(
    "headers",
    [{"X-Blumira-Client-Id": "your-client-id", "X-Blumira-Client-Secret": "your-client-secret"}, {"X-Blumira-Jwt-Token": "your-jwt"}],
)
def test_tools_list_with_either_credential_set(headers):
    with _client() as client:
        resp = client.post("/mcp", json=LIST_TOOLS, headers=MCP_HEADERS | headers)
    assert resp.status_code == 200
    assert "blumira_msp_findings_all" in resp.text


def _run_middleware(headers: list[tuple[bytes, bytes]]) -> dict:
    seen: dict = {}

    async def app(scope, receive, send):
        seen["credentials"] = _credentials_var.get()
        seen["client"] = get_client_from_context()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(_message):
        return None

    asyncio.run(GatewayCredentialsMiddleware(app)({"type": "http", "path": "/mcp", "headers": headers}, receive, send))
    return seen


def test_jwt_wins_and_bearer_prefix_is_stripped():
    seen = _run_middleware(
        [(b"x-blumira-client-id", b"cid"), (b"x-blumira-client-secret", b"sec"), (b"x-blumira-jwt-token", b"Bearer tok-1")]
    )
    assert seen["credentials"].jwt_token == "tok-1"
    assert seen["client"].auth_mode == "jwt"
    assert _credentials_var.get() is None


def test_oauth_credentials_reach_context():
    seen = _run_middleware([(b"x-blumira-client-id", b"cid"), (b"x-blumira-client-secret", b"sec")])
    creds = seen["credentials"]
    assert (creds.client_id, creds.client_secret, creds.jwt_token) == ("cid", "sec", None)
    assert seen["client"].auth_mode == "oauth"


def test_concurrent_requests_do_not_share_credentials():
    observed: list[tuple[str, str]] = []

    async def app(scope, receive, send):
        before = _credentials_var.get().jwt_token
        await asyncio.sleep(0.01)
        observed.append((before, _credentials_var.get().jwt_token))
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(_message):
        return None

    middleware = GatewayCredentialsMiddleware(app)

    def scope(tok: bytes) -> dict:
        return {"type": "http", "path": "/mcp", "headers": [(b"x-blumira-jwt-token", tok)]}

    async def both():
        await asyncio.gather(middleware(scope(b"tenant-a"), receive, send), middleware(scope(b"tenant-b"), receive, send))

    asyncio.run(both())
    assert sorted(observed) == [("tenant-a", "tenant-a"), ("tenant-b", "tenant-b")]


def test_credentials_repr_hides_secrets():
    seen = _run_middleware([(b"x-blumira-client-id", b"secret-id"), (b"x-blumira-client-secret", b"secret-value")])
    text = repr(seen["credentials"])
    assert "secret-id" not in text and "secret-value" not in text
