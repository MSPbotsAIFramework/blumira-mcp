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
"""FastMCP factory and the per-request credential middleware."""

import contextvars
import uuid
from collections.abc import Callable

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from ._arguments import EnvelopeFastMCP
from .api_client import BlumiraClient, BlumiraCredentials
from .config import Settings

HEADER_CLIENT_ID = "X-Blumira-Client-Id"
HEADER_CLIENT_SECRET = "X-Blumira-Client-Secret"
HEADER_JWT = "X-Blumira-Jwt-Token"
CREDENTIAL_HEADERS = [HEADER_CLIENT_ID, HEADER_CLIENT_SECRET, HEADER_JWT]

# Per-request isolation: the middleware sets these for the duration of one
# HTTP request and resets them in `finally`. Nothing credential-related is
# ever stored at module level.
_credentials_var: contextvars.ContextVar[BlumiraCredentials | None] = contextvars.ContextVar(
    "blumira_credentials", default=None
)
request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("blumira_request_id", default="-")

INSTRUCTIONS = (
    "Blumira is a cloud SIEM with automated detection and response for SMBs and "
    "MSPs. Findings are detections (threats, suspicious activity, operational "
    "issues) with a priority (1 = highest) and status; responders resolve them "
    "with a resolution code. Blumira Agent devices are endpoints running the "
    "Blumira agent; agent keys enrol them.\n"
    "Two scopes:\n"
    "- Organization tools (blumira_findings_*, blumira_agents_*, "
    "blumira_users_list) work on the key's own organization.\n"
    "- MSP tools (blumira_msp_*) work across sub-accounts: start with "
    "blumira_msp_accounts_list, then pass account_id; "
    "blumira_msp_findings_all covers every sub-account at once.\n"
    "Typical flow: blumira_findings_list(status=..., priority=1) -> "
    "blumira_findings_details -> blumira_resolutions_list -> "
    "blumira_findings_resolve. Comments need a sender user id from "
    "blumira_users_list. Lists return {items, page, total_pages, total_items, "
    "has_more}. Resolve, assign and comment tools change data: use them only "
    "when the user explicitly asks."
)


def get_client_from_context() -> BlumiraClient | None:
    """The client for the current request, or None outside a request."""
    credentials = _credentials_var.get()
    if credentials is None:
        return None
    return BlumiraClient(credentials)


def _strip_bearer(value: str) -> str:
    parts = value.split()
    if parts and parts[0].lower() == "bearer":
        parts = parts[1:]
    return " ".join(parts)


class GatewayCredentialsMiddleware:
    """Reads X-Blumira-* headers on /mcp requests into the request context.

    Needs either client id + secret or a JWT token; otherwise 401.
    """

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not scope.get("path", "").startswith("/mcp"):
            await self.app(scope, receive, send)
            return

        request = Request(scope)
        client_id = (request.headers.get(HEADER_CLIENT_ID) or "").strip()
        client_secret = (request.headers.get(HEADER_CLIENT_SECRET) or "").strip()
        jwt = _strip_bearer(request.headers.get(HEADER_JWT) or "")

        if not jwt and not (client_id and client_secret):
            await JSONResponse(
                {
                    "error": "Missing credentials",
                    "message": f"Send {HEADER_CLIENT_ID} and {HEADER_CLIENT_SECRET}, or {HEADER_JWT}",
                    "required_headers": CREDENTIAL_HEADERS,
                    "required_one_of": [[HEADER_CLIENT_ID, HEADER_CLIENT_SECRET], [HEADER_JWT]],
                },
                status_code=401,
            )(scope, receive, send)
            return

        credentials = (
            BlumiraCredentials(jwt_token=jwt) if jwt else BlumiraCredentials(client_id=client_id, client_secret=client_secret)
        )
        request_id = (request.headers.get("x-request-id") or "").strip()[:64] or uuid.uuid4().hex[:12]
        creds_token = _credentials_var.set(credentials)
        rid_token = request_id_var.set(request_id)
        try:
            await self.app(scope, receive, send)
        finally:
            _credentials_var.reset(creds_token)
            request_id_var.reset(rid_token)


def create_mcp_server(settings: Settings | None = None) -> FastMCP:
    """Build the FastMCP server and register every tool."""
    mcp = EnvelopeFastMCP(
        name="blumira-mcp",
        instructions=INSTRUCTIONS,
        # The service sits behind the gateway, so Host is never localhost;
        # DNS-rebinding protection would reject those requests with 421.
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
        stateless_http=True,
    )

    client_factory: Callable[[], BlumiraClient | None] = get_client_from_context

    from .tools import agents, findings, msp, navigation, resolutions, users

    for module in (navigation, findings, agents, users, resolutions, msp):
        module.register(mcp, client_factory)

    return mcp
