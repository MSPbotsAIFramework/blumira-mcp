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
"""Credential check and a per-area tool guide. All tools are always listed."""

from typing import Annotated, Literal

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..api_client import BlumiraClient
from ._common import READ_ONLY, ClientFactory, run_tool

DOMAIN_TOOLS: dict[str, dict[str, str]] = {
    "findings": {
        "blumira_findings_list": "List findings with filters.",
        "blumira_findings_get": "One finding.",
        "blumira_findings_details": "Analysis and evidence of a finding.",
        "blumira_findings_resolve": "Resolve a finding (write).",
        "blumira_findings_assign": "Set owners (write).",
        "blumira_findings_comments_list": "Comments of a finding.",
        "blumira_findings_comments_add": "Add a comment (write).",
    },
    "agents": {
        "blumira_agents_devices_list": "Agent devices.",
        "blumira_agents_devices_get": "One agent device.",
        "blumira_agents_keys_list": "Agent enrolment keys.",
        "blumira_agents_keys_get": "One agent key.",
    },
    "users": {"blumira_users_list": "Organization users."},
    "msp": {
        "blumira_msp_accounts_list": "Sub-accounts.",
        "blumira_msp_accounts_get": "One sub-account.",
        "blumira_msp_findings_all": "Findings across all sub-accounts.",
        "blumira_msp_findings_list": "Findings of one sub-account.",
        "blumira_msp_findings_get": "One sub-account finding.",
        "blumira_msp_findings_resolve": "Resolve (write).",
        "blumira_msp_findings_assign": "Set owners (write).",
        "blumira_msp_findings_comments_list": "Comments.",
        "blumira_msp_findings_comments_add": "Add a comment (write).",
        "blumira_msp_devices_list": "Agent devices of a sub-account.",
        "blumira_msp_devices_get": "One device.",
        "blumira_msp_keys_list": "Agent keys of a sub-account.",
        "blumira_msp_keys_get": "One key.",
        "blumira_msp_users_list": "Users of a sub-account.",
    },
    "resolutions": {"blumira_resolutions_list": "Resolution codes."},
}


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def blumira_navigate(
        domain: Annotated[
            Literal["findings", "agents", "users", "msp", "resolutions"],
            Field(description="Area to show tools for."),
        ],
    ) -> str:
        """Show which tools cover one area: findings, agents, users, msp or resolutions.

        All tools are always available; this is only a guide. Makes no API call.
        """

        async def action(_client: BlumiraClient) -> dict:
            return {"domain": domain, "tools": DOMAIN_TOOLS[domain]}

        return await run_tool("blumira_navigate", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def blumira_back() -> str:
        """List all areas and their tools. Kept for older clients; every tool is always available."""

        async def action(_client: BlumiraClient) -> dict:
            return {"domains": {name: sorted(tools) for name, tools in DOMAIN_TOOLS.items()}}

        return await run_tool("blumira_back", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def blumira_status() -> str:
        """Check that the Blumira credentials work and the API is reachable."""

        async def action(client: BlumiraClient) -> dict:
            await client.get("/health")
            return {"authenticated": True, "auth_mode": client.auth_mode, "api_base_url": client.base_url}

        return await run_tool("blumira_status", client_factory, action)
