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
"""Blumira Agent devices and enrolment keys of the organization."""

from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..api_client import BlumiraClient
from ._common import (
    READ_ONLY,
    ClientFactory,
    Limit,
    Offset,
    OrderBy,
    Page,
    PageSize,
    list_result,
    locate,
    page_params,
    path_id,
    run_tool,
    single_result,
)


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def blumira_agents_devices_list(
        page: Page = None,
        page_size: PageSize = None,
        limit: Limit = None,
        order_by: OrderBy = None,
        offset: Offset = None,
    ) -> str:
        """List endpoints running the Blumira agent: hostname, OS, version, status, last seen."""

        async def action(client: BlumiraClient) -> dict:
            number, size, start = locate(offset, page, page_size)
            return list_result(
                await client.get("/org/agents/devices", page_params(number, size, limit, order_by)), number, size, start
            )

        return await run_tool("blumira_agents_devices_list", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def blumira_agents_devices_get(
        device_id: Annotated[str, Field(description="Agent device id.")],
    ) -> str:
        """Get one agent device."""

        async def action(client: BlumiraClient) -> Any:
            return single_result(await client.get(f"/org/agents/devices/{path_id(device_id)}"))

        return await run_tool("blumira_agents_devices_get", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def blumira_agents_keys_list(
        page: Page = None,
        page_size: PageSize = None,
        limit: Limit = None,
        order_by: OrderBy = None,
        offset: Offset = None,
    ) -> str:
        """List agent enrolment keys and how many devices use each."""

        async def action(client: BlumiraClient) -> dict:
            number, size, start = locate(offset, page, page_size)
            return list_result(
                await client.get("/org/agents/keys", page_params(number, size, limit, order_by)), number, size, start
            )

        return await run_tool("blumira_agents_keys_list", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def blumira_agents_keys_get(
        key_id: Annotated[str, Field(description="Agent key id.")],
    ) -> str:
        """Get one agent enrolment key."""

        async def action(client: BlumiraClient) -> Any:
            return single_result(await client.get(f"/org/agents/keys/{path_id(key_id)}"))

        return await run_tool("blumira_agents_keys_get", client_factory, action)
