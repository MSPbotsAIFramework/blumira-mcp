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
"""Finding resolution codes."""

from mcp.server.fastmcp import FastMCP

from ..api_client import BlumiraClient
from ._common import READ_ONLY, ClientFactory, list_result, run_tool


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def blumira_resolutions_list() -> str:
        """List the resolution codes (e.g. valid, false positive, risk accepted) for resolving findings."""

        async def action(client: BlumiraClient) -> dict:
            return list_result(await client.get("/resolutions"))

        return await run_tool("blumira_resolutions_list", client_factory, action)
