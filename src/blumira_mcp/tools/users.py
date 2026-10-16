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
"""Users of the organization."""

from mcp.server.fastmcp import FastMCP

from ..api_client import BlumiraClient
from ._common import READ_ONLY, ClientFactory, Limit, OrderBy, Page, PageSize, list_result, page_params, run_tool


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def blumira_users_list(
        page: Page = None, page_size: PageSize = None, limit: Limit = None, order_by: OrderBy = None
    ) -> str:
        """List the organization's users with their ids, names and e-mail addresses.

        Use an id as the sender of a comment or as an owner when assigning a finding.
        """

        async def action(client: BlumiraClient) -> dict:
            params = page_params(page, page_size, limit)
            if order_by:
                params["order_by"] = order_by
            return list_result(await client.get("/org/users", params))

        return await run_tool("blumira_users_list", client_factory, action)
