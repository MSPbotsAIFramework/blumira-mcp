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
"""MSP tools: sub-accounts and their findings, agents and users."""

from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..api_client import BlumiraClient
from ._common import (
    READ_ONLY,
    WRITES,
    WRITES_IDEMPOTENT,
    AccountId,
    ClientFactory,
    CommentBody,
    DateTime,
    FindingId,
    Limit,
    Offset,
    OrderBy,
    Owners,
    OwnerType,
    Page,
    PageSize,
    Priority,
    Resolution,
    ResolutionNotes,
    Sender,
    Status,
    compact,
    list_result,
    locate,
    page_params,
    path_id,
    run_tool,
    single_result,
)


def _account(account_id: str) -> str:
    return f"/msp/accounts/{path_id(account_id)}"


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def blumira_msp_accounts_list(
        page: Page = None,
        page_size: PageSize = None,
        limit: Limit = None,
        order_by: OrderBy = None,
        offset: Offset = None,
    ) -> str:
        """List the MSP's sub-accounts (client organizations) with their account ids."""

        async def action(client: BlumiraClient) -> dict:
            number, size, start = locate(offset, page, page_size)
            return list_result(
                await client.get("/msp/accounts", page_params(number, size, limit, order_by)), number, size, start
            )

        return await run_tool("blumira_msp_accounts_list", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def blumira_msp_accounts_get(account_id: AccountId) -> str:
        """Get one MSP sub-account."""

        async def action(client: BlumiraClient) -> Any:
            return single_result(await client.get(_account(account_id)))

        return await run_tool("blumira_msp_accounts_get", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def blumira_msp_findings_all(
        page: Page = None,
        page_size: PageSize = None,
        limit: Limit = None,
        status: Status = None,
        priority: Priority = None,
        created_after: DateTime = None,
        created_before: DateTime = None,
        offset: Offset = None,
    ) -> str:
        """List findings across every MSP sub-account, filtered by status, priority or created window."""

        async def action(client: BlumiraClient) -> dict:
            number, size, start = locate(offset, page, page_size)
            params = page_params(number, size, limit) | compact(
                {"status": status, "priority": priority, "created_after": created_after, "created_before": created_before}
            )
            return list_result(await client.get("/msp/accounts/findings", params), number, size, start)

        return await run_tool("blumira_msp_findings_all", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def blumira_msp_findings_list(
        account_id: AccountId,
        page: Page = None,
        page_size: PageSize = None,
        status: Status = None,
        priority: Priority = None,
        offset: Offset = None,
    ) -> str:
        """List the findings of one MSP sub-account."""

        async def action(client: BlumiraClient) -> dict:
            number, size, start = locate(offset, page, page_size)
            params = page_params(number, size) | compact({"status": status, "priority": priority})
            return list_result(await client.get(f"{_account(account_id)}/findings", params), number, size, start)

        return await run_tool("blumira_msp_findings_list", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def blumira_msp_findings_get(account_id: AccountId, finding_id: FindingId) -> str:
        """Get one finding of an MSP sub-account."""

        async def action(client: BlumiraClient) -> Any:
            return single_result(await client.get(f"{_account(account_id)}/findings/{path_id(finding_id)}"))

        return await run_tool("blumira_msp_findings_get", client_factory, action)

    @mcp.tool(annotations=WRITES_IDEMPOTENT)
    async def blumira_msp_findings_resolve(
        account_id: AccountId, finding_id: FindingId, resolution: Resolution, resolution_notes: ResolutionNotes = None
    ) -> str:
        """Resolve a sub-account's finding with a resolution code. Only when the user explicitly asks."""

        async def action(client: BlumiraClient) -> Any:
            body = compact({"resolution": resolution, "resolution_notes": resolution_notes})
            result = await client.post(f"{_account(account_id)}/findings/{path_id(finding_id)}/resolve", body=body)
            return single_result(result) or {"resolved": True, "finding_id": finding_id}

        return await run_tool("blumira_msp_findings_resolve", client_factory, action)

    @mcp.tool(annotations=WRITES_IDEMPOTENT)
    async def blumira_msp_findings_assign(
        account_id: AccountId, finding_id: FindingId, owner_type: OwnerType, owners: Owners
    ) -> str:
        """Set the owners of a sub-account's finding. Only when the user explicitly asks."""

        async def action(client: BlumiraClient) -> Any:
            body = {"owner_type": owner_type, "owners": owners}
            result = await client.post(f"{_account(account_id)}/findings/{path_id(finding_id)}/assign", body=body)
            return single_result(result) or {"assigned": True, "finding_id": finding_id}

        return await run_tool("blumira_msp_findings_assign", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def blumira_msp_findings_comments_list(account_id: AccountId, finding_id: FindingId) -> str:
        """List the comments on a sub-account's finding."""

        async def action(client: BlumiraClient) -> dict:
            return list_result(await client.get(f"{_account(account_id)}/findings/{path_id(finding_id)}/comments"))

        return await run_tool("blumira_msp_findings_comments_list", client_factory, action)

    @mcp.tool(annotations=WRITES)
    async def blumira_msp_findings_comments_add(
        account_id: AccountId, finding_id: FindingId, body: CommentBody, sender: Sender
    ) -> str:
        """Add a comment to a sub-account's finding. Only when the user explicitly asks."""

        async def action(client: BlumiraClient) -> Any:
            if not body.strip():
                raise ValueError("body must not be empty")
            result = await client.post(
                f"{_account(account_id)}/findings/{path_id(finding_id)}/comments", body={"body": body, "sender": sender}
            )
            return single_result(result) or {"added": True, "finding_id": finding_id}

        return await run_tool("blumira_msp_findings_comments_add", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def blumira_msp_devices_list(
        account_id: AccountId, page: Page = None, page_size: PageSize = None, offset: Offset = None
    ) -> str:
        """List the agent devices of one MSP sub-account."""

        async def action(client: BlumiraClient) -> dict:
            number, size, start = locate(offset, page, page_size)
            return list_result(
                await client.get(f"{_account(account_id)}/agents/devices", page_params(number, size)), number, size, start
            )

        return await run_tool("blumira_msp_devices_list", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def blumira_msp_devices_get(
        account_id: AccountId, device_id: Annotated[str, Field(description="Agent device id.")]
    ) -> str:
        """Get one agent device of an MSP sub-account."""

        async def action(client: BlumiraClient) -> Any:
            return single_result(await client.get(f"{_account(account_id)}/agents/devices/{path_id(device_id)}"))

        return await run_tool("blumira_msp_devices_get", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def blumira_msp_keys_list(
        account_id: AccountId, page: Page = None, page_size: PageSize = None, offset: Offset = None
    ) -> str:
        """List the agent enrolment keys of one MSP sub-account."""

        async def action(client: BlumiraClient) -> dict:
            number, size, start = locate(offset, page, page_size)
            return list_result(
                await client.get(f"{_account(account_id)}/agents/keys", page_params(number, size)), number, size, start
            )

        return await run_tool("blumira_msp_keys_list", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def blumira_msp_keys_get(
        account_id: AccountId, key_id: Annotated[str, Field(description="Agent key id.")]
    ) -> str:
        """Get one agent enrolment key of an MSP sub-account."""

        async def action(client: BlumiraClient) -> Any:
            return single_result(await client.get(f"{_account(account_id)}/agents/keys/{path_id(key_id)}"))

        return await run_tool("blumira_msp_keys_get", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def blumira_msp_users_list(
        account_id: AccountId, page: Page = None, page_size: PageSize = None, offset: Offset = None
    ) -> str:
        """List the users of one MSP sub-account (ids usable as comment sender or owners)."""

        async def action(client: BlumiraClient) -> dict:
            number, size, start = locate(offset, page, page_size)
            return list_result(
                await client.get(f"{_account(account_id)}/users", page_params(number, size)), number, size, start
            )

        return await run_tool("blumira_msp_users_list", client_factory, action)
