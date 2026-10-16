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
"""Findings of the key's own organization."""

import inspect
from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..api_client import BlumiraClient
from ._common import (
    READ_ONLY,
    WRITES,
    WRITES_IDEMPOTENT,
    ClientFactory,
    CommentBody,
    DateTime,
    FindingId,
    Limit,
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
    page_params,
    path_id,
    run_tool,
    single_result,
)

# Filters accepted by blumira_findings_list. Two of them contain a dot, which a
# Python parameter cannot, so that tool is declared with an explicit signature.
_FILTERS: list[tuple[str, str, Any]] = [
    ("status", "status", Status),
    ("priority", "priority", Priority),
    ("category", "category", Annotated[int | None, Field(description="Finding category id.")]),
    ("name", "name", Annotated[str | None, Field(description="Exact finding name.")]),
    ("name_contains", "name.contains", Annotated[str | None, Field(alias="name.contains", description="Text the name contains.")]),
    ("name_regex", "name.regex", Annotated[str | None, Field(alias="name.regex", description="Regular expression the name matches.")]),
    ("created_after", "created_after", DateTime),
    ("created_before", "created_before", DateTime),
    ("modified_after", "modified_after", DateTime),
    ("modified_before", "modified_before", DateTime),
    ("blocked", "blocked", Annotated[bool | None, Field(description="true = only findings where traffic was blocked.")]),
]


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    async def blumira_findings_list(**kwargs: Any) -> str:
        """List findings (detections) with name, priority, status, category and times.

        Filter by status, priority, category, name, created / modified window or
        blocked. Use blumira_findings_details for evidence and recommendations.
        """

        async def action(client: BlumiraClient) -> dict:
            params = page_params(kwargs.get("page"), kwargs.get("page_size"), kwargs.get("limit"), kwargs.get("order_by"))
            for _python, api, _type in _FILTERS:
                value = kwargs.get(api, kwargs.get(_python))
                if value is not None:
                    params[api] = value
            return list_result(await client.get("/org/findings", params))

        return await run_tool("blumira_findings_list", client_factory, action)

    parameters = [
        inspect.Parameter("page", inspect.Parameter.KEYWORD_ONLY, default=None, annotation=Page),
        inspect.Parameter("page_size", inspect.Parameter.KEYWORD_ONLY, default=None, annotation=PageSize),
        inspect.Parameter("limit", inspect.Parameter.KEYWORD_ONLY, default=None, annotation=Limit),
        inspect.Parameter("order_by", inspect.Parameter.KEYWORD_ONLY, default=None, annotation=OrderBy),
    ] + [
        inspect.Parameter(python, inspect.Parameter.KEYWORD_ONLY, default=None, annotation=annotation)
        for python, _api, annotation in _FILTERS
    ]
    blumira_findings_list.__signature__ = inspect.Signature(parameters, return_annotation=str)
    mcp.tool(annotations=READ_ONLY)(blumira_findings_list)

    @mcp.tool(annotations=READ_ONLY)
    async def blumira_findings_get(finding_id: FindingId) -> str:
        """Get one finding's summary: name, priority, status, owners and timeline."""

        async def action(client: BlumiraClient) -> Any:
            return single_result(await client.get(f"/org/findings/{path_id(finding_id)}"))

        return await run_tool("blumira_findings_get", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def blumira_findings_details(finding_id: FindingId) -> str:
        """Get one finding's analysis: description, evidence summary and recommended workflow."""

        async def action(client: BlumiraClient) -> Any:
            return single_result(await client.get(f"/org/findings/{path_id(finding_id)}/details"))

        return await run_tool("blumira_findings_details", client_factory, action)

    @mcp.tool(annotations=WRITES_IDEMPOTENT)
    async def blumira_findings_resolve(
        finding_id: FindingId, resolution: Resolution, resolution_notes: ResolutionNotes = None
    ) -> str:
        """Resolve a finding with a resolution code. Changes data: only when the user explicitly asks."""

        async def action(client: BlumiraClient) -> Any:
            body = compact({"resolution": resolution, "resolution_notes": resolution_notes})
            result = await client.post(f"/org/findings/{path_id(finding_id)}/resolve", body=body)
            return single_result(result) or {"resolved": True, "finding_id": finding_id}

        return await run_tool("blumira_findings_resolve", client_factory, action)

    @mcp.tool(annotations=WRITES_IDEMPOTENT)
    async def blumira_findings_assign(finding_id: FindingId, owner_type: OwnerType, owners: Owners) -> str:
        """Set the responders, analysts or managers of a finding. Only when the user explicitly asks."""

        async def action(client: BlumiraClient) -> Any:
            body = {"owner_type": owner_type, "owners": owners}
            result = await client.post(f"/org/findings/{path_id(finding_id)}/assign", body=body)
            return single_result(result) or {"assigned": True, "finding_id": finding_id}

        return await run_tool("blumira_findings_assign", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def blumira_findings_comments_list(finding_id: FindingId) -> str:
        """List the comments on a finding."""

        async def action(client: BlumiraClient) -> dict:
            return list_result(await client.get(f"/org/findings/{path_id(finding_id)}/comments"))

        return await run_tool("blumira_findings_comments_list", client_factory, action)

    @mcp.tool(annotations=WRITES)
    async def blumira_findings_comments_add(finding_id: FindingId, body: CommentBody, sender: Sender) -> str:
        """Add a comment to a finding. Only when the user explicitly asks."""

        async def action(client: BlumiraClient) -> Any:
            if not body.strip():
                raise ValueError("body must not be empty")
            result = await client.post(f"/org/findings/{path_id(finding_id)}/comments", body={"body": body, "sender": sender})
            return single_result(result) or {"added": True, "finding_id": finding_id}

        return await run_tool("blumira_findings_comments_add", client_factory, action)
