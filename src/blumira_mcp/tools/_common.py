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
"""Shared argument types, result shaping and the error-handling wrapper."""

import logging
import time
from collections.abc import Awaitable, Callable
from typing import Annotated, Any, Literal
from urllib.parse import quote

from mcp.types import ToolAnnotations
from pydantic import Field

from .._json import dump_json_capped, error_envelope
from ..api_client import BlumiraClient, BlumiraError

logger = logging.getLogger("blumira_mcp.tools")

ClientFactory = Callable[[], BlumiraClient | None]

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200  # the API's own page_size maximum

READ_ONLY = ToolAnnotations(readOnlyHint=True, idempotentHint=True, openWorldHint=True)
WRITES = ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True)
WRITES_IDEMPOTENT = ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=True)

NOT_CONFIGURED = error_envelope(
    "not_configured",
    "Blumira credentials are missing for this request (X-Blumira-Client-Id / -Secret or X-Blumira-Jwt-Token).",
    False,
)

Page = Annotated[int | None, Field(description="Page number, from 1 (default 1).")]
PageSize = Annotated[int | None, Field(description=f"Records per page (default {DEFAULT_PAGE_SIZE}, max {MAX_PAGE_SIZE}).")]
Limit = Annotated[int | None, Field(description="Maximum total records across pages (API default 200).")]
OrderBy = Annotated[str | None, Field(description='Sort, e.g. "created;desc" or "name;asc,created;desc".')]
AccountId = Annotated[str, Field(description="MSP sub-account id (from blumira_msp_accounts_list).")]
FindingId = Annotated[str, Field(description="Finding id.")]
Status = Annotated[int | None, Field(description="Finding status id.")]
Priority = Annotated[int | None, Field(description="Finding priority, 1 (highest) to 5.")]
DateTime = Annotated[str | None, Field(description="ISO 8601 date-time in UTC, e.g. 2026-01-31T00:00:00Z.")]
Resolution = Annotated[
    int, Field(description="Resolution id from blumira_resolutions_list (e.g. 10 valid, 20 false positive).")
]
ResolutionNotes = Annotated[str | None, Field(description="Optional resolution notes.")]
OwnerType = Annotated[
    Literal["responder", "analyst", "manager"], Field(description="Which owner role to set.")
]
Owners = Annotated[
    list[str], Field(description="User ids (UUIDs) to assign; an empty list clears that role.")
]
CommentBody = Annotated[str, Field(description="Comment text (HTML allowed).")]
Sender = Annotated[str, Field(description="User id (UUID) of the author, from a users list tool.")]


def page_params(
    page: int | None = None, page_size: int | None = None, limit: int | None = None, order_by: str | None = None
) -> dict[str, Any]:
    size = DEFAULT_PAGE_SIZE if page_size is None else max(1, min(int(page_size), MAX_PAGE_SIZE))
    params: dict[str, Any] = {"page": max(1, int(page or 1)), "page_size": size}
    if limit is not None:
        params["limit"] = max(1, min(int(limit), 5000))
    if order_by:
        params["order_by"] = order_by
    return params


def list_result(document: Any) -> dict[str, Any]:
    """Shape ``{status, data, links, meta}`` as ``{items, count, page, total_pages, total_items, has_more}``."""
    doc = document if isinstance(document, dict) else {}
    items = doc.get("data")
    if items is None:
        items = []
    elif not isinstance(items, list):
        items = [items]
    meta = doc.get("meta") if isinstance(doc.get("meta"), dict) else {}
    links = doc.get("links") if isinstance(doc.get("links"), dict) else {}
    return {
        "items": items,
        "count": len(items),
        "page": meta.get("page"),
        "total_pages": meta.get("total_pages"),
        "total_items": meta.get("total_items"),
        "has_more": bool(links.get("next")),
    }


def single_result(document: Any) -> Any:
    if isinstance(document, dict) and "data" in document:
        return document["data"]
    return document


def path_id(value: Any) -> str:
    return quote(str(value).strip(), safe="")


def compact(values: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in values.items() if v is not None}


async def run_tool(
    name: str,
    client_factory: ClientFactory,
    action: Callable[[BlumiraClient], Awaitable[Any]],
) -> str:
    """Resolve the caller's client, run ``action``, and always return a string.

    Errors never escape as exceptions: they become the standard error envelope.
    """
    client = client_factory()
    if client is None:
        return NOT_CONFIGURED
    started = time.monotonic()
    try:
        result = await action(client)
    except BlumiraError as e:
        logger.info("tool=%s outcome=error status=%s ms=%d", name, e.status_code, _ms(started))
        return e.to_envelope()
    except ValueError as e:
        logger.info("tool=%s outcome=invalid_argument ms=%d", name, _ms(started))
        return error_envelope("invalid_argument", str(e), False)
    except Exception as e:  # noqa: BLE001 - tools must never raise
        logger.warning("tool=%s outcome=unexpected error=%s ms=%d", name, type(e).__name__, _ms(started))
        return error_envelope("upstream_error", f"Unexpected error: {type(e).__name__}", True)
    logger.info("tool=%s outcome=ok ms=%d", name, _ms(started))
    return result if isinstance(result, str) else dump_json_capped(result)


def _ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)
