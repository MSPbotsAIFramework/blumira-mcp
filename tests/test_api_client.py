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
"""OAuth / JWT auth, paging, filters and routing against a mocked Blumira API."""

import json

import httpx
import pytest

from blumira_mcp import api_client
from blumira_mcp.api_client import BlumiraClient, BlumiraCredentials
from blumira_mcp.server import _credentials_var, create_mcp_server

BASE = "/public-api/v1"
PAGE = {
    "status": "OK",
    "data": [{"id": "f1", "name": "Possible brute force", "priority": 1}],
    "links": {"self": "/org/findings?page=1", "next": "/org/findings?page=2", "prev": None},
    "meta": {"page": 1, "page_size": 50, "total_items": 75, "total_pages": 2},
}


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    async def instant(_seconds):
        return None

    monkeypatch.setattr(api_client.asyncio, "sleep", instant)


class FakeApi:
    def __init__(self, reply=None, token_status=200):
        self.requests: list[httpx.Request] = []
        self.reply = reply or (lambda r: httpx.Response(200, json={"status": "OK", "data": [], "links": {}, "meta": {}}))
        self.token_status = token_status

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.url.host == "auth.blumira.com":
            if self.token_status != 200:
                return httpx.Response(self.token_status, json={"error": "access_denied"})
            return httpx.Response(200, json={"access_token": "oauth-tok", "expires_in": 3600})
        return self.reply(request)

    def api(self) -> list[httpx.Request]:
        return [r for r in self.requests if r.url.host != "auth.blumira.com"]


async def _call(monkeypatch, fake: FakeApi, tool: str, args: dict, creds: BlumiraCredentials | None = None):
    http = httpx.AsyncClient(transport=httpx.MockTransport(fake))
    monkeypatch.setattr(api_client, "_get_shared_http_client", lambda: http)
    mcp = create_mcp_server()
    ctx = _credentials_var.set(creds or BlumiraCredentials(client_id="cid", client_secret="csecret"))
    try:
        content, _ = await mcp.call_tool(tool, args)
    finally:
        _credentials_var.reset(ctx)
    return json.loads(content[0].text)


async def test_oauth_exchange_then_bearer(monkeypatch):
    fake = FakeApi(lambda r: httpx.Response(200, json=PAGE))
    result = await _call(monkeypatch, fake, "blumira_findings_list", {"priority": 1, "name.contains": "brute", "page_size": 999})
    token_req, api_req = fake.requests
    assert str(token_req.url) == "https://auth.blumira.com/oauth/token"
    assert json.loads(token_req.content) == {
        "grant_type": "client_credentials",
        "client_id": "cid",
        "client_secret": "csecret",
        "audience": "https://api.blumira.com/public-api/v1",
    }
    assert api_req.headers["authorization"] == "Bearer oauth-tok"
    assert api_req.url.path == f"{BASE}/org/findings"
    params = api_req.url.params
    assert params["priority"] == "1" and params["name.contains"] == "brute" and params["page_size"] == "200"
    assert result["has_more"] is True and result["total_items"] == 75 and result["items"][0]["id"] == "f1"


async def test_jwt_skips_token_exchange(monkeypatch):
    fake = FakeApi()
    await _call(monkeypatch, fake, "blumira_users_list", {}, creds=BlumiraCredentials(jwt_token="given-jwt"))
    assert [r.url.host for r in fake.requests] == ["api.blumira.com"]
    assert fake.requests[0].headers["authorization"] == "Bearer given-jwt"


async def test_bad_credentials_map_to_unauthorized(monkeypatch):
    result = await _call(monkeypatch, FakeApi(token_status=401), "blumira_status", {})
    assert result["error"]["code"] == "unauthorized"
    assert "csecret" not in json.dumps(result)


async def test_token_fetched_once_per_client():
    fake = FakeApi()
    client = BlumiraClient(
        BlumiraCredentials(client_id="a", client_secret="b"), http_client=httpx.AsyncClient(transport=httpx.MockTransport(fake))
    )
    await client.get("/org/users")
    await client.get("/org/users")
    assert [r.url.host for r in fake.requests].count("auth.blumira.com") == 1


async def test_findings_regex_and_dates(monkeypatch):
    fake = FakeApi()
    await _call(monkeypatch, fake, "blumira_findings_list", {
        "name.regex": "^VPN", "created_after": "2026-10-01T00:00:00Z", "blocked": True, "order_by": "created;desc",
    })
    params = fake.api()[0].url.params
    assert params["name.regex"] == "^VPN" and params["created_after"] == "2026-10-01T00:00:00Z"
    assert params["blocked"] == "true" and params["order_by"] == "created;desc"


@pytest.mark.parametrize(
    "tool,args,path,body",
    [
        ("blumira_findings_resolve", {"finding_id": "f1", "resolution": 20, "resolution_notes": "lab traffic"},
         "/org/findings/f1/resolve", {"resolution": 20, "resolution_notes": "lab traffic"}),
        ("blumira_findings_assign", {"finding_id": "f1", "owner_type": "responder", "owners": ["u1"]},
         "/org/findings/f1/assign", {"owner_type": "responder", "owners": ["u1"]}),
        ("blumira_findings_comments_add", {"finding_id": "f1", "body": "Investigating", "sender": "u1"},
         "/org/findings/f1/comments", {"body": "Investigating", "sender": "u1"}),
        ("blumira_msp_findings_resolve", {"account_id": "a1", "finding_id": "f1", "resolution": 10},
         "/msp/accounts/a1/findings/f1/resolve", {"resolution": 10}),
        ("blumira_msp_findings_assign", {"account_id": "a1", "finding_id": "f1", "owner_type": "analyst", "owners": []},
         "/msp/accounts/a1/findings/f1/assign", {"owner_type": "analyst", "owners": []}),
        ("blumira_msp_findings_comments_add", {"account_id": "a1", "finding_id": "f1", "body": "Done", "sender": "u2"},
         "/msp/accounts/a1/findings/f1/comments", {"body": "Done", "sender": "u2"}),
    ],
)
async def test_write_bodies(monkeypatch, tool, args, path, body):
    fake = FakeApi(lambda r: httpx.Response(200, json={"status": "OK", "data": {"id": "f1"}}))
    await _call(monkeypatch, fake, tool, args)
    req = fake.api()[0]
    assert (req.method, req.url.path) == ("POST", BASE + path)
    assert json.loads(req.content) == body


@pytest.mark.parametrize(
    "tool,args,path",
    [
        ("blumira_findings_get", {"finding_id": "f1"}, "/org/findings/f1"),
        ("blumira_findings_details", {"finding_id": "f1"}, "/org/findings/f1/details"),
        ("blumira_findings_comments_list", {"finding_id": "f1"}, "/org/findings/f1/comments"),
        ("blumira_agents_devices_list", {}, "/org/agents/devices"),
        ("blumira_agents_devices_get", {"device_id": "d1"}, "/org/agents/devices/d1"),
        ("blumira_agents_keys_list", {}, "/org/agents/keys"),
        ("blumira_agents_keys_get", {"key_id": "k1"}, "/org/agents/keys/k1"),
        ("blumira_resolutions_list", {}, "/resolutions"),
        ("blumira_status", {}, "/health"),
        ("blumira_msp_accounts_list", {}, "/msp/accounts"),
        ("blumira_msp_accounts_get", {"account_id": "a1"}, "/msp/accounts/a1"),
        ("blumira_msp_findings_all", {"status": 10}, "/msp/accounts/findings"),
        ("blumira_msp_findings_list", {"account_id": "a1"}, "/msp/accounts/a1/findings"),
        ("blumira_msp_findings_get", {"account_id": "a1", "finding_id": "f1"}, "/msp/accounts/a1/findings/f1"),
        ("blumira_msp_findings_comments_list", {"account_id": "a1", "finding_id": "f1"}, "/msp/accounts/a1/findings/f1/comments"),
        ("blumira_msp_devices_list", {"account_id": "a1"}, "/msp/accounts/a1/agents/devices"),
        ("blumira_msp_devices_get", {"account_id": "a1", "device_id": "d1"}, "/msp/accounts/a1/agents/devices/d1"),
        ("blumira_msp_keys_list", {"account_id": "a1"}, "/msp/accounts/a1/agents/keys"),
        ("blumira_msp_keys_get", {"account_id": "a1", "key_id": "k1"}, "/msp/accounts/a1/agents/keys/k1"),
        ("blumira_msp_users_list", {"account_id": "a1"}, "/msp/accounts/a1/users"),
    ],
)
async def test_read_routing(monkeypatch, tool, args, path):
    fake = FakeApi()
    result = await _call(monkeypatch, fake, tool, args)
    req = fake.api()[0]
    assert (req.method, req.url.path) == ("GET", BASE + path)
    assert "error" not in result


async def test_navigation_needs_no_api_call(monkeypatch):
    fake = FakeApi()
    nav = await _call(monkeypatch, fake, "blumira_navigate", {"domain": "msp"})
    back = await _call(monkeypatch, fake, "blumira_back", {})
    assert "blumira_msp_findings_all" in nav["tools"] and "findings" in back["domains"]
    assert fake.requests == []


async def test_empty_comment_is_rejected(monkeypatch):
    fake = FakeApi()
    result = await _call(monkeypatch, fake, "blumira_findings_comments_add", {"finding_id": "f1", "body": "  ", "sender": "u1"})
    assert result["error"]["code"] == "invalid_argument" and fake.api() == []


# --- Page-number paging that survives truncation -------------------------------------------
# Blumira pages by page number + page_size only. A page cut to fit the response size limit
# continues by next_offset (record position), which reads the page that holds it and skips
# the records before it.

PAGED_TOOLS = [
    ("blumira_findings_list", {}, "/org/findings"),
    ("blumira_agents_devices_list", {}, "/org/agents/devices"),
    ("blumira_agents_keys_list", {}, "/org/agents/keys"),
    ("blumira_users_list", {}, "/org/users"),
    ("blumira_msp_accounts_list", {}, "/msp/accounts"),
    ("blumira_msp_findings_all", {}, "/msp/accounts/findings"),
    ("blumira_msp_findings_list", {"account_id": "a1"}, "/msp/accounts/a1/findings"),
    ("blumira_msp_devices_list", {"account_id": "a1"}, "/msp/accounts/a1/agents/devices"),
    ("blumira_msp_keys_list", {"account_id": "a1"}, "/msp/accounts/a1/agents/keys"),
    ("blumira_msp_users_list", {"account_id": "a1"}, "/msp/accounts/a1/users"),
]
TOOL_NAMES = [t[0] for t in PAGED_TOOLS]


def _paging_api(total: int, pad: int = 0) -> FakeApi:
    """Fake Blumira API that pages ``total`` records by page / page_size like the real one."""
    # many short fields: shortening long values cannot make a page of these fit
    records = [{"id": f"r{i}", **{f"f{j}": "x" * 70 for j in range(pad // 70)}} for i in range(total)]

    def reply(request: httpx.Request) -> httpx.Response:
        page = int(request.url.params.get("page", 1))
        size = int(request.url.params.get("page_size", 50))
        chunk = records[(page - 1) * size : page * size]
        pages = (total + size - 1) // size
        nxt = f"?page={page + 1}" if page < pages else None
        return httpx.Response(
            200,
            json={
                "status": "OK",
                "data": chunk,
                "links": {"self": f"?page={page}", "next": nxt, "prev": None},
                "meta": {"page": page, "page_size": size, "total_items": total, "total_pages": pages},
            },
        )

    return FakeApi(reply)


def _ids(result: dict) -> list[str]:
    return [r["id"] for r in result["items"]]


async def _walk(monkeypatch, fake, tool, extra, first_args):
    seen, args, calls = [], dict(extra, **first_args), 0
    while True:
        result = await _call(monkeypatch, fake, tool, args)
        calls += 1
        assert calls < 100
        assert "retry_page_size" not in result
        seen += _ids(result)
        if result.get("next_offset") is None:
            assert result["has_more"] is False
            return seen, calls
        args = dict(extra, offset=result["next_offset"])
        if "page_size" in first_args:
            args["page_size"] = first_args["page_size"]


@pytest.mark.parametrize("tool,extra,path", PAGED_TOOLS, ids=TOOL_NAMES)
async def test_cut_pages_walked_by_next_offset_return_every_record_once(monkeypatch, tool, extra, path):
    fake = _paging_api(130, pad=1400)  # 20 fields of 70 chars: a 50-record page does not fit 20,000
    seen, calls = await _walk(monkeypatch, fake, tool, extra, {})
    assert seen == [f"r{i}" for i in range(130)]
    assert calls > 3  # pages really were cut
    assert all(r.url.path == BASE + path for r in fake.api())


@pytest.mark.parametrize("tool,extra,path", PAGED_TOOLS, ids=TOOL_NAMES)
async def test_cut_pages_from_a_later_page(monkeypatch, tool, extra, path):
    fake = _paging_api(130, pad=1400)
    seen, _ = await _walk(monkeypatch, fake, tool, extra, {"page": 3, "page_size": 20})
    assert seen == [f"r{i}" for i in range(40, 130)]
    # every request keeps the caller's page size
    assert {r.url.params["page_size"] for r in fake.api()} == {"20"}


@pytest.mark.parametrize("tool,extra,path", PAGED_TOOLS, ids=TOOL_NAMES)
async def test_truncated_result_continues_by_offset_without_retry_page_size(monkeypatch, tool, extra, path):
    fake = _paging_api(130, pad=1400)
    result = await _call(monkeypatch, fake, tool, dict(extra, page=2))
    assert result["truncated"] is True
    assert "retry_page_size" not in result
    assert result["next_offset"] == 50 + result["count"]
    assert _ids(result) == [f"r{i}" for i in range(50, 50 + result["count"])]


@pytest.mark.parametrize(
    "offset,page,first",
    [(0, "1", "r0"), (7, "1", "r7"), (50, "2", "r50"), (73, "2", "r73"), (100, "3", "r100")],
)
async def test_offset_reads_the_page_that_holds_it(monkeypatch, offset, page, first):
    fake = _paging_api(130)
    result = await _call(monkeypatch, fake, "blumira_findings_list", {"offset": offset})
    (request,) = fake.api()
    assert request.url.params["page"] == page and request.url.params["page_size"] == "50"
    end = min((offset // 50 + 1) * 50, 130)
    assert _ids(result) == [f"r{i}" for i in range(offset, end)]
    assert result["items"][0]["id"] == first
    assert result["offset"] == offset
    assert result["next_offset"] == (end if end < 130 else None)


@pytest.mark.parametrize("tool,extra,path", PAGED_TOOLS, ids=TOOL_NAMES)
async def test_offset_past_the_end_is_empty(monkeypatch, tool, extra, path):
    fake = _paging_api(30)
    result = await _call(monkeypatch, fake, tool, dict(extra, offset=500, page_size=10))
    assert result["items"] == [] and result["count"] == 0
    assert result["has_more"] is False
    assert result["next_offset"] is None


@pytest.mark.parametrize("tool,extra,path", PAGED_TOOLS, ids=TOOL_NAMES)
async def test_offset_wins_over_page(monkeypatch, tool, extra, path):
    fake = _paging_api(130)
    result = await _call(monkeypatch, fake, tool, dict(extra, page=1, page_size=10, offset=25))
    (request,) = fake.api()
    assert request.url.params["page"] == "3" and request.url.params["page_size"] == "10"
    assert _ids(result) == [f"r{i}" for i in range(25, 30)]
    assert result["next_offset"] == 30


@pytest.mark.parametrize("tool,extra,path", PAGED_TOOLS, ids=TOOL_NAMES)
@pytest.mark.parametrize("page,page_size", [(None, None), (2, None), (3, 20), (0, 0), (1, 999)])
async def test_page_only_call_sends_the_same_request(monkeypatch, tool, extra, path, page, page_size):
    fake = _paging_api(130)
    args = dict(extra, **{k: v for k, v in {"page": page, "page_size": page_size}.items() if v is not None})
    result = await _call(monkeypatch, fake, tool, args)
    (request,) = fake.api()
    want_size = 50 if page_size is None else max(1, min(page_size, 200))
    want_page = max(1, page or 1)
    assert dict(request.url.params) == {"page": str(want_page), "page_size": str(want_size)}
    start = (want_page - 1) * want_size
    assert _ids(result) == [f"r{i}" for i in range(start, min(start + want_size, 130))]
    assert result["page"] == want_page
    assert result["total_items"] == 130
    assert result["has_more"] is (start + want_size < 130)


async def test_page_only_call_keeps_filters_and_limit(monkeypatch):
    fake = _paging_api(130)
    await _call(monkeypatch, fake, "blumira_findings_list", {"page": 2, "limit": 300, "order_by": "created;desc", "priority": 1})
    (request,) = fake.api()
    assert dict(request.url.params) == {
        "page": "2", "page_size": "50", "limit": "300", "order_by": "created;desc", "priority": "1"
    }
