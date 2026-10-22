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
"""tools/list snapshot and error-envelope mapping. No network access."""

import asyncio
import json

import pytest

from blumira_mcp.api_client import BlumiraError
from blumira_mcp.server import INSTRUCTIONS, create_mcp_server

# Tool names are a public contract: existing agents and tenant connections
# depend on them. Changing this snapshot is a breaking change.
EXPECTED_TOOLS: dict[str, set[str]] = {
    "blumira_navigate": {"domain"},
    "blumira_back": set(),
    "blumira_status": set(),
    "blumira_resolutions_list": set(),
    "blumira_users_list": set(),
    "blumira_agents_devices_list": set(),
    "blumira_agents_devices_get": {"device_id"},
    "blumira_agents_keys_list": set(),
    "blumira_agents_keys_get": {"key_id"},
    "blumira_findings_list": set(),
    "blumira_findings_get": {"finding_id"},
    "blumira_findings_details": {"finding_id"},
    "blumira_findings_resolve": {"finding_id", "resolution"},
    "blumira_findings_assign": {"finding_id", "owner_type", "owners"},
    "blumira_findings_comments_list": {"finding_id"},
    "blumira_findings_comments_add": {"finding_id", "body", "sender"},
    "blumira_msp_accounts_list": set(),
    "blumira_msp_accounts_get": {"account_id"},
    "blumira_msp_findings_all": set(),
    "blumira_msp_findings_list": {"account_id"},
    "blumira_msp_findings_get": {"account_id", "finding_id"},
    "blumira_msp_findings_resolve": {"account_id", "finding_id", "resolution"},
    "blumira_msp_findings_assign": {"account_id", "finding_id", "owner_type", "owners"},
    "blumira_msp_findings_comments_list": {"account_id", "finding_id"},
    "blumira_msp_findings_comments_add": {"account_id", "finding_id", "body", "sender"},
    "blumira_msp_devices_list": {"account_id"},
    "blumira_msp_devices_get": {"account_id", "device_id"},
    "blumira_msp_keys_list": {"account_id"},
    "blumira_msp_keys_get": {"account_id", "key_id"},
    "blumira_msp_users_list": {"account_id"},
}

WRITE_TOOLS = {
    "blumira_findings_resolve",
    "blumira_findings_assign",
    "blumira_findings_comments_add",
    "blumira_msp_findings_resolve",
    "blumira_msp_findings_assign",
    "blumira_msp_findings_comments_add",
}

FINDINGS_FILTERS = [
    "page", "page_size", "limit", "order_by", "status", "priority", "category", "name", "name.contains",
    "name.regex", "created_after", "created_before", "modified_after", "modified_before", "blocked", "offset",
]


@pytest.fixture(scope="module")
def tools():
    return {t.name: t for t in asyncio.run(create_mcp_server().list_tools())}


def test_all_tools_listed_without_navigation(tools):
    assert set(tools) == set(EXPECTED_TOOLS)


@pytest.mark.parametrize("name", sorted(EXPECTED_TOOLS))
def test_required_params(tools, name):
    assert set(tools[name].inputSchema.get("required", [])) == EXPECTED_TOOLS[name]


def test_findings_list_keeps_filter_names(tools):
    assert list(tools["blumira_findings_list"].inputSchema["properties"]) == FINDINGS_FILTERS


@pytest.mark.parametrize("name", sorted(EXPECTED_TOOLS))
def test_description_budget(tools, name):
    description = (tools[name].description or "").strip()
    assert description, f"{name} has no description"
    assert len(description) <= 500
    assert len(description.splitlines()[0]) <= 100
    assert "API:" not in description


@pytest.mark.parametrize("name", sorted(EXPECTED_TOOLS))
def test_every_param_is_documented(tools, name):
    for param, schema in tools[name].inputSchema.get("properties", {}).items():
        assert schema.get("description") or "enum" in json.dumps(schema), f"{name}.{param}"


@pytest.mark.parametrize("name", sorted(EXPECTED_TOOLS))
def test_annotations(tools, name):
    annotations = tools[name].annotations
    assert annotations is not None
    assert annotations.readOnlyHint is (name not in WRITE_TOOLS)
    assert not annotations.destructiveHint
    if name in WRITE_TOOLS:
        assert "explicitly asks" in tools[name].description


def test_instructions_present_and_bounded():
    assert INSTRUCTIONS and len(INSTRUCTIONS) <= 1500
    for name in ("blumira_findings_list", "blumira_msp_accounts_list", "blumira_findings_resolve"):
        assert name in INSTRUCTIONS


def test_navigate_covers_every_tool():
    from blumira_mcp.tools.navigation import DOMAIN_TOOLS

    listed = {tool for tools_ in DOMAIN_TOOLS.values() for tool in tools_}
    assert listed == set(EXPECTED_TOOLS) - {"blumira_navigate", "blumira_back", "blumira_status"}


@pytest.mark.parametrize(
    "status_code,expected_code,expected_retryable",
    [
        (0, "upstream_error", True),
        (400, "invalid_argument", False),
        (401, "unauthorized", False),
        (403, "unauthorized", False),
        (404, "not_found", False),
        (422, "invalid_argument", False),
        (429, "rate_limited", True),
        (500, "upstream_error", True),
        (503, "upstream_error", True),
    ],
)
def test_error_envelope_mapping(status_code, expected_code, expected_retryable):
    envelope = json.loads(BlumiraError(status_code, "boom").to_envelope())
    assert envelope == {
        "error": {"code": expected_code, "message": "boom", "retryable": expected_retryable}
    }
