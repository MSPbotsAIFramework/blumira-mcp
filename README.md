# Blumira MCP Server

An [MCP](https://modelcontextprotocol.io) server for the [Blumira](https://www.blumira.com)
SIEM public API. It lets an AI agent review and work Blumira findings (detections), look up
Blumira Agent devices and keys, and, for MSPs, do the same across all sub-accounts.

- Transport: MCP Streamable HTTP at `POST /mcp`, health probe at `GET /health`
- Stateless and multi-tenant: credentials arrive on every request as HTTP headers and are
  never stored; an OAuth access token is obtained per request and not cached
- Every tool is listed from the first `tools/list`
- Python 3.12, [uv](https://docs.astral.sh/uv/), FastMCP, httpx
- License: Apache-2.0, Copyright 2026 MSPbots.ai

## Authentication headers

Send **either** the client id and secret **or** a JWT token.

| Header | Required | Type | Default | Allowed values | Description | Example |
|---|---|---|---|---|---|---|
| `X-Blumira-Client-Id` | With secret | string | none | - | API client id (OAuth client credentials) | `your-client-id` |
| `X-Blumira-Client-Secret` | With client id | string | none | - | API client secret | `your-client-secret` |
| `X-Blumira-Jwt-Token` | Instead of id + secret | string | none | - | Pre-issued API JWT (a leading `Bearer ` is accepted) | `your-jwt` |

Where to get them:

- Create API credentials in the Blumira app's API access settings (organization keys work on
  the organization; MSP keys also work on every sub-account).
- With a client id and secret the server requests a token from
  `https://auth.blumira.com/oauth/token` (client credentials, audience
  `https://api.blumira.com/public-api/v1`) on each request. If a JWT token is sent, it is used
  directly and takes precedence.

A request to `/mcp` with neither credential set gets HTTP 401 describing both options.

## Tools

All tools return a JSON string. List tools take `page` (from 1) and `page_size` (default 50,
max 200), and return `{items, count, page, total_pages, total_items, has_more}`.

Organization:

| Tool | Purpose | Parameters (required in **bold**) |
|---|---|---|
| `blumira_navigate` | Show the tools of one area | **domain** (`findings`, `agents`, `users`, `msp`, `resolutions`) |
| `blumira_back` | List all areas and their tools | - |
| `blumira_status` | Check the credentials | - |
| `blumira_findings_list` | List findings | page, page_size, limit, order_by, status, priority, category, name, `name.contains`, `name.regex`, created_after, created_before, modified_after, modified_before, blocked |
| `blumira_findings_get` | One finding | **finding_id** |
| `blumira_findings_details` | Analysis and evidence of a finding | **finding_id** |
| `blumira_findings_resolve` | Resolve a finding (**write**) | **finding_id**, **resolution**, resolution_notes |
| `blumira_findings_assign` | Set owners (**write**) | **finding_id**, **owner_type** (`responder`, `analyst`, `manager`), **owners** |
| `blumira_findings_comments_list` | Comments on a finding | **finding_id** |
| `blumira_findings_comments_add` | Add a comment (**write**) | **finding_id**, **body**, **sender** |
| `blumira_agents_devices_list` | Agent devices | page, page_size, limit, order_by |
| `blumira_agents_devices_get` | One agent device | **device_id** |
| `blumira_agents_keys_list` | Agent enrolment keys | page, page_size, limit, order_by |
| `blumira_agents_keys_get` | One agent key | **key_id** |
| `blumira_users_list` | Users (ids for comments and owners) | page, page_size, limit, order_by |
| `blumira_resolutions_list` | Resolution codes | - |

MSP (sub-accounts):

| Tool | Purpose | Parameters (required in **bold**) |
|---|---|---|
| `blumira_msp_accounts_list` | Sub-accounts | page, page_size, limit, order_by |
| `blumira_msp_accounts_get` | One sub-account | **account_id** |
| `blumira_msp_findings_all` | Findings across all sub-accounts | page, page_size, limit, status, priority, created_after, created_before |
| `blumira_msp_findings_list` | Findings of one sub-account | **account_id**, page, page_size, status, priority |
| `blumira_msp_findings_get` | One finding | **account_id**, **finding_id** |
| `blumira_msp_findings_resolve` | Resolve (**write**) | **account_id**, **finding_id**, **resolution**, resolution_notes |
| `blumira_msp_findings_assign` | Set owners (**write**) | **account_id**, **finding_id**, **owner_type**, **owners** |
| `blumira_msp_findings_comments_list` | Comments | **account_id**, **finding_id** |
| `blumira_msp_findings_comments_add` | Add a comment (**write**) | **account_id**, **finding_id**, **body**, **sender** |
| `blumira_msp_devices_list` | Agent devices of a sub-account | **account_id**, page, page_size |
| `blumira_msp_devices_get` | One device | **account_id**, **device_id** |
| `blumira_msp_keys_list` | Agent keys of a sub-account | **account_id**, page, page_size |
| `blumira_msp_keys_get` | One key | **account_id**, **key_id** |
| `blumira_msp_users_list` | Users of a sub-account | **account_id**, page, page_size |

Errors come back as a JSON envelope instead of an exception:

```json
{"error": {"code": "unauthorized", "message": "Blumira rejected the client id / secret (token request failed)", "retryable": false}}
```

`code` is one of `not_configured`, `unauthorized`, `not_found`, `invalid_argument`,
`rate_limited`, `upstream_error`.

## Run locally

```bash
uv sync
uv run python -m blumira_mcp          # listens on 0.0.0.0:8080
```

or with Docker:

```bash
docker build --platform linux/amd64 -t blumira-mcp:dev .
docker run --rm -p 8080:8080 blumira-mcp:dev
```

Configuration (environment variables, all optional): `MCP_HTTP_HOST` (default `0.0.0.0`),
`MCP_HTTP_PORT` (default `8080`), `LOG_LEVEL` (default `INFO`). Credentials are never read from
the environment.

## Testing example

```bash
# list tools
curl -s http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "X-Blumira-Client-Id: your-client-id" \
  -H "X-Blumira-Client-Secret: your-client-secret" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'

# highest-priority findings
curl -s http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "X-Blumira-Client-Id: your-client-id" \
  -H "X-Blumira-Client-Secret: your-client-secret" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"blumira_findings_list","arguments":{"priority":1,"page_size":10}}}'
```

Unit tests (no network access needed):

```bash
uv run pytest
```

## Delivery notes

- **All tools always listed.** Older versions only listed navigation tools until one was
  called, which hid the other tools behind a stateless gateway. All 30 tools are now listed up
  front; `blumira_navigate` and `blumira_back` remain and only describe the tools.
- **Tool count (30).** Kept as is because the tool names and argument names (including
  `name.contains` and `name.regex`) are an existing contract.
- **Write tools.** Resolve, assign and comment tools change findings; they are annotated
  `readOnlyHint=false` and their descriptions tell the agent to act only on an explicit
  request. There are no delete tools.

## License

Apache License 2.0 - see [LICENSE](LICENSE) and [NOTICE](NOTICE).
