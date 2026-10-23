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

<div align="center">

## MSPbots Connector

**The MCP Gateway built for MSPs: visible, controlled, and your data stays where it belongs.**

[**Get started at connect.mspbots.ai →**](https://connect.mspbots.ai)

</div>

---

MSPbots Connector gives your AI clients one MCP URL to reach your entire MSP stack (RMM, PSA, documentation, security, finance), and gives you control over who can call which tool and a record of everything that was called.

**Hosted service: [connect.mspbots.ai](https://connect.mspbots.ai)** · Free to use.

### Why Connector

![MSPbots Connector](https://stgoss.mspbots.ai/files/mcp/mspbots-mcp.png)

| | |
|---|---|
| **Visible** | Every tool call is logged: who, which vendor, when. Usage dashboard, CSV export, SIEM streaming. |
| **Controlled** | Role-based, per-tool allowlist. Deny by default. |
| **Protected** | Credentials encrypted per record. AI clients never see your vendor passwords or tokens. |
| **MSP-native** | Built for the MSP stack only: RMM, PSA, documentation, security, finance. |

### Quick start

1. **Sign up** at [connect.mspbots.ai](https://connect.mspbots.ai).
2. **Connect your vendors.** Pick from 150+ connectors and authorize each one on the vendor's own page, or bring your own API keys. No extra vendor accounts needed.
3. **Set access.** Create roles and decide which tools each role may call. Nothing is allowed until you allow it.
4. **Add your MCP URL to your AI client.** Copy the URL from your Connector dashboard into Claude, ChatGPT, Cursor, VS Code, Gemini, Codex, or any MCP-capable client.
5. **Ask your AI to do real work**, and watch every call appear in the audit log.

### Features

**Unified gateway**
- One MCP URL for all your AI clients
- 150+ connectors across the MSP stack
- Custom MCP servers supported, free
- Authorization happens on each vendor's own page; the AI never sees passwords or tokens
- Bring your own credentials: use the vendor API keys you already have
- Multiple accounts per app; connect once, reuse across AI clients
- Tool search: finds the right action for the task
- One sign-in; vendor credentials are injected behind the scenes and OAuth tokens refresh automatically

**Visibility**
- Audit log for every tool call (who, which vendor, when)
- Usage dashboard: call volume, top vendors, error rate, per-user activity
- Export audit logs to CSV, or stream to Loki, Graylog, or LogScale (SIEM)
- Optional recording of tool arguments and result summaries (off by default, enabled per organization)

**Control**
- Per-role, per-tool allowlist, deny by default
- owner / admin / member roles
- SCIM provisioning with Entra ID, Okta, JumpCloud, and Google Workspace

**Security**
- Credentials encrypted one record at a time (AES-256-GCM, per-record key)
- AI clients authenticate with OAuth 2.1 + PKCE
- Vendor responses are scanned for prompt-injection patterns and returned as structured data. This is one layer of defense, not a guarantee against every attack.
- Static egress IP for customer firewall and API allowlisting

### Pricing

**Free.**

Links: [connect.mspbots.ai](https://connect.mspbots.ai) · [mspbots.ai](https://mspbots.ai)

---

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
max 200), and return `{items, count, page, total_pages, total_items, has_more}`. They also take `offset`
(record position from 0, overrides `page`) and return `offset` / `next_offset`: when a page is cut to fit
the response size limit, the rest of it is on no other page, so continue with `next_offset`, which starts
right after the last record returned.

Organization:

| Tool | Purpose | Parameters (required in **bold**) |
|---|---|---|
| `blumira_navigate` | Show the tools of one area | **domain** (`findings`, `agents`, `users`, `msp`, `resolutions`) |
| `blumira_back` | List all areas and their tools | - |
| `blumira_status` | Check the credentials | - |
| `blumira_findings_list` | List findings | page, page_size, limit, order_by, status, priority, category, name, `name.contains`, `name.regex`, created_after, created_before, modified_after, modified_before, blocked, offset |
| `blumira_findings_get` | One finding | **finding_id** |
| `blumira_findings_details` | Analysis and evidence of a finding | **finding_id** |
| `blumira_findings_resolve` | Resolve a finding (**write**) | **finding_id**, **resolution**, resolution_notes |
| `blumira_findings_assign` | Set owners (**write**) | **finding_id**, **owner_type** (`responder`, `analyst`, `manager`), **owners** |
| `blumira_findings_comments_list` | Comments on a finding | **finding_id** |
| `blumira_findings_comments_add` | Add a comment (**write**) | **finding_id**, **body**, **sender** |
| `blumira_agents_devices_list` | Agent devices | page, page_size, limit, order_by, offset |
| `blumira_agents_devices_get` | One agent device | **device_id** |
| `blumira_agents_keys_list` | Agent enrolment keys | page, page_size, limit, order_by, offset |
| `blumira_agents_keys_get` | One agent key | **key_id** |
| `blumira_users_list` | Users (ids for comments and owners) | page, page_size, limit, order_by, offset |
| `blumira_resolutions_list` | Resolution codes | - |

MSP (sub-accounts):

| Tool | Purpose | Parameters (required in **bold**) |
|---|---|---|
| `blumira_msp_accounts_list` | Sub-accounts | page, page_size, limit, order_by, offset |
| `blumira_msp_accounts_get` | One sub-account | **account_id** |
| `blumira_msp_findings_all` | Findings across all sub-accounts | page, page_size, limit, status, priority, created_after, created_before, offset |
| `blumira_msp_findings_list` | Findings of one sub-account | **account_id**, page, page_size, status, priority, offset |
| `blumira_msp_findings_get` | One finding | **account_id**, **finding_id** |
| `blumira_msp_findings_resolve` | Resolve (**write**) | **account_id**, **finding_id**, **resolution**, resolution_notes |
| `blumira_msp_findings_assign` | Set owners (**write**) | **account_id**, **finding_id**, **owner_type**, **owners** |
| `blumira_msp_findings_comments_list` | Comments | **account_id**, **finding_id** |
| `blumira_msp_findings_comments_add` | Add a comment (**write**) | **account_id**, **finding_id**, **body**, **sender** |
| `blumira_msp_devices_list` | Agent devices of a sub-account | **account_id**, page, page_size, offset |
| `blumira_msp_devices_get` | One device | **account_id**, **device_id** |
| `blumira_msp_keys_list` | Agent keys of a sub-account | **account_id**, page, page_size, offset |
| `blumira_msp_keys_get` | One key | **account_id**, **key_id** |
| `blumira_msp_users_list` | Users of a sub-account | **account_id**, page, page_size, offset |

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
