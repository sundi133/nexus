# MCP for people: AI clients through the Nexus gateway

AI clients like Cursor, Claude Desktop, VS Code and Claude Code use MCP servers to act with people's access: read tickets, query the CRM, open pull requests. Connected directly, those calls are invisible, and so is the data they carry. Through the Nexus gateway, each person's AI client is under the same controls as your AI agents:

- **Sign-in:** people sign in with Nexus once per client. MFA, conditional access and device trust apply, exactly as for any app.
- **Tool rules:** a person sees and calls only the tools their rules allow. Rules can name a person, a group, or everyone, and can restrict by tool, risk and arguments.
- **Audit:** every call is in the audit log as that person, with the client they used.
- **Data protection:** secrets in a call's arguments stop the call. Secrets in a tool's results are redacted before the AI reads them. Other sensitive data is monitored or redacted, per your settings.
- **Ending access:** offboarding, containment and "sign out everywhere" disconnect every AI client at once. People can also disconnect their own.

## Setting it up

1. Put the MCP server behind the gateway (**AI security → MCP servers → Add**) and approve its tools.
2. Add a rule for people: **Add a tool permission → Allow · people in the group** *Support* · every read tool, for example.
3. Tell people the server's address. The server page has ready-to-paste configuration:

   | Client | How |
   |---|---|
   | Cursor | `~/.cursor/mcp.json`: `{ "mcpServers": { "crm": { "url": "https://api.nexus.example.com/mcp/acme/crm" } } }` |
   | Claude Desktop | Settings → Connectors → *Add custom connector* → the address |
   | VS Code | `.vscode/mcp.json`: `{ "servers": { "crm": { "type": "http", "url": "…" } } }` |
   | Claude Code | `claude mcp add --transport http crm https://api.nexus.example.com/mcp/acme/crm` |

The first time, the client opens a Nexus sign-in in the browser. After that it keeps working until the person is signed out everywhere, disconnects the client, or stops using it for 30 days.

## How the sign-in works

It follows the MCP authorization spec, so standard clients need nothing special:

1. **The gateway asks for a token.** It answers `401` with protected-resource metadata (RFC 9728) naming Nexus as the authorization server.
2. **The client discovers Nexus.** The metadata is at `/.well-known/oauth-authorization-server/oidc/<org>` (RFC 8414) and `…/.well-known/openid-configuration`.
3. **The client registers itself** (RFC 7591) as a public client. It may only receive codes on the same machine (`http://127.0.0.1`, `http://localhost`) or in its own app scheme (`cursor://…`, `vscode://…`), never at a web address.
4. **The person signs in** in the browser: authorization code with PKCE, for this gateway resource (RFC 8707). Nexus checks:
   - that the person has at least one tool rule on that server;
   - conditional access, where organization-wide policies apply to the *MCP gateway (AI clients)*.
5. **Tokens:**
   - an access token for one hour, valid only for the gateway;
   - a refresh token that **rotates on every use**. If an old refresh token is presented again (someone copied it), the whole authorization ends and it's audited (`mcp.grant_revoked`, reason `refresh_token_reused`).

## Data protection

**AI security → MCP servers → Data protection for tool calls.** It applies to every server, for agents and people.

| Data | In arguments (what leaves) | In results (what the AI reads) |
|---|---|---|
| API keys, tokens, passwords | **Block** (default) | **Redact** (default) |
| Private keys | **Block** | **Redact** |
| Payment cards, US SSNs | Off | Monitor |
| IBANs, email lists | Off | Off |

- **Blocked calls** return an error to the AI ("the arguments contain an AWS access key") and never reach the tool.
- **Redacted values** become `[redacted: AWS access key]`.
- **The audit record** of each call lists the findings (`dlp_arguments`, `dlp_results`): the kind of data and how many, never the data.

It uses the same detectors as the browser extension ([BROWSER-EXTENSION.md](BROWSER-EXTENSION.md)): Luhn-checked cards, checksummed IBANs, and code-aware password detection.

## What admins see

- **The audit log:**
  - `mcp.tool_called` and `mcp.tool_denied`, with the person as the actor and `via: "Cursor"`;
  - `mcp.client_authorized`, including refusals (no tools, conditional access);
  - `mcp.grant_revoked`.
- **A person's AI clients:** `GET /v1/users/{id}/mcp-connections`, and disconnect with `DELETE …/{grantId}`.
- **Self-service:** people manage theirs under **My security → AI clients**.

## How it's tested

`apps/api/test/mcp-people.e2e.test.ts` uses a real MCP client (the official SDK) against a real MCP server through the gateway. It covers:
- discovery;
- registration, refused for web redirects and secret-based clients;
- sign-in refused without tools;
- a group rule giving read tools only;
- a resource outside the gateway refused;
- calls audited as the person;
- a key in results redacted, and cards monitored, then redacted after a policy change;
- a call with a key in its arguments stopped before the tool;
- refresh rotation, and reuse ending the grant;
- "sign out everywhere" cutting off the client's token at once.
