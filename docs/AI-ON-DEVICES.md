# AI on devices

The Nexus agent finds the AI tools people run and the MCP servers they connect them to. The console then shows, for the whole fleet and for each device:
- which person runs which AI clients;
- which MCP servers those clients use;
- whether those servers go through the Nexus MCP gateway.

A device policy can require that they do.

## What the agent reads

Only these known config files, in each account's home directory:

| Client | File (macOS; Windows and Linux use the platform's equivalent) |
|---|---|
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Claude Code | `~/.claude.json` (user servers and per-project servers) |
| Cursor | `~/.cursor/mcp.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |
| VS Code | `…/Code/User/mcp.json` and `settings.json` (`mcp.servers`) |
| Cline | `…/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json` |
| Gemini CLI | `~/.gemini/settings.json` |
| Codex | `~/.codex/config.toml` |
| Zed | `~/.config/zed/settings.json` (`context_servers`) |

It also lists installed AI apps, CLIs and editor extensions: Claude, ChatGPT, Cursor, Windsurf, Ollama, LM Studio, Copilot, Cline, Continue, Codex and others.

**For each MCP server, the agent reports only:**
- its name, client, account and transport;
- where it connects: the URL without query string or credentials, or the package, container image or program base name it runs;
- the *names* of its environment variables;
- whether a secret is written into the config in plain text.

**The agent never sends:**
- secret values or other arguments;
- project paths;
- file contents, prompts or conversations.

The agent unwraps local proxies (`mcp-remote`, `supergateway`, `mcp-proxy`), so a remote server doesn't pass as a local one.

## How servers are classified

| Status | Meaning |
|---|---|
| **Via Nexus** | The URL is this organization's Nexus MCP gateway: tool policy and the audit log apply |
| **Bypasses gateway** | Connects straight to a server the organization put behind the gateway. Point the client at the gateway URL instead |
| **Ungoverned** | Any other remote MCP server |
| **Allowed host** | A remote host the device policy allows |
| **Local** | Runs on the device (stdio, or HTTP on localhost) |

Separately, **Token in config** flags a server whose config file holds an API key or token in plain text, detected by variable name or by known token formats (GitHub, Slack, OpenAI, AWS, Google, Notion, Linear…). Anyone who can read that file, or any backup of it, gets the token.

## Where to see it

- **AI on devices** (under AI security) shows every MCP server once, with how many devices and people use it, worst first. Expand a row to see which devices use it. The page also lists AI tools by how many devices have them.
- **A device's AI tab** shows that device's servers and tools.
- **Audit log:** `device.ai_changed` records servers appearing on or leaving a device, including their status. You can alert on it.

## The policy

**Device policies → AI tools use approved MCP servers.** It's off by default and starts in audit mode:

| Setting | Default |
|---|---|
| Remote MCP hosts allowed without the gateway (`mcp.corp.com`, `*.corp.com`) | none |
| Allow MCP servers that run on the device | yes |
| Allow tokens written into MCP config files | no |

A device fails when an enabled server bypasses the gateway, uses a remote host that isn't allowed, or holds a token in its config. Local servers also fail it when they aren't allowed. The check names each problem, and the device's user sees how to fix it. Enforce it, with a grace period, once audit mode shows what people use. Devices whose agent doesn't report AI tools yet show as *unknown*.

## Limits

- It only sees the clients above, and servers defined in their user-level config. Project files inside repositories (`.mcp.json`, `.cursor/mcp.json` in a repo) aren't scanned, because the agent doesn't walk the disk. Claude Code's per-project servers are covered, since they live in `~/.claude.json`.
- It reports configuration, not traffic. A server configured but never used still shows. A client that connects without a config file doesn't.
- Browser-based AI (ChatGPT or Claude on the web) isn't covered. That needs a browser extension or network controls.
