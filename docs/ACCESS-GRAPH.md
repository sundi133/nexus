# Access graph and risk scores

**AI security → Access graph** answers *which human, on which device, with which AI client or agent, can reach which tools*. It also ranks people by risk, with the reasons.

## The graph

For each person:

```
person ─ uses ─▶ device ─▶ AI client (Cursor, Claude Desktop, Codex…) ─ server name ─▶ MCP server
   │                                                                                    │
   │                                              via Nexus: policy + audit ─▶ Nexus gateway server ─▶ approved tools (by risk)
   │                                              bypasses gateway ┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄▶ (the server it should go through)
   └─ owns ─▶ AI agent ─ may use N destructive, M read… ─▶ Nexus gateway server
```

- **Green:** goes through the Nexus gateway, where tool policy and the audit log apply.
- **Orange:** a remote MCP server that isn't behind the gateway.
- **Red:**
  - a server that bypasses the gateway (goes straight to one you govern through it);
  - a token written into a config file;
  - reach to destructive tools;
  - a non-compliant device.
- **Agents:** an agent's reach comes from the same policy engine the gateway enforces. It's the approved tools its permission rules allow.

## The score

Each person's score adds up named factors, capped at 100. When the same factor shows up on several devices, it counts once at full weight plus 5 per extra device, up to the factor's cap.

| Factor | Points |
|---|---|
| MCP server bypasses the Nexus gateway | 30 (up to 40) |
| No MFA | 25 |
| Device isn't compliant (enforced policies) | 20 (up to 30) |
| Tokens written into MCP config files | 20 (up to 30) |
| Administrator (owner or admin) | 15 |
| Admin without MFA | +15 |
| Ungoverned MCP servers | 15, +5 each (up to 25) |
| Owns an agent that can take destructive actions | 15 (up to 20) |
| Keeps starting blocked apps (7 days) | 10 (up to 15) |
| Delegated admin rights | 5 |
| Device compliance unknown | 5 (up to 10) |
| Owns an agent that acts outside the company | 5 (up to 10) |

**Levels:** low under 20, medium 20–44, high 45–69, critical 70 and above. Every factor comes with a sentence saying what to fix, e.g. *gh-direct (Claude Desktop) on sams-mac connects straight to servers you govern through the gateway*.

## Alerts

Every hour Nexus stores each person's score. When someone rises to **high** or **critical**:
- the audit log records `user.risk_raised`, with the factors;
- the built-in alert **Someone's risk became high** fires, so it reaches your on-call and SIEM like any other alert.

The first run after rollout only records a baseline, so turning this on doesn't raise an alert for everyone at once.

## Permissions

Viewing the scores and the graph needs organization-wide `users:read` and `devices:read`. Help desk and security analysts have both; admins scoped to groups don't.

## How to test it

1. Enroll a device and assign it to a person (**All devices → the device → Assign user**).
2. On that device, add an MCP server to Cursor or Claude Desktop that points straight at a server you've put behind the gateway (e.g. `https://api.githubcopilot.com/mcp/`). Also add one with an API key pasted into its config.
3. Within a minute, **Access graph** shows the person with *MCP server bypasses the Nexus gateway* and *Tokens written into MCP config files*. The graph draws a dashed red line to the gateway server it should use.
4. Register an AI agent owned by someone, give it a permission rule on a gateway server with a destructive tool, and see *Owns an agent that can take destructive actions*.
5. After the next hourly run, the audit log has `user.risk_raised` for anyone who crossed into high, and **Alerts** shows *Someone's risk became high*.

## Limits

- Scores are computed when you open the page. That's fine for thousands of people; beyond that they'd come from the hourly stored scores.
- The graph starts from people. Unassigned devices and agents without an owner don't appear yet.
- MCP clients that people connect through the gateway themselves aren't modelled: only agents go through the gateway today.
