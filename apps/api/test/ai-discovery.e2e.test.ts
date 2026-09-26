import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { newId } from "../src/platform/ids.js";
import { bootApp, PASSWORD, uniqueEmail } from "./harness.js";
import { SoftDevice } from "./soft-device.js";

/** AI on devices: MCP servers and AI tools reported by agents, classified against the org's MCP gateway. */

let h: Awaited<ReturnType<typeof bootApp>>;
let admin = "";
let orgId = "";
let slug = "";
let gateway = "";

const healthy = { disk_encryption: { status: "on" }, firewall: { status: "on" }, screen_lock: { status: "on", delay_seconds: 60 }, system_integrity: { status: "on" } };

async function agentCall(path: string, payload: unknown, proof: string) {
  const res = await h.app.request(path, { method: "POST", headers: { "content-type": "application/json", authorization: `NexusDevice ${proof}` }, body: JSON.stringify(payload) });
  return { status: res.status, body: (await res.json()) as Record<string, any> };
}
async function enrolled(hostname: string) {
  const d = await new SoftDevice().init();
  const t = await h.call("POST", "/v1/devices/enrollment-tokens", { token: admin, body: { name: `t-${hostname}`, max_uses: 1 } });
  const payload = { token: t.body.token, device: { hostname, platform: "macos", os_name: "macOS", os_version: "15.1", os_build: "x", arch: "arm64", model: "Mac", serial: `SER-${hostname}`, agent_version: "0.3.0" } };
  const r = await agentCall("/v1/agent/enroll", payload, await d.proof("/v1/agent/enroll", JSON.stringify(payload), { enroll: true }));
  d.id = r.body.device_id;
  return d;
}
async function checkin(d: SoftDevice, ai?: unknown) {
  const payload = { device: { agent_version: "0.3.0" }, posture: healthy, ...(ai === undefined ? {} : { inventory: { cpu: "M3", ai } }) };
  return agentCall("/v1/agent/checkin", payload, await d.proof("/v1/agent/checkin", JSON.stringify(payload)));
}
const device = async (id: string) => (await h.call("GET", `/v1/devices/${id}`, { token: admin })).body;
const check = async (id: string) => (await device(id)).checks.find((c: any) => c.key === "ai_mcp_governed");

const srv = (o: Record<string, unknown>) => ({ client: "Cursor", user: "sam", scope: "user", transport: "http", ...o });
const samAI = () => ({
  tools: [
    { name: "Cursor", kind: "app", version: "1.4.0" },
    { name: "Claude Code", kind: "cli", user: "sam" },
  ],
  mcp_servers: [
    srv({ name: "github", url: `${gateway}/github` }), // through Nexus
    srv({ name: "github-direct", client: "Claude Desktop", url: "https://api.githubcopilot.com/mcp/" }), // straight to what Nexus fronts
    srv({ name: "linear", url: "https://mcp.linear.app/sse", transport: "sse", inline_secrets: true }),
    srv({ name: "fs", transport: "stdio", command: "npx", package: "@modelcontextprotocol/server-filesystem", url: undefined }),
    srv({ name: "old", url: "https://old.example.com/mcp", disabled: true }),
    srv({ name: "dev", url: "http://localhost:9100/mcp" }), // loopback: runs on the device
  ],
});

beforeAll(async () => {
  h = await bootApp();
  admin = (await h.call("POST", "/v1/signup", { body: { organization_name: "AI Co", email: uniqueEmail("root"), password: PASSWORD, given_name: "Root" } })).body.token;
  await h.call("PATCH", "/v1/org/settings", { token: admin, body: { mfa_policy: "off" } });
  const me = (await h.call("GET", "/v1/me", { token: admin })).body;
  orgId = me.organization.id;
  slug = me.organization.slug;
  gateway = `${h.deps.cfg.apiPublicUrl}/mcp/${slug}`;
  // An upstream the org governs through the gateway (created directly: the API would connect to it).
  await h.deps.db.tenant(orgId, (tx) =>
    tx.insertInto("mcp_servers").values({ id: newId(), org_id: orgId, name: "GitHub", slug: "github", url: "https://api.githubcopilot.com/mcp", server_info: JSON.stringify({}) }).execute(),
  );
});
afterAll(() => h.close());

describe("AI on devices", () => {
  it("classifies each MCP server against the gateway", async () => {
    const sam = await enrolled("sams-mac");
    expect((await checkin(sam, samAI())).status).toBe(200);
    const ai = (await device(sam.id)).ai;
    const by = Object.fromEntries(ai.mcp_servers.map((s: any) => [s.name, s]));
    expect(by.github).toMatchObject({ governance: "gateway", target: expect.stringContaining(`/mcp/${slug}/github`) });
    expect(by["github-direct"]).toMatchObject({ governance: "bypass", via: "GitHub", client: "Claude Desktop" });
    expect(by.linear).toMatchObject({ governance: "remote", transport: "sse", inline_secrets: true, target: "mcp.linear.app/sse" });
    expect(by.fs).toMatchObject({ governance: "local", target: "@modelcontextprotocol/server-filesystem" });
    expect(by.old).toMatchObject({ disabled: true });
    expect(by.dev).toMatchObject({ governance: "local", target: "localhost:9100/mcp" });
    expect(ai.tools).toEqual([
      { name: "Cursor", kind: "app", version: "1.4.0", user: null },
      { name: "Claude Code", kind: "cli", version: null, user: "sam" },
    ]);
  });

  it("aggregates across the fleet, worst first", async () => {
    const kim = await enrolled("kims-mac");
    await checkin(kim, { tools: [{ name: "Cursor", kind: "app", version: "1.5.0" }], mcp_servers: [srv({ user: "kim", name: "linear-mcp", url: "https://MCP.linear.app/sse/", transport: "sse" })] });
    const old = await enrolled("old-agent"); // an agent that doesn't report AI yet
    await checkin(old);

    const f = (await h.call("GET", "/v1/devices/ai-inventory", { token: admin })).body;
    expect(f.summary).toEqual({ devices: 3, reporting: 2, with_ai_tools: 2, with_mcp: 2, ungoverned: 2, inline_secrets: 1 });
    expect(f.servers.map((s: any) => s.governance)).toEqual(["bypass", "remote", "local", "local", "gateway"]); // the disabled one isn't counted
    const linear = f.servers.find((s: any) => s.governance === "remote");
    expect(linear).toMatchObject({ target: "mcp.linear.app/sse", devices: 2, names: ["linear", "linear-mcp"], inline_secrets: 1 });
    expect(linear.on.map((o: any) => o.hostname)).toEqual(["kims-mac", "sams-mac"]);
    expect(f.tools[0]).toEqual({ name: "Cursor", kind: "app", devices: 2, versions: ["1.4.0", "1.5.0"] });
  });

  it("audits servers appearing and disappearing, but not the first report", async () => {
    const sam = (await h.call("GET", "/v1/devices?q=sams-mac", { token: admin })).body.data[0];
    const events = async () => (await h.call("GET", `/v1/audit/events?type=device.ai_changed&limit=10`, { token: admin })).body.data;
    expect(await events()).toEqual([]);
    // The device's key signs check-ins: reuse the enrolled SoftDevice by re-enrolling is impossible, so report from a new one.
    const pat = await enrolled("pats-mac");
    await checkin(pat, { tools: [], mcp_servers: [] });
    await checkin(pat, { tools: [], mcp_servers: [srv({ user: "pat", name: "notion", url: "https://mcp.notion.com/mcp", inline_secrets: true })] });
    const ev = await events();
    expect(ev).toHaveLength(1);
    expect(ev[0]).toMatchObject({ type: "device.ai_changed", target: { display: "pats-mac" }, details: { added_count: 1, removed_count: 0, added: [{ name: "notion", target: "mcp.notion.com/mcp", governance: "remote", inline_secrets: true }] } });
    expect(sam.hostname).toBe("sams-mac");
  });

  it("the policy: off by default, then audits, allows hosts, and fails on bypass and secrets", async () => {
    const sam = (await h.call("GET", "/v1/devices?q=sams-mac", { token: admin })).body.data[0];
    expect(await check(sam.id)).toBeUndefined();
    const pol = (await h.call("GET", "/v1/device-policies", { token: admin })).body.data.find((p: any) => p.key === "ai_mcp_governed");
    expect(pol).toMatchObject({ enabled: false, mode: "audit", title: "AI tools use approved MCP servers", params: { allowed_hosts: [], allow_local: true, allow_inline_secrets: false } });

    const put = (params: Record<string, unknown>, mode = "audit") => h.call("PUT", "/v1/device-policies/ai_mcp_governed", { token: admin, body: { enabled: true, mode, params: { allowed_hosts: [], allow_local: true, allow_inline_secrets: false, ...params } } });
    expect((await put({})).status).toBe(200);
    const c = await check(sam.id);
    expect(c).toMatchObject({ status: "fail", enforced: false });
    expect(c.detail).toContain("github-direct (Claude Desktop) connects straight to GitHub, bypassing the Nexus gateway");
    expect(c.detail).toContain("linear (Cursor) uses mcp.linear.app");
    expect(c.detail).toContain("token written into its config file");
    expect((await device(sam.id)).compliance).toBe("compliant"); // audit mode doesn't count

    // Allowing Linear's host and inline secrets leaves only the bypass.
    await put({ allowed_hosts: ["*.linear.app"], allow_inline_secrets: true });
    expect((await check(sam.id)).detail).toBe("github-direct (Claude Desktop) connects straight to GitHub, bypassing the Nexus gateway");
    expect((await device(sam.id)).ai.mcp_servers.find((s: any) => s.name === "linear").governance).toBe("allowed");
    expect((await h.call("PUT", "/v1/device-policies/ai_mcp_governed", { token: admin, body: { enabled: true, params: { allowed_hosts: ["not a host!"], allow_local: true, allow_inline_secrets: true } } })).status).toBe(400);

    // Enforced: kim (only Linear, now allowed) passes; the device without an AI report is unknown.
    await put({ allowed_hosts: ["*.linear.app"], allow_inline_secrets: true, allow_local: false }, "enforce");
    const kim = (await h.call("GET", "/v1/devices?q=kims-mac", { token: admin })).body.data[0];
    expect(await check(kim.id)).toMatchObject({ status: "pass", detail: "1 MCP server, all approved" });
    const s = await check(sam.id);
    expect(s.detail).toContain("fs (Cursor) runs on the device (@modelcontextprotocol/server-filesystem)");
    expect((await device(sam.id)).compliance).toBe("non_compliant");
    const old = (await h.call("GET", "/v1/devices?q=old-agent", { token: admin })).body.data[0];
    expect(await check(old.id)).toMatchObject({ status: "unknown" });
  });

  it("drops a malformed AI report without losing the check-in", async () => {
    const d = await enrolled("weird-mac");
    const r = await checkin(d, { tools: "nope", mcp_servers: [{ name: 1 }] });
    expect(r.status).toBe(200);
    const detail = await device(d.id);
    expect(detail.ai).toBeNull();
    expect(detail.inventory).toMatchObject({ cpu: "M3" });
  });
});
