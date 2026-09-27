import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { parse } from "yaml";
import { type IO, run } from "@nexus/cli";
import { bootApp, PASSWORD, uniqueEmail } from "./harness.js";

/** The `nexus` CLI (INT-05) against the real API, with an API key: a GitOps round trip. */

let h: Awaited<ReturnType<typeof bootApp>>;
let key = "";
const files = new Map<string, string>();

function io(env: Record<string, string> = {}, answer?: boolean): IO & { stdout: string; stderr: string } {
  const o = {
    stdout: "",
    stderr: "",
    env: { NEXUS_URL: "http://api.test", NEXUS_TOKEN: key, ...env },
    fetch: ((url: string | URL | Request, init?: RequestInit) => (url instanceof Request ? h.app.request(url) : h.app.request(String(url).replace("http://api.test", ""), init))) as typeof fetch,
    out: (s: string) => void (o.stdout += s),
    err: (s: string) => void (o.stderr += s),
    readFile: async (p: string) => {
      const f = files.get(p);
      if (f === undefined) throw new Error(`ENOENT ${p}`);
      return f;
    },
    writeFile: async (p: string, d: string) => void files.set(p, d),
    confirm: answer === undefined ? undefined : async () => answer,
    home: "/home/test",
  };
  return o;
}

beforeAll(async () => {
  h = await bootApp();
  const email = uniqueEmail("root");
  const token = (await h.call("POST", "/v1/signup", { body: { organization_name: "CLI Co", email, password: PASSWORD, given_name: "Root" } })).body.token;
  await h.call("PATCH", "/v1/org/settings", { token, body: { mfa_policy: "off" } });
  const me = (await h.call("GET", "/v1/me", { token })).body.user.id;
  await h.call("POST", "/v1/agents", { token, body: { name: "Deploy bot", owner_user_id: me } });
  const r = await h.call("POST", "/v1/api-keys", { token, body: { name: "GitOps", scopes: ["org:manage", "groups:write", "alerts:manage", "alerts:read", "agents:read", "agents:suspend", "agents:manage", "mcp:manage", "audit:read", "users:read"] } });
  key = r.body.key;
});
afterAll(async () => {
  await h.close();
});

describe("nexus CLI", () => {
  it("exports the config as YAML, without secrets", async () => {
    const o = io();
    expect(await run(["config", "export", "-o", "nexus.yaml"], o)).toBe(0);
    const doc = parse(files.get("nexus.yaml")!);
    expect(doc.version).toBe(1);
    expect(doc.agents[0].name).toBe("Deploy bot");
    expect(files.get("nexus.yaml")).toMatch(/^# Votal Nexus config/);
  });

  it("plans and applies an edited file, asking first", async () => {
    const doc = parse(files.get("nexus.yaml")!);
    doc.groups = [{ name: "SRE", description: "On-call engineers" }];
    doc.mcp_servers = [{ slug: "pager", name: "Pager tools", url: "http://127.0.0.1:9/mcp", auth: { kind: "bearer", token_env: "PAGER_MCP_TOKEN" }, permissions: [{ effect: "allow", subject: "agent:Deploy bot", tools: ["*"], risks: ["read"] }] }];
    files.set("nexus.yaml", JSON.stringify(doc)); // YAML is a superset of JSON

    const p = io({ PAGER_MCP_TOKEN: "pd-secret" });
    expect(await run(["config", "plan", "-f", "nexus.yaml"], p)).toBe(0);
    expect(p.stdout).toContain("+ groups: SRE");
    expect(p.stdout).toContain("+ mcp_servers: pager");
    expect(p.stdout).toMatch(/Plan: 2 to create, 1 to change, 0 to delete\./);

    const noTty = io({ PAGER_MCP_TOKEN: "pd-secret" });
    expect(await run(["config", "apply", "-f", "nexus.yaml"], noTty)).toBe(1);
    expect(noTty.stderr).toContain("--yes");

    const declined = io({ PAGER_MCP_TOKEN: "pd-secret" }, false);
    expect(await run(["config", "apply", "-f", "nexus.yaml"], declined)).toBe(1);

    const yes = io({ PAGER_MCP_TOKEN: "pd-secret" }, true);
    expect(await run(["config", "apply", "-f", "nexus.yaml"], yes)).toBe(0);
    expect(yes.stdout).toMatch(/Applied 3 changes/);
    const again = io({ PAGER_MCP_TOKEN: "pd-secret" });
    await run(["config", "plan", "-f", "nexus.yaml"], again);
    expect(again.stdout).toContain("No changes.");
  });

  it("reports config problems clearly", async () => {
    const doc = parse(files.get("nexus.yaml")!);
    doc.mcp_servers[0].permissions[0].subject = "agent:Ghost";
    files.set("bad.yaml", JSON.stringify(doc));
    const o = io({ PAGER_MCP_TOKEN: "x" });
    expect(await run(["config", "plan", "-f", "bad.yaml"], o)).toBe(1);
    expect(o.stderr).toContain('unknown agent "Ghost"');
  });

  it("suspends an agent, lists alerts and verifies the audit log", async () => {
    const s = io();
    expect(await run(["agents", "suspend", "Deploy", "bot", "--reason", "incident 42"], s)).toBe(0);
    expect(s.stdout).toContain("Suspended Deploy bot");
    const l = io();
    await run(["agents", "list"], l);
    expect(l.stdout).toMatch(/SUSPENDED\s+Deploy bot/);
    const a = io();
    expect(await run(["alerts", "list"], a)).toBe(0);
    const v = io();
    expect(await run(["audit", "verify"], v)).toBe(0);
    expect(v.stdout).toMatch(/^OK: /);
  });

  it("needs credentials, and explains usage", async () => {
    const o = io({ NEXUS_URL: "", NEXUS_TOKEN: "" });
    o.env = {};
    expect(await run(["whoami"], o)).toBe(1);
    expect(o.stderr).toContain("nexus login");
    const u = io();
    expect(await run(["frobnicate"], u)).toBe(1);
    expect(u.stderr).toContain("Unknown command");
  });

  it("saves credentials with login", async () => {
    const o = io();
    o.env = {};
    expect(await run(["login", "--url", "http://api.test", "--token", key], o)).toBe(0);
    expect(JSON.parse(files.get("/home/test/.config/nexus/credentials.json")!)).toEqual({ url: "http://api.test", token: key });
    const w = io();
    w.env = {};
    expect(await run(["whoami"], w)).toBe(0);
  });
});
