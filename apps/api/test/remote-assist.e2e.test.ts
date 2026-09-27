import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { serve } from "@hono/node-server";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { WebSocket } from "ws";
import { attachRemoteAssistRelay, type Relay } from "../src/remote-assist/relay.js";
import { bootApp, PASSWORD, uniqueEmail } from "./harness.js";
import { SoftDevice } from "./soft-device.js";

/** Remote Assist: asked for, allowed at the Mac, relayed to the requester's browser only. */

let h: Awaited<ReturnType<typeof bootApp>>;
let db: pg.Client;
let server: Server;
let relay: Relay;
let base = "";
let admin = "";
let other = "";
const ORIGIN = "http://localhost:3100";
const devices: Record<string, { d: SoftDevice; id: string }> = {};

async function agentCall(path: string, payload: unknown, d: SoftDevice, enroll = false) {
  const body = JSON.stringify(payload);
  const res = await h.app.request(path, { method: "POST", headers: { "content-type": "application/json", authorization: `NexusDevice ${await d.proof(path, body, { enroll })}` }, body });
  const text = await res.text();
  return { status: res.status, body: (text ? JSON.parse(text) : null) as Record<string, any> };
}
const posture = { disk_encryption: { status: "on" }, firewall: { status: "on" }, screen_lock: { status: "on", delay_seconds: 60 }, system_integrity: { status: "on" } };
const checkin = async (name: string, extra: Record<string, unknown> = {}) => (await agentCall("/v1/agent/checkin", { device: {}, posture, ...extra }, devices[name]!.d)).body;
const decode = (jws: string) => JSON.parse(Buffer.from(jws.split(".")[1]!, "base64url").toString());
const state = (sid: string, s: string, detail = "") => agentCall(`/v1/agent/remote-assist/${sid}/state`, { state: s, detail }, devices.mac!.d);

/** Opens a websocket; resolves once open, or rejects with the HTTP status it was refused with. */
function open(url: string, opts: { protocols?: string[]; headers?: Record<string, string>; origin?: string }) {
  return new Promise<WebSocket>((resolve, reject) => {
    const ws = new WebSocket(url, opts.protocols ?? [], { headers: opts.headers, origin: opts.origin });
    ws.once("open", () => resolve(ws));
    ws.once("unexpected-response", (_req, res) => reject(new Error(`HTTP ${res.statusCode}`)));
    ws.once("error", reject);
  });
}
const tunnel = async (sid: string) => {
  const path = `/v1/agent/remote-assist/${sid}/tunnel`;
  return open(`${base.replace("http", "ws")}${path}`, { headers: { authorization: `NexusDevice ${await devices.mac!.d.proof(path, "", { method: "GET" })}` } });
};
const viewer = async (sid: string, token = admin, origin = ORIGIN) => {
  const t = await h.call("POST", `/v1/remote-assist/sessions/${sid}/ticket`, { token });
  if (t.status !== 200) throw new Error(t.body.code);
  return { ws: await open(t.body.ws_url, { protocols: ["binary", `nexus-ticket.${t.body.ticket}`], origin }), ticket: t.body.ticket, url: t.body.ws_url };
};
const next = (ws: WebSocket) => new Promise<{ data: Buffer; binary: boolean }>((r) => ws.once("message", (data, binary) => r({ data: data as Buffer, binary })));
const closed = (ws: WebSocket) => new Promise<number>((r) => (ws.readyState === WebSocket.CLOSED ? r(-1) : ws.once("close", (code) => r(code))));

beforeAll(async () => {
  h = await bootApp();
  server = serve({ fetch: h.app.fetch, port: 0 }) as Server;
  await new Promise((r) => server.once("listening", r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  h.deps.cfg.apiPublicUrl = base;
  relay = attachRemoteAssistRelay(server, h.deps);
  db = new pg.Client({ connectionString: process.env.NEXUS_DATABASE_OWNER_URL });
  await db.connect();
  admin = (await h.call("POST", "/v1/signup", { body: { organization_name: "Assist Co", email: uniqueEmail("root"), password: PASSWORD, given_name: "Root" } })).body.token;
  await h.call("PATCH", "/v1/org/settings", { token: admin, body: { mfa_policy: "off" } });
  const e = uniqueEmail("admin2");
  await h.call("POST", "/v1/users", { token: admin, body: { email: e, given_name: "Ada", password: PASSWORD, roles: ["admin"] } });
  other = (await h.call("POST", "/v1/auth/login", { body: { email: e, password: PASSWORD } })).body.token;
  const t = (await h.call("POST", "/v1/devices/enrollment-tokens", { token: admin, body: { name: "all" } })).body.token;
  for (const [name, platform] of [["mac", "macos"], ["linux", "linux"]] as const) {
    const d = await new SoftDevice().init();
    const r = await agentCall("/v1/agent/enroll", { token: t, device: { hostname: name, platform, os_version: "1", agent_version: "0.3.0" } }, d, true);
    d.id = r.body.device_id;
    devices[name] = { d, id: r.body.device_id };
    await checkin(name);
  }
});
afterAll(async () => {
  relay.close();
  await new Promise((r) => server.close(r));
  await db.end();
  await h.close();
});

describe("Remote Assist", () => {
  let sid = "";

  it("asks the Mac, and nothing is viewable until the person there allows it", async () => {
    expect((await h.call("POST", `/v1/devices/${devices.linux!.id}/remote-assist`, { token: admin, body: { reason: "Printer help" } })).body.code).toBe("unsupported_platform");
    const r = await h.call("POST", `/v1/devices/${devices.mac!.id}/remote-assist`, { token: admin, body: { reason: "VPN won't connect", minutes: 30 } });
    expect(r.status).toBe(201);
    expect(r.body).toMatchObject({ status: "asking", hostname: "mac", mine: true, reason: "VPN won't connect" });
    sid = r.body.id;
    expect((await h.call("POST", `/v1/devices/${devices.mac!.id}/remote-assist`, { token: admin, body: { reason: "again" } })).body.code).toBe("session_open");

    const cmds = (await checkin("mac")).commands as { id: string; jws: string }[];
    expect(decode(cmds[0]!.jws)).toMatchObject({ act: "remote_assist", args: { session_id: sid, requester: expect.stringContaining("root"), reason: "VPN won't connect", minutes: 30 } });
    expect((await h.call("POST", `/v1/remote-assist/sessions/${sid}/ticket`, { token: admin })).body.code).toBe("not_active");
    await expect(tunnel(sid)).rejects.toThrow("HTTP 410"); // no tunnel before it's allowed

    const acc = await state(sid, "accepted", "Allowed by jo");
    expect(acc.status, JSON.stringify(acc.body)).toBe(204);
    const s = (await h.call("GET", `/v1/remote-assist/sessions/${sid}`, { token: admin })).body;
    expect(s).toMatchObject({ status: "active", detail: "Allowed by jo" });
    expect(new Date(s.expires_at).getTime() - Date.now()).toBeGreaterThan(29 * 60_000); // the 30 minutes asked for
    expect((await state(sid, "declined")).body.code).toBe("session_closed"); // a decision is final
  });

  it("relays the Mac's screen sharing to the requester's browser, both ways", async () => {
    const agent = await tunnel(sid);
    const opened = next(agent);
    const v = await viewer(sid);
    expect((await opened).data.toString()).toBe("open");
    const got = next(v.ws);
    agent.send(Buffer.from("RFB 003.889\n"));
    expect((await got).data.toString()).toBe("RFB 003.889\n");
    const back = next(agent);
    v.ws.send(Buffer.from("RFB 003.008\n"));
    expect((await back).data.toString()).toBe("RFB 003.008\n");

    // The ticket was single-use, only the requester gets one, and it only works from the console.
    await expect(open(v.url, { protocols: ["binary", `nexus-ticket.${v.ticket}`], origin: ORIGIN })).rejects.toThrow("HTTP 401");
    expect((await h.call("POST", `/v1/remote-assist/sessions/${sid}/ticket`, { token: other })).status).toBe(403);
    const t2 = (await h.call("POST", `/v1/remote-assist/sessions/${sid}/ticket`, { token: admin })).body;
    await expect(open(t2.ws_url, { protocols: ["binary", `nexus-ticket.${t2.ticket}`], origin: "https://evil.example" })).rejects.toThrow("HTTP 403");

    // Closing the viewer closes the tunnel it used; the agent then opens a fresh one.
    const agentGone = closed(agent);
    v.ws.close();
    expect(await agentGone).toBe(1000);
    const again = await tunnel(sid);
    const opened2 = next(again);
    const v2 = await viewer(sid);
    expect((await opened2).data.toString()).toBe("open");

    // Ending it cuts both sides off, and the agent's next tunnel is refused.
    const ends = [closed(again), closed(v2.ws)];
    const end = await h.call("POST", `/v1/remote-assist/sessions/${sid}/end`, { token: other });
    expect(end.body).toMatchObject({ status: "ended", detail: expect.stringContaining("Ended by") });
    expect(await Promise.all(ends)).toContain(4000);
    await expect(tunnel(sid)).rejects.toThrow("HTTP 410");
    expect((await state(sid, "ended")).body.code).toBe("session_closed");

    const types = (await db.query("SELECT type FROM audit_events WHERE details->>'session_id' = $1 ", [sid])).rows.map((r: { type: string }) => r.type);
    expect(types).toEqual(expect.arrayContaining(["remote_assist.requested", "remote_assist.accepted", "remote_assist.viewed", "remote_assist.ended"]));
    expect(types.filter((t: string) => t === "remote_assist.viewed")).toHaveLength(2);
  });

  it("records a decline, and closes requests nobody answers", async () => {
    const a = (await h.call("POST", `/v1/devices/${devices.mac!.id}/remote-assist`, { token: admin, body: { reason: "Check Outlook" } })).body;
    await state(a.id, "declined", "Declined by jo");
    expect((await h.call("GET", `/v1/remote-assist/sessions/${a.id}`, { token: admin })).body).toMatchObject({ status: "declined", detail: "Declined by jo" });
    expect((await h.call("POST", `/v1/remote-assist/sessions/${a.id}/ticket`, { token: admin })).body.code).toBe("not_active");

    const b = (await h.call("POST", `/v1/devices/${devices.mac!.id}/remote-assist`, { token: admin, body: { reason: "Anyone there?" } })).body;
    await db.query("UPDATE remote_assist_sessions SET expires_at = now() - interval '1 second' WHERE id = $1", [b.id]);
    expect((await h.call("GET", `/v1/remote-assist/sessions/${b.id}`, { token: admin })).body).toMatchObject({ status: "expired", detail: "Nobody answered in time" });
    const list = (await h.call("GET", `/v1/devices/${devices.mac!.id}/remote-assist`, { token: admin })).body.data;
    expect(list.map((s: any) => s.status)).toEqual(["expired", "declined", "ended"]);
  });
});
