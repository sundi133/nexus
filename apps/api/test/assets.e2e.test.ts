import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { bootApp, PASSWORD, uniqueEmail } from "./harness.js";
import { SoftDevice } from "./soft-device.js";

/** Asset management: records, check-out history, devices matched by serial, import, and offboarding. */

let h: Awaited<ReturnType<typeof bootApp>>;
let admin = "";
let helpdesk = "";
let readonly = "";
const people: Record<string, { id: string; email: string }> = {};
const soon = (days: number) => new Date(Date.now() + days * 86_400_000).toISOString().slice(0, 10);

beforeAll(async () => {
  h = await bootApp();
  admin = (await h.call("POST", "/v1/signup", { body: { organization_name: "Asset Co", email: uniqueEmail("root"), password: PASSWORD, given_name: "Root" } })).body.token;
  await h.call("PATCH", "/v1/org/settings", { token: admin, body: { mfa_policy: "off" } });
  for (const [n, roles] of [["ana", []], ["ben", []], ["hd", ["helpdesk"]], ["ro", ["readonly"]]] as const) {
    const email = uniqueEmail(n);
    people[n] = { email, id: (await h.call("POST", "/v1/users", { token: admin, body: { email, given_name: n, password: PASSWORD, roles } })).body.id };
  }
  helpdesk = (await h.call("POST", "/v1/auth/login", { body: { email: people.hd!.email, password: PASSWORD } })).body.token;
  readonly = (await h.call("POST", "/v1/auth/login", { body: { email: people.ro!.email, password: PASSWORD } })).body.token;
  // An enrolled Mac whose serial matches an asset.
  const t = (await h.call("POST", "/v1/devices/enrollment-tokens", { token: admin, body: { name: "t" } })).body.token;
  const d = await new SoftDevice().init();
  const body = JSON.stringify({ token: t, device: { hostname: "ana-mbp", platform: "macos", os_version: "15.0", serial: "C02XK1ABMD6T", model: "MacBookPro18,3" } });
  await h.app.request("/v1/agent/enroll", { method: "POST", headers: { "content-type": "application/json", authorization: `NexusDevice ${await d.proof("/v1/agent/enroll", body, { enroll: true })}` }, body });
  const d2 = await new SoftDevice().init();
  const body2 = JSON.stringify({ token: t, device: { hostname: "lab-mini", platform: "macos", os_version: "15.0", serial: "H4TX9ZZQ1", model: "Macmini9,1" } });
  await h.app.request("/v1/agent/enroll", { method: "POST", headers: { "content-type": "application/json", authorization: `NexusDevice ${await d2.proof("/v1/agent/enroll", body2, { enroll: true })}` }, body: body2 });
});
afterAll(() => h.close());

describe("assets", () => {
  let laptop = "";

  it("records hardware and matches enrolled devices by serial", async () => {
    const r = await h.call("POST", "/v1/assets", { token: helpdesk, body: { tag: "A-0001", name: "Ana's laptop", kind: "laptop", make: "Apple", model: "MacBook Pro 14", serial: "c02xk1abmd6t ", purchase_date: "2025-01-10", purchase_cost: 2499, warranty_until: soon(30) } });
    expect(r.status).toBe(201);
    laptop = r.body.id;
    expect(r.body).toMatchObject({ status: "in_stock", warranty: "expiring", purchase_cost: 2499, device: { hostname: "ana-mbp" } });
    expect((await h.call("POST", "/v1/assets", { token: helpdesk, body: { tag: "a-0001" } })).body.code).toBe("tag_taken");
    expect((await h.call("POST", "/v1/assets", { token: readonly, body: { tag: "A-9" } })).status).toBe(403);
    expect((await h.call("GET", "/v1/assets", { token: readonly })).status).toBe(200);
  });

  it("checks assets out and in, keeping who had it when", async () => {
    const out = await h.call("POST", `/v1/assets/${laptop}/checkout`, { token: helpdesk, body: { user_id: people.ana!.id, note: "New hire kit" } });
    expect(out.body).toMatchObject({ status: "assigned", assigned_to: { email: people.ana!.email, left: false } });
    expect((await h.call("POST", `/v1/assets/${laptop}/checkout`, { token: helpdesk, body: { user_id: people.ben!.id } })).body.code).toBe("already_assigned");
    const back = await h.call("POST", `/v1/assets/${laptop}/checkin`, { token: helpdesk, body: { status: "in_repair", note: "Cracked screen" } });
    expect(back.body).toMatchObject({ status: "in_repair", assigned_to: null });
    await h.call("POST", `/v1/assets/${laptop}/checkout`, { token: helpdesk, body: { user_id: people.ana!.id } });
    const hist = (await h.call("GET", `/v1/assets/${laptop}`, { token: readonly })).body.history;
    expect(hist.map((e: any) => [e.kind, e.user, e.status])).toEqual([
      ["checked_out", people.ana!.email, "assigned"],
      ["checked_in", people.ana!.email, "in_repair"],
      ["checked_out", people.ana!.email, "assigned"],
      ["created", null, "in_stock"],
    ]);
  });

  it("imports a spreadsheet and fills in enrolled devices", async () => {
    const r = await h.call("POST", "/v1/assets/import", {
      token: admin,
      body: {
        rows: [
          { tag: "M-100", name: "Dell monitor", kind: "monitor", assigned_to_email: people.ben!.email.toUpperCase() },
          { tag: "M-101", kind: "monitor", assigned_to_email: "nobody@else.example" },
          { tag: "A-0001", name: "Ana's laptop", kind: "laptop", serial: "C02XK1ABMD6T", location: "Berlin" },
          { tag: "m-100", kind: "monitor" },
        ],
      },
    });
    expect(r.body).toMatchObject({ created: 2, updated: 1 });
    expect(r.body.errors.map((e: any) => e.row)).toEqual([2, 4]);
    const summary = (await h.call("GET", "/v1/assets", { token: admin })).body.summary;
    expect(summary).toMatchObject({ total: 3, assigned: 2, unenrolled_devices: 1 });
    expect((await h.call("POST", "/v1/assets/from-devices", { token: admin })).body).toEqual({ created: 1 });
    const mini = (await h.call("GET", "/v1/assets?q=lab-mini", { token: admin })).body.data[0];
    expect(mini).toMatchObject({ tag: "H4TX9ZZQ1", make: "Apple", kind: "desktop", device: { hostname: "lab-mini" } });
    expect((await h.call("GET", "/v1/assets", { token: admin })).body.summary.unenrolled_devices).toBe(0);
  });

  it("lists what to collect when someone is offboarded", async () => {
    const preview = (await h.call("GET", `/v1/users/${people.ben!.id}/offboarding`, { token: admin })).body;
    expect(preview.assets.map((a: any) => a.tag)).toEqual(["M-100"]);
    const r = await h.call("POST", `/v1/users/${people.ben!.id}/offboard`, { token: admin, body: { reason: "Left" } });
    expect(r.body.assets.map((a: any) => a.tag)).toEqual(["M-100"]); // still to collect
    const inbox = (await h.call("GET", "/v1/me/notifications?limit=30&filter=all", { token: admin })).body.data;
    expect(inbox.some((n: any) => n.title.startsWith("Collect") && n.body.includes("M-100"))).toBe(true);
    const list = (await h.call("GET", `/v1/assets?assigned_to=${people.ben!.id}`, { token: admin })).body;
    expect(list.data[0]).toMatchObject({ tag: "M-100", status: "assigned", assigned_to: { left: true } });
    expect(list.summary.to_collect).toBe(1);
  });
});
