import http from "node:http";
import type { AddressInfo } from "node:net";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { bootApp, PASSWORD, uniqueEmail } from "./harness.js";

/** HR systems (BambooHR, Workday) drive joiners, movers and leavers. */

let h: Awaited<ReturnType<typeof bootApp>>;
let server: http.Server;
let base = "";
let owner: pg.Client;
let admin = "";
let orgId = "";
const dom = `hr${Date.now().toString(36)}.test`;
const mail = (l: string) => `${l}@${dom}`;
const BAMBOO_KEY = "bamboo-key-123";
const day = (offset: number) => new Date(Date.now() + offset * 86_400_000).toISOString().slice(0, 10);

type BEmp = { id: string; firstName: string; lastName: string; preferredName?: string; workEmail: string; jobTitle: string; department: string; supervisorEId: string | null; status: string; terminationDate: string };
const bamboo: { employees: BEmp[] } = { employees: [] };
const workday: { rows: Record<string, unknown>[] } = { rows: [] };

async function handle(req: http.IncomingMessage, res: http.ServerResponse) {
  const url = new URL(req.url!, base);
  const auth = req.headers.authorization ?? "";
  const json = (code: number, body: unknown) => res.writeHead(code, { "content-type": "application/json" }).end(JSON.stringify(body));
  if (url.pathname === "/bamboo/acme/v1/reports/custom" && req.method === "POST") {
    if (auth !== `Basic ${Buffer.from(`${BAMBOO_KEY}:x`).toString("base64")}`) return json(401, { error: "Invalid API key" });
    let raw = "";
    for await (const c of req) raw += c;
    const fields = (JSON.parse(raw) as { fields: string[] }).fields;
    return json(200, { title: "Nexus", fields: fields.map((id) => ({ id })), employees: bamboo.employees.map((e) => Object.fromEntries(fields.map((f) => [f, (e as Record<string, unknown>)[f] ?? null]))) });
  }
  if (url.pathname === "/ccx/service/customreport2/acme/isu_nexus/Nexus_Workers") {
    if (auth !== `Basic ${Buffer.from("ISU_Nexus:wd-pass").toString("base64")}`) return json(401, { error: "invalid username or password" });
    if (url.searchParams.get("format") !== "json") return json(400, { error: "format" });
    return json(200, { Report_Entry: workday.rows });
  }
  json(404, { error: "not found" });
}

const users = async () => (await h.call("GET", "/v1/users?limit=200", { token: admin })).body.data as { id: string; email: string; status: string; title: string; department: string; given_name: string; managed_by: string | null }[];
const user = async (l: string) => (await users()).find((u) => u.email === mail(l));
const managerOf = async (l: string) => {
  const u = await user(l);
  const m = (await owner.query("SELECT m.email FROM users u LEFT JOIN users m ON m.id = u.manager_id WHERE u.id = $1", [u!.id])).rows[0];
  return m?.email ?? null;
};
const statusOf = async (l: string) => (await owner.query("SELECT status FROM users WHERE email = $1", [mail(l)])).rows[0]?.status;
const sync = async (id: string) => {
  expect((await h.call("POST", `/v1/directory/connections/${id}/sync`, { token: admin, body: {} })).status).toBeLessThan(300);
  await h.jobs.runOnce({ orgId });
};
const emp = (id: string, first: string, dept: string, sup: string | null, extra: Partial<BEmp> = {}): BEmp => ({ id, firstName: first, lastName: "Acme", workEmail: mail(first.toLowerCase()), jobTitle: "Engineer", department: dept, supervisorEId: sup, status: "Active", terminationDate: "0000-00-00", ...extra });

beforeAll(async () => {
  server = http.createServer((req, res) => void handle(req, res).catch((e) => res.writeHead(500).end(String(e))));
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  h = await bootApp({ bamboohrBase: `${base}/bamboo` });
  owner = new pg.Client({ connectionString: process.env.NEXUS_DATABASE_OWNER_URL });
  await owner.connect();
  admin = (await h.call("POST", "/v1/signup", { body: { organization_name: "HR Co", email: uniqueEmail("root"), password: PASSWORD, given_name: "Root" } })).body.token;
  await h.call("PATCH", "/v1/org/settings", { token: admin, body: { mfa_policy: "off" } });
  orgId = (await h.call("GET", "/v1/me", { token: admin })).body.organization.id;
  bamboo.employees = [
    emp("1", "Ann", "Leadership", null, { jobTitle: "CEO" }),
    emp("2", "Bob", "Engineering", "1", { preferredName: "Bobby" }),
    emp("3", "Cat", "Engineering", "2"),
    emp("4", "Dan", "Sales", "1", { terminationDate: day(-10), status: "Inactive" }), // already gone: never created
    emp("5", "Eve", "Sales", "1", { terminationDate: day(14) }), // leaving in two weeks: still here
  ];
});
afterAll(async () => {
  server.close();
  await owner.end();
  await h.close();
});

describe("BambooHR", () => {
  let id = "";
  const creds = (over: Record<string, unknown> = {}) => ({ provider: "bamboohr", subdomain: "acme", api_key: BAMBOO_KEY, ...over });

  it("tests the connection, with departments as groups", async () => {
    expect((await h.call("POST", "/v1/directory/test", { token: admin, body: creds({ api_key: "wrong" }) })).body.code).toBe("directory_unreachable");
    expect((await h.call("POST", "/v1/directory/test", { token: admin, body: creds({ subdomain: "../evil" }) })).status).toBe(400);
    const ok = await h.call("POST", "/v1/directory/test", { token: admin, body: creds() });
    expect(ok.body).toEqual({
      users: 5,
      active_users: 4,
      groups: [
        { id: "department:engineering", name: "Engineering", members: 2 },
        { id: "department:leadership", name: "Leadership", members: 1 },
        { id: "department:sales", name: "Sales", members: 1 },
      ],
    });
  });

  it("joiners: previews and creates people, their departments and their managers", async () => {
    const r = await h.call("POST", "/v1/directory/connections", { token: admin, body: { ...creds(), name: "BambooHR", deprovision: "offboard", invite_new_users: false } });
    expect(r.status, JSON.stringify(r.body)).toBe(201);
    id = r.body.data[0].id;
    expect(r.body.data[0]).toMatchObject({ provider: "bamboohr", provider_name: "BambooHR", account: "acme.bamboohr.com", deprovision: "offboard" });
    expect(JSON.stringify(r.body)).not.toContain(BAMBOO_KEY);

    const p = (await h.call("POST", `/v1/directory/connections/${id}/preview`, { token: admin, body: {} })).body;
    expect(p.create_users.map((u: { email: string }) => u.email).sort()).toEqual([mail("ann"), mail("bob"), mail("cat"), mail("eve")]);
    expect(p.managers).toEqual(
      expect.arrayContaining([
        { email: mail("bob"), from: null, to: mail("ann") },
        { email: mail("cat"), from: null, to: mail("bob") },
      ]),
    );
    await sync(id);
    expect(await user("bob")).toMatchObject({ given_name: "Bobby", department: "Engineering", title: "Engineer", status: "staged", managed_by: "BambooHR" });
    expect(await user("dan")).toBeUndefined();
    expect(await managerOf("cat")).toBe(mail("bob"));
    expect(await managerOf("ann")).toBeNull();
    const groups = (await h.call("GET", "/v1/groups", { token: admin })).body.data.map((g: { name: string }) => g.name);
    expect(groups).toEqual(expect.arrayContaining(["Engineering", "Leadership", "Sales"]));
  });

  it("movers: title, department, groups and manager follow HR", async () => {
    Object.assign(bamboo.employees.find((e) => e.id === "3")!, { department: "Sales", jobTitle: "Account executive", supervisorEId: "5" });
    const p = (await h.call("POST", `/v1/directory/connections/${id}/preview`, { token: admin, body: {} })).body;
    expect(p.update_users).toEqual([{ email: mail("cat"), changes: { title: { from: "Engineer", to: "Account executive" }, department: { from: "Engineering", to: "Sales" } } }]);
    expect(p.managers).toEqual([{ email: mail("cat"), from: mail("bob"), to: mail("eve") }]);
    await sync(id);
    expect(await user("cat")).toMatchObject({ department: "Sales", title: "Account executive" });
    expect(await managerOf("cat")).toBe(mail("eve"));
    const sales = (await h.call("GET", "/v1/groups", { token: admin })).body.data.find((g: { name: string }) => g.name === "Sales");
    const members = (await h.call("GET", `/v1/groups/${sales.id}/members`, { token: admin })).body.data.map((m: { email: string }) => m.email).sort();
    expect(members).toEqual([mail("cat"), mail("eve")]);
  });

  it("leavers: offboarded once their last day has passed, with the reason from HR", async () => {
    await owner.query("UPDATE users SET status = 'active' WHERE email = $1", [mail("eve")]);
    await sync(id); // her last day is in two weeks: nothing happens
    expect(await statusOf("eve")).toBe("active");

    bamboo.employees.find((e) => e.id === "5")!.terminationDate = day(-1);
    const p = (await h.call("POST", `/v1/directory/connections/${id}/preview`, { token: admin, body: {} })).body;
    expect(p.offboard_users).toEqual([{ email: mail("eve"), reason: `Left the company in BambooHR (last day ${day(-1)})` }]);
    await sync(id);
    expect(await statusOf("eve")).toBe("deprovisioned");
    const ev = (await owner.query("SELECT actor_display, details FROM audit_events WHERE org_id = $1 AND type = 'user.offboarded' AND target_display = $2", [orgId, mail("eve")])).rows[0];
    expect(ev).toMatchObject({ actor_display: "BambooHR sync", details: { reason: `Left the company in BambooHR (last day ${day(-1)})` } });
    // Offboarded people aren't put back in groups, and aren't managers any more for new syncs.
    const sales = (await h.call("GET", "/v1/groups", { token: admin })).body.data.find((g: { name: string }) => g.name === "Sales");
    expect((await h.call("GET", `/v1/groups/${sales.id}/members`, { token: admin })).body.data.map((m: { email: string }) => m.email)).toEqual([mail("cat")]);
    await sync(id);
    expect(await statusOf("eve")).toBe("deprovisioned");
  });

  it("never makes a manager loop", async () => {
    bamboo.employees.find((e) => e.id === "1")!.supervisorEId = "2"; // Ann ↔ Bob
    await sync(id);
    const both = [await managerOf("ann"), await managerOf("bob")];
    expect(both.filter((m) => m !== null)).toHaveLength(1); // one of them was set, the other refused
  });
});

describe("Workday", () => {
  const url = () => `${base}/ccx/service/customreport2/acme/isu_nexus/Nexus_Workers`;
  const creds = (over: Record<string, unknown> = {}) => ({ provider: "workday", report_url: url(), username: "ISU_Nexus", password: "wd-pass", fields: { employee_id: "Worker_ID", department: "Supervisory_Organization" }, ...over });

  it("reads a custom report with renamed columns and Workday-shaped values", async () => {
    workday.rows = [
      { Worker_ID: "W-10", Email_Address: mail("wally"), First_Name: "Wally", Last_Name: "Day", Business_Title: "Analyst", Supervisory_Organization: { Descriptor: "Finance" }, Manager_Employee_ID: "W-11", Active: "1" },
      { Worker_ID: "W-11", Email_Address: mail("wanda"), First_Name: "Wanda", Last_Name: "Day", Business_Title: "Controller", Supervisory_Organization: [{ Descriptor: "Finance" }], Active: "1" },
      { Worker_ID: "W-12", Email_Address: mail("walt"), First_Name: "Walt", Last_Name: "Day", Active: "0", Termination_Date: `${day(-3)}-07:00` },
    ];
    expect((await h.call("POST", "/v1/directory/test", { token: admin, body: creds({ password: "nope" }) })).body.code).toBe("directory_unreachable");
    const notReport = await h.call("POST", "/v1/directory/test", { token: admin, body: creds({ report_url: `${base}/somewhere/else` }) });
    expect(notReport.body.detail ?? notReport.body.title).toContain("custom report URL");
    expect((await h.call("POST", "/v1/directory/test", { token: admin, body: creds() })).body).toEqual({ users: 3, active_users: 2, groups: [{ id: "department:finance", name: "Finance", members: 2 }] });

    const r = await h.call("POST", "/v1/directory/connections", { token: admin, body: { ...creds(), name: "Workday", invite_new_users: false } });
    expect(r.status, JSON.stringify(r.body)).toBe(201);
    const conn = r.body.data.find((c: { provider: string }) => c.provider === "workday");
    expect(JSON.stringify(r.body)).not.toContain("wd-pass");
    await sync(conn.id);
    expect(await user("wally")).toMatchObject({ department: "Finance", title: "Analyst", managed_by: "Workday" });
    expect(await managerOf("wally")).toBe(mail("wanda"));
    expect(await user("walt")).toBeUndefined();
  });
});
