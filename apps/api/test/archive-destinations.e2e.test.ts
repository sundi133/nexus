import { createHash } from "node:crypto";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { gunzipSync } from "node:zlib";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { deliver } from "../src/integrations/stream.js";
import { signV4 } from "../src/platform/sigv4.js";
import { bootApp, PASSWORD, uniqueEmail } from "./harness.js";

/** Audit archives to S3 / GCS and streaming to Microsoft Sentinel (AUD-04). */

type Received = { method: string; path: string; headers: http.IncomingHttpHeaders; body: Buffer };
const received: Received[] = [];
const failures: Record<string, number[]> = {}; // path prefix → status codes to answer next
let server: http.Server;
let base = "";
const TENANT = "7f0f7c4e-3a55-4a57-9c1e-2d8f4a6b1c00";
const CLIENT = "1b2c3d4e-5f60-4718-8293-a4b5c6d7e8f9";
const DCR = "dcr-0123456789abcdef0123456789abcdef";

let h: Awaited<ReturnType<typeof bootApp>>;
let owner: pg.Client;
let admin = "";
let orgId = "";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const create = (body: Record<string, unknown>) => h.call("POST", "/v1/event-destinations", { token: admin, body });
const dest = async (id: string) => ((await h.call("GET", "/v1/event-destinations", { token: admin })).body.data as Record<string, any>[]).find((d) => d.id === id)!;
const newUser = (tag: string) => h.call("POST", "/v1/users", { token: admin, body: { email: uniqueEmail(tag), given_name: tag } });
const puts = () => received.filter((r) => r.method === "PUT");
/** Backdate this org's audit events, as if they'd been waiting a while. */
const age = (minutes: number) => owner.query(`UPDATE audit_events SET ts = ts - make_interval(mins => $2) WHERE org_id = $1`, [orgId, minutes]);
/** Delivery waits for older transactions anywhere in the cluster (other test files) to finish: poll. */
async function deliverUntil(id: string, done: () => boolean, tries = 40) {
  for (let i = 0; i < tries; i++) {
    await owner.query("UPDATE event_destinations SET next_attempt_at = now() WHERE id = $1", [id]);
    await deliver(h.deps, orgId, id);
    if (done()) return;
    await sleep(100);
  }
  throw new Error("delivery didn't happen");
}

beforeAll(async () => {
  server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c)).on("end", () => {
      const path = req.url!;
      const failing = Object.keys(failures).find((p) => path.startsWith(p) && failures[p]!.length);
      if (failing) return res.writeHead(failures[failing]!.shift()!).end("<Error><Code>SlowDown</Code><Message>Please reduce your request rate.</Message></Error>");
      const body = Buffer.concat(chunks);
      received.push({ method: req.method!, path, headers: req.headers, body });
      if (path === `/entra/${TENANT}/oauth2/v2.0/token`) {
        const form = new URLSearchParams(body.toString());
        if (form.get("client_secret") !== "right-secret")
          return res.writeHead(401, { "content-type": "application/json" }).end(JSON.stringify({ error: "invalid_client", error_description: "AADSTS7000215: Invalid client secret provided.\r\nTrace ID: x" }));
        return res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ access_token: "azure-token", expires_in: 3599 }));
      }
      res.writeHead(req.method === "PUT" ? 200 : 204).end();
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  h = await bootApp({ entraLoginBase: `${base}/entra` });
  owner = new pg.Client({ connectionString: process.env.NEXUS_DATABASE_OWNER_URL });
  await owner.connect();
  admin = (await h.call("POST", "/v1/signup", { body: { organization_name: "Archive Co", email: uniqueEmail("ada"), password: PASSWORD, given_name: "Ada" } })).body.token;
  await h.call("PATCH", "/v1/org/settings", { token: admin, body: { mfa_policy: "off" } });
  orgId = (await h.call("GET", "/v1/me", { token: admin })).body.organization.id;
});
afterAll(async () => {
  server.close();
  await owner.end();
  await h.close();
});

describe("setting up a bucket", () => {
  it("asks for what each kind needs, and derives the bucket URL", async () => {
    expect((await create({ kind: "s3", name: "No bucket", secret: "s", config: { region: "us-east-1", access_key_id: "AK" } })).body).toMatchObject({ code: "missing_field", title: "The bucket is required" });
    expect((await create({ kind: "s3", name: "No secret", config: { bucket: "bkt-1", region: "us-east-1", access_key_id: "AK" } })).body.title).toBe("A secret access key is required");
    expect((await create({ kind: "s3", name: "Bad region", secret: "s", config: { bucket: "bkt-1", region: "mars", access_key_id: "AK" } })).status).toBe(400);
    expect((await create({ kind: "sentinel", name: "No rule", url: "https://x.ingest.monitor.azure.com", secret: "s", config: { tenant_id: TENANT, client_id: CLIENT } })).body.title).toBe("The data collection rule ID is required");

    const aws = await create({ kind: "s3", name: "AWS archive", secret: "s", config: { bucket: "acme-audit", region: "eu-west-1", access_key_id: "AKIAEXAMPLE", prefix: "/nexus/" } });
    expect(aws.status, JSON.stringify(aws.body)).toBe(201);
    const byName = (n: string) => (aws.body.data as Record<string, any>[]).find((d) => d.name === n);
    expect(byName("AWS archive")).toMatchObject({ url: "https://acme-audit.s3.eu-west-1.amazonaws.com/", config: { prefix: "/nexus/", access_key_id: "AKIAEXAMPLE" } });
    const dotted = await create({ kind: "s3", name: "Dotted", secret: "s", url: "https://evil.example.com", config: { bucket: "audit.acme.com", region: "us-east-2", access_key_id: "AK" } });
    expect((dotted.body.data as Record<string, any>[]).find((d) => d.name === "Dotted")!.url).toBe("https://s3.us-east-2.amazonaws.com/audit.acme.com"); // the URL can't be pointed elsewhere
    const gcs = await create({ kind: "gcs", name: "GCS archive", secret: "s", config: { bucket: "acme-audit", access_key_id: "GOOG1EXAMPLE" } });
    expect((gcs.body.data as Record<string, any>[]).find((d) => d.name === "GCS archive")!.url).toBe("https://storage.googleapis.com/acme-audit");
    for (const d of gcs.body.data as { id: string }[]) await h.call("DELETE", `/v1/event-destinations/${d.id}`, { token: admin });
  });
});

describe("S3 archive", () => {
  let id = "";
  const creds = { bucket: "audit", access_key_id: "AKIDTEST", prefix: "nexus/prod" };

  it("collects events into one object, written after five minutes", async () => {
    await age(60); // setup events are old news; the archive starts now
    const r = await create({ kind: "s3", name: "Archive", secret: "archive-secret", config: { ...creds, endpoint: base } });
    id = (r.body.data as { id: string; name: string }[]).find((d) => d.name === "Archive")!.id;
    expect((await dest(id)).url).toBe(`${base}/audit`);
    for (const t of ["a1", "a2", "a3"]) await newUser(t);

    // Not yet: waits for more events, and schedules itself for when the oldest turns five minutes old.
    const held = async () => (await owner.query("SELECT next_attempt_at > now() + interval '1 minute' AS held FROM event_destinations WHERE id = $1", [id])).rows[0].held as boolean;
    for (let i = 0; i < 40 && !(await held()); i++) {
      await deliver(h.deps, orgId, id);
      await sleep(100);
    }
    expect(puts()).toHaveLength(0);
    const due = (await owner.query("SELECT next_attempt_at - (SELECT min(ts) FROM audit_events WHERE org_id = $1 AND type = 'user.created') AS wait FROM event_destinations WHERE id = $2", [orgId, id])).rows[0].wait;
    expect(due.minutes).toBe(5);

    await age(6);
    await deliverUntil(id, () => puts().length > 0);
    const put = puts()[0]!;
    expect(decodeURIComponent(put.path)).toMatch(/^\/audit\/nexus\/prod\/year=\d{4}\/month=\d{2}\/day=\d{2}\/\d{8}T\d{6}Z-[0-9a-f-]{36}\.jsonl\.gz$/);
    expect(put.headers["content-type"]).toBe("application/gzip");
    expect(put.headers["content-md5"]).toBe(createHash("md5").update(put.body).digest("base64"));
    expect(put.headers.authorization).toMatch(/^AWS4-HMAC-SHA256 Credential=AKIDTEST\/\d{8}\/us-east-1\/s3\/aws4_request, SignedHeaders=content-md5;content-type;host;x-amz-content-sha256;x-amz-date, Signature=[0-9a-f]{64}$/);
    const lines = gunzipSync(put.body).toString().trim().split("\n").map((l) => JSON.parse(l));
    expect(lines.filter((l) => l.type === "user.created")).toHaveLength(3);
    expect((await dest(id))).toMatchObject({ status: "healthy", backlog: 0 });
  });

  it("rewrites the same object after a failed write, so retries don't duplicate", async () => {
    received.length = 0;
    await newUser("b1");
    await age(6);
    failures["/audit/"] = [503];
    await deliverUntil(id, () => received.length === 0 && failures["/audit/"]!.length === 0);
    expect((await dest(id))).toMatchObject({ status: "failing", last_error: "HTTP 503: SlowDown (Please reduce your request rate.)" });
    await deliverUntil(id, () => puts().length > 0);
    const [first] = puts();
    const again = (await h.call("POST", `/v1/event-destinations/${id}/test`, { token: admin })).body;
    expect(again).toEqual({ ok: true, http_status: 200, error: "" });
    expect(puts()[1]!.path).toMatch(/^\/audit\/nexus\/prod\/_nexus-test\//); // test objects stay out of the date partitions
    expect(decodeURIComponent(first!.path)).toMatch(/year=/);
    expect((await dest(id)).status).toBe("healthy");
  });

  it("recomputes the bucket URL when the bucket changes", async () => {
    const r = await h.call("PATCH", `/v1/event-destinations/${id}`, { token: admin, body: { config: { bucket: "audit-2", prefix: "" } } });
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    expect((await dest(id))).toMatchObject({ url: `${base}/audit-2`, config: { bucket: "audit-2", access_key_id: "AKIDTEST", endpoint: base } });
    expect((await dest(id)).config.prefix).toBeUndefined();
    await h.call("DELETE", `/v1/event-destinations/${id}`, { token: admin });
  });
});

describe("Microsoft Sentinel", () => {
  let id = "";
  const posts = () => received.filter((r) => r.path.startsWith("/dataCollectionRules/"));
  const tokenCalls = () => received.filter((r) => r.path.startsWith("/entra/"));

  it("says clearly when the app registration is wrong", async () => {
    received.length = 0;
    await age(60);
    const r = await create({ kind: "sentinel", name: "Sentinel", url: base, secret: "wrong-secret", format: "ocsf", config: { tenant_id: TENANT, client_id: CLIENT, dcr_id: DCR, stream: "Custom-VotalNexus_CL" } });
    id = (r.body.data as { id: string; name: string }[]).find((d) => d.name === "Sentinel")!.id;
    const t = (await h.call("POST", `/v1/event-destinations/${id}/test`, { token: admin })).body;
    expect(t).toEqual({ ok: false, http_status: 401, error: "Couldn't sign in to Microsoft Entra ID: AADSTS7000215: Invalid client secret provided." });
  });

  it("sends rows to the data collection rule's stream, with one token for many batches", async () => {
    await h.call("PATCH", `/v1/event-destinations/${id}`, { token: admin, body: { secret: "right-secret" } });
    received.length = 0;
    await newUser("s1");
    await deliverUntil(id, () => posts().length > 0);
    await newUser("s2");
    await deliverUntil(id, () => posts().length > 1);
    expect(tokenCalls()).toHaveLength(1);
    const form = new URLSearchParams(tokenCalls()[0]!.body.toString());
    expect(Object.fromEntries(form)).toMatchObject({ grant_type: "client_credentials", client_id: CLIENT, scope: "https://monitor.azure.com//.default" });
    const post = posts()[0]!;
    expect(post.path).toBe(`/dataCollectionRules/${DCR}/streams/Custom-VotalNexus_CL?api-version=2023-01-01`);
    expect(post.headers.authorization).toBe("Bearer azure-token");
    const rows = JSON.parse(post.body.toString()) as Record<string, any>[];
    const row = rows.find((x) => x.EventType === "user.created")!;
    expect(Object.keys(row).sort()).toEqual(["Event", "EventId", "EventType", "TimeGenerated"]);
    expect(row.Event).toMatchObject({ class_uid: 3001 }); // OCSF Account Change
    expect((await dest(id)).status).toBe("healthy");
    await h.call("DELETE", `/v1/event-destinations/${id}`, { token: admin });
  });
});

/**
 * Against a real S3 implementation, when one is available (CI starts MinIO):
 * NEXUS_TEST_S3_ENDPOINT=http://127.0.0.1:9000 with the default minioadmin credentials.
 */
describe.skipIf(!process.env.NEXUS_TEST_S3_ENDPOINT)("real S3 (MinIO)", () => {
  const endpoint = process.env.NEXUS_TEST_S3_ENDPOINT!;
  const creds = { accessKeyId: process.env.NEXUS_TEST_S3_KEY ?? "minioadmin", secretAccessKey: process.env.NEXUS_TEST_S3_SECRET ?? "minioadmin", region: "us-east-1" };
  const bucket = `nexus-test-${Date.now()}`;
  const s3 = async (method: string, path: string) => {
    const url = new URL(`${endpoint}${path}`);
    const headers = signV4({ method, url }, creds);
    delete headers.host;
    const res = await fetch(url, { method, headers });
    return { status: res.status, text: await res.text() };
  };

  it("accepts our signed writes, and the archive reads back", async () => {
    expect((await s3("PUT", `/${bucket}`)).status).toBe(200);
    await age(60);
    const r = await create({ kind: "s3", name: "MinIO", secret: creds.secretAccessKey, config: { bucket, endpoint, access_key_id: creds.accessKeyId, region: "us-east-1" } });
    const id = (r.body.data as { id: string; name: string }[]).find((d) => d.name === "MinIO")!.id;
    expect((await h.call("POST", `/v1/event-destinations/${id}/test`, { token: admin })).body).toEqual({ ok: true, http_status: 200, error: "" });
    await newUser("m1");
    await age(6);
    await deliverUntil(id, () => true);
    for (let i = 0; i < 40 && (await dest(id)).status !== "healthy"; i++) await deliverUntil(id, () => true);
    expect((await dest(id)).status).toBe("healthy");
    const listing = await s3("GET", `/${bucket}?list-type=2&prefix=year%3D`);
    const key = /<Key>([^<]+)<\/Key>/.exec(listing.text)![1]!;
    const url = new URL(`${endpoint}/${bucket}/${key.split("/").map(encodeURIComponent).join("/")}`);
    const headers = signV4({ method: "GET", url }, creds);
    delete headers.host;
    const obj = Buffer.from(await (await fetch(url, { headers })).arrayBuffer());
    expect(gunzipSync(obj).toString()).toContain('"type":"user.created"');
    await h.call("DELETE", `/v1/event-destinations/${id}`, { token: admin });
  });
});
