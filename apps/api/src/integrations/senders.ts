import { createHash, createHmac } from "node:crypto";
import { gzipSync } from "node:zlib";
import { networkError } from "../platform/outbound.js";
import { signV4 } from "../platform/sigv4.js";

/**
 * Delivery to one destination kind. Returns how many of the given events were
 * accepted (in order), so the cursor advances exactly that far.
 */

export type Kind = "webhook" | "splunk_hec" | "datadog" | "s3" | "gcs" | "sentinel";
export type SendResult = { delivered: number; status: number; error: string };
export type Outgoing = { id: string; type: string; time: Date; body: Record<string, unknown> };
export type SendContext = { entraLoginBase: string; test?: boolean };

export const BATCH: Record<Kind, number> = { webhook: 50, splunk_hec: 500, datadog: 500, s3: 1000, gcs: 1000, sentinel: 500 };
/** Archives collect events into fewer, bigger objects: written at a full batch or once the oldest event has waited this long. */
export const ARCHIVE_FLUSH_MS = 5 * 60_000;
export const isArchive = (kind: Kind) => kind === "s3" || kind === "gcs";
/** Collectors cap request size (Splunk HEC and Azure at about 1 MB): larger batches go out in parts. */
const MAX_REQUEST_BYTES = 900_000;

async function request(method: string, url: string, body: string | Buffer, headers: Record<string, string>): Promise<{ status: number; error: string; text: string }> {
  try {
    const res = await fetch(url, { method, body, headers: { "user-agent": "Votal-Nexus/1.0", ...headers }, signal: AbortSignal.timeout(15_000), redirect: "error" });
    const text = (await res.text()).slice(0, 2000);
    return { status: res.status, error: res.ok ? "" : `HTTP ${res.status}${text ? `: ${text.slice(0, 300)}` : ""}`, text };
  } catch (err) {
    return { status: 0, error: `Couldn't connect: ${networkError(err)}`, text: "" };
  }
}
const post = (url: string, body: string | Buffer, headers: Record<string, string>) => request("POST", url, body, headers);

/** Stripe-style: HMAC-SHA256 over "<unix time>.<body>", so receivers can reject replays. */
export function webhookSignature(secret: string, body: string, t = Math.floor(Date.now() / 1000)) {
  return `t=${t},v1=${createHmac("sha256", secret).update(`${t}.${body}`).digest("hex")}`;
}

/** Sends in parts of at most MAX_REQUEST_BYTES; counts what got through before the first failure. */
async function inParts<T>(items: T[], encode: (items: T[]) => string, sendPart: (body: string) => Promise<{ status: number; error: string }>): Promise<SendResult> {
  let delivered = 0;
  let status = 200;
  while (delivered < items.length) {
    let n = items.length - delivered;
    let body = encode(items.slice(delivered, delivered + n));
    while (n > 1 && Buffer.byteLength(body) > MAX_REQUEST_BYTES) {
      n = Math.ceil(n / 2);
      body = encode(items.slice(delivered, delivered + n));
    }
    const r = await sendPart(body);
    status = r.status;
    if (r.error) return { delivered, status, error: r.error };
    delivered += n;
  }
  return { delivered, status, error: "" };
}

/**
 * Object key for a batch: Hive-style date partitions (for Athena, BigQuery,
 * Snowflake external tables) and a name derived from the first event, so a
 * retried batch overwrites its own object instead of duplicating it.
 */
export function archiveKey(prefix: string | undefined, first: Outgoing, test = false) {
  const p = prefix?.replace(/^\/+|\/+$/g, "") ? `${prefix.replace(/^\/+|\/+$/g, "")}/` : "";
  const t = first.time.toISOString();
  const stamp = `${t.slice(0, 19).replace(/[-:]/g, "")}Z`;
  if (test) return `${p}_nexus-test/${stamp}-${first.id}.jsonl.gz`;
  return `${p}year=${t.slice(0, 4)}/month=${t.slice(5, 7)}/day=${t.slice(8, 10)}/${stamp}-${first.id}.jsonl.gz`;
}

async function putObject(bucketUrl: string, key: string, body: Buffer, creds: { accessKeyId: string; secretAccessKey: string; region: string }) {
  const url = new URL(`${bucketUrl.replace(/\/+$/, "")}/${key.split("/").map(encodeURIComponent).join("/")}`);
  const headers = signV4(
    {
      method: "PUT",
      url,
      // Content-MD5 lets buckets with Object Lock (WORM retention for audit archives) accept the write.
      headers: { "content-type": "application/gzip", "content-md5": createHash("md5").update(body).digest("base64") },
      body,
    },
    creds,
  );
  delete headers.host; // fetch sets it
  return request("PUT", url.toString(), body, headers);
}

const entraTokens = new Map<string, { token: string; expires: number }>();

/** Client-credentials token for the Azure Monitor ingestion API, cached until shortly before it expires. */
async function azureMonitorToken(loginBase: string, tenantId: string, clientId: string, secret: string): Promise<{ token?: string; status: number; error: string }> {
  const key = createHash("sha256").update(`${tenantId}\n${clientId}\n${secret}`).digest("hex");
  const cached = entraTokens.get(key);
  if (cached && cached.expires > Date.now()) return { token: cached.token, status: 200, error: "" };
  const r = await post(
    `${loginBase}/${encodeURIComponent(tenantId)}/oauth2/v2.0/token`,
    new URLSearchParams({ grant_type: "client_credentials", client_id: clientId, client_secret: secret, scope: "https://monitor.azure.com//.default" }).toString(),
    { "content-type": "application/x-www-form-urlencoded" },
  );
  let parsed: { access_token?: string; expires_in?: number; error_description?: string } = {};
  try {
    parsed = JSON.parse(r.text);
  } catch {
    /* not JSON */
  }
  if (r.error || !parsed.access_token) {
    const why = parsed.error_description?.split("\r\n")[0] ?? r.error;
    return { status: r.status, error: `Couldn't sign in to Microsoft Entra ID: ${why}` };
  }
  entraTokens.set(key, { token: parsed.access_token, expires: Date.now() + Math.max(60, (parsed.expires_in ?? 3600) - 300) * 1000 });
  return { token: parsed.access_token, status: 200, error: "" };
}

export async function send(kind: Kind, url: string, secret: string, config: Record<string, string>, events: Outgoing[], ctx: SendContext): Promise<SendResult> {
  if (!events.length) return { delivered: 0, status: 200, error: "" };
  switch (kind) {
    case "webhook": {
      for (let i = 0; i < events.length; i++) {
        const e = events[i]!;
        const body = JSON.stringify(e.body);
        const r = await post(url, body, {
          "content-type": "application/json",
          "nexus-event-id": e.id,
          "nexus-event-type": e.type,
          "nexus-signature": webhookSignature(secret, body),
        });
        if (r.error) return { delivered: i, status: r.status, error: r.error };
      }
      return { delivered: events.length, status: 200, error: "" };
    }
    case "splunk_hec":
      return inParts(
        events,
        (part) =>
          part
            .map((e) =>
              JSON.stringify({
                time: e.time.getTime() / 1000,
                host: "nexus",
                source: "votal-nexus",
                sourcetype: config.sourcetype || "votal:nexus:audit",
                ...(config.index ? { index: config.index } : {}),
                event: e.body,
              }),
            )
            .join("\n"),
        (body) => post(url, body, { "content-type": "application/json", authorization: `Splunk ${secret}` }),
      );
    case "datadog":
      return inParts(
        events,
        (part) =>
          JSON.stringify(
            part.map((e) => ({ ddsource: "votal-nexus", service: config.service || "nexus", hostname: "nexus", ddtags: config.tags ?? "", message: JSON.stringify(e.body), event_type: e.type, date: e.time.toISOString() })),
          ),
        (body) => post(url, body, { "content-type": "application/json", "dd-api-key": secret }),
      );
    case "s3":
    case "gcs": {
      // One object per batch: gzipped, newline-delimited JSON.
      const body = gzipSync(events.map((e) => JSON.stringify(e.body)).join("\n") + "\n");
      const r = await putObject(url, archiveKey(config.prefix, events[0]!, ctx.test), body, {
        accessKeyId: config.access_key_id ?? "",
        secretAccessKey: secret,
        region: kind === "gcs" ? "auto" : config.region || "us-east-1",
      });
      return { delivered: r.error ? 0 : events.length, status: r.status, error: r.error && storageError(r) };
    }
    case "sentinel": {
      // Azure Monitor Logs Ingestion API, into the customer's data collection rule (Sentinel reads the workspace table).
      const auth = await azureMonitorToken(ctx.entraLoginBase, config.tenant_id ?? "", config.client_id ?? "", secret);
      if (!auth.token) return { delivered: 0, status: auth.status, error: auth.error };
      const endpoint = `${url.replace(/\/+$/, "")}/dataCollectionRules/${encodeURIComponent(config.dcr_id ?? "")}/streams/${encodeURIComponent(config.stream ?? "")}?api-version=2023-01-01`;
      return inParts(
        events,
        (part) => JSON.stringify(part.map((e) => ({ TimeGenerated: e.time.toISOString(), EventId: e.id, EventType: e.type, Event: e.body }))),
        (body) => post(endpoint, body, { "content-type": "application/json", authorization: `Bearer ${auth.token}` }),
      );
    }
  }
}

/** S3 errors are XML; surface the code and message rather than the raw document. */
function storageError(r: { error: string; text: string; status: number }) {
  const code = /<Code>([^<]+)<\/Code>/.exec(r.text)?.[1];
  const message = /<Message>([^<]+)<\/Message>/.exec(r.text)?.[1];
  return code ? `HTTP ${r.status}: ${code}${message ? ` (${message})` : ""}` : r.error;
}
