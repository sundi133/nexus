import { createHmac } from "node:crypto";

/**
 * Delivery to one destination kind. Returns how many of the given events were
 * accepted (in order), so the cursor advances exactly that far.
 */

export type Kind = "webhook" | "splunk_hec" | "datadog";
export type SendResult = { delivered: number; status: number; error: string };
export type Outgoing = { id: string; type: string; time: Date; body: Record<string, unknown> };

export const BATCH: Record<Kind, number> = { webhook: 50, splunk_hec: 500, datadog: 500 };

async function post(url: string, body: string, headers: Record<string, string>): Promise<{ status: number; error: string }> {
  try {
    const res = await fetch(url, { method: "POST", body, headers: { "user-agent": "Votal-Nexus/1.0", ...headers }, signal: AbortSignal.timeout(15_000), redirect: "error" });
    const text = res.ok ? "" : (await res.text()).slice(0, 300);
    return { status: res.status, error: res.ok ? "" : `HTTP ${res.status}${text ? `: ${text}` : ""}` };
  } catch (err) {
    return { status: 0, error: `Couldn't connect: ${(err as Error).message}` };
  }
}

/** Stripe-style: HMAC-SHA256 over "<unix time>.<body>", so receivers can reject replays. */
export function webhookSignature(secret: string, body: string, t = Math.floor(Date.now() / 1000)) {
  return `t=${t},v1=${createHmac("sha256", secret).update(`${t}.${body}`).digest("hex")}`;
}

export async function send(kind: Kind, url: string, secret: string, config: Record<string, string>, events: Outgoing[]): Promise<SendResult> {
  if (kind === "webhook") {
    for (let i = 0; i < events.length; i++) {
      const e = events[i]!;
      const body = JSON.stringify(e.body);
      const r = await post(url, body, {
        "content-type": "application/json",
        "nexus-event-id": e.id,
        "nexus-event-type": e.type,
        "nexus-signature": webhookSignature(secret, body),
      });
      if (r.error) return { delivered: i, ...r };
    }
    return { delivered: events.length, status: 200, error: "" };
  }
  if (kind === "splunk_hec") {
    const body = events
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
      .join("\n");
    const r = await post(url, body, { "content-type": "application/json", authorization: `Splunk ${secret}` });
    return { delivered: r.error ? 0 : events.length, ...r };
  }
  const body = JSON.stringify(
    events.map((e) => ({ ddsource: "votal-nexus", service: config.service || "nexus", hostname: "nexus", ddtags: config.tags ?? "", message: JSON.stringify(e.body), event_type: e.type, date: e.time.toISOString() })),
  );
  const r = await post(url, body, { "content-type": "application/json", "dd-api-key": secret });
  return { delivered: r.error ? 0 : events.length, ...r };
}
