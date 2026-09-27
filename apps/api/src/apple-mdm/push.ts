import http2 from "node:http2";

/**
 * Wakes a Mac so it checks in for MDM commands: an APNs push to the device's token, on the MDM
 * topic, with only {"mdm": PushMagic} (no content: the device fetches commands over HTTPS itself).
 * Authenticated with the organization's MDM push certificate (TLS client certificate).
 */
export type PushResult = { ok: boolean; status: number; reason?: string };

export async function pushMdm(opts: { url: string; certPem: string; keyPem: string; topic: string; token: string; pushMagic: string; timeoutMs?: number }): Promise<PushResult> {
  const session = http2.connect(opts.url, opts.url.startsWith("https:") ? { cert: opts.certPem, key: opts.keyPem } : {});
  try {
    return await new Promise<PushResult>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("APNs didn't answer in time")), opts.timeoutMs ?? 10_000);
      session.on("error", (e) => (clearTimeout(timer), reject(e)));
      const req = session.request({ ":method": "POST", ":path": `/3/device/${opts.token}`, "apns-topic": opts.topic, "apns-priority": "10", "content-type": "application/json" });
      let status = 0;
      let body = "";
      req.on("response", (h) => (status = Number(h[":status"])));
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        clearTimeout(timer);
        let reason: string | undefined;
        try {
          reason = body ? (JSON.parse(body) as { reason?: string }).reason : undefined;
        } catch {}
        resolve({ ok: status === 200, status, reason });
      });
      req.on("error", (e) => (clearTimeout(timer), reject(e)));
      req.end(JSON.stringify({ mdm: opts.pushMagic }));
    });
  } finally {
    session.close();
  }
}
