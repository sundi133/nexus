import http2 from "node:http2";
import { importPKCS8, SignJWT } from "jose";
import type { PushPayload, PushSender, PushTarget } from "./push.js";

/**
 * Apple Push Notification service over HTTP/2 with a token-based (.p8)
 * provider key. The provider JWT is reused for 50 minutes (Apple rejects
 * refreshing more often than every 20 and accepts up to 60).
 */
export type ApnsConfig = { teamId: string; keyId: string; bundleId: string; privateKey: string; production: boolean; base?: string };

export class ApnsSender implements PushSender {
  private jwt: { token: string; at: number } | null = null;
  private session: http2.ClientHttp2Session | null = null;
  private readonly base: string;

  constructor(private readonly cfg: ApnsConfig) {
    this.base = cfg.base ?? (cfg.production ? "https://api.push.apple.com" : "https://api.sandbox.push.apple.com");
  }

  private async providerToken() {
    if (this.jwt && Date.now() - this.jwt.at < 50 * 60_000) return this.jwt.token;
    const key = await importPKCS8(this.cfg.privateKey, "ES256");
    const token = await new SignJWT({}).setProtectedHeader({ alg: "ES256", kid: this.cfg.keyId }).setIssuer(this.cfg.teamId).setIssuedAt().sign(key);
    this.jwt = { token, at: Date.now() };
    return token;
  }

  private connect() {
    if (this.session && !this.session.closed && !this.session.destroyed) return this.session;
    const s = http2.connect(this.base);
    s.on("error", () => s.destroy());
    s.on("goaway", () => s.close());
    s.unref();
    this.session = s;
    return s;
  }

  async send(target: PushTarget, payload: PushPayload): Promise<{ ok: boolean; invalidToken?: boolean }> {
    if (target.platform !== "ios") return { ok: false };
    const body = JSON.stringify({
      aps: { alert: { title: payload.title }, sound: "default", "thread-id": payload.category },
      category: payload.category,
      id: payload.id,
    });
    const headers = {
      ":method": "POST",
      ":path": `/3/device/${encodeURIComponent(target.token)}`,
      authorization: `bearer ${await this.providerToken()}`,
      "apns-topic": this.cfg.bundleId,
      "apns-push-type": "alert",
      "apns-priority": payload.priority === "high" ? "10" : "5",
      "apns-expiration": String(Math.floor(Date.now() / 1000) + (payload.priority === "high" ? 120 : 86400)),
      "content-type": "application/json",
    };
    return new Promise((resolve) => {
      let req: http2.ClientHttp2Stream;
      try {
        req = this.connect().request(headers);
      } catch {
        this.session = null;
        return resolve({ ok: false });
      }
      let status = 0;
      let data = "";
      req.setTimeout(10_000, () => req.close(http2.constants.NGHTTP2_CANCEL));
      req.on("response", (h) => (status = Number(h[":status"])));
      req.on("data", (c) => (data += c));
      req.on("end", () => {
        if (status === 200) return resolve({ ok: true });
        let reason = "";
        try {
          reason = JSON.parse(data).reason ?? "";
        } catch {
          /* empty */
        }
        // 410: the app was uninstalled; 400 BadDeviceToken: the token isn't valid for this topic/environment.
        resolve({ ok: false, invalidToken: status === 410 || reason === "BadDeviceToken" || reason === "Unregistered" });
      });
      req.on("error", () => resolve({ ok: false }));
      req.end(body);
    });
  }

  close() {
    this.session?.close();
  }
}
