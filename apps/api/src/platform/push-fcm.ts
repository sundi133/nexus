import { importPKCS8, SignJWT } from "jose";
import type { PushPayload, PushSender, PushTarget } from "./push.js";

/** Firebase Cloud Messaging HTTP v1 with a service account (OAuth 2 JWT bearer). */
export type FcmConfig = { projectId: string; clientEmail: string; privateKey: string; tokenUrl?: string; base?: string };

const GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";

export class FcmSender implements PushSender {
  private access: { token: string; exp: number } | null = null;
  private readonly tokenUrl: string;
  private readonly base: string;

  constructor(private readonly cfg: FcmConfig) {
    this.tokenUrl = cfg.tokenUrl ?? GOOGLE_TOKEN_URL;
    this.base = cfg.base ?? "https://fcm.googleapis.com";
  }

  static fromServiceAccount(json: string, overrides: { tokenUrl?: string; base?: string } = {}) {
    const sa = JSON.parse(json) as { project_id: string; client_email: string; private_key: string };
    return new FcmSender({ projectId: sa.project_id, clientEmail: sa.client_email, privateKey: sa.private_key, ...overrides });
  }

  private async accessToken() {
    if (this.access && this.access.exp - 60_000 > Date.now()) return this.access.token;
    const now = Math.floor(Date.now() / 1000);
    const assertion = await new SignJWT({ scope: "https://www.googleapis.com/auth/firebase.messaging" })
      .setProtectedHeader({ alg: "RS256", typ: "JWT" })
      .setIssuer(this.cfg.clientEmail)
      .setAudience(this.tokenUrl)
      .setIssuedAt(now)
      .setExpirationTime(now + 3600)
      .sign(await importPKCS8(this.cfg.privateKey, "RS256"));
    const res = await fetch(this.tokenUrl, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion }),
      signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok) throw new Error(`FCM auth failed: HTTP ${res.status}`);
    const body = (await res.json()) as { access_token: string; expires_in: number };
    this.access = { token: body.access_token, exp: Date.now() + body.expires_in * 1000 };
    return this.access.token;
  }

  async send(target: PushTarget, payload: PushPayload): Promise<{ ok: boolean; invalidToken?: boolean }> {
    if (target.platform !== "android") return { ok: false };
    try {
      const res = await fetch(`${this.base}/v1/projects/${encodeURIComponent(this.cfg.projectId)}/messages:send`, {
        method: "POST",
        headers: { authorization: `Bearer ${await this.accessToken()}`, "content-type": "application/json" },
        body: JSON.stringify({
          message: {
            token: target.token,
            notification: { title: payload.title },
            data: { category: payload.category, id: payload.id },
            android: { priority: payload.priority === "high" ? "HIGH" : "NORMAL", ttl: payload.priority === "high" ? "120s" : "86400s", notification: { tag: payload.category } },
          },
        }),
        signal: AbortSignal.timeout(10_000),
      });
      if (res.ok) return { ok: true };
      const err = (await res.json().catch(() => ({}))) as { error?: { status?: string; details?: { errorCode?: string }[] } };
      const code = err.error?.details?.find((d) => d.errorCode)?.errorCode ?? err.error?.status;
      return { ok: false, invalidToken: res.status === 404 || code === "UNREGISTERED" || code === "INVALID_ARGUMENT" };
    } catch {
      return { ok: false };
    }
  }
}
