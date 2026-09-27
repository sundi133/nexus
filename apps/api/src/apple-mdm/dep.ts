import { createHmac, randomBytes } from "node:crypto";
import forge from "node-forge";

/**
 * Apple's device enrollment service (Apple Business Manager, "DEP"): OAuth 1.0a-signed session,
 * then JSON calls with the session token. And the ABM server token: an S/MIME envelope encrypted
 * to the key Nexus made, holding the OAuth credentials.
 */

export type DepToken = { consumer_key: string; consumer_secret: string; access_token: string; access_secret: string; access_token_expiry: string };

export class DepError extends Error {
  constructor(
    message: string,
    readonly status = 0,
  ) {
    super(message);
  }
}

/** Opens the .p7m server token ABM gives you (S/MIME text, or plain base64/DER). */
export function openServerToken(raw: string | Buffer, keyPem: string): DepToken {
  let der: string;
  const text = Buffer.isBuffer(raw) ? raw.toString("latin1") : raw;
  if (/Content-Type:/i.test(text)) {
    const body = text.split(/\r?\n\r?\n/).slice(1).join("\n").replace(/[^A-Za-z0-9+/=]/g, "");
    der = forge.util.decode64(body);
  } else if (/^[A-Za-z0-9+/=\s]+$/.test(text)) {
    der = forge.util.decode64(text.replace(/\s/g, ""));
  } else {
    der = text;
  }
  let content: string;
  try {
    const msg = forge.pkcs7.messageFromAsn1(forge.asn1.fromDer(der)) as forge.pkcs7.PkcsEnvelopedData;
    const key = forge.pki.privateKeyFromPem(keyPem);
    const recipient = msg.recipients[0];
    if (!recipient) throw new Error("no recipient");
    msg.decrypt(recipient, key);
    content = (msg.content as forge.util.ByteStringBuffer).getBytes();
  } catch {
    throw new DepError("That server token doesn't open with Nexus's key. Download a new token from Apple Business Manager for this MDM server (after uploading Nexus's current public key).");
  }
  const json = /\{[\s\S]*\}/.exec(content)?.[0];
  let tok: DepToken;
  try {
    tok = JSON.parse(json ?? "");
  } catch {
    throw new DepError("The server token's contents aren't what Apple sends");
  }
  if (!tok.consumer_key || !tok.consumer_secret || !tok.access_token || !tok.access_secret) throw new DepError("The server token is missing its credentials");
  return tok;
}

const enc = (s: string) => encodeURIComponent(s).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);

/** OAuth 1.0a (HMAC-SHA1) Authorization header, as the DEP /session endpoint expects. */
export function oauthHeader(method: string, url: string, t: DepToken, nonce = randomBytes(16).toString("hex"), timestamp = Math.floor(Date.now() / 1000).toString()) {
  const params: Record<string, string> = {
    oauth_consumer_key: t.consumer_key,
    oauth_token: t.access_token,
    oauth_signature_method: "HMAC-SHA1",
    oauth_timestamp: timestamp,
    oauth_nonce: nonce,
    oauth_version: "1.0",
  };
  const base = [method.toUpperCase(), enc(url), enc(Object.keys(params).sort().map((k) => `${enc(k)}=${enc(params[k]!)}`).join("&"))].join("&");
  const signature = createHmac("sha1", `${enc(t.consumer_secret)}&${enc(t.access_secret)}`).update(base).digest("base64");
  return "OAuth " + Object.entries({ ...params, oauth_signature: signature }).map(([k, v]) => `${enc(k)}="${enc(v)}"`).join(", ");
}

export type DepDevice = { serial_number: string; model?: string; description?: string; color?: string; os?: string; profile_status?: string; profile_uuid?: string; device_assigned_date?: string; op_type?: string };

export class DepClient {
  private session: string | null = null;
  constructor(
    private readonly base: string,
    private readonly token: DepToken,
  ) {}

  private async auth() {
    const url = `${this.base}/session`;
    const res = await fetch(url, { headers: { authorization: oauthHeader("GET", url, this.token) }, signal: AbortSignal.timeout(20_000) });
    const body = (await res.json().catch(() => ({}))) as { auth_session_token?: string };
    if (!res.ok || !body.auth_session_token) throw new DepError(`Apple refused the server token (HTTP ${res.status}): it may have expired or been revoked in Apple Business Manager`, res.status);
    this.session = body.auth_session_token;
  }

  async call<T>(method: string, path: string, body?: unknown, retried = false): Promise<T> {
    if (!this.session) await this.auth();
    const res = await fetch(`${this.base}${path}`, {
      method,
      headers: { "x-adm-auth-session": this.session!, "x-server-protocol-version": "3", "content-type": "application/json;charset=UTF8", "user-agent": "Votal Nexus MDM" },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
      signal: AbortSignal.timeout(30_000),
    });
    // A new session token may come back on any response.
    const next = res.headers.get("x-adm-auth-session");
    if (next) this.session = next;
    if (res.status === 401 && !retried) {
      this.session = null;
      return this.call(method, path, body, true);
    }
    const text = await res.text();
    if (!res.ok) throw new DepError(`Apple device enrollment ${method} ${path} failed (HTTP ${res.status}): ${text.slice(0, 200)}`, res.status);
    return (text ? JSON.parse(text) : {}) as T;
  }

  account() {
    return this.call<{ server_name: string; org_name: string; server_uuid?: string }>("GET", "/account");
  }

  /** Every device assigned to this server (first sync), following the cursor. */
  async allDevices() {
    const devices: DepDevice[] = [];
    let cursor: string | undefined;
    for (let i = 0; i < 1000; i++) {
      const r = await this.call<{ devices?: DepDevice[]; cursor: string; more_to_follow: boolean }>("POST", "/server/devices", { limit: 1000, ...(cursor ? { cursor } : {}) });
      devices.push(...(r.devices ?? []));
      cursor = r.cursor;
      if (!r.more_to_follow) break;
    }
    return { devices, cursor: cursor ?? null };
  }

  /** Changes since the cursor (added, modified, deleted). */
  async changes(cursor: string) {
    const devices: DepDevice[] = [];
    let c = cursor;
    for (let i = 0; i < 1000; i++) {
      const r = await this.call<{ devices?: DepDevice[]; cursor: string; more_to_follow: boolean }>("POST", "/devices/sync", { limit: 1000, cursor: c });
      devices.push(...(r.devices ?? []));
      c = r.cursor;
      if (!r.more_to_follow) break;
    }
    return { devices, cursor: c };
  }

  defineProfile(profile: Record<string, unknown>) {
    return this.call<{ profile_uuid: string; devices?: Record<string, string> }>("POST", "/profile", profile);
  }

  assign(profileUuid: string, serials: string[]) {
    return this.call<{ profile_uuid: string; devices: Record<string, string> }>("PUT", "/profile/devices", { profile_uuid: profileUuid, devices: serials });
  }
}
