import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import dgram from "node:dgram";
import { sql } from "kysely";
import type { Deps } from "../context.js";
import { audit } from "../audit/record.js";
import { RateLimiter } from "../auth/ratelimit.js";
import { verifyPassword } from "../auth/passwords.js";
import { verifiedFactorTypes, verifyUserTotp } from "../auth/routes.js";

/**
 * Nexus as a RADIUS server (RFC 2865, PAP) for VPNs and Wi-Fi controllers.
 *
 * - Clients (a VPN concentrator, a Wi-Fi controller) are known by source address, each with its
 *   own shared secret. Packets from anyone else are dropped.
 * - Every Access-Request must carry a valid Message-Authenticator (RFC 3579), and every answer
 *   carries one first (the Blast-RADIUS mitigation, RFC 9765 guidance).
 * - People sign in with their Nexus password; when the organization wants MFA, the answer is
 *   an Access-Challenge for their authenticator-app code.
 * - Retransmissions get the same answer (an in-flight request isn't processed twice).
 */

export const CODE = { AccessRequest: 1, AccessAccept: 2, AccessReject: 3, AccessChallenge: 11 } as const;
export const ATTR = { UserName: 1, UserPassword: 2, ChapPassword: 3, ReplyMessage: 18, State: 24, Class: 25, EapMessage: 79, MessageAuthenticator: 80 } as const;

export type Packet = { code: number; id: number; authenticator: Buffer; attrs: { type: number; value: Buffer }[] };

export function decode(buf: Buffer): Packet | null {
  if (buf.length < 20) return null;
  const length = buf.readUInt16BE(2);
  if (length < 20 || length > 4096 || length > buf.length) return null;
  const attrs: Packet["attrs"] = [];
  for (let p = 20; p < length; ) {
    const type = buf[p]!;
    const len = buf[p + 1]!;
    if (len < 2 || p + len > length) return null;
    attrs.push({ type, value: buf.subarray(p + 2, p + len) });
    p += len;
  }
  return { code: buf[0]!, id: buf[1]!, authenticator: buf.subarray(4, 20), attrs };
}

export function encode(p: Packet): Buffer {
  const attrs = Buffer.concat(p.attrs.map((a) => Buffer.concat([Buffer.from([a.type, a.value.length + 2]), a.value])));
  const head = Buffer.alloc(20);
  head[0] = p.code;
  head[1] = p.id;
  head.writeUInt16BE(20 + attrs.length, 2);
  p.authenticator.copy(head, 4);
  return Buffer.concat([head, attrs]);
}

const attr = (p: Packet, type: number) => p.attrs.find((a) => a.type === type)?.value;
const md5 = (...parts: Buffer[]) => createHash("md5").update(Buffer.concat(parts)).digest();

/** RFC 2865 §5.2: User-Password, hidden with the shared secret and the Request Authenticator. */
export function hidePassword(password: string, secret: Buffer, requestAuth: Buffer): Buffer {
  const p = Buffer.from(password, "utf8");
  const padded = Buffer.alloc(Math.max(16, Math.ceil(p.length / 16) * 16));
  p.copy(padded);
  const out = Buffer.alloc(padded.length);
  let prev = requestAuth;
  for (let i = 0; i < padded.length; i += 16) {
    const b = md5(secret, prev);
    for (let j = 0; j < 16; j++) out[i + j] = padded[i + j]! ^ b[j]!;
    prev = out.subarray(i, i + 16);
  }
  return out;
}

export function revealPassword(hidden: Buffer, secret: Buffer, requestAuth: Buffer): string {
  if (hidden.length < 16 || hidden.length % 16 || hidden.length > 128) return "";
  const out = Buffer.alloc(hidden.length);
  let prev = requestAuth;
  for (let i = 0; i < hidden.length; i += 16) {
    const b = md5(secret, prev);
    for (let j = 0; j < 16; j++) out[i + j] = hidden[i + j]! ^ b[j]!;
    prev = hidden.subarray(i, i + 16);
  }
  const end = out.indexOf(0);
  return out.subarray(0, end < 0 ? out.length : end).toString("utf8");
}

/** RFC 3579 §3.2: HMAC-MD5 of the packet with the Message-Authenticator zeroed. */
export function messageAuthenticator(packet: Buffer, secret: Buffer, authenticatorField: Buffer): Buffer {
  const copy = Buffer.from(packet);
  authenticatorField.copy(copy, 4);
  const p = decode(copy)!;
  // Zero the Message-Authenticator's value in place.
  let off = 20;
  for (const a of p.attrs) {
    if (a.type === ATTR.MessageAuthenticator) copy.fill(0, off + 2, off + 18);
    off += a.value.length + 2;
  }
  return createHmac("md5", secret).update(copy).digest();
}

/** An answer, signed: Message-Authenticator first, then the Response Authenticator. */
export function respond(code: number, req: Packet, secret: Buffer, attrs: { type: number; value: Buffer }[]): Buffer {
  const withMa = [{ type: ATTR.MessageAuthenticator, value: Buffer.alloc(16) }, ...attrs];
  let pkt = encode({ code, id: req.id, authenticator: req.authenticator, attrs: withMa });
  const ma = messageAuthenticator(pkt, secret, req.authenticator);
  ma.copy(pkt, 22); // first attribute's value
  const auth = md5(pkt.subarray(0, 4), req.authenticator, pkt.subarray(20), secret);
  pkt = Buffer.from(pkt);
  auth.copy(pkt, 4);
  return pkt;
}

const text = (s: string) => Buffer.from(s.slice(0, 250), "utf8");

// ---- The server ------------------------------------------------------------------------------------------

type Challenge = { orgId: string; userId: string; email: string; client: string; expires: number; tries: number };

export function startRadiusServer(deps: Deps, opts: { port: number; host?: string }) {
  const sock = dgram.createSocket("udp4");
  const perUser = new RateLimiter(10, 5 * 60_000, "radius-user");
  const challenges = new Map<string, Challenge>();
  const answered = new Map<string, { at: number; reply: Promise<Buffer | null> }>();
  const meta = (ip: string) => ({ ip, userAgent: "radius", requestId: "" });

  async function handle(msg: Buffer, ip: string): Promise<Buffer | null> {
    const req = decode(msg);
    if (!req || req.code !== CODE.AccessRequest) return null;
    const client = await deps.db.unscoped(async (tx) => (await sql<{ org_id: string; client_id: string; name: string; secret: Buffer }>`SELECT * FROM nexus_radius_client_for(${ip}::inet)`.execute(tx)).rows[0]);
    if (!client) return null; // not a client of anyone: silence (RFC 2865 §3)
    const secret = deps.sealer.open(client.secret, `radius_client:${client.client_id}`);
    // Blast-RADIUS: a request without a valid Message-Authenticator is dropped.
    const ma = attr(req, ATTR.MessageAuthenticator);
    if (!ma || ma.length !== 16 || !timingSafeEqual(ma, messageAuthenticator(msg.subarray(0, msg.readUInt16BE(2)), secret, req.authenticator))) return null;
    await deps.db.tenant(client.org_id, (tx) => sql`UPDATE radius_clients SET last_used_at = now() WHERE id = ${client.client_id} AND (last_used_at IS NULL OR last_used_at < now() - interval '5 minutes')`.execute(tx));

    const reject = (message: string) => respond(CODE.AccessReject, req, secret, [{ type: ATTR.ReplyMessage, value: text(message) }]);
    const record = (outcome: "success" | "failure", who: { id: string | null; email: string }, reason: string) =>
      deps.db.tenant(client.org_id, (tx) =>
        audit(tx, client.org_id, { meta: meta(ip) }, {
          type: "radius.auth",
          outcome,
          actor: who.id ? { type: "user", id: who.id, display: who.email } : { type: "system", id: null, display: who.email || "unknown" },
          target: { type: "radius_client", id: client.client_id, display: client.name },
          details: { reason },
        }),
      );
    if (attr(req, ATTR.ChapPassword) || attr(req, ATTR.EapMessage)) return reject("Use PAP (password) authentication with Nexus");
    const hidden = attr(req, ATTR.UserPassword);
    if (!hidden) return reject("A password is required");
    const password = revealPassword(hidden, secret, req.authenticator);

    const accept = async (userId: string, email: string, reason: string) => {
      const groups = await deps.db.tenant(client.org_id, (tx) =>
        tx.selectFrom("group_members").innerJoin("groups", "groups.id", "group_members.group_id").select("groups.name").where("group_members.user_id", "=", userId).orderBy("groups.name").limit(20).execute(),
      );
      await record("success", { id: userId, email }, reason);
      // Class: group names, for the VPN or Wi-Fi controller's own policies (e.g. a VLAN per group).
      return respond(CODE.AccessAccept, req, secret, [{ type: ATTR.ReplyMessage, value: text("Welcome") }, ...groups.map((g) => ({ type: ATTR.Class, value: text(`group:${g.name}`) }))]);
    };

    // The answer to a challenge: an authenticator-app code.
    const state = attr(req, ATTR.State);
    if (state) {
      const key = state.toString("hex");
      const ch = challenges.get(key);
      if (!ch || ch.orgId !== client.org_id || ch.expires < Date.now()) {
        challenges.delete(key);
        return reject("The sign-in timed out; start again");
      }
      const ok = await deps.db.tenant(client.org_id, (tx) => verifyUserTotp(tx, deps, ch.userId, password.trim()));
      if (ok) {
        challenges.delete(key);
        return accept(ch.userId, ch.email, "password+totp");
      }
      if (++ch.tries >= 3) challenges.delete(key);
      await record("failure", { id: ch.userId, email: ch.email }, "wrong_code");
      return ch.tries >= 3 ? reject("Wrong code") : respond(CODE.AccessChallenge, req, secret, [{ type: ATTR.ReplyMessage, value: text("Wrong code. Enter the code from your authenticator app") }, { type: ATTR.State, value: state }]);
    }

    const email = (attr(req, ATTR.UserName)?.toString("utf8") ?? "").trim().toLowerCase();
    if (!email) return reject("A user name is required");
    if (!(await perUser.take(`${client.org_id}:${email}`))) return reject("Too many attempts; try again later");
    const found = await deps.db.tenant(client.org_id, async (tx) => {
      const u = await tx.selectFrom("users").select(["id", "email", "status", "password_hash"]).where(sql`lower(email)`, "=", email).executeTakeFirst();
      const settings = await tx.selectFrom("directory_service_settings").select("radius_mfa").executeTakeFirst();
      return { u, mfa: settings?.radius_mfa ?? "if_enrolled", factors: u ? await verifiedFactorTypes(tx, u.id) : [] };
    });
    const u = found.u;
    if (!u || u.status !== "active" || !(await verifyPassword(u.password_hash, password))) {
      await record("failure", { id: u?.id ?? null, email }, "bad_password");
      return reject("Wrong user name or password");
    }
    const hasTotp = found.factors.includes("totp");
    if (found.mfa === "off" || (found.mfa === "if_enrolled" && !found.factors.length)) return accept(u.id, u.email, "password");
    if (!hasTotp) {
      await record("failure", { id: u.id, email: u.email }, "no_authenticator_app");
      return reject("This network needs a code from an authenticator app: add one in Nexus under My security");
    }
    const key = randomBytes(16);
    challenges.set(key.toString("hex"), { orgId: client.org_id, userId: u.id, email: u.email, client: client.client_id, expires: Date.now() + 120_000, tries: 0 });
    return respond(CODE.AccessChallenge, req, secret, [{ type: ATTR.ReplyMessage, value: text("Enter the code from your authenticator app") }, { type: ATTR.State, value: key }]);
  }

  sock.on("message", (msg, rinfo) => {
    // Retransmissions (same client, identifier and authenticator) get the same answer.
    const key = `${rinfo.address}:${rinfo.port}:${msg[1]}:${msg.subarray(4, 20).toString("hex")}`;
    let entry = answered.get(key);
    if (!entry) {
      entry = { at: Date.now(), reply: handle(msg, rinfo.address).catch((e) => (console.error("[radius]", e), null)) };
      answered.set(key, entry);
    }
    void entry.reply.then((r) => r && sock.send(r, rinfo.port, rinfo.address));
  });
  const sweep = setInterval(() => {
    const now = Date.now();
    for (const [k, v] of answered) if (now - v.at > 30_000) answered.delete(k);
    for (const [k, v] of challenges) if (v.expires < now) challenges.delete(k);
  }, 10_000);
  sweep.unref();

  return new Promise<{ port: number; close: () => Promise<void> }>((resolve) => {
    sock.bind(opts.port, opts.host ?? "0.0.0.0", () => {
      resolve({
        port: sock.address().port,
        close: () =>
          new Promise((r) => {
            clearInterval(sweep);
            sock.close(() => r());
          }),
      });
    });
  });
}
