import { createRoute, z } from "@hono/zod-openapi";
import { resolveTxt as systemResolveTxt } from "node:dns/promises";
import { randomBytes } from "node:crypto";
import { sql } from "kysely";
import type { App, Deps } from "../context.js";
import { audit } from "../audit/record.js";
import { verifiedFactorTypes } from "../auth/routes.js";
import { requirePermission, requireRecentMfa } from "../auth/guard.js";
import { notifyRoles } from "../notify/send.js";
import type { Tx } from "../platform/db.js";
import { isUniqueViolation } from "../platform/db.js";
import { badRequest, conflict, notFound } from "../platform/errors.js";
import { newId } from "../platform/ids.js";
import { enqueue, registerJobHandler, type JobRunner } from "../platform/jobs.js";
import { bearer, body, Id, iso, json, problemResponses } from "../schemas.js";
import { getSettings } from "./settings.js";

/**
 * Verified email domains (ORG-02). Proving DNS control makes a domain the
 * organization's: nobody else can sign up with, invite or sync people from
 * it. Checked again daily; a removed record is reported, then released.
 */

const RECORD_PREFIX = "_nexus-verification";
const GRACE_MS = 7 * 86400_000;
// Mailbox providers: nobody can prove these, and claiming one would be meaningless.
const PUBLIC_MAIL = new Set(["gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "yahoo.com", "icloud.com", "me.com", "aol.com", "proton.me", "protonmail.com", "gmx.com", "yandex.com", "mail.com", "zoho.com"]);

export const domainOf = (email: string) => email.split("@").pop()!.toLowerCase();
export const recordName = (domain: string) => `${RECORD_PREFIX}.${domain}`;
export const recordValue = (token: string) => `nexus-verification=${token}`;

async function txtHas(deps: Deps, domain: string, token: string): Promise<{ ok: boolean; error: string }> {
  const resolve = deps.resolveTxt ?? systemResolveTxt;
  try {
    const records = (await resolve(recordName(domain))).map((chunks) => chunks.join(""));
    if (records.includes(recordValue(token))) return { ok: true, error: "" };
    return { ok: false, error: records.length ? `Found TXT records at ${recordName(domain)}, but not the Nexus one` : `No TXT record at ${recordName(domain)} yet` };
  } catch (err) {
    const code = (err as { code?: string }).code;
    return { ok: false, error: code === "ENOTFOUND" || code === "ENODATA" ? `No TXT record at ${recordName(domain)} yet. DNS changes can take up to an hour.` : `DNS lookup failed (${code ?? "error"})` };
  }
}

/**
 * Whether this org may add a person with this email. Refuses emails from a
 * domain another organization has verified, and — when the org restricts
 * itself — emails outside its own verified domains.
 */
export async function emailAdmission(tx: Tx, orgId: string, email: string): Promise<string | null> {
  const domain = domainOf(email);
  const owner = (await sql<{ o: string | null }>`SELECT nexus_domain_claimed_by(${domain}) AS o`.execute(tx)).rows[0]!.o;
  if (owner && owner !== orgId) return `${domain} is managed by another Nexus organization`;
  const settings = await getSettings(tx, orgId);
  if (settings.restrict_to_verified_domains && owner !== orgId) {
    const any = await tx.selectFrom("org_domains").select("id").where("status", "in", ["verified", "failing"]).executeTakeFirst();
    if (any) return `Only people from your verified domains can be added (${domain} isn't one)`;
  }
  return null;
}

export async function assertEmailAllowed(tx: Tx, orgId: string, email: string) {
  const why = await emailAdmission(tx, orgId, email);
  if (why) throw badRequest("domain_not_allowed", why, { errors: [{ path: "email", message: why }] });
}

const Domain = z
  .object({
    id: Id,
    domain: z.string(),
    status: z.enum(["pending", "verified", "failing"]),
    record: z.object({ type: z.literal("TXT"), name: z.string(), value: z.string() }),
    verified_at: z.string().nullable(),
    last_checked_at: z.string().nullable(),
    last_error: z.string(),
    people: z.number().int().openapi({ description: "People in this organization with an email in the domain" }),
  })
  .openapi("OrgDomain");

async function list(tx: Tx) {
  const rows = await tx.selectFrom("org_domains").selectAll().orderBy("created_at").execute();
  const counts = await sql<{ d: string; n: number }>`SELECT lower(split_part(email, '@', 2)) AS d, count(*)::int AS n FROM users WHERE status <> 'deprovisioned' GROUP BY 1`.execute(tx);
  return rows.map((r) => ({
    id: r.id,
    domain: r.domain,
    status: r.status,
    record: { type: "TXT" as const, name: recordName(r.domain), value: recordValue(r.token) },
    verified_at: r.verified_at ? iso(r.verified_at) : null,
    last_checked_at: r.last_checked_at ? iso(r.last_checked_at) : null,
    last_error: r.last_error,
    people: counts.rows.find((c) => c.d === r.domain)?.n ?? 0,
  }));
}

const DOMAIN_RE = /^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

export function registerDomainRoutes(app: App) {
  const listOut = { 200: json(z.object({ data: z.array(Domain) })), ...problemResponses };
  const idParam = { params: z.object({ id: Id }) };

  app.openapi(
    createRoute({ method: "get", path: "/v1/org/domains", tags: ["Organization"], summary: "Your email domains and their verification", security: bearer, responses: listOut }),
    async (c) => {
      const p = requirePermission(c, "org:manage");
      return c.json({ data: await c.get("deps").db.tenant(p.orgId, list) }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/org/domains",
      tags: ["Organization"],
      summary: "Add a domain to verify",
      description: "Publish the returned TXT record, then call verify.",
      security: bearer,
      request: body(z.object({ domain: z.string().trim().toLowerCase().max(253) })),
      responses: { 201: json(z.object({ data: z.array(Domain) }), "Added"), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "org:manage");
      const domain = c.req.valid("json").domain.replace(/\.$/, "");
      if (!DOMAIN_RE.test(domain)) throw badRequest("invalid_domain", "Enter a domain like example.com");
      if (PUBLIC_MAIL.has(domain)) throw badRequest("public_domain", `${domain} is a public email provider; it can't belong to one organization`);
      try {
        const data = await c.get("deps").db.tenant(p.orgId, async (tx) => {
          await tx.insertInto("org_domains").values({ id: newId(), org_id: p.orgId, domain, token: randomBytes(18).toString("base64url"), created_by: p.userId }).execute();
          await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "org.domain_added", target: { type: "domain", id: null, display: domain } });
          return list(tx);
        });
        return c.json({ data }, 201);
      } catch (err) {
        if (isUniqueViolation(err)) throw conflict("domain_exists", `${domain} is already on your list`);
        throw err;
      }
    },
  );

  app.openapi(
    createRoute({ method: "post", path: "/v1/org/domains/{id}/verify", tags: ["Organization"], summary: "Check the DNS record now", security: bearer, request: idParam, responses: listOut }),
    async (c) => {
      const p = requirePermission(c, "org:manage");
      const { id } = c.req.valid("param");
      const deps = c.get("deps");
      const d = await deps.db.tenant(p.orgId, (tx) => tx.selectFrom("org_domains").selectAll().where("id", "=", id).executeTakeFirst());
      if (!d) throw notFound("Domain");
      const check = await txtHas(deps, d.domain, d.token);
      try {
        const data = await deps.db.tenant(p.orgId, async (tx) => {
          await tx
            .updateTable("org_domains")
            .set(check.ok ? { status: "verified", verified_at: d.verified_at ?? new Date(), last_checked_at: new Date(), last_error: "", failing_since: null } : { last_checked_at: new Date(), last_error: check.error })
            .where("id", "=", id)
            .execute();
          if (check.ok && d.status !== "verified") {
            await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "org.domain_verified", target: { type: "domain", id: null, display: d.domain } });
          }
          return list(tx);
        });
        return c.json({ data }, 200);
      } catch (err) {
        if (isUniqueViolation(err)) throw conflict("domain_claimed", `${d.domain} is already verified by another Nexus organization. Contact support if you own it.`);
        throw err;
      }
    },
  );

  app.openapi(
    createRoute({ method: "delete", path: "/v1/org/domains/{id}", tags: ["Organization"], summary: "Remove a domain (requires recent MFA)", security: bearer, request: idParam, responses: listOut }),
    async (c) => {
      const p = requirePermission(c, "org:manage");
      const { id } = c.req.valid("param");
      const data = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
        const r = await tx.deleteFrom("org_domains").where("id", "=", id).returning("domain").executeTakeFirst();
        if (!r) throw notFound("Domain");
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "org.domain_removed", target: { type: "domain", id: null, display: r.domain } });
        return list(tx);
      });
      return c.json({ data }, 200);
    },
  );
}

/** Daily: verified domains must keep their record. Lost for 7 days → released. */
export async function recheckDomain(deps: Deps, orgId: string, domainId: string) {
  const d = await deps.db.tenant(orgId, (tx) => tx.selectFrom("org_domains").selectAll().where("id", "=", domainId).executeTakeFirst());
  if (!d || d.status === "pending") return;
  const check = await txtHas(deps, d.domain, d.token);
  await deps.db.tenant(orgId, async (tx) => {
    const meta = { ip: "", userAgent: "nexus-scheduler", requestId: "" };
    const actor = { type: "system" as const, id: null, display: "Nexus" };
    if (check.ok) {
      await tx.updateTable("org_domains").set({ status: "verified", last_checked_at: new Date(), last_error: "", failing_since: null }).where("id", "=", d.id).execute();
      return;
    }
    const since = d.failing_since ?? new Date();
    if (Date.now() - since.getTime() > GRACE_MS) {
      await tx.updateTable("org_domains").set({ status: "pending", verified_at: null, failing_since: null, last_checked_at: new Date(), last_error: check.error }).where("id", "=", d.id).execute();
      await audit(tx, orgId, { meta }, { type: "org.domain_released", outcome: "failure", actor, target: { type: "domain", id: null, display: d.domain }, details: { reason: check.error } });
      await notifyRoles(tx, orgId, ["owner", "admin"], { category: "org.domains", severity: "critical", title: `${d.domain} is no longer verified`, body: `Its DNS record has been missing for 7 days, so the domain was released. Add the record back and verify it again.`, link: "/settings/organization" });
      return;
    }
    await tx.updateTable("org_domains").set({ status: "failing", failing_since: since, last_checked_at: new Date(), last_error: check.error }).where("id", "=", d.id).execute();
    if (!d.failing_since) {
      await notifyRoles(tx, orgId, ["owner", "admin"], { category: "org.domains", severity: "warning", title: `Can't find the verification record for ${d.domain}`, body: `${check.error}. If it isn't restored within 7 days, the domain is released and others could claim it.`, link: "/settings/organization" });
    }
  });
}

registerJobHandler("domain.recheck", async (deps, job) => {
  await recheckDomain(deps, job.org_id, String((job.payload as { domain_id: string }).domain_id));
});

export function scheduleDomainRechecks(jobs: JobRunner, deps: Deps) {
  let last = 0;
  jobs.onTick(async () => {
    if (Date.now() - last < 3600_000) return; // hourly scan; each domain is rechecked daily
    last = Date.now();
    const due = await deps.db.unscoped(async (tx) => (await sql<{ org_id: string; domain_id: string }>`SELECT * FROM nexus_domains_to_recheck()`.execute(tx)).rows);
    for (const d of due) await deps.db.tenant(d.org_id, (tx) => enqueue(tx, d.org_id, "domain.recheck", { domain_id: d.domain_id }, { dedupeKey: `domain.recheck:${d.domain_id}` }));
  });
}
