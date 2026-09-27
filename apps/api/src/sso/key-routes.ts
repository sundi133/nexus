import { createRoute, z } from "@hono/zod-openapi";
import type { Context } from "hono";
import type { App, Env, Principal } from "../context.js";
import { audit } from "../audit/record.js";
import { requirePermission, requireRecentMfa } from "../auth/guard.js";
import { verifiedFactorTypes } from "../auth/routes.js";
import { notifyRoles } from "../notify/send.js";
import type { Tx } from "../platform/db.js";
import { conflict } from "../platform/errors.js";
import { bearer, iso, isoOrNull, json, problemResponses } from "../schemas.js";
import { createKey } from "./keys.js";
import { activeSamlCert, createSamlCert, fingerprint } from "./saml-cert.js";

/**
 * Signing key & certificate lifecycle (SPEC SSO-07).
 * - OIDC: rotate = new active key; the old key is retired but stays in JWKS for 7 days.
 * - SAML: SPs pin certificates, so rotation has an overlap step: create a `next`
 *   certificate (published in metadata next to the active one), update apps,
 *   then activate it. The previous certificate is retired.
 */

const SigningKey = z
  .object({
    kid: z.string(),
    purpose: z.enum(["oidc", "saml"]),
    status: z.enum(["next", "active", "retired"]),
    created_at: z.string(),
    retired_at: z.string().nullable(),
    expires_at: z.string().nullable(),
    fingerprint: z.string().nullable(),
    certificate: z.string().nullable(),
  })
  .openapi("SigningKey");

async function listKeys(tx: Tx) {
  const rows = await tx
    .selectFrom("signing_keys")
    .select(["kid", "purpose", "status", "created_at", "retired_at", "not_after", "cert_pem"])
    .orderBy("created_at", "desc")
    .limit(30)
    .execute();
  return rows.map((r) => ({
    kid: r.kid,
    purpose: r.purpose,
    status: r.status,
    created_at: iso(r.created_at),
    retired_at: isoOrNull(r.retired_at),
    expires_at: isoOrNull(r.not_after),
    fingerprint: r.cert_pem ? fingerprint(r.cert_pem) : null,
    certificate: r.status === "retired" ? null : r.cert_pem,
  }));
}

async function stepUp(c: Context<Env>, tx: Tx, p: Principal) {
  requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
}

const retire = (tx: Tx, purpose: "oidc" | "saml") =>
  tx.updateTable("signing_keys").set({ status: "retired", retired_at: new Date() }).where("purpose", "=", purpose).where("status", "=", "active").execute();

export function registerKeyRoutes(app: App) {
  const listResponse = { 200: json(z.object({ data: z.array(SigningKey) })), ...problemResponses };

  app.openapi(
    createRoute({ method: "get", path: "/v1/org/signing-keys", tags: ["Organization"], summary: "SSO signing keys and certificates", security: bearer, responses: listResponse }),
    async (c) => {
      const p = requirePermission(c, "apps:read");
      const deps = c.get("deps");
      const data = await deps.db.tenant(p.orgId, async (tx) => {
        await activeSamlCert(tx, deps, p.orgId); // make sure there is one to show
        return listKeys(tx);
      });
      return c.json({ data }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/org/signing-keys/oidc/rotate",
      tags: ["Organization"],
      summary: "Rotate the OIDC token signing key (requires recent MFA)",
      description: "Apps that fetch JWKS pick up the new key automatically; tokens signed by the old key keep verifying until they expire.",
      security: bearer,
      responses: listResponse,
    }),
    async (c) => {
      const p = requirePermission(c, "apps:write");
      const deps = c.get("deps");
      const data = await deps.db.tenant(p.orgId, async (tx) => {
        await stepUp(c, tx, p);
        await retire(tx, "oidc");
        await createKey(tx, deps, p.orgId);
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "sso.key_rotated", target: { type: "organization", id: p.orgId }, details: { purpose: "oidc" } });
        return listKeys(tx);
      });
      return c.json({ data }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/org/signing-keys/saml/next",
      tags: ["Organization"],
      summary: "Start a SAML certificate rotation: create the next certificate (requires recent MFA)",
      description: "The new certificate is added to IdP metadata but doesn't sign anything yet. Update apps that pin the certificate, then activate it.",
      security: bearer,
      responses: listResponse,
    }),
    async (c) => {
      const p = requirePermission(c, "apps:write");
      const deps = c.get("deps");
      const data = await deps.db.tenant(p.orgId, async (tx) => {
        await stepUp(c, tx, p);
        const existing = await tx.selectFrom("signing_keys").select("kid").where("purpose", "=", "saml").where("status", "=", "next").executeTakeFirst();
        if (existing) throw conflict("rotation_in_progress", "A next certificate already exists. Activate or discard it first.");
        await activeSamlCert(tx, deps, p.orgId);
        const cert = await createSamlCert(tx, deps, p.orgId, "next");
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, {
          type: "sso.cert_rotation_started",
          target: { type: "organization", id: p.orgId },
          details: { fingerprint: cert.fingerprintSha256 },
        });
        return listKeys(tx);
      });
      return c.json({ data }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/org/signing-keys/saml/activate",
      tags: ["Organization"],
      summary: "Finish a SAML certificate rotation: start signing with the next certificate (requires recent MFA)",
      security: bearer,
      responses: listResponse,
    }),
    async (c) => {
      const p = requirePermission(c, "apps:write");
      const deps = c.get("deps");
      const data = await deps.db.tenant(p.orgId, async (tx) => {
        await stepUp(c, tx, p);
        const next = await tx.selectFrom("signing_keys").select(["kid", "cert_pem"]).where("purpose", "=", "saml").where("status", "=", "next").executeTakeFirst();
        if (!next) throw conflict("no_rotation", "There's no next certificate to activate. Start a rotation first.");
        await retire(tx, "saml");
        await tx.updateTable("signing_keys").set({ status: "active" }).where("kid", "=", next.kid).execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, {
          type: "sso.cert_rotated",
          target: { type: "organization", id: p.orgId },
          details: { fingerprint: fingerprint(next.cert_pem!) },
        });
        await notifyRoles(tx, p.orgId, ["owner", "admin"], {
          category: "sso.certificate",
          severity: "warning",
          title: "SAML signing certificate rotated",
          body: `Apps that pin the certificate must now trust ${fingerprint(next.cert_pem!).slice(0, 23)}…; if one stops accepting sign-ins, update its certificate.`,
          link: "/settings/organization#certificates",
        });
        return listKeys(tx);
      });
      return c.json({ data }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "delete",
      path: "/v1/org/signing-keys/saml/next",
      tags: ["Organization"],
      summary: "Discard a pending SAML certificate rotation",
      security: bearer,
      responses: listResponse,
    }),
    async (c) => {
      const p = requirePermission(c, "apps:write");
      const data = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const r = await tx.deleteFrom("signing_keys").where("purpose", "=", "saml").where("status", "=", "next").executeTakeFirst();
        if (Number(r.numDeletedRows) === 0) throw conflict("no_rotation", "There's no pending rotation");
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "sso.cert_rotation_discarded", target: { type: "organization", id: p.orgId } });
        return listKeys(tx);
      });
      return c.json({ data }, 200);
    },
  );
}
