import { createRoute, z } from "@hono/zod-openapi";
import type { Context } from "hono";
import { sql } from "kysely";
import { X509Certificate } from "node:crypto";
import type { App, Env, Principal } from "../context.js";
import { audit } from "../audit/record.js";
import { AuthResult, verifiedFactorTypes } from "../auth/routes.js";
import { requirePermission, requireRecentMfa } from "../auth/guard.js";
import { RateLimiter } from "../auth/ratelimit.js";
import { isUniqueViolation, type Tx } from "../platform/db.js";
import { ApiError, badRequest, conflict, notFound } from "../platform/errors.js";
import { newId } from "../platform/ids.js";
import { assertSafeUrl, UnsafeUrlError } from "../platform/outbound.js";
import { bearer, body, Id, iso, isoOrNull, json, problemResponses } from "../schemas.js";
import { discover, FederationError } from "./oidc-rp.js";
import { parseIdpMetadata, spMetadata } from "./saml-sp.js";
import { idpForEmail } from "./enforce.js";
import { completeFederation, secretAad, spEndpoints, startFederation } from "./service.js";

const completeLimiter = new RateLimiter(30, 5 * 60_000, "federation-complete"); // per IP
const discoverLimiter = new RateLimiter(60, 5 * 60_000, "federation-discover"); // per IP

const Mfa = z.enum(["when_signalled", "always", "never"]).openapi({
  description: "when_signalled: the IdP's MFA counts when it says MFA was used (amr / AuthnContext); always: every sign-in through it counts as MFA; never: Nexus MFA always applies",
});
const Domain = z.string().trim().toLowerCase().regex(/^(?=.{1,253}$)([a-z0-9-]+\.)+[a-z]{2,}$/, "A domain like acme.com");
const Certificate = z.object({ subject: z.string(), not_after: z.string(), fingerprint_sha256: z.string() });

const Provider = z
  .object({
    id: Id,
    name: z.string(),
    protocol: z.enum(["oidc", "saml"]),
    issuer: z.string().nullable(),
    client_id: z.string().nullable(),
    scopes: z.string(),
    idp_entity_id: z.string().nullable(),
    idp_sso_url: z.string().nullable(),
    certificates: z.array(Certificate),
    email_attribute: z.string(),
    domains: z.array(z.string()),
    jit_provisioning: z.boolean(),
    mfa: Mfa,
    required: z.boolean(),
    enabled: z.boolean(),
    last_test_ok_at: z.string().nullable(),
    last_login_at: z.string().nullable(),
    linked_users: z.number().int(),
    created_at: z.string(),
  })
  .openapi("IdentityProvider");
const ServiceProvider = z
  .object({ oidc_redirect_uri: z.string(), saml_acs_url: z.string(), saml_entity_id: z.string(), saml_metadata_url: z.string() })
  .openapi("FederationServiceProvider", { description: "What to enter at the IdP" });
const ListResponse = z.object({ data: z.array(Provider), service_provider: ServiceProvider });

function certInfo(pem: string): z.infer<typeof Certificate> {
  const c = new X509Certificate(pem);
  return { subject: c.subject.replace(/\n/g, ", "), not_after: new Date(c.validTo).toISOString(), fingerprint_sha256: c.fingerprint256 };
}
function checkCerts(pems: string[]) {
  const out: string[] = [];
  for (const raw of pems) {
    const b64 = raw.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
    const pem = `-----BEGIN CERTIFICATE-----\n${b64.match(/.{1,64}/g)?.join("\n") ?? ""}\n-----END CERTIFICATE-----\n`;
    try {
      certInfo(pem);
    } catch {
      throw badRequest("bad_certificate", "That isn't a valid X.509 certificate (PEM or base64)");
    }
    out.push(pem);
  }
  return out;
}

async function list(tx: Tx): Promise<z.infer<typeof Provider>[]> {
  const rows = await tx
    .selectFrom("identity_providers")
    .selectAll()
    .select((eb) => eb.selectFrom("federated_identities").whereRef("federated_identities.idp_id", "=", "identity_providers.id").select(sql<number>`count(*)::int`.as("n")).as("linked_users"))
    .orderBy("created_at")
    .execute();
  return rows.map((r) => ({
    id: r.id,
    name: r.name,
    protocol: r.protocol,
    issuer: r.issuer,
    client_id: r.client_id,
    scopes: r.scopes,
    idp_entity_id: r.idp_entity_id,
    idp_sso_url: r.idp_sso_url,
    certificates: r.idp_certs.map(certInfo),
    email_attribute: r.email_attribute,
    domains: r.domains,
    jit_provisioning: r.jit_provisioning,
    mfa: r.mfa,
    required: r.required,
    enabled: r.enabled,
    last_test_ok_at: isoOrNull(r.last_test_ok_at),
    last_login_at: isoOrNull(r.last_login_at),
    linked_users: r.linked_users ?? 0,
    created_at: iso(r.created_at),
  }));
}

async function listResponse(c: Context<Env>, tx: Tx, orgId: string) {
  const org = await tx.selectFrom("organizations").select("slug").where("id", "=", orgId).executeTakeFirstOrThrow();
  return { data: await list(tx), service_provider: spEndpoints(c.get("deps"), org.slug) };
}

async function stepUp(c: Context<Env>, tx: Tx, p: Principal) {
  requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
}

/** Domains must be verified by this organization, and each is signed in by one IdP. */
async function checkDomains(tx: Tx, domains: string[], exceptIdp?: string) {
  if (!domains.length) throw badRequest("domains_required", "Choose at least one verified domain for this IdP to sign in");
  const verified = new Set((await tx.selectFrom("org_domains").select("domain").where("status", "in", ["verified", "failing"]).execute()).map((d) => d.domain));
  const missing = domains.filter((d) => !verified.has(d));
  if (missing.length) throw badRequest("domain_not_verified", `Verify ${missing.join(", ")} first (Organization → Domains)`);
  let q = tx.selectFrom("identity_providers").select(["name", "domains"]).where(sql<boolean>`domains && ${sql.val(domains)}::text[]`);
  if (exceptIdp) q = q.where("id", "<>", exceptIdp);
  const clash = await q.executeTakeFirst();
  if (clash) throw conflict("domain_in_use", `${clash.domains.filter((d) => domains.includes(d)).join(", ")} already signs in through ${clash.name}`);
}

const fedError = (err: unknown, status: 400 | 401 = 400) => {
  if (err instanceof FederationError) return new ApiError(status, err.code, err.message);
  if (err instanceof UnsafeUrlError) return badRequest("unsafe_url", err.message);
  return err;
};

export function registerFederationRoutes(app: App) {
  // ---- Signing in (public) ---------------------------------------------------------

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/auth/federation/discover",
      tags: ["Auth"],
      summary: "Does this email sign in through an identity provider?",
      description: "Home-realm discovery by email domain. Says nothing about whether the account exists.",
      request: body(z.object({ email: z.email() })),
      responses: {
        200: json(z.object({ federated: z.boolean(), provider: z.object({ name: z.string() }).nullable(), required: z.boolean() }).openapi("FederationDiscovery")),
        ...problemResponses,
      },
    }),
    async (c) => {
      if (!(await discoverLimiter.take(c.get("meta").ip))) throw new ApiError(429, "rate_limited", "Too many requests. Try again in a few minutes.");
      const idp = await idpForEmail(c.get("deps"), c.req.valid("json").email);
      return c.json({ federated: !!idp, provider: idp ? { name: idp.name } : null, required: !!idp?.required }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/auth/federation/start",
      tags: ["Auth"],
      summary: "Start signing in through the organization's identity provider",
      description: "Returns the IdP URL to send the browser to, and the `state` that comes back with the answer (bind it to the browser, e.g. in a cookie).",
      request: body(z.object({ email: z.email(), return_to: z.string().max(500).optional(), client: z.enum(["web", "mobile", "cli"]).default("web") })),
      responses: { 200: json(z.object({ redirect_url: z.string(), state: z.string() }).openapi("FederationStart")), ...problemResponses },
    }),
    async (c) => {
      const input = c.req.valid("json");
      const deps = c.get("deps");
      const idp = await idpForEmail(deps, input.email);
      if (!idp) throw notFound("Identity provider for this email");
      try {
        return c.json(await startFederation(deps, { orgId: idp.org_id, idpId: idp.idp_id, purpose: "login", returnTo: input.return_to, client: input.client, loginHint: input.email.toLowerCase() }), 200);
      } catch (err) {
        throw fedError(err);
      }
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/auth/federation/complete",
      tags: ["Auth"],
      summary: "Finish signing in with what the identity provider sent back",
      description: "OIDC: `code` (or `error`). SAML: `saml_response`. `state` is the OIDC state / SAML RelayState. A test sign-in (started by an admin) returns `purpose: test` and creates no session.",
      request: body(
        z.object({
          state: z.string().uuid(),
          code: z.string().max(4096).optional(),
          saml_response: z.string().max(400_000).optional(),
          error: z.string().max(200).optional(),
          error_description: z.string().max(1000).optional(),
          client: z.enum(["web", "mobile", "cli"]).optional(),
        }),
      ),
      responses: {
        200: json(
          z.union([
            AuthResult.extend({ purpose: z.literal("login"), return_to: z.string() }),
            z.object({ purpose: z.literal("test"), idp_id: Id, state: z.string() }),
          ]),
        ),
        ...problemResponses,
      },
    }),
    async (c) => {
      const meta = c.get("meta");
      if (!(await completeLimiter.take(meta.ip))) throw new ApiError(429, "rate_limited", "Too many sign-in attempts. Try again in a few minutes.");
      const { client: _client, ...input } = c.req.valid("json");
      let r;
      try {
        r = await completeFederation(c.get("deps"), meta, input);
      } catch (err) {
        throw fedError(err, 401);
      }
      if (r.purpose === "test") return c.json(r, 200);
      return c.json(
        {
          purpose: "login" as const,
          token: r.token,
          session: { id: r.session.id, state: r.session.state, expires_at: iso(r.session.expires_at) },
          mfa: { required: r.session.state === "pending_mfa", enrollment_required: r.session.state === "enroll_mfa", factors: r.factors as ("totp" | "push" | "webauthn")[] },
          return_to: r.return_to,
        },
        200,
      );
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/federation/saml/{slug}/metadata",
      tags: ["Auth"],
      summary: "SAML service provider metadata, for the IdP admin",
      request: { params: z.object({ slug: z.string().max(64) }) },
      responses: { 200: { description: "SAML metadata", content: { "application/samlmetadata+xml": { schema: z.string() } } }, ...problemResponses },
    }),
    async (c) => {
      const deps = c.get("deps");
      const { slug } = c.req.valid("param");
      const exists = await deps.db.unscoped(async (tx) => (await sql<{ t: boolean }>`SELECT nexus_org_slug_taken(${slug}) AS t`.execute(tx)).rows[0]?.t);
      if (!exists) throw notFound("Organization");
      const ep = spEndpoints(deps, slug.toLowerCase());
      return c.body(spMetadata(ep.saml_entity_id, ep.saml_acs_url), 200, { "content-type": "application/samlmetadata+xml" });
    },
  );

  // ---- Managing identity providers ----------------------------------------------------

  const idParam = { params: z.object({ id: Id }) };
  const Settings = {
    domains: z.array(Domain).max(50),
    jit_provisioning: z.boolean(),
    mfa: Mfa,
    email_attribute: z.string().max(256),
    scopes: z.string().max(500).regex(/(^|\s)openid(\s|$)/, "Scopes must include openid"),
  };

  app.openapi(
    createRoute({ method: "get", path: "/v1/identity-providers", tags: ["Identity providers"], summary: "Identity providers people sign in with", security: bearer, responses: { 200: json(ListResponse), ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "org:manage");
      return c.json(await c.get("deps").db.tenant(p.orgId, (tx) => listResponse(c, tx, p.orgId)), 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/identity-providers",
      tags: ["Identity providers"],
      summary: "Connect an identity provider (requires recent MFA)",
      description:
        "OIDC: `issuer`, `client_id`, `client_secret` (the issuer's discovery document is checked now). SAML: `metadata_xml`, or `idp_entity_id` + `idp_sso_url` + `certificates`. Run a test sign-in before making it required.",
      security: bearer,
      request: body(
        z.object({
          name: z.string().trim().min(1).max(100),
          protocol: z.enum(["oidc", "saml"]),
          issuer: z.string().url().max(500).optional(),
          client_id: z.string().max(500).optional(),
          client_secret: z.string().max(2000).optional(),
          metadata_xml: z.string().max(500_000).optional(),
          idp_entity_id: z.string().max(1000).optional(),
          idp_sso_url: z.string().url().max(1000).optional(),
          certificates: z.array(z.string().max(20_000)).max(5).optional(),
          domains: Settings.domains,
          jit_provisioning: Settings.jit_provisioning.default(true),
          mfa: Settings.mfa.default("when_signalled"),
          email_attribute: Settings.email_attribute.default(""),
          scopes: Settings.scopes.default("openid email profile"),
        }),
      ),
      responses: { 201: json(ListResponse, "Created"), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "org:manage");
      const input = c.req.valid("json");
      const deps = c.get("deps");
      const id = newId();
      let proto: Record<string, unknown>;
      try {
        if (input.protocol === "oidc") {
          if (!input.issuer || !input.client_id || !input.client_secret) throw badRequest("missing_field", "OIDC needs the issuer URL, client ID and client secret");
          const issuer = input.issuer; // exactly as the IdP publishes it (discovery checks this)
          await discover(issuer, deps.cfg.allowPrivateOutbound, true);
          proto = { issuer, client_id: input.client_id.trim(), client_secret: deps.sealer.seal(Buffer.from(input.client_secret.trim()), secretAad(id)), scopes: input.scopes };
        } else {
          const m = input.metadata_xml ? parseIdpMetadata(input.metadata_xml) : null;
          const entity = input.idp_entity_id ?? m?.entity_id;
          const sso = input.idp_sso_url ?? m?.sso_url;
          const certs = input.certificates?.length ? input.certificates : (m?.certs ?? []);
          if (!entity || !sso || !certs.length) throw badRequest("missing_field", "SAML needs the IdP's metadata, or its entity ID, sign-in URL and signing certificate");
          await assertSafeUrl(sso, { allowPrivate: deps.cfg.allowPrivateOutbound });
          proto = { idp_entity_id: entity, idp_sso_url: sso, idp_certs: checkCerts(certs), email_attribute: input.email_attribute };
        }
      } catch (err) {
        throw fedError(err);
      }
      try {
        const out = await deps.db.tenant(p.orgId, async (tx) => {
          await stepUp(c, tx, p);
          await checkDomains(tx, input.domains);
          await tx
            .insertInto("identity_providers")
            .values({ id, org_id: p.orgId, name: input.name, protocol: input.protocol, domains: input.domains, jit_provisioning: input.jit_provisioning, mfa: input.mfa, created_by: p.userId, ...proto })
            .execute();
          await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, {
            type: "federation.idp_created",
            target: { type: "identity_provider", id, display: input.name },
            details: { protocol: input.protocol, domains: input.domains, jit_provisioning: input.jit_provisioning, mfa: input.mfa, issuer: proto.issuer ?? proto.idp_entity_id },
          });
          return listResponse(c, tx, p.orgId);
        });
        return c.json(out, 201);
      } catch (err) {
        if (isUniqueViolation(err)) throw conflict("name_taken", "An identity provider with this name already exists");
        throw err;
      }
    },
  );

  app.openapi(
    createRoute({
      method: "patch",
      path: "/v1/identity-providers/{id}",
      tags: ["Identity providers"],
      summary: "Change an identity provider (requires recent MFA)",
      description:
        "Making it `required` (no passwords or passkeys for its domains, except break-glass accounts) needs a successful test sign-in since its connection settings last changed.",
      security: bearer,
      request: {
        ...idParam,
        ...body(
          z.object({
            name: z.string().trim().min(1).max(100).optional(),
            client_id: z.string().max(500).optional(),
            client_secret: z.string().max(2000).optional(),
            idp_sso_url: z.string().url().max(1000).optional(),
            certificates: z.array(z.string().max(20_000)).min(1).max(5).optional(),
            metadata_xml: z.string().max(500_000).optional(),
            domains: Settings.domains.optional(),
            jit_provisioning: Settings.jit_provisioning.optional(),
            mfa: Settings.mfa.optional(),
            email_attribute: Settings.email_attribute.optional(),
            scopes: Settings.scopes.optional(),
            required: z.boolean().optional(),
            enabled: z.boolean().optional(),
          }),
        ),
      },
      responses: { 200: json(ListResponse), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "org:manage");
      const { id } = c.req.valid("param");
      const input = c.req.valid("json");
      const deps = c.get("deps");
      const set: Record<string, unknown> = {};
      try {
        if (input.name) set.name = input.name;
        if (input.client_id) set.client_id = input.client_id.trim();
        if (input.client_secret) set.client_secret = deps.sealer.seal(Buffer.from(input.client_secret.trim()), secretAad(id));
        if (input.metadata_xml) {
          const m = parseIdpMetadata(input.metadata_xml);
          Object.assign(set, { idp_entity_id: m.entity_id, idp_sso_url: m.sso_url, idp_certs: checkCerts(m.certs) });
        }
        if (input.idp_sso_url) {
          await assertSafeUrl(input.idp_sso_url, { allowPrivate: deps.cfg.allowPrivateOutbound });
          set.idp_sso_url = input.idp_sso_url;
        }
        if (input.certificates) set.idp_certs = checkCerts(input.certificates);
      } catch (err) {
        throw fedError(err);
      }
      // Connection changes need a fresh test before the IdP can be (re-)required.
      const connectionChanged = ["client_id", "client_secret", "idp_entity_id", "idp_sso_url", "idp_certs"].some((k) => k in set) || input.email_attribute !== undefined || input.scopes !== undefined;
      for (const k of ["domains", "jit_provisioning", "mfa", "email_attribute", "scopes", "enabled"] as const) if (input[k] !== undefined) set[k] = input[k];
      const out = await deps.db.tenant(p.orgId, async (tx) => {
        await stepUp(c, tx, p);
        const before = await tx.selectFrom("identity_providers").selectAll().where("id", "=", id).executeTakeFirst();
        if (!before) throw notFound("Identity provider");
        if (input.domains) await checkDomains(tx, input.domains, id);
        if (connectionChanged) set.last_test_ok_at = null;
        if (input.required !== undefined) {
          if (input.required && (connectionChanged || !before.last_test_ok_at)) throw conflict("test_first", "Run a successful test sign-in with this IdP before requiring it");
          if (input.required && !(input.enabled ?? before.enabled)) throw conflict("disabled", "Turn the IdP on before requiring it");
          set.required = input.required;
        }
        if (input.enabled === false) set.required = false; // an off IdP can't be the only way in
        await tx.updateTable("identity_providers").set({ ...set, updated_at: new Date() }).where("id", "=", id).execute();
        const changes = Object.fromEntries(Object.entries(set).filter(([k]) => !["client_secret", "idp_certs"].includes(k)));
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, {
          type: "federation.idp_updated",
          target: { type: "identity_provider", id, display: (set.name as string) ?? before.name },
          details: { changes, secret_rotated: !!input.client_secret, certificates_changed: "idp_certs" in set },
        });
        return listResponse(c, tx, p.orgId);
      });
      return c.json(out, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "delete",
      path: "/v1/identity-providers/{id}",
      tags: ["Identity providers"],
      summary: "Disconnect an identity provider (requires recent MFA)",
      description: "People it signed in keep their Nexus accounts; they sign in with a password reset or a passkey afterwards.",
      security: bearer,
      request: idParam,
      responses: { 200: json(ListResponse), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "org:manage");
      const { id } = c.req.valid("param");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        await stepUp(c, tx, p);
        const r = await tx.deleteFrom("identity_providers").where("id", "=", id).returning("name").executeTakeFirst();
        if (!r) throw notFound("Identity provider");
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "federation.idp_deleted", target: { type: "identity_provider", id, display: r.name } });
        return listResponse(c, tx, p.orgId);
      });
      return c.json(out, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/identity-providers/{id}/test",
      tags: ["Identity providers"],
      summary: "Start a test sign-in",
      description: "Sign in at the IdP as anyone; Nexus shows what came back and who it would sign in, without creating a session.",
      security: bearer,
      request: idParam,
      responses: { 200: json(z.object({ redirect_url: z.string(), state: z.string() })), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "org:manage");
      try {
        return c.json(await startFederation(c.get("deps"), { orgId: p.orgId, idpId: c.req.valid("param").id, purpose: "test", requestedBy: p.userId }), 200);
      } catch (err) {
        throw fedError(err);
      }
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/identity-providers/{id}/tests/{state}",
      tags: ["Identity providers"],
      summary: "The outcome of a test sign-in",
      security: bearer,
      request: { params: z.object({ id: Id, state: z.string().uuid() }) },
      responses: {
        200: json(z.object({ done: z.boolean(), result: z.record(z.string(), z.unknown()).nullable() }).openapi("FederationTestResult")),
        ...problemResponses,
      },
    }),
    async (c) => {
      const p = requirePermission(c, "org:manage");
      const { id, state } = c.req.valid("param");
      const r = await c.get("deps").db.tenant(p.orgId, (tx) =>
        tx.selectFrom("federation_requests").select(["result", "used_at", "requested_by"]).where("id", "=", state).where("idp_id", "=", id).where("purpose", "=", "test").executeTakeFirst(),
      );
      if (!r || r.requested_by !== p.userId) throw notFound("Test sign-in");
      return c.json({ done: !!r.result, result: (r.result as Record<string, unknown>) ?? null }, 200);
    },
  );
}
