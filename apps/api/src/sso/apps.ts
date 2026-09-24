import { createRoute, z } from "@hono/zod-openapi";
import { createHash, randomBytes } from "node:crypto";
import { sql, type Insertable } from "kysely";
import type { Database } from "../platform/db-types.js";
import type { App, Deps, Principal, RequestMeta } from "../context.js";
import { audit } from "../audit/record.js";
import { requirePermission, requireSession } from "../auth/guard.js";
import type { Tx } from "../platform/db.js";
import { isUniqueViolation } from "../platform/db.js";
import { badRequest, conflict, notFound } from "../platform/errors.js";
import { newId } from "../platform/ids.js";
import { bearer, body, Id, iso, json, problemResponses } from "../schemas.js";
import { activeSamlCert, type SamlCert } from "./saml-cert.js";
import { AttributeMapping, DEFAULT_ATTRIBUTES, idpUrls, parseSpMetadata, type SamlConfig } from "./saml.js";

export const hashSecret = (s: string) => createHash("sha256").update(s).digest();
const newClientId = () => `nx_${randomBytes(12).toString("base64url")}`;
const newClientSecret = () => `nxcs_${randomBytes(32).toString("base64url")}`;

/** The tenant's OIDC issuer: the web origin, so login and protocol endpoints share the user's session. */
export const issuerFor = (deps: Deps, slug: string) => `${deps.cfg.publicUrl}/oidc/${slug}`;

const RedirectUri = z
  .string()
  .url()
  .refine((u) => {
    const url = new URL(u);
    return url.protocol === "https:" || url.hostname === "localhost" || url.hostname === "127.0.0.1" || !url.protocol.startsWith("http");
  }, "Redirect URIs must use https (http is only allowed for localhost)")
  .refine((u) => !u.includes("#"), "Redirect URIs can't contain a fragment");

const AppSchema = z
  .object({
    id: Id,
    name: z.string(),
    protocol: z.enum(["oidc", "saml"]),
    status: z.enum(["active", "disabled"]),
    launch_url: z.string(),
    catalog_key: z.string().nullable(),
    assignment_count: z.number().int(),
    oidc: z
      .object({
        client_id: z.string(),
        client_type: z.enum(["confidential", "public"]),
        redirect_uris: z.array(z.string()),
        issuer: z.string(),
        discovery_url: z.string(),
      })
      .nullable(),
    saml: z
      .object({
        entity_id: z.string(),
        acs_url: z.string(),
        name_id_format: z.enum(["email", "persistent"]),
        sign: z.enum(["assertion", "response_and_assertion"]),
        default_relay_state: z.string().nullable(),
        attributes: z.array(AttributeMapping),
        idp_entity_id: z.string(),
        idp_sso_url: z.string(),
        idp_metadata_url: z.string(),
        idp_certificate: z.string().openapi({ description: "PEM" }),
        certificate_fingerprint: z.string().openapi({ description: "SHA-256" }),
        certificate_expires_at: z.string(),
      })
      .nullable(),
    created_at: z.string(),
    updated_at: z.string(),
  })
  .openapi("Application");

const SpUrl = z
  .string()
  .url()
  .refine((u) => {
    const url = new URL(u);
    return url.protocol === "https:" || url.hostname === "localhost" || url.hostname === "127.0.0.1";
  }, "Must use https (http is only allowed for localhost)");

const OidcInput = z.object({
  name: z.string().trim().min(1).max(100),
  protocol: z.literal("oidc"),
  client_type: z.enum(["confidential", "public"]).default("confidential").openapi({
    description: "`public` for SPAs and native apps (no secret; PKCE required)",
  }),
  redirect_uris: z.array(RedirectUri).min(1).max(20),
  launch_url: z.union([z.string().url(), z.literal("")]).default(""),
});

const SamlInput = z.object({
  name: z.string().trim().min(1).max(100),
  protocol: z.literal("saml"),
  metadata_xml: z.string().max(200_000).optional().openapi({ description: "The app's SAML metadata; fills entity_id and acs_url" }),
  entity_id: z.string().trim().min(1).max(1024).optional(),
  acs_url: SpUrl.optional(),
  name_id_format: z.enum(["email", "persistent"]).default("email"),
  sign: z.enum(["assertion", "response_and_assertion"]).default("assertion"),
  default_relay_state: z.string().max(1024).optional(),
  attributes: z.array(AttributeMapping).max(50).optional().openapi({ description: "Omit for the defaults (email, firstName, lastName, displayName, groups)" }),
  launch_url: z.union([z.string().url(), z.literal("")]).default(""),
});

const AppInput = z.discriminatedUnion("protocol", [OidcInput, SamlInput]).openapi("ApplicationInput");

const AppPatch = z
  .object({
    name: z.string().trim().min(1).max(100),
    redirect_uris: z.array(RedirectUri).min(1).max(20),
    launch_url: z.union([z.string().url(), z.literal("")]),
    status: z.enum(["active", "disabled"]),
    saml: z
      .object({
        entity_id: z.string().trim().min(1).max(1024),
        acs_url: SpUrl,
        name_id_format: z.enum(["email", "persistent"]),
        sign: z.enum(["assertion", "response_and_assertion"]),
        default_relay_state: z.string().max(1024).nullable(),
        attributes: z.array(AttributeMapping).max(50),
      })
      .partial(),
  })
  .partial()
  .openapi("ApplicationPatch");

const Assignment = z
  .object({ principal_type: z.enum(["user", "group"]), principal_id: Id, display: z.string(), detail: z.string(), created_at: z.string() })
  .openapi("AppAssignment");

type AppRow = Awaited<ReturnType<typeof appQuery>>[number];
const appQuery = (tx: Tx) =>
  tx
    .selectFrom("applications")
    .selectAll("applications")
    .select((eb) =>
      eb
        .selectFrom("app_assignments")
        .whereRef("app_assignments.app_id", "=", "applications.id")
        .select((e) => e.fn.countAll<number>().as("n"))
        .as("assignment_count"),
    )
    .orderBy("applications.name")
    .execute();

async function orgSlug(tx: Tx) {
  return (await tx.selectFrom("organizations").select("slug").executeTakeFirstOrThrow()).slug;
}

function toApp(a: AppRow, deps: Deps, slug: string, cert?: SamlCert): z.infer<typeof AppSchema> {
  const issuer = issuerFor(deps, slug);
  const cfg = a.config as unknown as SamlConfig;
  const idp = idpUrls(deps, slug);
  return {
    id: a.id,
    name: a.name,
    protocol: a.protocol,
    status: a.status,
    launch_url: a.launch_url,
    catalog_key: a.catalog_key,
    assignment_count: Number(a.assignment_count ?? 0),
    oidc:
      a.protocol === "oidc" && a.client_id
        ? {
            client_id: a.client_id,
            client_type: a.client_secret_hash ? "confidential" : "public",
            redirect_uris: a.redirect_uris,
            issuer,
            discovery_url: `${issuer}/.well-known/openid-configuration`,
          }
        : null,
    saml:
      a.protocol === "saml" && cert
        ? {
            entity_id: cfg.entity_id,
            acs_url: cfg.acs_url,
            name_id_format: cfg.name_id_format,
            sign: cfg.sign,
            default_relay_state: cfg.default_relay_state ?? null,
            attributes: cfg.attributes ?? DEFAULT_ATTRIBUTES,
            idp_entity_id: idp.entityId,
            idp_sso_url: idp.ssoUrl,
            idp_metadata_url: idp.metadataUrl,
            idp_certificate: cert.certPem,
            certificate_fingerprint: cert.fingerprintSha256,
            certificate_expires_at: iso(cert.notAfter),
          }
        : null,
    created_at: iso(a.created_at),
    updated_at: iso(a.updated_at),
  };
}

/** Serializes apps, loading the tenant's SAML certificate only when a SAML app is present. */
async function render(tx: Tx, deps: Deps, orgId: string, apps: AppRow[]) {
  const slug = await orgSlug(tx);
  const cert = apps.some((a) => a.protocol === "saml") ? await activeSamlCert(tx, deps, orgId) : undefined;
  return apps.map((a) => toApp(a, deps, slug, cert));
}

async function getApp(tx: Tx, id: string) {
  const a = (await appQuery(tx)).find((x) => x.id === id);
  if (!a) throw notFound("Application");
  return a;
}

/** Apps a user can use: assigned directly or through any of their groups. */
export async function assignedAppIds(tx: Tx, userId: string) {
  const rows = await sql<{ app_id: string }>`
    SELECT DISTINCT a.app_id FROM app_assignments a
    WHERE (a.principal_type = 'user' AND a.principal_id = ${userId})
       OR (a.principal_type = 'group' AND a.principal_id IN (SELECT group_id FROM group_members WHERE user_id = ${userId}))`.execute(tx);
  return new Set(rows.rows.map((r) => r.app_id));
}

export type AppInput = z.infer<typeof AppInput>;

/** Creates an OIDC or SAML app. Shared by POST /v1/apps and catalog installs. */
export async function createApplication(deps: Deps, p: Principal, meta: RequestMeta, input: AppInput, catalogKey: string | null) {
  const id = newId();
  let secret: string | null = null;
  let values: Insertable<Database["applications"]>;
  if (input.protocol === "oidc") {
    secret = input.client_type === "confidential" ? newClientSecret() : null;
    values = {
      id,
      org_id: p.orgId,
      name: input.name,
      protocol: "oidc",
      catalog_key: catalogKey,
      launch_url: input.launch_url,
      client_id: newClientId(),
      client_secret_hash: secret ? hashSecret(secret) : null,
      redirect_uris: input.redirect_uris,
      config: JSON.stringify({}),
      updated_at: new Date(),
    };
  } else {
    let sp = { entity_id: input.entity_id, acs_url: input.acs_url };
    if (input.metadata_xml) {
      try {
        sp = { ...parseSpMetadata(input.metadata_xml), ...Object.fromEntries(Object.entries(sp).filter(([, v]) => v)) };
      } catch (err) {
        throw badRequest("invalid_metadata", (err as Error).message);
      }
    }
    if (!sp.entity_id || !sp.acs_url) throw badRequest("invalid_request", "Provide the app's metadata, or its entity ID and ACS URL");
    if (!SpUrl.safeParse(sp.acs_url).success) throw badRequest("invalid_acs_url", "The ACS URL must use https (http is only allowed for localhost)");
    const cfg: SamlConfig = {
      entity_id: sp.entity_id,
      acs_url: sp.acs_url,
      name_id_format: input.name_id_format,
      sign: input.sign,
      ...(input.default_relay_state ? { default_relay_state: input.default_relay_state } : {}),
      ...(input.attributes ? { attributes: input.attributes } : {}),
    };
    const slug = await deps.db.tenant(p.orgId, orgSlug);
    values = {
      id,
      org_id: p.orgId,
      name: input.name,
      protocol: "saml",
      catalog_key: catalogKey,
      // Default launch: IdP-initiated sign-in from the app launcher.
      launch_url: input.launch_url || `${deps.cfg.publicUrl}/saml/${slug}/start/${id}`,
      client_id: null,
      client_secret_hash: null,
      config: JSON.stringify(cfg),
      updated_at: new Date(),
    };
  }
  try {
    const app = await deps.db.tenant(p.orgId, async (tx) => {
      await tx.insertInto("applications").values(values).execute();
      await audit(tx, p.orgId, { principal: p, meta }, {
        type: "app.created",
        target: { type: "application", id, display: input.name },
        details: {
          protocol: input.protocol,
          catalog: catalogKey,
          ...(input.protocol === "oidc" ? { client_type: input.client_type, redirect_uris: input.redirect_uris } : { config: JSON.parse(values.config as string) }),
        },
      });
      return (await render(tx, deps, p.orgId, [await getApp(tx, id)]))[0]!;
    });
    return { app, client_secret: secret };
  } catch (err) {
    if (isUniqueViolation(err)) {
      const constraint = (err as { constraint?: string }).constraint;
      throw constraint === "applications_saml_entity"
        ? conflict("entity_taken", "Another app already uses this SAML entity ID")
        : conflict("name_taken", "An application with this name already exists");
    }
    throw err;
  }
}

export const ApplicationCreated = z.object({ app: AppSchema, client_secret: z.string().nullable() }).openapi("ApplicationCreated");

export function registerAppRoutes(app: App) {
  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/apps",
      tags: ["Applications"],
      summary: "List SSO applications",
      security: bearer,
      responses: { 200: json(z.object({ data: z.array(AppSchema) })), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "apps:read");
      const deps = c.get("deps");
      const out = await deps.db.tenant(p.orgId, async (tx) => render(tx, deps, p.orgId, await appQuery(tx)));
      return c.json({ data: out }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/apps",
      tags: ["Applications"],
      summary: "Create an SSO application (OIDC or SAML)",
      description:
        "OIDC: confidential clients get `client_secret` exactly once. SAML: pass the app's metadata, or its entity ID and ACS URL; the response includes the IdP values to paste into the app.",
      security: bearer,
      request: body(AppInput),
      responses: {
        201: json(ApplicationCreated, "Created"),
        ...problemResponses,
      },
    }),
    async (c) => {
      const p = requirePermission(c, "apps:write");
      const out = await createApplication(c.get("deps"), p, c.get("meta"), c.req.valid("json"), null);
      return c.json(out, 201);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/apps/{id}",
      tags: ["Applications"],
      summary: "Get an application",
      security: bearer,
      request: { params: z.object({ id: Id }) },
      responses: { 200: json(AppSchema), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "apps:read");
      const deps = c.get("deps");
      const out = await deps.db.tenant(p.orgId, async (tx) => (await render(tx, deps, p.orgId, [await getApp(tx, c.req.valid("param").id)]))[0]!);
      return c.json(out, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "patch",
      path: "/v1/apps/{id}",
      tags: ["Applications"],
      summary: "Update an application",
      security: bearer,
      request: { params: z.object({ id: Id }), ...body(AppPatch) },
      responses: { 200: json(AppSchema), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "apps:write");
      const { id } = c.req.valid("param");
      const patch = c.req.valid("json");
      const deps = c.get("deps");
      const out = await deps.db.tenant(p.orgId, async (tx) => {
        const before = await getApp(tx, id);
        const { saml, ...rest } = patch;
        if (saml && before.protocol !== "saml") throw badRequest("not_saml", "SAML settings only apply to SAML apps");
        const config = saml ? JSON.stringify({ ...(before.config as object), ...saml }) : undefined;
        await tx
          .updateTable("applications")
          .set({ ...rest, ...(config ? { config } : {}), updated_at: new Date() })
          .where("id", "=", id)
          .execute();
        const changes = Object.fromEntries(
          Object.entries(patch)
            .filter(([k, v]) => JSON.stringify(before[k as keyof typeof before]) !== JSON.stringify(v))
            .map(([k, v]) => [k, { from: before[k as keyof typeof before], to: v }]),
        );
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, {
          type: patch.status === "disabled" && before.status === "active" ? "app.disabled" : "app.updated",
          target: { type: "application", id, display: before.name },
          details: { changes },
        });
        return (await render(tx, deps, p.orgId, [await getApp(tx, id)]))[0]!;
      });
      return c.json(out, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "delete",
      path: "/v1/apps/{id}",
      tags: ["Applications"],
      summary: "Delete an application (existing tokens expire on their own)",
      security: bearer,
      request: { params: z.object({ id: Id }) },
      responses: { 204: { description: "Deleted" }, ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "apps:write");
      const { id } = c.req.valid("param");
      await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const a = await getApp(tx, id);
        await tx.deleteFrom("applications").where("id", "=", id).execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "app.deleted", target: { type: "application", id, display: a.name } });
      });
      return c.body(null, 204);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/apps/{id}/secret",
      tags: ["Applications"],
      summary: "Rotate the client secret (the old one stops working immediately)",
      security: bearer,
      request: { params: z.object({ id: Id }) },
      responses: { 200: json(z.object({ client_secret: z.string() }).openapi("ClientSecret")), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "apps:write");
      const { id } = c.req.valid("param");
      const secret = newClientSecret();
      await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const a = await getApp(tx, id);
        if (a.protocol !== "oidc" || !a.client_secret_hash) throw badRequest("not_confidential", "Only confidential OIDC clients have a secret");
        await tx.updateTable("applications").set({ client_secret_hash: hashSecret(secret), updated_at: new Date() }).where("id", "=", id).execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "app.secret_rotated", target: { type: "application", id, display: a.name } });
      });
      return c.json({ client_secret: secret }, 200);
    },
  );

  // ---- Assignments ---------------------------------------------------------------

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/apps/{id}/assignments",
      tags: ["Applications"],
      summary: "Who can use this app",
      security: bearer,
      request: { params: z.object({ id: Id }) },
      responses: { 200: json(z.object({ data: z.array(Assignment) })), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "apps:read");
      const { id } = c.req.valid("param");
      const rows = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        await getApp(tx, id);
        return sql<{ principal_type: "user" | "group"; principal_id: string; display: string; detail: string; created_at: Date }>`
          SELECT a.principal_type, a.principal_id, a.created_at,
            COALESCE(NULLIF(trim(u.given_name || ' ' || u.family_name), ''), u.email, g.name, '(deleted)') AS display,
            COALESCE(u.email, (SELECT count(*)::text || ' members' FROM group_members m WHERE m.group_id = g.id), '') AS detail
          FROM app_assignments a
          LEFT JOIN users u ON a.principal_type = 'user' AND u.id = a.principal_id
          LEFT JOIN groups g ON a.principal_type = 'group' AND g.id = a.principal_id
          WHERE a.app_id = ${id}
          ORDER BY a.principal_type DESC, display`.execute(tx);
      });
      return c.json({ data: rows.rows.map((r) => ({ ...r, created_at: iso(r.created_at) })) }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/apps/{id}/assignments",
      tags: ["Applications"],
      summary: "Give users or groups access to this app",
      security: bearer,
      request: {
        params: z.object({ id: Id }),
        ...body(z.object({ principals: z.array(z.object({ type: z.enum(["user", "group"]), id: Id })).min(1).max(500) })),
      },
      responses: { 204: { description: "Assigned" }, ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "apps:assign");
      const { id } = c.req.valid("param");
      const { principals } = c.req.valid("json");
      await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const a = await getApp(tx, id);
        const userIds = principals.filter((x) => x.type === "user").map((x) => x.id);
        const groupIds = principals.filter((x) => x.type === "group").map((x) => x.id);
        const users = userIds.length ? await tx.selectFrom("users").select("id").where("id", "in", userIds).execute() : [];
        const groups = groupIds.length ? await tx.selectFrom("groups").select("id").where("id", "in", groupIds).execute() : [];
        if (users.length !== new Set(userIds).size || groups.length !== new Set(groupIds).size) throw notFound("One or more users or groups");
        const added = await tx
          .insertInto("app_assignments")
          .values(principals.map((x) => ({ org_id: p.orgId, app_id: id, principal_type: x.type, principal_id: x.id })))
          .onConflict((oc) => oc.doNothing())
          .returning(["principal_type", "principal_id"])
          .execute();
        if (added.length) {
          await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, {
            type: "app.assigned",
            target: { type: "application", id, display: a.name },
            details: { principals: added },
          });
        }
      });
      return c.body(null, 204);
    },
  );

  app.openapi(
    createRoute({
      method: "delete",
      path: "/v1/apps/{id}/assignments/{type}/{principalId}",
      tags: ["Applications"],
      summary: "Remove a user's or group's access",
      security: bearer,
      request: { params: z.object({ id: Id, type: z.enum(["user", "group"]), principalId: Id }) },
      responses: { 204: { description: "Removed" }, ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "apps:assign");
      const { id, type, principalId } = c.req.valid("param");
      await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const a = await getApp(tx, id);
        const r = await tx
          .deleteFrom("app_assignments")
          .where("app_id", "=", id)
          .where("principal_type", "=", type)
          .where("principal_id", "=", principalId)
          .executeTakeFirst();
        if (Number(r.numDeletedRows) === 0) throw notFound("Assignment");
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, {
          type: "app.unassigned",
          target: { type: "application", id, display: a.name },
          details: { principal_type: type, principal_id: principalId },
        });
      });
      return c.body(null, 204);
    },
  );

  // ---- App launcher (every signed-in user) -----------------------------------------

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/me/apps",
      tags: ["Me"],
      summary: "Apps I can launch",
      security: bearer,
      responses: {
        200: json(
          z.object({ data: z.array(z.object({ id: Id, name: z.string(), protocol: z.enum(["oidc", "saml"]), launch_url: z.string() }).openapi("MyApp")) }),
        ),
        ...problemResponses,
      },
    }),
    async (c) => {
      const p = requireSession(c);
      const rows = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const ids = [...(await assignedAppIds(tx, p.userId))];
        if (!ids.length) return [];
        return tx
          .selectFrom("applications")
          .select(["id", "name", "protocol", "launch_url"])
          .where("id", "in", ids)
          .where("status", "=", "active")
          .orderBy("name")
          .execute();
      });
      return c.json({ data: rows }, 200);
    },
  );
}
