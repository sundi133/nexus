import { createHash, randomBytes } from "node:crypto";
import net from "node:net";
import { createRoute, z } from "@hono/zod-openapi";
import type { App } from "../context.js";
import { audit } from "../audit/record.js";
import { requirePermission, requireRecentMfa } from "../auth/guard.js";
import { verifiedFactorTypes } from "../auth/routes.js";
import type { Tx } from "../platform/db.js";
import { badRequest, conflict, notFound } from "../platform/errors.js";
import { newId } from "../platform/ids.js";
import { bearer, body, Id, iso, isoOrNull, json, problemResponses } from "../schemas.js";
import { BASE } from "./ldap.js";

/** Admin side of Nexus as an LDAP directory and a RADIUS server. */

const Settings = z.object({
  ldap_enabled: z.boolean(),
  radius_enabled: z.boolean(),
  radius_mfa: z.enum(["required", "if_enrolled", "off"]).openapi({ description: "Ask RADIUS sign-ins for an authenticator-app code: always, when the person has MFA, or never" }),
});

const Overview = Settings.extend({
  ldap: z.object({
    address: z.string().nullable().openapi({ description: "Where apps connect (ldaps://host:port), if this deployment runs the LDAP service" }),
    base_dn: z.string(),
    users_dn: z.string(),
    groups_dn: z.string(),
    service_accounts: z.array(z.object({ id: Id, name: z.string(), dn: z.string(), created_at: z.string(), last_used_at: z.string().nullable() })),
  }),
  radius: z.object({
    address: z.string().nullable().openapi({ description: "Where VPNs and Wi-Fi controllers send requests (host:port, UDP)" }),
    clients: z.array(z.object({ id: Id, name: z.string(), address: z.string(), created_at: z.string(), last_used_at: z.string().nullable() })),
  }),
}).openapi("DirectoryServices");

async function settingsOf(tx: Tx) {
  const s = await tx.selectFrom("directory_service_settings").selectAll().executeTakeFirst();
  return { ldap_enabled: s?.ldap_enabled ?? false, radius_enabled: s?.radius_enabled ?? false, radius_mfa: s?.radius_mfa ?? ("if_enrolled" as const) };
}

/** Accepts "10.0.0.5" or "10.0.0.0/24"; refuses ranges broad enough to catch other people's traffic. */
export function parseRange(input: string): string | null {
  const [ip, bits] = input.trim().split("/");
  const v = net.isIP(ip ?? "");
  if (!v) return null;
  const max = v === 4 ? 32 : 128;
  const prefix = bits === undefined ? max : Number(bits);
  if (!Number.isInteger(prefix) || prefix > max || prefix < (v === 4 ? 16 : 48)) return null;
  return `${ip}/${prefix}`;
}

export function registerDirectoryServiceRoutes(app: App) {
  const ldapAddress = process.env.NEXUS_LDAP_PUBLIC_ADDRESS || null;
  const radiusAddress = process.env.NEXUS_RADIUS_PUBLIC_ADDRESS || null;

  app.openapi(
    createRoute({ method: "get", path: "/v1/directory-services", tags: ["Directory services"], summary: "LDAP and RADIUS: settings, service accounts and clients", security: bearer, responses: { 200: json(Overview), ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "org:manage");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const slug = (await tx.selectFrom("organizations").select("slug").where("id", "=", p.orgId).executeTakeFirstOrThrow()).slug;
        const base = `o=${slug},${BASE}`;
        const accounts = await tx.selectFrom("ldap_service_accounts").selectAll().where("revoked_at", "is", null).orderBy("name").execute();
        const clients = await tx.selectFrom("radius_clients").selectAll().where("revoked_at", "is", null).orderBy("name").execute();
        return {
          ...(await settingsOf(tx)),
          ldap: {
            address: ldapAddress,
            base_dn: base,
            users_dn: `ou=users,${base}`,
            groups_dn: `ou=groups,${base}`,
            service_accounts: accounts.map((a) => ({ id: a.id, name: a.name, dn: `cn=${a.name},ou=services,${base}`, created_at: iso(a.created_at), last_used_at: isoOrNull(a.last_used_at) })),
          },
          radius: { address: radiusAddress, clients: clients.map((r) => ({ id: r.id, name: r.name, address: String(r.address), created_at: iso(r.created_at), last_used_at: isoOrNull(r.last_used_at) })) },
        };
      });
      return c.json(out, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "put",
      path: "/v1/directory-services",
      tags: ["Directory services"],
      summary: "Turn LDAP and RADIUS on or off",
      security: bearer,
      request: body(Settings),
      responses: { 200: json(Settings), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "org:manage");
      const input = c.req.valid("json");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
        const before = await settingsOf(tx);
        const row = { ...input, updated_at: new Date() };
        await tx.insertInto("directory_service_settings").values({ org_id: p.orgId, ...row }).onConflict((oc) => oc.column("org_id").doUpdateSet(row)).execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "directory_services.updated", details: { from: before, to: input } });
        return input;
      });
      return c.json(out, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/directory-services/ldap/service-accounts",
      tags: ["Directory services"],
      summary: "Create an LDAP service account (its password is shown once)",
      description: "Apps bind as it to search the directory (read-only). Give each app its own.",
      security: bearer,
      request: body(z.object({ name: z.string().trim().toLowerCase().regex(/^[a-z0-9][a-z0-9-]{0,62}$/, "Lowercase letters, digits and dashes") })),
      responses: { 201: json(z.object({ id: Id, name: z.string(), dn: z.string(), password: z.string() })), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "org:manage");
      const { name } = c.req.valid("json");
      const password = randomBytes(24).toString("base64url");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
        if (await tx.selectFrom("ldap_service_accounts").select("id").where("name", "=", name).where("revoked_at", "is", null).executeTakeFirst()) throw conflict("name_taken", "There's already a service account with that name");
        const id = newId();
        await tx.insertInto("ldap_service_accounts").values({ id, org_id: p.orgId, name, secret_hash: createHash("sha256").update(password).digest("hex"), created_by: p.userId, last_used_at: null, revoked_at: null }).execute();
        const slug = (await tx.selectFrom("organizations").select("slug").where("id", "=", p.orgId).executeTakeFirstOrThrow()).slug;
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "ldap.service_account_created", target: { type: "ldap_service_account", id, display: name } });
        return { id, name, dn: `cn=${name},ou=services,o=${slug},${BASE}`, password };
      });
      return c.json(out, 201);
    },
  );

  app.openapi(
    createRoute({ method: "delete", path: "/v1/directory-services/ldap/service-accounts/{id}", tags: ["Directory services"], summary: "Revoke an LDAP service account", security: bearer, request: { params: z.object({ id: Id }) }, responses: { 204: { description: "Revoked" }, ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "org:manage");
      const { id } = c.req.valid("param");
      await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const a = await tx.updateTable("ldap_service_accounts").set({ revoked_at: new Date() }).where("id", "=", id).where("revoked_at", "is", null).returning("name").executeTakeFirst();
        if (!a) throw notFound("Service account");
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "ldap.service_account_revoked", target: { type: "ldap_service_account", id, display: a.name } });
      });
      return c.body(null, 204);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/directory-services/radius/clients",
      tags: ["Directory services"],
      summary: "Register a RADIUS client (its shared secret is shown once)",
      description: "A VPN concentrator or Wi-Fi controller, by the address it sends from (an IP or a range of at least /16, /48 for IPv6). Addresses can't overlap another client's.",
      security: bearer,
      request: body(z.object({ name: z.string().trim().min(1).max(100), address: z.string().max(50) })),
      responses: { 201: json(z.object({ id: Id, name: z.string(), address: z.string(), secret: z.string() })), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "org:manage");
      const input = c.req.valid("json");
      const address = parseRange(input.address);
      if (!address) throw badRequest("invalid_address", "An IP address, or a range no broader than /16 (IPv4) or /48 (IPv6)");
      const secret = randomBytes(24).toString("base64url");
      const deps = c.get("deps");
      const out = await deps.db
        .tenant(p.orgId, async (tx) => {
          requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
          const id = newId();
          await tx.insertInto("radius_clients").values({ id, org_id: p.orgId, name: input.name, address, secret: deps.sealer.seal(Buffer.from(secret), `radius_client:${id}`), created_by: p.userId, last_used_at: null, revoked_at: null }).execute();
          await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "radius.client_created", target: { type: "radius_client", id, display: input.name }, details: { address } });
          return { id, name: input.name, address, secret };
        })
        .catch((e: { code?: string }) => {
          if (e?.code === "23P01") throw conflict("address_taken", "That address overlaps a RADIUS client that's already registered");
          throw e;
        });
      return c.json(out, 201);
    },
  );

  app.openapi(
    createRoute({ method: "delete", path: "/v1/directory-services/radius/clients/{id}", tags: ["Directory services"], summary: "Remove a RADIUS client", security: bearer, request: { params: z.object({ id: Id }) }, responses: { 204: { description: "Removed" }, ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "org:manage");
      const { id } = c.req.valid("param");
      await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const r = await tx.updateTable("radius_clients").set({ revoked_at: new Date() }).where("id", "=", id).where("revoked_at", "is", null).returning("name").executeTakeFirst();
        if (!r) throw notFound("RADIUS client");
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "radius.client_removed", target: { type: "radius_client", id, display: r.name } });
      });
      return c.body(null, 204);
    },
  );
}
