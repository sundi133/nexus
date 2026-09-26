import { randomBytes } from "node:crypto";
import { createRoute, z } from "@hono/zod-openapi";
import type { JWK } from "jose";
import { sql } from "kysely";
import type { App } from "../context.js";
import { audit } from "../audit/record.js";
import { requirePermission, requireRecentMfa } from "../auth/guard.js";
import { verifiedFactorTypes } from "../auth/routes.js";
import type { Tx } from "../platform/db.js";
import { isUniqueViolation } from "../platform/db.js";
import { badRequest, conflict, notFound } from "../platform/errors.js";
import { newId } from "../platform/ids.js";
import { assertSafeUrl, UnsafeUrlError } from "../platform/outbound.js";
import { bearer, body, Id, iso, json, patchOf, problemResponses, Timestamp } from "../schemas.js";
import { issuerFor } from "../sso/apps.js";
import { STALE_DAYS, suspendAgents } from "./lifecycle.js";
import { gatewayBase, hashAgentSecret, workloadJwks } from "./tokens.js";

/** AI agent registry, credentials and kill switch (SPEC AGT-01/02/03/06/07). */

const Environment = z.enum(["production", "staging", "development"]);
const RiskTier = z.enum(["low", "medium", "high", "critical"]);

const AgentInput = z.object({
  name: z.string().trim().min(1).max(100),
  description: z.string().trim().max(1000).default(""),
  owner_user_id: Id.nullable().default(null),
  owner_group_id: Id.nullable().default(null),
  environment: Environment.default("production"),
  runtime: z.string().trim().max(100).default("").openapi({ example: "Claude Agent SDK" }),
  model: z.string().trim().max(100).default("").openapi({ example: "claude-sonnet-5" }),
  risk_tier: RiskTier.default("medium"),
  tags: z.array(z.string().trim().min(1).max(50).regex(/^[a-z0-9][a-z0-9._:-]*$/, "Tags are lowercase letters, digits and . _ : -")).max(20).default([]),
  token_ttl_minutes: z.number().int().min(5).max(60).default(15),
});

const Credential = z
  .object({
    id: Id,
    kind: z.enum(["secret", "public_key", "federated"]),
    name: z.string(),
    hint: z.string().openapi({ description: "Secrets: the last characters. Keys: the key ID or thumbprint." }),
    issuer: z.string().nullable(),
    subject: z.string().nullable(),
    audience: z.string().nullable(),
    expires_at: Timestamp.nullable(),
    last_used_at: Timestamp.nullable(),
    created_at: Timestamp,
  })
  .openapi("AgentCredential");

export const Agent = z
  .object({
    id: Id,
    name: z.string(),
    description: z.string(),
    owner: z.object({ type: z.enum(["user", "group"]), id: Id, name: z.string(), active: z.boolean() }).nullable(),
    environment: Environment,
    runtime: z.string(),
    model: z.string(),
    risk_tier: RiskTier,
    tags: z.array(z.string()),
    client_id: z.string(),
    status: z.enum(["active", "suspended"]),
    status_reason: z.string(),
    token_ttl_minutes: z.number().int(),
    last_seen_at: Timestamp.nullable(),
    last_token_at: Timestamp.nullable(),
    stale: z.boolean().openapi({ description: `No token or gateway call for ${STALE_DAYS} days` }),
    credentials: z.number().int(),
    created_at: Timestamp,
    updated_at: Timestamp,
  })
  .openapi("Agent");

const Endpoints = z
  .object({ token_endpoint: z.string(), issuer: z.string(), gateway: z.string() })
  .openapi("AgentEndpoints", { description: "Where the agent gets tokens, and the MCP gateway they're for" });

const agentQuery = (tx: Tx) =>
  tx
    .selectFrom("ai_agents")
    .leftJoin("users as ou", "ou.id", "ai_agents.owner_user_id")
    .leftJoin("groups as og", "og.id", "ai_agents.owner_group_id")
    .selectAll("ai_agents")
    .select((eb) => [
      "ou.email as owner_email",
      "ou.given_name as owner_given",
      "ou.family_name as owner_family",
      "ou.status as owner_status",
      "og.name as owner_group_name",
      eb.selectFrom("agent_credentials").whereRef("agent_credentials.agent_id", "=", "ai_agents.id").where("revoked_at", "is", null).select((e) => e.fn.countAll<number>().as("n")).as("credentials"),
    ]);
type Row = Awaited<ReturnType<ReturnType<typeof agentQuery>["executeTakeFirstOrThrow"]>>;

const staleCutoff = () => new Date(Date.now() - STALE_DAYS * 86_400_000);

const toAgent = (a: Row): z.infer<typeof Agent> => ({
  id: a.id,
  name: a.name,
  description: a.description,
  owner: a.owner_user_id
    ? { type: "user", id: a.owner_user_id, name: `${a.owner_given ?? ""} ${a.owner_family ?? ""}`.trim() || (a.owner_email ?? ""), active: a.owner_status === "active" }
    : a.owner_group_id
      ? { type: "group", id: a.owner_group_id, name: a.owner_group_name ?? "", active: true }
      : null,
  environment: a.environment,
  runtime: a.runtime,
  model: a.model,
  risk_tier: a.risk_tier,
  tags: a.tags,
  client_id: a.client_id,
  status: a.status,
  status_reason: a.status_reason,
  token_ttl_minutes: a.token_ttl_minutes,
  last_seen_at: a.last_seen_at ? iso(a.last_seen_at) : null,
  last_token_at: a.last_token_at ? iso(a.last_token_at) : null,
  stale: (a.last_seen_at ?? a.created_at) < staleCutoff(),
  credentials: Number(a.credentials ?? 0),
  created_at: iso(a.created_at),
  updated_at: iso(a.updated_at),
});

const toCredential = (c: { id: string; kind: "secret" | "public_key" | "federated"; name: string; hint: string; fed_issuer: string | null; fed_subject: string | null; fed_audience: string | null; expires_at: Date | null; last_used_at: Date | null; created_at: Date }) => ({
  id: c.id,
  kind: c.kind,
  name: c.name,
  hint: c.hint,
  issuer: c.fed_issuer,
  subject: c.fed_subject,
  audience: c.fed_audience,
  expires_at: c.expires_at ? iso(c.expires_at) : null,
  last_used_at: c.last_used_at ? iso(c.last_used_at) : null,
  created_at: iso(c.created_at),
});

async function getAgent(tx: Tx, id: string) {
  const a = await agentQuery(tx).where("ai_agents.id", "=", id).executeTakeFirst();
  if (!a) throw notFound("Agent");
  return a;
}

/** Every agent has exactly one accountable owner: an active person or a group. */
async function checkOwner(tx: Tx, owner: { owner_user_id: string | null; owner_group_id: string | null }) {
  if (!owner.owner_user_id === !owner.owner_group_id) throw badRequest("owner_required", "Give the agent one owner: a person or a group");
  if (owner.owner_user_id) {
    const u = await tx.selectFrom("users").select("status").where("id", "=", owner.owner_user_id).executeTakeFirst();
    if (!u) throw notFound("Owner");
    if (u.status !== "active") throw badRequest("owner_inactive", "The owner must be an active person");
  } else if (!(await tx.selectFrom("groups").select("id").where("id", "=", owner.owner_group_id!).executeTakeFirst())) throw notFound("Owner group");
}

const CredentialInput = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("secret"), name: z.string().trim().max(100).default(""), expires_in_days: z.number().int().min(1).max(730).default(180) }),
  z.object({
    kind: z.literal("public_key"),
    name: z.string().trim().max(100).default(""),
    jwk: z.record(z.string(), z.unknown()).openapi({ description: "The agent's public key as a JWK (EC P-256/P-384, Ed25519 or RSA ≥ 2048). The private key never leaves the agent." }),
  }),
  z.object({
    kind: z.literal("federated"),
    name: z.string().trim().max(100).default(""),
    issuer: z.string().url().max(300).openapi({ example: "https://token.actions.githubusercontent.com" }),
    subject: z.string().trim().min(1).max(300).openapi({ example: "repo:acme/support-bot:ref:refs/heads/main", description: "Matched exactly" }),
    audience: z.string().trim().max(300).optional().openapi({ description: "Defaults to the organization's issuer URL" }),
  }),
]);

function checkPublicJwk(jwk: Record<string, unknown>): { jwk: JWK; hint: string } {
  if ("d" in jwk || "p" in jwk || "k" in jwk) throw badRequest("private_key", "That's a private (or symmetric) key. Send only the public key; the private key stays with the agent.");
  const ok = (jwk.kty === "EC" && (jwk.crv === "P-256" || jwk.crv === "P-384")) || (jwk.kty === "OKP" && jwk.crv === "Ed25519") || (jwk.kty === "RSA" && typeof jwk.n === "string" && Buffer.from(jwk.n, "base64url").length >= 256);
  if (!ok) throw badRequest("unsupported_key", "Use an EC P-256/P-384, Ed25519, or RSA (2048-bit or more) public key");
  const alg = jwk.kty === "EC" ? (jwk.crv === "P-256" ? "ES256" : "ES384") : jwk.kty === "OKP" ? "EdDSA" : ((jwk.alg as string) ?? "RS256");
  const pub = Object.fromEntries(Object.entries(jwk).filter(([k]) => ["kty", "crv", "x", "y", "n", "e", "kid"].includes(k))) as JWK;
  return { jwk: { ...pub, alg }, hint: String(jwk.kid ?? String(jwk.x ?? jwk.n).slice(0, 12)) };
}

export function registerAiAgentRoutes(app: App) {
  const stepUp = async (c: Parameters<typeof requireRecentMfa>[0], tx: Tx, p: Parameters<typeof requireRecentMfa>[1]) => requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/agents",
      tags: ["Agents"],
      summary: "List AI agents",
      security: bearer,
      request: { query: z.object({ status: z.enum(["active", "suspended"]).optional(), owner_user_id: Id.optional(), q: z.string().trim().max(100).optional() }) },
      responses: { 200: json(z.object({ data: z.array(Agent), endpoints: Endpoints })), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "agents:read");
      const q = c.req.valid("query");
      const deps = c.get("deps");
      const { rows, slug } = await deps.db.tenant(p.orgId, async (tx) => {
        let query = agentQuery(tx).orderBy("ai_agents.name");
        if (q.status) query = query.where("ai_agents.status", "=", q.status);
        if (q.owner_user_id) query = query.where("ai_agents.owner_user_id", "=", q.owner_user_id);
        if (q.q) query = query.where((eb) => eb.or([eb("ai_agents.name", "ilike", `%${q.q!.replace(/[%_\\]/g, "\\$&")}%`), sql<boolean>`${q.q!.toLowerCase()} = ANY(ai_agents.tags)`]));
        const org = await tx.selectFrom("organizations").select("slug").where("id", "=", p.orgId).executeTakeFirstOrThrow();
        return { rows: await query.execute(), slug: org.slug };
      });
      const issuer = issuerFor(deps, slug);
      return c.json({ data: rows.map(toAgent), endpoints: { issuer, token_endpoint: `${issuer}/token`, gateway: gatewayBase(deps, slug) } }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/agents",
      tags: ["Agents"],
      summary: "Register an AI agent",
      security: bearer,
      request: body(AgentInput),
      responses: { 201: json(Agent, "Registered"), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "agents:manage");
      const input = c.req.valid("json");
      const id = newId();
      try {
        const a = await c.get("deps").db.tenant(p.orgId, async (tx) => {
          await checkOwner(tx, input);
          await tx
            .insertInto("ai_agents")
            .values({ id, org_id: p.orgId, ...input, client_id: `agt_${randomBytes(12).toString("base64url")}`, created_by: p.apiKey ? null : p.userId, updated_at: new Date() })
            .execute();
          await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "agent.registered", target: { type: "agent", id, display: input.name }, details: { ...input } });
          return getAgent(tx, id);
        });
        return c.json(toAgent(a), 201);
      } catch (err) {
        if (isUniqueViolation(err)) throw conflict("name_taken", "An agent with this name already exists");
        throw err;
      }
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/agents/{id}",
      tags: ["Agents"],
      summary: "Get an agent and its credentials",
      security: bearer,
      request: { params: z.object({ id: Id }) },
      responses: { 200: json(z.object({ agent: Agent, credentials: z.array(Credential), endpoints: Endpoints })), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "agents:read");
      const deps = c.get("deps");
      const { id } = c.req.valid("param");
      const r = await deps.db.tenant(p.orgId, async (tx) => ({
        agent: await getAgent(tx, id),
        creds: await tx.selectFrom("agent_credentials").selectAll().where("agent_id", "=", id).where("revoked_at", "is", null).orderBy("created_at").execute(),
        slug: (await tx.selectFrom("organizations").select("slug").where("id", "=", p.orgId).executeTakeFirstOrThrow()).slug,
      }));
      const issuer = issuerFor(deps, r.slug);
      return c.json({ agent: toAgent(r.agent), credentials: r.creds.map(toCredential), endpoints: { issuer, token_endpoint: `${issuer}/token`, gateway: gatewayBase(deps, r.slug) } }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "patch",
      path: "/v1/agents/{id}",
      tags: ["Agents"],
      summary: "Update an agent",
      description: "Changing the owner of a suspended agent doesn't reactivate it; do that separately.",
      security: bearer,
      request: { params: z.object({ id: Id }), ...body(patchOf(AgentInput)) },
      responses: { 200: json(Agent), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "agents:manage");
      const { id } = c.req.valid("param");
      const patch = c.req.valid("json");
      try {
        const a = await c.get("deps").db.tenant(p.orgId, async (tx) => {
          const before = await getAgent(tx, id);
          if (patch.owner_user_id !== undefined || patch.owner_group_id !== undefined) {
            // Setting one kind of owner replaces the other.
            const owner = patch.owner_user_id ? { owner_user_id: patch.owner_user_id, owner_group_id: null } : patch.owner_group_id ? { owner_user_id: null, owner_group_id: patch.owner_group_id } : { owner_user_id: patch.owner_user_id ?? before.owner_user_id, owner_group_id: patch.owner_group_id ?? before.owner_group_id };
            await checkOwner(tx, owner);
            Object.assign(patch, owner);
          }
          await tx.updateTable("ai_agents").set({ ...patch, updated_at: new Date() }).where("id", "=", id).execute();
          await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "agent.updated", target: { type: "agent", id, display: before.name }, details: { changes: patch } });
          return getAgent(tx, id);
        });
        return c.json(toAgent(a), 200);
      } catch (err) {
        if (isUniqueViolation(err)) throw conflict("name_taken", "An agent with this name already exists");
        throw err;
      }
    },
  );

  app.openapi(
    createRoute({
      method: "delete",
      path: "/v1/agents/{id}",
      tags: ["Agents"],
      summary: "Delete an agent",
      description: "Its credentials and tokens stop working at once. The audit trail stays.",
      security: bearer,
      request: { params: z.object({ id: Id }) },
      responses: { 204: { description: "Deleted" }, ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "agents:manage");
      const { id } = c.req.valid("param");
      await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const a = await getAgent(tx, id);
        await stepUp(c, tx, p);
        await tx.deleteFrom("ai_agents").where("id", "=", id).execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "agent.deleted", target: { type: "agent", id, display: a.name } });
      });
      return c.body(null, 204);
    },
  );

  // ---- Credentials ----

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/agents/{id}/credentials",
      tags: ["Agents"],
      summary: "Add a credential",
      description:
        "secret: a client secret, shown once. public_key: the agent signs a private_key_jwt with its own key. federated: the agent presents a token from a workload identity provider (GitHub Actions, AWS, GCP, Kubernetes), so no secret is stored anywhere.",
      security: bearer,
      request: { params: z.object({ id: Id }), ...body(CredentialInput) },
      responses: { 201: json(z.object({ credential: Credential, secret: z.string().optional().openapi({ description: "Only for kind=secret; shown once" }) }), "Created"), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "agents:manage");
      const deps = c.get("deps");
      const { id } = c.req.valid("param");
      const input = c.req.valid("json");
      const credId = newId();
      let secret: string | undefined;
      let values: Record<string, unknown> = {};
      if (input.kind === "secret") {
        secret = `agts_${randomBytes(32).toString("base64url")}`;
        values = { secret_hash: hashAgentSecret(secret), hint: secret.slice(-4), expires_at: new Date(Date.now() + input.expires_in_days * 86_400_000) };
      } else if (input.kind === "public_key") {
        const k = checkPublicJwk(input.jwk);
        values = { public_jwk: JSON.stringify(k.jwk), key_id: k.jwk.kid ?? null, hint: k.hint };
      }
      const out = await deps.db.tenant(p.orgId, async (tx) => {
        const a = await getAgent(tx, id);
        await stepUp(c, tx, p);
        if (input.kind === "federated") {
          const slug = (await tx.selectFrom("organizations").select("slug").where("id", "=", p.orgId).executeTakeFirstOrThrow()).slug;
          try {
            await assertSafeUrl(input.issuer, { allowPrivate: deps.cfg.allowPrivateOutbound });
            await workloadJwks(input.issuer, deps.cfg.allowPrivateOutbound);
          } catch (e) {
            throw badRequest("issuer_unreachable", e instanceof UnsafeUrlError ? e.message : `Couldn't use ${input.issuer}: ${(e as Error).message}`);
          }
          values = { fed_issuer: input.issuer, fed_subject: input.subject, fed_audience: input.audience || issuerFor(deps, slug), hint: input.subject.slice(0, 60) };
        }
        await tx.insertInto("agent_credentials").values({ id: credId, org_id: p.orgId, agent_id: id, kind: input.kind, name: input.name, created_by: p.apiKey ? null : p.userId, ...values }).execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "agent.credential_added", target: { type: "agent", id, display: a.name }, details: { credential_id: credId, kind: input.kind, name: input.name, ...(input.kind === "federated" ? { issuer: input.issuer, subject: input.subject } : {}) } });
        return tx.selectFrom("agent_credentials").selectAll().where("id", "=", credId).executeTakeFirstOrThrow();
      });
      return c.json({ credential: toCredential(out), ...(secret ? { secret } : {}) }, 201);
    },
  );

  app.openapi(
    createRoute({
      method: "delete",
      path: "/v1/agents/{id}/credentials/{credentialId}",
      tags: ["Agents"],
      summary: "Revoke a credential",
      description: "New tokens can't be obtained with it. Tokens already issued run out within the agent's token lifetime; use suspend to stop them now.",
      security: bearer,
      request: { params: z.object({ id: Id, credentialId: Id }) },
      responses: { 204: { description: "Revoked" }, ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "agents:manage");
      const { id, credentialId } = c.req.valid("param");
      await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const a = await getAgent(tx, id);
        const r = await tx.updateTable("agent_credentials").set({ revoked_at: new Date() }).where("id", "=", credentialId).where("agent_id", "=", id).where("revoked_at", "is", null).executeTakeFirst();
        if (!Number(r.numUpdatedRows)) throw notFound("Credential");
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "agent.credential_revoked", target: { type: "agent", id, display: a.name }, details: { credential_id: credentialId } });
      });
      return c.body(null, 204);
    },
  );

  // ---- Kill switch ----

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/agents/{id}/suspend",
      tags: ["Agents"],
      summary: "Suspend an agent (kill switch)",
      description: "Every token the agent holds stops working at once, and it can't get new ones until reactivated.",
      security: bearer,
      request: { params: z.object({ id: Id }), ...body(z.object({ reason: z.string().trim().max(500).default("") })) },
      responses: { 200: json(Agent), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "agents:suspend");
      const { id } = c.req.valid("param");
      const { reason } = c.req.valid("json");
      const a = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        await getAgent(tx, id);
        await suspendAgents(tx, p.orgId, [id], reason, { principal: p, meta: c.get("meta") });
        return getAgent(tx, id);
      });
      return c.json(toAgent(a), 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/agents/suspend",
      tags: ["Agents"],
      summary: "Suspend every agent a person owns",
      security: bearer,
      request: body(z.object({ owner_user_id: Id, reason: z.string().trim().max(500).default("") })),
      responses: { 200: json(z.object({ suspended: z.array(z.string()) })), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "agents:suspend");
      const { owner_user_id, reason } = c.req.valid("json");
      const names = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const ids = (await tx.selectFrom("ai_agents").select("id").where("owner_user_id", "=", owner_user_id).where("status", "=", "active").execute()).map((a) => a.id);
        return (await suspendAgents(tx, p.orgId, ids, reason, { principal: p, meta: c.get("meta") })).map((r) => r.name);
      });
      return c.json({ suspended: names }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/agents/{id}/activate",
      tags: ["Agents"],
      summary: "Reactivate a suspended agent",
      description: "It needs an active owner. Tokens from before the suspension stay invalid; the agent gets new ones.",
      security: bearer,
      request: { params: z.object({ id: Id }) },
      responses: { 200: json(Agent), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "agents:manage");
      const { id } = c.req.valid("param");
      const a = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const before = await getAgent(tx, id);
        if (before.status === "active") return before;
        if (before.owner_user_id ? before.owner_status !== "active" : !before.owner_group_id) throw conflict("owner_required", "Give the agent an active owner first");
        await stepUp(c, tx, p);
        await tx.updateTable("ai_agents").set({ status: "active", status_reason: "", updated_at: new Date() }).where("id", "=", id).execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "agent.activated", target: { type: "agent", id, display: before.name } });
        return getAgent(tx, id);
      });
      return c.json(toAgent(a), 200);
    },
  );
}
