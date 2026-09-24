import { createRoute, z } from "@hono/zod-openapi";
import { sql } from "kysely";
import type { App, Principal } from "../context.js";
import { audit } from "../audit/record.js";
import { requirePermission, requireRecentMfa } from "../auth/guard.js";
import { verifiedFactorTypes } from "../auth/routes.js";
import { notifyRoles } from "../notify/send.js";
import type { Tx } from "../platform/db.js";
import { bearer, body, json, problemResponses } from "../schemas.js";
import { diff, getSettings, OrgSettings, saveSettings, type OrgSettings as Settings } from "./settings.js";

const BaselineItem = z
  .object({
    id: z.string(),
    title: z.string(),
    description: z.string(),
    compliant: z.boolean(),
    current: z.string(),
    recommended: z.string(),
    impact: z.string().openapi({ description: "What changes for people if this is applied" }),
    auto_apply: z.boolean().openapi({ description: "Whether 'Apply baseline' can fix this automatically" }),
  })
  .openapi("BaselineItem");

const Baseline = z
  .object({ score: z.number().openapi({ description: "Share of baseline items met, 0..1" }), items: z.array(BaselineItem) })
  .openapi("SecureBaseline");

const RECOMMENDED: Settings = { mfa_policy: "everyone", session_ttl_hours: 12 };

async function mfaImpact(tx: Tx, policy: Settings["mfa_policy"]) {
  // Active users without a verified factor who would be asked to enroll under `policy`.
  const r = await sql<{ everyone: number; admins: number }>`
    SELECT
      count(*) FILTER (WHERE NOT mfa)::int AS everyone,
      count(*) FILTER (WHERE NOT mfa AND admin)::int AS admins
    FROM (
      SELECT EXISTS (SELECT 1 FROM auth_factors f WHERE f.user_id = u.id AND f.verified_at IS NOT NULL) AS mfa,
             EXISTS (SELECT 1 FROM user_roles r WHERE r.user_id = u.id) AS admin
      FROM users u WHERE u.status = 'active'
    ) x`.execute(tx);
  const row = r.rows[0]!;
  return policy === "everyone" ? row.everyone : policy === "admins" ? row.admins : 0;
}

async function baseline(tx: Tx, orgId: string) {
  const s = await getSettings(tx, orgId);
  const owners = await sql<{ n: number }>`
    SELECT count(*)::int AS n FROM user_roles r JOIN users u ON u.id = r.user_id WHERE r.role = 'owner' AND u.status = 'active'`.execute(tx);
  const enrollNow = await mfaImpact(tx, "everyone");
  const items: z.infer<typeof BaselineItem>[] = [
    {
      id: "mfa_everyone",
      title: "Require MFA for everyone",
      description: "A stolen password alone should never be enough to sign in.",
      compliant: s.mfa_policy === "everyone",
      current: { off: "Not required", admins: "Admins only", everyone: "Everyone" }[s.mfa_policy],
      recommended: "Everyone",
      impact: enrollNow
        ? `${enrollNow} user${enrollNow === 1 ? "" : "s"} without MFA will be asked to set it up at their next sign-in. Nobody is signed out.`
        : "Everyone already has MFA. No one is affected.",
      auto_apply: true,
    },
    {
      id: "session_lifetime",
      title: "Sign-ins expire within 12 hours",
      description: "Shorter sessions limit how long a stolen session cookie stays useful.",
      compliant: s.session_ttl_hours <= 12,
      current: `${s.session_ttl_hours} hours`,
      recommended: "12 hours",
      impact: "Applies to new sign-ins. Existing sessions keep their expiry.",
      auto_apply: true,
    },
    {
      id: "second_owner",
      title: "At least two owners",
      description: "Avoid being locked out of your organization if one owner loses access.",
      compliant: owners.rows[0]!.n >= 2,
      current: `${owners.rows[0]!.n} owner${owners.rows[0]!.n === 1 ? "" : "s"}`,
      recommended: "2 or more",
      impact: "Promote a trusted admin to owner from their user page.",
      auto_apply: false,
    },
  ];
  return { settings: s, result: { score: items.filter((i) => i.compliant).length / items.length, items } };
}

async function applySettings(tx: Tx, p: Principal, meta: Parameters<typeof audit>[2]["meta"], before: Settings, after: Settings, via: string) {
  const changes = diff(before, after);
  if (Object.keys(changes).length === 0) return changes;
  await saveSettings(tx, p.orgId, after);
  await audit(tx, p.orgId, { principal: p, meta }, {
    type: "org.settings_updated",
    target: { type: "organization", id: p.orgId },
    details: { changes, via },
  });
  if (changes.mfa_policy) {
    await notifyRoles(tx, p.orgId, ["owner", "admin", "security_analyst"], {
      category: "security.policy_change",
      severity: "warning",
      title: `MFA policy changed to "${after.mfa_policy}"`,
      body: `Changed by ${p.email}. Users without MFA will be asked to enroll at their next sign-in.`,
      link: "/settings/organization",
    });
  }
  return changes;
}

async function assertStepUp(c: Parameters<typeof requireRecentMfa>[0], tx: Tx, p: Principal) {
  requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
}

export function registerOrgRoutes(app: App) {
  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/org/settings",
      tags: ["Organization"],
      summary: "Organization security settings",
      security: bearer,
      responses: { 200: json(OrgSettings), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "users:read");
      return c.json(await c.get("deps").db.tenant(p.orgId, (tx) => getSettings(tx, p.orgId)), 200);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/org/settings/impact",
      tags: ["Organization"],
      summary: "Preview who a proposed MFA policy would affect, before saving it",
      security: bearer,
      request: { query: z.object({ mfa_policy: OrgSettings.shape.mfa_policy }) },
      responses: { 200: json(z.object({ users_to_enroll: z.number().int() }).openapi("PolicyImpact")), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "users:read");
      const { mfa_policy } = c.req.valid("query");
      const n = await c.get("deps").db.tenant(p.orgId, (tx) => mfaImpact(tx, mfa_policy));
      return c.json({ users_to_enroll: n }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "patch",
      path: "/v1/org/settings",
      tags: ["Organization"],
      summary: "Update security settings (requires recent MFA)",
      security: bearer,
      request: body(OrgSettings.partial()),
      responses: { 200: json(OrgSettings), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "org:manage");
      const patch = c.req.valid("json");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        await assertStepUp(c, tx, p);
        const before = await getSettings(tx, p.orgId);
        const after = { ...before, ...patch };
        await applySettings(tx, p, c.get("meta"), before, after, "settings");
        return after;
      });
      return c.json(out, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/org/baseline",
      tags: ["Organization"],
      summary: "Secure baseline: recommended settings, current state and impact (SPEC OPS-01)",
      security: bearer,
      responses: { 200: json(Baseline), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "users:read");
      const { result } = await c.get("deps").db.tenant(p.orgId, (tx) => baseline(tx, p.orgId));
      return c.json(result, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/org/baseline/apply",
      tags: ["Organization"],
      summary: "Apply every auto-fixable baseline recommendation in one step (requires recent MFA)",
      security: bearer,
      responses: {
        200: json(z.object({ applied: z.array(z.string()), baseline: Baseline }).openapi("BaselineApplied")),
        ...problemResponses,
      },
    }),
    async (c) => {
      const p = requirePermission(c, "org:manage");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        await assertStepUp(c, tx, p);
        const { settings } = await baseline(tx, p.orgId);
        const after: Settings = {
          ...settings,
          mfa_policy: RECOMMENDED.mfa_policy,
          session_ttl_hours: Math.min(settings.session_ttl_hours, RECOMMENDED.session_ttl_hours),
        };
        const changes = await applySettings(tx, p, c.get("meta"), settings, after, "secure_baseline");
        return { applied: Object.keys(changes), baseline: (await baseline(tx, p.orgId)).result };
      });
      return c.json(out, 200);
    },
  );
}
