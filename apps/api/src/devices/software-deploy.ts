import { createRoute, z } from "@hono/zod-openapi";
import { sql } from "kysely";
import type { App, RequestMeta } from "../context.js";
import { audit } from "../audit/record.js";
import { requirePermission, requireRecentMfa } from "../auth/guard.js";
import { verifiedFactorTypes } from "../auth/routes.js";
import type { Tx } from "../platform/db.js";
import type { DevicePlatform } from "../platform/db-types.js";
import { badRequest, conflict, notFound } from "../platform/errors.js";
import { newId } from "../platform/ids.js";
import { isUniqueViolation } from "../platform/db.js";
import { bearer, body, Id, iso, isoOrNull, json, problemResponses } from "../schemas.js";

/**
 * App deployment (like JumpCloud Software Management). Admins keep a catalog of packages (winget
 * and MSI on Windows, .pkg on macOS, apt and dnf on Linux) and assign each to every device on its
 * platform or to a group's devices, to install or to remove. Each device gets its list inside the
 * signed device policy (see enforcement.ts), makes itself match in the background, re-checks
 * hourly, and reports each app's state. Installers run as root/SYSTEM, so managing the catalog
 * and assignments is owner/admin only (devices:software) with a recent MFA, and audited.
 */

const Kind = z.enum(["winget", "msi", "pkg", "apt", "dnf"]);
type Kind = z.infer<typeof Kind>;
const PLATFORM_OF: Record<Kind, DevicePlatform> = { winget: "windows", msi: "windows", pkg: "macos", apt: "linux", dnf: "linux" };
// Kept in step with the agent's own checks (agent/internal/software): it refuses anything else.
const REF: Record<Kind, [RegExp, string]> = {
  winget: [/^[A-Za-z0-9][A-Za-z0-9.+_-]{0,127}$/, "A winget package ID, like Zoom.Zoom"],
  msi: [/^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$/, "The MSI's ProductCode, like {12345678-1234-1234-1234-123456789012}"],
  pkg: [/^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$/, "The package's receipt ID (pkgutil --pkgs), like us.zoom.pkg.videomeeting"],
  apt: [/^[a-z0-9][a-z0-9.+-]{0,127}$/, "A Debian package name, like htop"],
  dnf: [/^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$/, "An RPM package name, like htop"],
};

const PackageIn = z.object({
  name: z.string().trim().min(1).max(100),
  description: z.string().trim().max(500).default(""),
  kind: Kind.openapi({ description: "winget / msi (Windows), pkg (macOS), apt / dnf (Linux)" }),
  ref: z.string().trim().max(255).openapi({ description: "winget ID, MSI ProductCode, pkg receipt ID, or package name: how the agent finds it" }),
  url: z.string().trim().max(2000).default("").openapi({ description: "msi / pkg: the installer's https URL" }),
  sha256: z.string().trim().toLowerCase().max(64).default("").openapi({ description: "msi / pkg: the installer's SHA-256 (the agent refuses a download that doesn't match)" }),
  args: z.array(z.string().min(1).max(500).regex(/^[^\r\n\0]*$/)).max(20).default([]).openapi({ description: "Extra installer arguments (MSI properties, winget or package-manager options)" }),
});
type PackageIn = z.infer<typeof PackageIn>;

function validate(p: PackageIn) {
  const [re, hint] = REF[p.kind];
  if (!re.test(p.ref)) throw badRequest("invalid_ref", hint);
  if (p.kind === "msi" || p.kind === "pkg") {
    let u: URL | null = null;
    try {
      u = new URL(p.url);
    } catch {}
    if (!u || u.protocol !== "https:") throw badRequest("invalid_url", "Give the installer's https URL");
    if (!/^[0-9a-f]{64}$/.test(p.sha256)) throw badRequest("invalid_sha256", "Give the installer's SHA-256 (64 hexadecimal characters): the agent checks every download against it");
  } else if (p.url || p.sha256) throw badRequest("invalid_url", `${p.kind} packages come from the package manager's own sources: no URL or hash`);
}

const Counts = z.object({ targeted: z.number().int(), installed: z.number().int(), absent: z.number().int(), failed: z.number().int(), unsupported: z.number().int(), pending: z.number().int() });
const Assignment = z.object({
  id: Id,
  action: z.enum(["install", "remove"]),
  group_id: Id.nullable(),
  group_name: z.string().nullable(),
  user_id: Id.nullable().openapi({ description: "One person's devices (an approved request)" }),
  user_email: z.string().nullable(),
  created_at: z.string(),
});
const PackageOut = PackageIn.extend({ id: Id, platform: z.enum(["macos", "windows", "linux"]), created_at: z.string(), updated_at: z.string(), assignments: z.array(Assignment), counts: Counts }).openapi("SoftwarePackage");

type Pkg = { id: string; name: string; platform: DevicePlatform; kind: Kind; ref: string; url: string; sha256: string; args: string[] };
type Asg = { package_id: string; action: "install" | "remove"; group_id: string | null; user_id?: string | null };

/** What a device should have: per package, install or remove (install wins when both apply). */
function desiredFor(pkgs: Pkg[], asgs: Asg[], device: { platform: DevicePlatform; primary_user_id?: string | null }, groups: Set<string>) {
  const out = new Map<string, "install" | "remove">();
  for (const a of asgs) {
    const p = pkgs.find((x) => x.id === a.package_id);
    if (!p || p.platform !== device.platform) continue;
    if (a.user_id && a.user_id !== device.primary_user_id) continue;
    if (a.group_id && !groups.has(a.group_id)) continue;
    if (out.get(p.id) !== "install") out.set(p.id, a.action);
  }
  return out;
}

export type PolicySoftware = { id: string; name: string; action: "install" | "remove"; kind: Kind; ref: string; url?: string; sha256?: string; args?: string[] };

/** The apps in a device's signed policy. */
export async function softwareFor(tx: Tx, device: { platform: DevicePlatform; primary_user_id: string | null }): Promise<PolicySoftware[]> {
  const asgs = await tx.selectFrom("software_assignments").select(["package_id", "action", "group_id", "user_id"]).execute();
  if (!asgs.length) return [];
  const pkgs = (await tx.selectFrom("software_packages").select(["id", "name", "platform", "kind", "ref", "url", "sha256", "args"]).where("platform", "=", device.platform).orderBy("name").execute()) as Pkg[];
  const groups = device.primary_user_id ? new Set((await tx.selectFrom("group_members").select("group_id").where("user_id", "=", device.primary_user_id).execute()).map((g) => g.group_id)) : new Set<string>();
  const want = desiredFor(pkgs, asgs, device, groups);
  return pkgs
    .filter((p) => want.has(p.id))
    .map((p) => ({ id: p.id, name: p.name, action: want.get(p.id)!, kind: p.kind, ref: p.ref, ...(p.url ? { url: p.url, sha256: p.sha256 } : {}), ...(p.args.length ? { args: p.args } : {}) }));
}

export const SoftwareReport = z
  .array(z.object({ id: z.string().max(64), status: z.enum(["installed", "absent", "failed", "unsupported"]), detail: z.string().max(500).default(""), at: z.string().max(40).optional() }))
  .max(500);

/** Stores what the agent reports for its apps, and audits installs, removals and new failures. */
export async function recordSoftware(tx: Tx, device: { id: string; org_id: string; hostname: string }, rep: z.infer<typeof SoftwareReport>, meta: RequestMeta) {
  const known = new Map((await tx.selectFrom("software_packages").select(["id", "name"]).execute()).map((p) => [p.id, p.name]));
  const rows = rep.filter((r) => known.has(r.id));
  const before = new Map((await tx.selectFrom("device_software").select(["package_id", "status", "detail"]).where("device_id", "=", device.id).execute()).map((r) => [r.package_id, r]));
  // What the device no longer reports is no longer assigned to it.
  const gone = [...before.keys()].filter((id) => !rows.some((r) => r.id === id));
  if (gone.length) await tx.deleteFrom("device_software").where("device_id", "=", device.id).where("package_id", "in", gone).execute();
  for (const r of rows) {
    const prev = before.get(r.id);
    if (prev?.status === r.status && prev.detail === r.detail) continue;
    await tx
      .insertInto("device_software")
      .values({ org_id: device.org_id, device_id: device.id, package_id: r.id, status: r.status, detail: r.detail, updated_at: new Date() })
      .onConflict((oc) => oc.columns(["device_id", "package_id"]).doUpdateSet({ status: r.status, detail: r.detail, updated_at: new Date() }))
      .execute();
    const did = r.detail === "installed by Nexus" ? "installed" : r.detail === "removed by Nexus" ? "removed" : r.status === "failed" && prev?.status !== "failed" ? "failed" : null;
    if (!did) continue;
    await audit(tx, device.org_id, { meta }, {
      type: `device.software_${did}`,
      outcome: did === "failed" ? "failure" : "success",
      actor: { type: "system", id: null, display: "Nexus agent" },
      target: { type: "device", id: device.id, display: device.hostname },
      details: { package_id: r.id, package: known.get(r.id), status: r.status, detail: r.detail },
    });
  }
}

async function loadPackages(tx: Tx, ids?: string[]) {
  let q = tx.selectFrom("software_packages").selectAll().orderBy(sql`lower(name)`);
  if (ids) q = q.where("id", "in", ids);
  const pkgs = await q.execute();
  if (!pkgs.length) return [];
  const asgs = await tx
    .selectFrom("software_assignments")
    .leftJoin("groups", "groups.id", "software_assignments.group_id")
    .leftJoin("users", "users.id", "software_assignments.user_id")
    .select(["software_assignments.id", "software_assignments.package_id", "software_assignments.action", "software_assignments.group_id", "software_assignments.user_id", "software_assignments.created_at", "groups.name as group_name", "users.email as user_email"])
    .orderBy("software_assignments.created_at")
    .execute();
  const states = await tx.selectFrom("device_software").select(["device_id", "package_id", "status"]).execute();
  const devices = await tx.selectFrom("devices").select(["id", "platform", "primary_user_id"]).where("status", "=", "active").execute();
  const members = await tx.selectFrom("group_members").select(["group_id", "user_id"]).where("group_id", "in", [...new Set(asgs.map((a) => a.group_id).filter((g): g is string => !!g)), "00000000-0000-0000-0000-000000000000"]).execute();
  const groupsOf = new Map<string, Set<string>>();
  for (const m of members) groupsOf.set(m.user_id, (groupsOf.get(m.user_id) ?? new Set()).add(m.group_id));
  const targeted = new Map<string, Set<string>>(); // package → devices it applies to
  for (const d of devices) {
    for (const id of desiredFor(pkgs as Pkg[], asgs, d, (d.primary_user_id && groupsOf.get(d.primary_user_id)) || new Set()).keys()) targeted.set(id, (targeted.get(id) ?? new Set()).add(d.id));
  }
  return pkgs.map((p) => {
    const on = targeted.get(p.id) ?? new Set<string>();
    const mine = states.filter((s) => s.package_id === p.id && on.has(s.device_id));
    const n = (st: string) => mine.filter((s) => s.status === st).length;
    return {
      id: p.id,
      name: p.name,
      description: p.description,
      platform: p.platform,
      kind: p.kind,
      ref: p.ref,
      url: p.url,
      sha256: p.sha256,
      args: p.args,
      created_at: iso(p.created_at),
      updated_at: iso(p.updated_at),
      assignments: asgs
        .filter((a) => a.package_id === p.id)
        .map((a) => ({ id: a.id, action: a.action, group_id: a.group_id, group_name: a.group_name ?? null, user_id: a.user_id, user_email: a.user_email ?? null, created_at: iso(a.created_at) })),
      counts: { targeted: on.size, installed: n("installed"), absent: n("absent"), failed: n("failed"), unsupported: n("unsupported"), pending: on.size - mine.length },
    };
  });
}

export function registerSoftwareDeployRoutes(app: App) {
  app.openapi(
    createRoute({ method: "get", path: "/v1/software-packages", tags: ["Devices"], summary: "The app catalog, with assignments and where each app stands", security: bearer, responses: { 200: json(z.object({ data: z.array(PackageOut) })), ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "devices:read");
      return c.json({ data: await c.get("deps").db.tenant(p.orgId, (tx) => loadPackages(tx)) }, 200);
    },
  );

  app.openapi(
    createRoute({ method: "post", path: "/v1/software-packages", tags: ["Devices"], summary: "Add an app to the catalog", security: bearer, request: body(PackageIn), responses: { 201: json(PackageOut), ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "devices:software");
      const input = c.req.valid("json");
      validate(input);
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
        const id = newId();
        await tx.insertInto("software_packages").values({ id, org_id: p.orgId, ...input, platform: PLATFORM_OF[input.kind], args: JSON.stringify(input.args), created_by: p.userId }).execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "device.software_package_saved", target: { type: "software_package", id, display: input.name }, details: { kind: input.kind, ref: input.ref, url: input.url, sha256: input.sha256, args: input.args } });
        return (await loadPackages(tx, [id]))[0]!;
      });
      return c.json(out, 201);
    },
  );

  app.openapi(
    createRoute({ method: "put", path: "/v1/software-packages/{id}", tags: ["Devices"], summary: "Change an app (devices pick up the change at their next check-in)", security: bearer, request: { params: z.object({ id: Id }), ...body(PackageIn) }, responses: { 200: json(PackageOut), ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "devices:software");
      const { id } = c.req.valid("param");
      const input = c.req.valid("json");
      validate(input);
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
        const cur = await tx.selectFrom("software_packages").select("kind").where("id", "=", id).executeTakeFirst();
        if (!cur) throw notFound("App");
        if (PLATFORM_OF[cur.kind] !== PLATFORM_OF[input.kind]) throw badRequest("platform_change", "An app can't move to another platform; add a new one");
        await tx.updateTable("software_packages").set({ ...input, args: JSON.stringify(input.args), updated_at: new Date() }).where("id", "=", id).execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "device.software_package_saved", target: { type: "software_package", id, display: input.name }, details: { kind: input.kind, ref: input.ref, url: input.url, sha256: input.sha256, args: input.args } });
        return (await loadPackages(tx, [id]))[0]!;
      });
      return c.json(out, 200);
    },
  );

  app.openapi(
    createRoute({ method: "delete", path: "/v1/software-packages/{id}", tags: ["Devices"], summary: "Remove an app from the catalog (it stays installed where it is)", security: bearer, request: { params: z.object({ id: Id }) }, responses: { 204: { description: "Removed" }, ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "devices:software");
      const { id } = c.req.valid("param");
      await c.get("deps").db.tenant(p.orgId, async (tx) => {
        requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
        const r = await tx.deleteFrom("software_packages").where("id", "=", id).returning("name").executeTakeFirst();
        if (!r) throw notFound("App");
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "device.software_package_deleted", target: { type: "software_package", id, display: r.name } });
      });
      return c.body(null, 204);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/software-packages/{id}/assignments",
      tags: ["Devices"],
      summary: "Install or remove an app on every device on its platform, or on a group's devices",
      description: "A group's devices are those whose primary user is in the group. When install and remove both apply to a device, install wins.",
      security: bearer,
      request: { params: z.object({ id: Id }), ...body(z.object({ action: z.enum(["install", "remove"]), group_id: Id.nullable().default(null).openapi({ description: "null: every device on the app's platform" }) })) },
      responses: { 201: json(PackageOut), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "devices:software");
      const { id } = c.req.valid("param");
      const input = c.req.valid("json");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
        const pkg = await tx.selectFrom("software_packages").select(["name", "kind"]).where("id", "=", id).executeTakeFirst();
        if (!pkg) throw notFound("App");
        if (input.action === "remove" && pkg.kind === "pkg") throw badRequest("cannot_remove", "macOS packages have no uninstaller; remove the app with a script");
        const group = input.group_id ? await tx.selectFrom("groups").select("name").where("id", "=", input.group_id).executeTakeFirst() : null;
        if (input.group_id && !group) throw notFound("Group");
        const aid = newId();
        try {
          await tx.insertInto("software_assignments").values({ id: aid, org_id: p.orgId, package_id: id, action: input.action, group_id: input.group_id, created_by: p.userId }).execute();
        } catch (e) {
          if (isUniqueViolation(e)) throw conflict("already_assigned", group ? `${pkg.name} is already assigned to ${group.name}` : `${pkg.name} is already assigned to every device`);
          throw e;
        }
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "device.software_assigned", target: { type: "software_package", id, display: pkg.name }, details: { assignment_id: aid, action: input.action, group_id: input.group_id, group: group?.name ?? "every device" } });
        return (await loadPackages(tx, [id]))[0]!;
      });
      return c.json(out, 201);
    },
  );

  app.openapi(
    createRoute({ method: "delete", path: "/v1/software-packages/{id}/assignments/{assignment_id}", tags: ["Devices"], summary: "Stop an assignment (installed copies stay)", security: bearer, request: { params: z.object({ id: Id, assignment_id: Id }) }, responses: { 204: { description: "Removed" }, ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "devices:software");
      const { id, assignment_id } = c.req.valid("param");
      await c.get("deps").db.tenant(p.orgId, async (tx) => {
        requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
        const r = await tx.deleteFrom("software_assignments").where("id", "=", assignment_id).where("package_id", "=", id).returning(["action", "group_id"]).executeTakeFirst();
        if (!r) throw notFound("Assignment");
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "device.software_unassigned", target: { type: "software_package", id }, details: { assignment_id, action: r.action, group_id: r.group_id } });
      });
      return c.body(null, 204);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/software-packages/{id}/devices",
      tags: ["Devices"],
      summary: "Where an app stands on each device it's assigned to",
      security: bearer,
      request: { params: z.object({ id: Id }) },
      responses: { 200: json(z.object({ data: z.array(z.object({ device_id: Id, hostname: z.string(), action: z.enum(["install", "remove"]), status: z.string(), detail: z.string(), updated_at: z.string().nullable() })) })), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "devices:read");
      const { id } = c.req.valid("param");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const pkg = (await tx.selectFrom("software_packages").select(["id", "name", "platform", "kind", "ref", "url", "sha256", "args"]).where("id", "=", id).executeTakeFirst()) as Pkg | undefined;
        if (!pkg) throw notFound("App");
        const asgs = await tx.selectFrom("software_assignments").select(["package_id", "action", "group_id", "user_id"]).where("package_id", "=", id).execute();
        const devices = await tx.selectFrom("devices").select(["id", "hostname", "platform", "primary_user_id"]).where("status", "=", "active").where("platform", "=", pkg.platform).orderBy("hostname").execute();
        const members = await tx.selectFrom("group_members").select(["group_id", "user_id"]).where("group_id", "in", [...asgs.map((a) => a.group_id).filter((g): g is string => !!g), "00000000-0000-0000-0000-000000000000"]).execute();
        const states = new Map((await tx.selectFrom("device_software").selectAll().where("package_id", "=", id).execute()).map((s) => [s.device_id, s]));
        const data = [];
        for (const d of devices) {
          const groups = new Set(members.filter((m) => m.user_id === d.primary_user_id).map((m) => m.group_id));
          const action = desiredFor([pkg], asgs, d, groups).get(id);
          if (!action) continue;
          const s = states.get(d.id);
          data.push({ device_id: d.id, hostname: d.hostname, action, status: s?.status ?? "pending", detail: s?.detail ?? "", updated_at: isoOrNull(s?.updated_at ?? null) });
        }
        return { data };
      });
      return c.json(out, 200);
    },
  );
}
