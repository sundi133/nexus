/**
 * Directory sync planning (DIR-08). Pure: remote directory + local state →
 * exactly what would change, so the same plan backs the preview, the
 * mass-deprovisioning guard and the apply step.
 *
 * Rules:
 *  - Remote users are matched by link, else adopted by email, else created (staged).
 *  - A linked user who disappears from scope, or is suspended remotely, is
 *    suspended here (when deprovision = "suspend"). Sync reactivates only users
 *    it suspended itself — never an admin's suspension or a contained account.
 *  - Deprovisioned local users are left alone.
 *  - Synced groups mirror remote membership exactly; local-only groups are untouched.
 */

export type RemoteUser = { external_id: string; email: string; given_name: string; family_name: string; title: string; department: string; active: boolean };
export type RemoteGroup = { external_id: string; name: string; description: string; member_ids: string[] };
export type Remote = { users: RemoteUser[]; groups: RemoteGroup[] };

export type LocalUser = { id: string; email: string; given_name: string; family_name: string; title: string; department: string; status: "staged" | "active" | "suspended" | "deprovisioned" };
export type LocalGroup = { id: string; name: string; description: string; member_ids: string[] };
export type Link = { kind: "user" | "group"; external_id: string; local_id: string; suspended_by_sync: boolean };
export type Local = { users: LocalUser[]; groups: LocalGroup[]; links: Link[] };

export type Settings = { provider: "google" | "entra"; deprovision: "suspend" | "none"; sync_groups: boolean; group_filter: string[] };

const FIELDS = ["email", "given_name", "family_name", "title", "department"] as const;
type Changes = Partial<Record<(typeof FIELDS)[number], { from: string; to: string }>>;

export type Plan = {
  create_users: RemoteUser[];
  link_users: { local_id: string; email: string; external_id: string }[];
  update_users: { local_id: string; email: string; changes: Changes }[];
  suspend_users: { local_id: string; email: string; reason: string }[];
  reactivate_users: { local_id: string; email: string }[];
  create_groups: RemoteGroup[];
  link_groups: { local_id: string; name: string; external_id: string }[];
  update_groups: { local_id: string; name: string; changes: { name?: { from: string; to: string }; description?: { from: string; to: string } } }[];
  /** Keyed by remote group ID; users by remote ID (adds) and local ID (removes). */
  membership: { group_external_id: string; group_name: string; add: string[]; remove: string[] }[];
  skipped: { email: string; reason: string }[];
  guard: { tripped: boolean; suspensions: number; threshold: number };
};

export const PROVIDER_NAME = { google: "Google Workspace", entra: "Microsoft Entra ID" } as const;

const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const norm = (e: string) => e.trim().toLowerCase();

/** Suspending more than this at once needs an admin's approval: a misconfigured scope shouldn't lock out the company. */
export const guardThreshold = (activeLinked: number) => Math.max(5, Math.ceil(activeLinked * 0.1));

export function plan(remote: Remote, local: Local, s: Settings): Plan {
  const src = PROVIDER_NAME[s.provider];
  const out: Plan = {
    create_users: [], link_users: [], update_users: [], suspend_users: [], reactivate_users: [],
    create_groups: [], link_groups: [], update_groups: [], membership: [], skipped: [],
    guard: { tripped: false, suspensions: 0, threshold: 0 },
  };

  // --- scope -----------------------------------------------------------------------
  const filter = new Set(s.group_filter);
  const scopedGroups = filter.size ? remote.groups.filter((g) => filter.has(g.external_id)) : remote.groups;
  const inScopeIds = filter.size ? new Set(scopedGroups.flatMap((g) => g.member_ids)) : null;

  // One remote account per email; skip unusable ones loudly.
  const byEmail = new Map<string, RemoteUser>();
  const remoteUsers: RemoteUser[] = [];
  const inScope = new Set<string>(); // every in-scope remote account, usable or not
  for (const u of remote.users) {
    if (inScopeIds && !inScopeIds.has(u.external_id)) continue;
    inScope.add(u.external_id);
    const email = norm(u.email);
    if (!EMAIL.test(email)) {
      out.skipped.push({ email: u.email || `(${u.external_id})`, reason: "No valid email address" });
      continue;
    }
    if (byEmail.has(email)) {
      out.skipped.push({ email, reason: `More than one ${src} account uses this email` });
      continue;
    }
    const clean = { ...u, email };
    byEmail.set(email, clean);
    remoteUsers.push(clean);
  }

  // --- users -----------------------------------------------------------------------
  const localById = new Map(local.users.map((u) => [u.id, u]));
  const localByEmail = new Map(local.users.map((u) => [norm(u.email), u]));
  const userLinks = new Map(local.links.filter((l) => l.kind === "user").map((l) => [l.external_id, l]));
  const linkedLocalIds = new Set([...userLinks.values()].map((l) => l.local_id));
  const seenLocal = new Set<string>();

  for (const r of remoteUsers) {
    const link = userLinks.get(r.external_id);
    let lu = link ? localById.get(link.local_id) : undefined;
    if (!lu) {
      const byMail = localByEmail.get(r.email);
      if (byMail && !linkedLocalIds.has(byMail.id)) {
        lu = byMail;
        out.link_users.push({ local_id: lu.id, email: r.email, external_id: r.external_id });
      } else if (byMail) {
        out.skipped.push({ email: r.email, reason: "Already linked to another directory account" });
        continue;
      } else {
        if (r.active) out.create_users.push(r);
        continue; // suspended remotely and unknown here: nothing to do
      }
    }
    seenLocal.add(lu.id);
    if (lu.status === "deprovisioned") continue;

    const changes: Changes = {};
    for (const f of FIELDS) {
      const to = f === "email" ? r.email : r[f];
      const from = f === "email" ? norm(lu.email) : lu[f];
      if (to !== from && !(f !== "email" && to === "")) changes[f] = { from: lu[f], to };
    }
    if (Object.keys(changes).length) out.update_users.push({ local_id: lu.id, email: lu.email, changes });

    if (!r.active && lu.status !== "suspended" && s.deprovision === "suspend") {
      out.suspend_users.push({ local_id: lu.id, email: lu.email, reason: `Suspended in ${src}` });
    } else if (r.active && lu.status === "suspended" && link?.suspended_by_sync) {
      out.reactivate_users.push({ local_id: lu.id, email: lu.email });
    }
  }

  // Linked users that are gone from the (scoped) directory.
  for (const link of userLinks.values()) {
    const lu = localById.get(link.local_id);
    if (!lu || seenLocal.has(lu.id) || lu.status === "suspended" || lu.status === "deprovisioned") continue;
    if (s.deprovision !== "suspend") continue;
    if (inScope.has(link.external_id)) continue; // still there, just skipped this run (e.g. a duplicate email): don't punish it
    const stillThere = remote.users.some((u) => u.external_id === link.external_id);
    out.suspend_users.push({ local_id: lu.id, email: lu.email, reason: stillThere ? `No longer in the synced ${src} groups` : `Removed from ${src}` });
  }

  // --- groups ----------------------------------------------------------------------
  if (s.sync_groups) {
    const groupLinks = new Map(local.links.filter((l) => l.kind === "group").map((l) => [l.external_id, l]));
    const linkedGroupIds = new Set([...groupLinks.values()].map((l) => l.local_id));
    const localGroupById = new Map(local.groups.map((g) => [g.id, g]));
    const localGroupByName = new Map(local.groups.map((g) => [g.name.toLowerCase(), g]));
    // Remote user → local user, as it will be after this plan runs (null: will be created).
    const localFor = new Map<string, string | null>();
    for (const r of remoteUsers) {
      const link = userLinks.get(r.external_id);
      const lu = (link && localById.get(link.local_id)) || (!link ? localByEmail.get(r.email) : undefined);
      if (lu && !out.skipped.some((x) => x.email === r.email)) localFor.set(r.external_id, lu.id);
      else if (out.create_users.includes(r)) localFor.set(r.external_id, null);
    }

    for (const g of scopedGroups) {
      const link = groupLinks.get(g.external_id);
      let lg = link ? localGroupById.get(link.local_id) : undefined;
      if (!lg) {
        const byName = localGroupByName.get(g.name.toLowerCase());
        if (byName && !linkedGroupIds.has(byName.id)) {
          lg = byName;
          out.link_groups.push({ local_id: lg.id, name: g.name, external_id: g.external_id });
        } else if (byName) {
          out.skipped.push({ email: g.name, reason: "A group with this name is already synced from another directory group" });
          continue;
        } else {
          out.create_groups.push(g);
        }
      }
      if (lg) {
        const changes: Plan["update_groups"][number]["changes"] = {};
        if (lg.name !== g.name) changes.name = { from: lg.name, to: g.name };
        if (g.description && lg.description !== g.description) changes.description = { from: lg.description, to: g.description };
        if (Object.keys(changes).length) out.update_groups.push({ local_id: lg.id, name: lg.name, changes });
      }
      const want = new Set(g.member_ids.filter((id) => localFor.has(id)));
      const have = new Set(lg?.member_ids ?? []);
      const wantLocal = new Set([...want].map((id) => localFor.get(id)).filter((x): x is string => !!x));
      const add = [...want].filter((id) => {
        const l = localFor.get(id);
        return l === null || (l !== undefined && !have.has(l));
      });
      const remove = [...have].filter((id) => !wantLocal.has(id));
      if (add.length || remove.length) out.membership.push({ group_external_id: g.external_id, group_name: g.name, add, remove });
    }
  }

  const activeLinked = [...userLinks.values()].filter((l) => {
    const u = localById.get(l.local_id);
    return u && (u.status === "active" || u.status === "staged");
  }).length;
  out.guard = { suspensions: out.suspend_users.length, threshold: guardThreshold(activeLinked), tripped: false };
  out.guard.tripped = out.guard.suspensions > out.guard.threshold;
  return out;
}

export function summarize(p: Plan) {
  return {
    create_users: p.create_users.length,
    link_users: p.link_users.length,
    update_users: p.update_users.length,
    suspend_users: p.suspend_users.length,
    reactivate_users: p.reactivate_users.length,
    create_groups: p.create_groups.length,
    update_groups: p.update_groups.length + p.link_groups.length,
    membership_changes: p.membership.reduce((n, m) => n + m.add.length + m.remove.length, 0),
    skipped: p.skipped.length,
  };
}
