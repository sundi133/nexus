/**
 * Admin RBAC v1: built-in roles mapped to a permission catalog (SPEC RBAC-01).
 * This is deliberately a thin interface so it can be backed by Cedar policies
 * (ARCHITECTURE §6) without touching callers.
 */
export const ROLES = ["owner", "admin", "helpdesk", "security_analyst", "readonly"] as const;
export type Role = (typeof ROLES)[number];

export const PERMISSIONS = [
  "org:manage",
  "admins:manage",
  "users:read",
  "users:write",
  "users:lifecycle", // suspend / activate / contain / revoke sessions
  "groups:read",
  "groups:write",
  "audit:read",
  "apps:read",
  "apps:write", // create/configure SSO apps and their secrets
  "apps:assign", // who can use which app
  "devices:read",
  "devices:write", // enroll/remove devices, assign users, device policies
  "policies:write", // conditional access policies
  "devices:updates", // agent software rollouts (fleet-wide changes, so not helpdesk)
  "devices:actions", // refresh, lock and restart a device
  "devices:wipe", // erase a device through its MDM (irreversible)
  "devices:query", // run live osquery queries on devices (reads anything osquery can see)
  "devices:enforce", // block apps and domains on devices (can stop people working)
  "directory:sync", // connect Google Workspace / Entra ID (can create and suspend many users)
  "api_keys:manage", // create and revoke API keys
  "integrations:manage", // webhooks and SIEM streaming (they export the audit log)
  "access:manage", // what can be requested and how it's approved; see and revoke all grants
  "agents:read",
  "agents:manage", // register AI agents and their credentials
  "agents:suspend", // the kill switch (incident response)
  "mcp:manage", // MCP servers, tool approval and tool permissions
  "alerts:read",
  "alerts:triage", // acknowledge, assign, snooze and resolve alerts
  "alerts:manage", // alert rules and on-call paging
] as const;
export type Permission = (typeof PERMISSIONS)[number];

const READ: Permission[] = ["users:read", "groups:read", "audit:read", "apps:read", "devices:read", "agents:read", "alerts:read"];

const GRANTS: Record<Role, readonly Permission[]> = {
  owner: PERMISSIONS,
  admin: PERMISSIONS.filter((p) => p !== "admins:manage"),
  helpdesk: [...READ, "users:write", "users:lifecycle", "apps:assign", "devices:write", "devices:actions", "alerts:triage"],
  security_analyst: [...READ, "users:lifecycle", "devices:actions", "devices:query", "agents:suspend", "alerts:triage"],
  readonly: READ,
};

/** What an API key may be granted: everything except managing admins and keys (a key can't entrench itself). */
export const GRANTABLE_TO_KEYS: readonly Permission[] = PERMISSIONS.filter((p) => p !== "admins:manage" && p !== "api_keys:manage" && p !== "integrations:manage" && p !== "devices:wipe" && p !== "devices:query" && p !== "devices:enforce");

export function permissionsFor(roles: readonly Role[]): Permission[] {
  const set = new Set<Permission>();
  for (const r of roles) for (const p of GRANTS[r] ?? []) set.add(p);
  return PERMISSIONS.filter((p) => set.has(p));
}

export function can(roles: readonly Role[], perm: Permission): boolean {
  return roles.some((r) => GRANTS[r]?.includes(perm));
}

export const isAdmin = (roles: readonly Role[]) => roles.length > 0;

// ---- RBAC v2: custom roles and scoped grants (SPEC RBAC-02, RBAC-03) ----------------------

/** Permissions a grant can limit to groups: they act on people (and their devices). */
export const SCOPABLE: readonly Permission[] = ["users:read", "users:write", "users:lifecycle", "devices:read", "devices:write", "devices:actions"];
/** Kept organization-wide in a scoped grant, so a scoped admin can find their way around. */
export const SCOPED_EXTRAS: readonly Permission[] = ["groups:read", "apps:read"];
/** Built-in roles that can be limited to groups. Owner and Admin manage the organization itself. */
export const SCOPABLE_ROLES = ["helpdesk", "security_analyst", "readonly"] as const;
/** Never in a custom role: managing admins stays with owners. */
export const NOT_IN_CUSTOM_ROLES: readonly Permission[] = ["admins:manage"];

export const rolePermissions = (role: Role) => [...(GRANTS[role] ?? [])];

/** Where a permission applies: everywhere, or within these groups. */
export type Grants = ReadonlyMap<Permission, "all" | ReadonlySet<string>>;

export function resolveGrants(roles: readonly Role[], extra: { permissions: readonly string[]; scope: readonly string[] }[]): Grants {
  const out = new Map<Permission, "all" | Set<string>>();
  const all = (p: Permission) => out.set(p, "all");
  for (const r of roles) for (const p of GRANTS[r] ?? []) all(p);
  for (const g of extra) {
    for (const raw of g.permissions) {
      const p = raw as Permission;
      if (!PERMISSIONS.includes(p)) continue;
      if (!g.scope.length || SCOPED_EXTRAS.includes(p)) {
        all(p);
        continue;
      }
      if (!SCOPABLE.includes(p)) continue; // e.g. audit:read in a scoped grant: dropped, it would see everyone
      const cur = out.get(p);
      if (cur === "all") continue;
      const set = cur ?? new Set<string>();
      for (const id of g.scope) set.add(id);
      out.set(p, set);
    }
  }
  return out;
}

/** Org-wide permissions, and the ones held only within some groups. */
export function describeGrants(g: Grants) {
  const all: Permission[] = [];
  const scoped: Partial<Record<Permission, string[]>> = {};
  for (const perm of PERMISSIONS) {
    const v = g.get(perm);
    if (v === "all") all.push(perm);
    else if (v) scoped[perm] = [...v];
  }
  return { all, scoped };
}
