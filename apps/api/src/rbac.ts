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
  "directory:sync", // connect Google Workspace / Entra ID (can create and suspend many users)
  "api_keys:manage", // create and revoke API keys
  "integrations:manage", // webhooks and SIEM streaming (they export the audit log)
] as const;
export type Permission = (typeof PERMISSIONS)[number];

const READ: Permission[] = ["users:read", "groups:read", "audit:read", "apps:read", "devices:read"];

const GRANTS: Record<Role, readonly Permission[]> = {
  owner: PERMISSIONS,
  admin: PERMISSIONS.filter((p) => p !== "admins:manage"),
  helpdesk: [...READ, "users:write", "users:lifecycle", "apps:assign", "devices:write"],
  security_analyst: [...READ, "users:lifecycle"],
  readonly: READ,
};

/** What an API key may be granted: everything except managing admins and keys (a key can't entrench itself). */
export const GRANTABLE_TO_KEYS: readonly Permission[] = PERMISSIONS.filter((p) => p !== "admins:manage" && p !== "api_keys:manage" && p !== "integrations:manage");

export function permissionsFor(roles: readonly Role[]): Permission[] {
  const set = new Set<Permission>();
  for (const r of roles) for (const p of GRANTS[r] ?? []) set.add(p);
  return PERMISSIONS.filter((p) => set.has(p));
}

export function can(roles: readonly Role[], perm: Permission): boolean {
  return roles.some((r) => GRANTS[r]?.includes(perm));
}

export const isAdmin = (roles: readonly Role[]) => roles.length > 0;
