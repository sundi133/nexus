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
] as const;
export type Permission = (typeof PERMISSIONS)[number];

const READ: Permission[] = ["users:read", "groups:read", "audit:read"];

const GRANTS: Record<Role, readonly Permission[]> = {
  owner: PERMISSIONS,
  admin: PERMISSIONS.filter((p) => p !== "admins:manage"),
  helpdesk: [...READ, "users:write", "users:lifecycle"],
  security_analyst: [...READ, "users:lifecycle"],
  readonly: READ,
};

export function permissionsFor(roles: readonly Role[]): Permission[] {
  const set = new Set<Permission>();
  for (const r of roles) for (const p of GRANTS[r] ?? []) set.add(p);
  return PERMISSIONS.filter((p) => set.has(p));
}

export function can(roles: readonly Role[], perm: Permission): boolean {
  return roles.some((r) => GRANTS[r]?.includes(perm));
}

export const isAdmin = (roles: readonly Role[]) => roles.length > 0;
