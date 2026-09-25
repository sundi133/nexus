import { z } from "@hono/zod-openapi";
import { PERMISSIONS, ROLES } from "./rbac.js";

// ---- Shared primitives -------------------------------------------------------

export const Id = z.uuid().openapi({ example: "01926f4e-7b3a-7c1e-9d2f-3a4b5c6d7e8f" });
export const Timestamp = z.iso.datetime().openapi({ example: "2026-10-05T12:00:00.000Z" });
export const Role = z.enum(ROLES).openapi("Role");
export const Permission = z.enum(PERMISSIONS).openapi("Permission");

export const Problem = z
  .object({
    type: z.string(),
    status: z.number().int(),
    code: z.string().openapi({ example: "not_found" }),
    title: z.string(),
  })
  .passthrough()
  .openapi("Problem");

export const Cursor = z.object({
  cursor: z.string().optional().openapi({ description: "Opaque cursor from `next_cursor`" }),
  limit: z.coerce.number().int().min(1).max(200).default(50),
});

export const page = <T extends z.ZodTypeAny>(item: T, name: string) =>
  z.object({ data: z.array(item), next_cursor: z.string().nullable() }).openapi(name);

export const problemResponses = {
  400: { description: "Invalid request", content: { "application/problem+json": { schema: Problem } } },
  401: { description: "Not authenticated", content: { "application/problem+json": { schema: Problem } } },
  403: { description: "Forbidden", content: { "application/problem+json": { schema: Problem } } },
  404: { description: "Not found", content: { "application/problem+json": { schema: Problem } } },
  409: { description: "Conflict", content: { "application/problem+json": { schema: Problem } } },
} as const;

export const json = <T extends z.ZodTypeAny>(schema: T, description = "OK") => ({
  description,
  content: { "application/json": { schema } },
});

export const body = <T extends z.ZodTypeAny>(schema: T) => ({
  body: { content: { "application/json": { schema } }, required: true },
});

export const bearer = [{ bearer: [] }];

// ---- Resources ------------------------------------------------------------------

export const UserStatus = z.enum(["staged", "active", "suspended", "deprovisioned"]).openapi("UserStatus");

export const User = z
  .object({
    id: Id,
    email: z.email(),
    given_name: z.string(),
    family_name: z.string(),
    display_name: z.string(),
    title: z.string(),
    department: z.string(),
    status: UserStatus,
    roles: z.array(Role),
    mfa_enrolled: z.boolean(),
    managed_by: z.string().nullable().openapi({ description: "The directory this person is synced from (its values win on the next sync), or null" }),
    break_glass: z.boolean().openapi({ description: "An emergency owner account: exempt from lockout-prone policies, alerts on every use" }),
    manager_id: Id.nullable().openapi({ description: "Their manager (approves access requests with a manager stage)" }),
    last_login_at: Timestamp.nullable(),
    created_at: Timestamp,
    updated_at: Timestamp,
  })
  .openapi("User");

export const Organization = z
  .object({ id: Id, name: z.string(), slug: z.string(), created_at: Timestamp })
  .openapi("Organization");

export const Session = z
  .object({
    id: Id,
    state: z.enum(["pending_mfa", "enroll_mfa", "active"]),
    client: z.string(),
    ip: z.string(),
    user_agent: z.string(),
    current: z.boolean(),
    mfa_at: Timestamp.nullable(),
    created_at: Timestamp,
    last_seen_at: Timestamp,
    expires_at: Timestamp,
  })
  .openapi("Session");

export const Factor = z
  .object({
    id: Id,
    type: z.enum(["totp", "push", "webauthn"]),
    name: z.string(),
    verified: z.boolean(),
    last_used_at: Timestamp.nullable(),
    created_at: Timestamp,
  })
  .openapi("Factor");

export const Group = z
  .object({
    id: Id,
    name: z.string(),
    description: z.string(),
    member_count: z.number().int(),
    created_at: Timestamp,
    updated_at: Timestamp,
  })
  .openapi("Group");

export const AuditEvent = z
  .object({
    id: Id,
    ts: Timestamp,
    type: z.string().openapi({ example: "user.suspended" }),
    outcome: z.enum(["success", "failure", "denied"]),
    actor: z.object({ type: z.string(), id: Id.nullable(), display: z.string() }),
    target: z.object({ type: z.string(), id: Id.nullable(), display: z.string() }),
    session_id: Id.nullable(),
    ip: z.string(),
    user_agent: z.string(),
    details: z.record(z.string(), z.unknown()),
  })
  .openapi("AuditEvent");

export const NotificationAction = z
  .object({ id: z.string(), label: z.string(), style: z.enum(["primary", "danger"]).optional() })
  .openapi("NotificationAction");

export const Notification = z
  .object({
    id: Id,
    category: z.string().openapi({ example: "security.alert" }),
    severity: z.enum(["info", "warning", "critical"]),
    title: z.string(),
    body: z.string(),
    entity: z.object({ type: z.string(), id: Id }).nullable(),
    link: z.string(),
    actions: z.array(NotificationAction),
    read: z.boolean(),
    created_at: Timestamp,
  })
  .openapi("Notification");

// ---- Serializers (DB row → API shape) -----------------------------------------

const iso = (d: Date) => d.toISOString();
const isoOrNull = (d: Date | null) => (d ? d.toISOString() : null);

export function displayName(u: { given_name: string; family_name: string; email: string }) {
  return `${u.given_name} ${u.family_name}`.trim() || u.email;
}

export type UserRow = {
  id: string;
  email: string;
  given_name: string;
  family_name: string;
  title: string;
  department: string;
  status: z.infer<typeof UserStatus>;
  last_login_at: Date | null;
  created_at: Date;
  updated_at: Date;
  roles: string[] | null;
  mfa_enrolled: boolean | 0 | 1 | null; // Kysely SqlBool
  managed_by?: string | null; // directory provider key
  break_glass?: boolean;
  manager_id?: string | null;
};

export const toUser = (u: UserRow): z.infer<typeof User> => ({
  id: u.id,
  email: u.email,
  given_name: u.given_name,
  family_name: u.family_name,
  display_name: displayName(u),
  title: u.title,
  department: u.department,
  status: u.status,
  roles: (u.roles ?? []) as z.infer<typeof Role>[],
  mfa_enrolled: Boolean(u.mfa_enrolled),
  managed_by: u.managed_by === "google" ? "Google Workspace" : u.managed_by === "entra" ? "Microsoft Entra ID" : u.managed_by === "scim" ? "SCIM" : null,
  break_glass: u.break_glass ?? false,
  manager_id: u.manager_id ?? null,
  last_login_at: isoOrNull(u.last_login_at),
  created_at: iso(u.created_at),
  updated_at: iso(u.updated_at),
});

export { iso, isoOrNull };

type NoDefault<T> = T extends z.ZodDefault<infer I> ? I : T;

/**
 * A PATCH body: every field optional, and no defaults. (Zod 4's `.partial()`
 * keeps `.default()`s, so a PATCH naming one field would reset all the others.)
 */
export function patchOf<S extends z.ZodRawShape>(o: z.ZodObject<S>): z.ZodObject<{ [K in keyof S]: z.ZodOptional<NoDefault<S[K]>> }> {
  const shape: Record<string, z.ZodType> = {};
  for (const [k, v] of Object.entries(o.shape)) shape[k] = (v instanceof z.ZodDefault ? (v.unwrap() as z.ZodType) : (v as z.ZodType)).optional();
  return z.object(shape) as never;
}
