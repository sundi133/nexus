import { sql } from "kysely";
import type { Tx } from "../platform/db.js";

/**
 * Guards for people with admin access against sources that act on many people at once
 * (SCIM, directory sync, directory passwords). Whoever controls such a source (an admin, a
 * leaked SCIM token, a directory pointed elsewhere) must not be able to take over or remove
 * the organization's owners.
 */

/** Holds an admin role, a custom role or a scoped role, or is a break-glass account. */
export async function isPrivileged(tx: Tx, userId: string) {
  const r = await sql<{ p: boolean }>`
    SELECT EXISTS (SELECT 1 FROM user_roles WHERE user_id = ${userId})
        OR EXISTS (SELECT 1 FROM role_grants WHERE user_id = ${userId})
        OR EXISTS (SELECT 1 FROM users WHERE id = ${userId} AND break_glass) AS p`.execute(tx);
  return r.rows[0]!.p;
}

/** The only active owner: removing or suspending them would leave nobody in charge. */
export async function isLastOwner(tx: Tx, userId: string) {
  const owners = await tx
    .selectFrom("user_roles")
    .innerJoin("users", "users.id", "user_roles.user_id")
    .select("user_roles.user_id")
    .where("user_roles.role", "=", "owner")
    .where("users.status", "=", "active")
    .execute();
  return owners.length <= 1 && owners.some((o) => o.user_id === userId);
}

/** SQL: the user in this column has no admin access (for lists a scoped admin sees). */
export const notPrivileged = (column: string) =>
  sql<boolean>`NOT EXISTS (SELECT 1 FROM user_roles r WHERE r.user_id = ${sql.ref(column)})
    AND NOT EXISTS (SELECT 1 FROM role_grants g WHERE g.user_id = ${sql.ref(column)})
    AND NOT EXISTS (SELECT 1 FROM users bg WHERE bg.id = ${sql.ref(column)} AND bg.break_glass)`;
