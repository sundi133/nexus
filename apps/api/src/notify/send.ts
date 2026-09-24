import type { NotificationAction } from "../platform/db-types.js";
import type { Tx } from "../platform/db.js";
import { newId } from "../platform/ids.js";
import type { Role } from "../rbac.js";

export type NotificationInput = {
  category: string; // e.g. "security.alert", "auth.mfa_challenge"
  severity?: "info" | "warning" | "critical";
  title: string;
  body?: string;
  entity?: { type: string; id: string };
  link?: string;
  actions?: NotificationAction[];
};

/**
 * Writes inbox rows (the source of truth, ARCHITECTURE §11). A DB trigger
 * announces each insert; the realtime hub fans it out to SSE clients, and
 * channel delivery (push, email, Slack) hangs off the same rows.
 */
export async function notifyUsers(tx: Tx, orgId: string, userIds: string[], n: NotificationInput) {
  if (userIds.length === 0) return;
  await tx
    .insertInto("notifications")
    .values(
      userIds.map((uid) => ({
        id: newId(),
        org_id: orgId,
        recipient_user_id: uid,
        category: n.category,
        severity: n.severity ?? "info",
        title: n.title,
        body: n.body ?? "",
        entity_type: n.entity?.type ?? "",
        entity_id: n.entity?.id ?? null,
        link: n.link ?? "",
        actions: JSON.stringify(n.actions ?? []),
      })),
    )
    .execute();
}

/** Recipients by admin role, e.g. security alerts go to owners + admins + security analysts. */
export async function notifyRoles(tx: Tx, orgId: string, roles: Role[], n: NotificationInput) {
  const rows = await tx
    .selectFrom("user_roles")
    .innerJoin("users", "users.id", "user_roles.user_id")
    .where("user_roles.role", "in", roles)
    .where("users.status", "=", "active")
    .select("user_roles.user_id")
    .distinct()
    .execute();
  await notifyUsers(
    tx,
    orgId,
    rows.map((r) => r.user_id),
    n,
  );
}
