import type { Principal, RequestMeta } from "../context.js";
import { audit } from "../audit/record.js";
import type { Tx } from "../platform/db.js";
import { notifyRoles, notifyUsers } from "../notify/send.js";

/** Agents not seen (no token, no gateway call) for this long are flagged as stale (AGT-07). */
export const STALE_DAYS = 30;

type Who = { principal?: Principal; meta: RequestMeta; actor?: { type: "user" | "system" | "api_key" | "agent"; id: string | null; display?: string } };

/**
 * The kill switch (AGT-06): suspends the agent and invalidates every token it
 * holds. The MCP gateway checks both on each call, so it takes effect at once.
 */
export async function suspendAgents(tx: Tx, orgId: string, ids: string[], reason: string, who: Who) {
  if (!ids.length) return [];
  const now = new Date();
  const rows = await tx
    .updateTable("ai_agents")
    .set({ status: "suspended", status_reason: reason, tokens_valid_after: now, updated_at: now })
    .where("id", "in", ids)
    .returning(["id", "name", "owner_user_id"])
    .execute();
  for (const a of rows) {
    await audit(tx, orgId, who, { type: "agent.suspended", ...(who.actor ? { actor: who.actor } : {}), target: { type: "agent", id: a.id, display: a.name }, details: { reason } });
    if (a.owner_user_id && a.owner_user_id !== who.principal?.userId) {
      await notifyUsers(tx, orgId, [a.owner_user_id], {
        category: "security.alert",
        severity: "warning",
        title: `Your agent ${a.name} was suspended`,
        body: reason || "Its tokens no longer work. Ask an admin to reactivate it.",
        entity: { type: "agent", id: a.id },
        link: `/agents/${a.id}`,
      });
    }
  }
  return rows;
}

/** When someone leaves or is contained, the agents they own stop too, until reassigned (AGT-07). */
export async function suspendOwnedAgents(tx: Tx, orgId: string, userId: string, reason: string, who: Who) {
  const owned = await tx.selectFrom("ai_agents").select("id").where("owner_user_id", "=", userId).where("status", "=", "active").execute();
  const rows = await suspendAgents(tx, orgId, owned.map((a) => a.id), reason, who);
  if (rows.length) {
    await notifyRoles(tx, orgId, ["owner", "admin"], {
      category: "security.alert",
      severity: "warning",
      title: `${rows.length} agent${rows.length === 1 ? "" : "s"} suspended: ${reason}`,
      body: `${rows.map((r) => r.name).join(", ")}. Give ${rows.length === 1 ? "it" : "them"} a new owner, then reactivate.`,
      link: "/agents?status=suspended",
    });
  }
  return rows.map((r) => r.name);
}
