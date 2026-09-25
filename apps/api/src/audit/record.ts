import type { Principal, RequestMeta } from "../context.js";
import type { Tx } from "../platform/db.js";
import { newId } from "../platform/ids.js";

export type AuditInput = {
  type: string; // e.g. "user.created", "auth.login"
  outcome?: "success" | "failure" | "denied";
  target?: { type: string; id: string | null; display?: string };
  details?: Record<string, unknown>;
  /** Override the actor (e.g. during login, before a principal exists). */
  actor?: { type: "user" | "system" | "api_key"; id: string | null; display?: string };
  sessionId?: string | null;
};

/**
 * Records an audit event inside the caller's transaction, so the event exists
 * if and only if the change it describes was committed.
 */
export async function audit(
  tx: Tx,
  orgId: string,
  who: { principal?: Principal; display?: string; meta: RequestMeta },
  e: AuditInput,
) {
  const key = who.principal?.apiKey;
  const actor = e.actor ?? {
    type: key ? ("api_key" as const) : who.principal ? ("user" as const) : ("system" as const),
    id: key ? key.id : (who.principal?.userId ?? null),
    display: who.display ?? who.principal?.email ?? "",
  };
  await tx
    .insertInto("audit_events")
    .values({
      id: newId(),
      org_id: orgId,
      type: e.type,
      outcome: e.outcome ?? "success",
      actor_type: actor.type,
      actor_id: actor.id,
      actor_display: actor.display ?? "",
      target_type: e.target?.type ?? "",
      target_id: e.target?.id ?? null,
      target_display: e.target?.display ?? "",
      session_id: e.sessionId ?? (who.principal?.sessionId || null),
      ip: who.meta.ip,
      user_agent: who.meta.userAgent,
      details: JSON.stringify(e.details ?? {}),
    })
    .execute();
}
