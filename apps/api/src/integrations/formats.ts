/**
 * Audit events as they leave Nexus: our own JSON, or OCSF 1.3 for SIEMs
 * (Splunk, Datadog, Sentinel and Security Lake all ingest OCSF).
 */

export type AuditRow = {
  id: string;
  org_id: string;
  ts: Date;
  type: string;
  outcome: "success" | "failure" | "denied";
  actor_type: string;
  actor_id: string | null;
  actor_display: string;
  target_type: string;
  target_id: string | null;
  target_display: string;
  session_id: string | null;
  ip: string;
  user_agent: string;
  details: unknown;
};

export function nexusEvent(e: AuditRow) {
  return {
    id: e.id,
    type: e.type,
    occurred_at: e.ts.toISOString(),
    outcome: e.outcome,
    org_id: e.org_id,
    actor: { type: e.actor_type, id: e.actor_id, display: e.actor_display },
    target: e.target_type ? { type: e.target_type, id: e.target_id, display: e.target_display } : null,
    ip: e.ip || null,
    user_agent: e.user_agent || null,
    details: e.details ?? {},
  };
}

// OCSF classes we map to (category_uid, class_uid).
const CLASSES = {
  authentication: { category_uid: 3, category_name: "Identity & Access Management", class_uid: 3002, class_name: "Authentication" },
  account: { category_uid: 3, category_name: "Identity & Access Management", class_uid: 3001, class_name: "Account Change" },
  group: { category_uid: 3, category_name: "Identity & Access Management", class_uid: 3006, class_name: "Group Management" },
  entity: { category_uid: 3, category_name: "Identity & Access Management", class_uid: 3004, class_name: "Entity Management" },
  api: { category_uid: 6, category_name: "Application Activity", class_uid: 6003, class_name: "API Activity" },
} as const;

function classify(type: string): { cls: (typeof CLASSES)[keyof typeof CLASSES]; activity_id: number; activity_name: string } {
  const [domain, verb = ""] = type.split(".");
  if (domain === "auth" || type === "sso.login" || type === "device.trust_verified") {
    const logoff = verb.includes("logout");
    return { cls: CLASSES.authentication, activity_id: logoff ? 2 : 1, activity_name: logoff ? "Logoff" : "Logon" };
  }
  if (domain === "user") {
    // Account Change activities: 1 Create, 3 Password Change, 4 Password Reset, 5 Enable, 6 Disable, 7 Delete, 99 Other.
    const map: Record<string, [number, string]> = {
      created: [1, "Create"], imported: [1, "Create"], activated: [5, "Enable"], suspended: [6, "Disable"], contain: [6, "Disable"],
      offboarded: [7, "Delete"], password_changed: [3, "Password Change"], password_reset: [4, "Password Reset"],
    };
    const [id, name] = map[verb] ?? [99, "Other"];
    return { cls: CLASSES.account, activity_id: id, activity_name: name };
  }
  if (domain === "group") {
    const map: Record<string, [number, string]> = { members_added: [3, "Add User"], members_removed: [4, "Remove User"], deleted: [5, "Delete"], created: [6, "Create"] };
    const [id, name] = map[verb] ?? [99, "Other"];
    return { cls: CLASSES.group, activity_id: id, activity_name: name };
  }
  if (["app", "device", "agent", "access", "directory", "api_key", "org"].includes(domain!)) {
    const id = verb.startsWith("created") || verb.endsWith("_created") ? 1 : verb.includes("deleted") || verb.includes("revoked") ? 4 : 3;
    return { cls: CLASSES.entity, activity_id: id, activity_name: id === 1 ? "Create" : id === 4 ? "Delete" : "Update" };
  }
  return { cls: CLASSES.api, activity_id: 99, activity_name: "Other" };
}

export function ocsfEvent(e: AuditRow) {
  const { cls, activity_id, activity_name } = classify(e.type);
  const ok = e.outcome === "success";
  return {
    ...cls,
    activity_id,
    activity_name,
    type_uid: cls.class_uid * 100 + activity_id,
    time: e.ts.getTime(),
    severity_id: ok ? 1 : e.outcome === "denied" ? 3 : 2,
    status_id: ok ? 1 : 2,
    status: ok ? "Success" : "Failure",
    status_detail: e.outcome,
    message: `${e.actor_display || e.actor_type} ${e.type}${e.target_display ? ` ${e.target_display}` : ""}`,
    metadata: { version: "1.3.0", uid: e.id, event_code: e.type, tenant_uid: e.org_id, product: { name: "Votal Nexus", vendor_name: "Votal" } },
    actor: { user: { uid: e.actor_id ?? undefined, name: e.actor_display, type: e.actor_type } },
    ...(e.target_type === "user" ? { user: { uid: e.target_id ?? undefined, name: e.target_display } } : {}),
    ...(e.target_type && e.target_type !== "user" ? { resources: [{ type: e.target_type, uid: e.target_id ?? undefined, name: e.target_display }] } : {}),
    ...(e.ip ? { src_endpoint: { ip: e.ip } } : {}),
    ...(e.user_agent ? { http_request: { user_agent: e.user_agent } } : {}),
    ...(e.session_id ? { session: { uid: e.session_id } } : {}),
    unmapped: e.details ?? {},
  };
}

export const formatEvent = (format: "nexus" | "ocsf", e: AuditRow) => (format === "ocsf" ? ocsfEvent(e) : nexusEvent(e));

/** Prefix filters: "user." matches user.created; an exact type matches itself. */
export const matchesFilter = (filter: string[], type: string) => filter.length === 0 || filter.some((f) => type === f || (f.endsWith(".") && type.startsWith(f)) || (f.endsWith("*") && type.startsWith(f.slice(0, -1))));
