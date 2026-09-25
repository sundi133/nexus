"use client";

import type { AuditEvent } from "@nexus/api-client";
import { ChevronRight } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { StatusPill } from "@/components/ui/misc";
import { cn, formatDateTime, timeAgo } from "@/lib/utils";

const VERBS: Record<string, string> = {
  "org.created": "created the organization",
  "user.created": "created user",
  "user.updated": "updated",
  "user.suspend": "suspended",
  "user.activate": "reactivated",
  "user.contain": "contained",
  "user.revoke_sessions": "signed out everywhere:",
  "user.reset_mfa": "reset MFA for",
  "user.roles_changed": "changed admin roles for",
  "user.mfa_enrolled": "enrolled an authenticator",
  "user.mfa_removed": "removed an MFA method",
  "auth.login": "signed in",
  "auth.logout": "signed out",
  "auth.mfa": "verified MFA",
  "auth.step_up": "re-verified with MFA",
  "session.revoked": "revoked a session",
  "group.created": "created group",
  "group.updated": "updated group",
  "group.deleted": "deleted group",
  "group.members_added": "added members to",
  "group.members_removed": "removed members from",
  "org.settings_updated": "changed security settings",
  "sso.login": "signed in to",
  "device.enrolled": "enrolled",
  "device.removed": "removed the device",
  "device.user_assigned": "changed the primary user of",
  "device.policy_updated": "changed the device policy",
  "device.enrollment_token_created": "created an enrollment token",
  "device.enrollment_token_revoked": "revoked an enrollment token",
  "sso.key_rotated": "rotated the OIDC signing key",
  "sso.cert_rotation_started": "started a SAML certificate rotation",
  "sso.cert_rotated": "activated a new SAML certificate",
  "sso.cert_rotation_discarded": "discarded a SAML certificate rotation",
  "app.created": "added the app",
  "app.updated": "updated the app",
  "app.disabled": "disabled sign-in for",
  "app.deleted": "deleted the app",
  "app.secret_rotated": "rotated the client secret of",
  "app.assigned": "gave access to",
  "app.unassigned": "removed access to",
  "user.invited": "sent an invitation to",
  "user.invitation_accepted": "accepted their invitation",
  "user.imported": "imported users from CSV",
  "user.suspended": "suspended",
  "user.activated": "reactivated",
  "user.offboarded": "offboarded",
  "directory.connection_created": "connected directory",
  "directory.scim_token_rotated": "replaced the SCIM token for",
  "directory.mass_change_approved": "approved held changes from",
  "federation.idp_created": "connected identity provider",
  "federation.idp_updated": "changed identity provider",
  "federation.idp_deleted": "disconnected identity provider",
  "federation.tested": "ran a test sign-in with",
  "group.dynamic_updated": "updated the members of",
  "agent.registered": "registered the agent",
  "agent.updated": "updated the agent",
  "agent.deleted": "deleted the agent",
  "agent.credential_added": "added a credential to",
  "agent.credential_revoked": "revoked a credential of",
  "agent.suspended": "suspended the agent",
  "agent.activated": "reactivated the agent",
  "agent.token_issued": "got an access token",
  "mcp.server_registered": "registered the MCP server",
  "mcp.server_updated": "changed the MCP server",
  "mcp.server_removed": "removed the MCP server",
  "mcp.tools_discovered": "found tool changes on",
  "mcp.tools_approved": "approved tools on",
  "mcp.tools_blocked": "blocked tools on",
  "mcp.tool_risk_set": "set the risk class of",
  "mcp.permission_added": "added a tool permission on",
  "mcp.permission_changed": "changed a tool permission on",
  "mcp.permission_removed": "removed a tool permission on",
  "mcp.tool_called": "called",
  "mcp.tool_denied": "was denied",
  "audit.sealed": "sealed a block of the audit log",
  "audit.integrity_failed": "detected tampering in the audit log",
  "alert.opened": "raised",
  "alert.acknowledged": "acknowledged",
  "alert.resolved": "resolved",
  "alert.snoozed": "snoozed",
  "alert.assigned": "assigned",
  "alert.rule_created": "added the alert rule",
  "alert.rule_changed": "changed the alert rule",
  "alert.oncall_connected": "connected on-call paging",
  "report.generated": "generated a report",
};

export function describe(e: AuditEvent) {
  if (e.type === "auth.login" && e.outcome !== "success") {
    const reason = String(e.details.reason ?? "");
    return reason === "bad_password" ? "failed to sign in (wrong password)" : `was denied sign-in (${reason.replace(/_/g, " ")})`;
  }
  if (e.type === "auth.login" && e.details.method === "federation") return `signed in with ${String(e.details.idp)}`;
  if (e.type === "device.compliance_changed") return `reports ${e.target.display} is ${String(e.details.to).replace("_", "-")} (was ${String(e.details.from).replace("_", "-")}):`;
  if (e.type === "sso.login" && e.outcome === "denied") return "was blocked from (not assigned)";
  if (e.type === "auth.mfa" && e.outcome === "denied" && e.details.reason === "not_me") return "reported a sign-in they didn't start (blocked)";
  if (e.type === "auth.mfa" && e.outcome === "denied" && e.details.reason === "wrong_number") return "tapped the wrong number on a sign-in (blocked)";
  if (e.type === "auth.mfa" && e.outcome !== "success") return "failed MFA verification";
  return VERBS[e.type] ?? e.type;
}

function targetHref(e: AuditEvent) {
  if (!e.target.id) return null;
  if (e.target.type === "user") return `/users/${e.target.id}`;
  if (e.target.type === "group") return `/groups/${e.target.id}`;
  if (e.target.type === "application") return `/apps/${e.target.id}`;
  if (e.target.type === "device") return `/devices/${e.target.id}`;
  if (e.target.type === "agent") return `/agents/${e.target.id}`;
  if (e.target.type === "alert") return `/alerts/${e.target.id}`;
  if (e.target.type === "mcp_server") return `/mcp/${e.target.id}`;
  if (e.target.type === "mcp_tool" && e.details.server_id) return `/mcp/${String(e.details.server_id)}`;
  return null;
}

const OUTCOME_TONE = { success: "success", failure: "danger", denied: "warning" } as const;

/** Human-readable audit rows; expand to see the raw event (docs/UI.md §5.7). */
export function ActivityList({ events, compact }: { events: AuditEvent[]; compact?: boolean }) {
  const [open, setOpen] = useState<string | null>(null);
  return (
    <ul className="divide-y divide-border">
      {events.map((e) => {
        const href = targetHref(e);
        const showTarget = e.target.display && !["auth.login", "auth.logout", "auth.mfa", "auth.step_up", "agent.token_issued"].includes(e.type);
        return (
          <li key={e.id}>
            <button
              onClick={() => setOpen(open === e.id ? null : e.id)}
              className="flex w-full items-center gap-3 px-4 py-2.5 text-left text-[13px] hover:bg-bg-subtle"
              aria-expanded={open === e.id}
            >
              <ChevronRight className={cn("size-3.5 shrink-0 text-fg-subtle transition-transform", open === e.id && "rotate-90")} />
              <span className="min-w-0 flex-1 truncate">
                <span className="font-medium">{e.actor.display || "System"}</span>{" "}
                <span className="text-fg-muted">{describe(e)}</span>{" "}
                {showTarget ? (
                  href ? (
                    <Link href={href} onClick={(ev) => ev.stopPropagation()} className="font-medium hover:underline">
                      {e.target.display}
                    </Link>
                  ) : (
                    <span className="font-medium">{e.target.display}</span>
                  )
                ) : null}
              </span>
              {e.outcome !== "success" ? <StatusPill tone={OUTCOME_TONE[e.outcome]}>{e.outcome}</StatusPill> : null}
              {!compact && e.ip ? <span className="hidden font-mono text-xs text-fg-subtle lg:inline">{e.ip}</span> : null}
              <time className="shrink-0 text-xs text-fg-subtle tabular" dateTime={e.ts} title={formatDateTime(e.ts)}>
                {timeAgo(e.ts)}
              </time>
            </button>
            {open === e.id ? (
              <pre className="mx-4 mb-3 overflow-x-auto rounded-md border border-border bg-bg-subtle p-3 font-mono text-xs leading-relaxed text-fg-muted">
                {JSON.stringify(e, null, 2)}
              </pre>
            ) : null}
          </li>
        );
      })}
    </ul>
  );
}
