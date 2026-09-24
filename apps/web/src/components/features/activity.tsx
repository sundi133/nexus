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
};

export function describe(e: AuditEvent) {
  if (e.type === "auth.login" && e.outcome !== "success") {
    const reason = String(e.details.reason ?? "");
    return reason === "bad_password" ? "failed to sign in (wrong password)" : `was denied sign-in (${reason.replace(/_/g, " ")})`;
  }
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
        const showTarget = e.target.display && !["auth.login", "auth.logout", "auth.mfa", "auth.step_up"].includes(e.type);
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
