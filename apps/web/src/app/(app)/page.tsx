"use client";

import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, ArrowRight, CheckCircle2, Circle, Info, ShieldAlert } from "lucide-react";
import Link from "next/link";
import { ActivityList } from "@/components/features/activity";
import { Button } from "@/components/ui/button";
import { Card, CardHeader, EmptyState, PageHeader, Skeleton } from "@/components/ui/misc";
import { api, unwrap } from "@/lib/api";
import { qk, useMe } from "@/lib/queries";
import { cn } from "@/lib/utils";

const SEVERITY = {
  critical: { icon: ShieldAlert, cls: "border-danger/30 bg-danger-soft text-danger" },
  warning: { icon: AlertTriangle, cls: "border-warning/30 bg-warning-soft text-warning" },
  info: { icon: Info, cls: "border-primary/20 bg-primary-soft text-primary" },
} as const;

export default function OverviewPage() {
  const { data: me } = useMe();
  const { data, isPending } = useQuery({ queryKey: qk.overview, queryFn: () => unwrap(api.GET("/v1/overview")) });
  const apps = useQuery({ queryKey: ["apps"], queryFn: () => unwrap(api.GET("/v1/apps")), enabled: !!me?.permissions.includes("apps:read") });

  if (me && me.permissions.length === 0) {
    return (
      <>
        <PageHeader title={`Hi ${me.user.given_name}`} description="Your account is managed by your organization." />
        <Card className="p-6">
          <p className="text-[13px]">Keep your account secure from <Link href="/settings/security" className="text-primary hover:underline">My security</Link>.</p>
        </Card>
      </>
    );
  }

  const s = data?.stats;
  const mfaForEveryone = !data?.needs_attention.some((i) => i.id === "mfa_not_required");
  const checklist = [
    { done: !!me?.user.mfa_enrolled, label: "Protect your own account with a passkey or MFA", href: "/settings/security" },
    { done: !!data && mfaForEveryone, label: "Require MFA for everyone (secure baseline)", href: "/settings/organization" },
    { done: (s?.users_total ?? 0) > 1, label: "Invite your team (one by one or by CSV)", href: "/users?import=1" },
    { done: (s?.groups ?? 0) > 0, label: "Organize people into groups", href: "/groups?new=1" },
    { done: (s?.devices ?? 0) > 0, label: "Enroll a device with the Nexus agent", href: "/devices" },
    { done: (apps.data?.data.length ?? 0) > 0, label: "Connect an app with SSO", href: "/apps" },
  ];
  const doneCount = checklist.filter((c) => c.done).length;

  return (
    <>
      <PageHeader title="Overview" description={me ? `Security posture for ${me.organization.name}` : undefined} />

      {doneCount < 4 ? (
        <Card className="mb-6">
          <CardHeader title="Get set up" description={`${doneCount} of ${checklist.length} steps done`} />
          <ul className="divide-y divide-border">
            {checklist.map((c) => (
              <li key={c.label} className="flex items-center gap-3 px-4 py-2.5 text-[13px]">
                {c.done ? <CheckCircle2 className="size-4 text-success" /> : <Circle className="size-4 text-fg-subtle" />}
                <span className={cn(c.done && "text-fg-muted line-through", !c.href && "text-fg-subtle")}>{c.label}</span>
                {!c.done && c.href ? (
                  <Button asChild size="sm" variant="ghost" className="ml-auto">
                    <Link href={c.href}>
                      Start <ArrowRight />
                    </Link>
                  </Button>
                ) : null}
              </li>
            ))}
          </ul>
        </Card>
      ) : null}

      <section className="mb-6" aria-labelledby="attention">
        <h2 id="attention" className="mb-2 text-sm font-semibold">
          Needs attention
        </h2>
        {isPending ? (
          <Skeleton className="h-16" />
        ) : data?.needs_attention.length ? (
          <div className="grid gap-2">
            {data.needs_attention.map((item) => {
              const sev = SEVERITY[item.severity];
              return (
                <div key={item.id} className={cn("flex items-center gap-3 rounded-lg border px-4 py-3", sev.cls)}>
                  <sev.icon className="size-5 shrink-0" />
                  <div className="min-w-0 flex-1">
                    <p className="text-[13px] font-semibold text-fg">{item.title}</p>
                    <p className="text-[13px] text-fg-muted">{item.description}</p>
                  </div>
                  <Button asChild size="sm">
                    <Link href={item.link}>
                      {item.action_label} <ArrowRight />
                    </Link>
                  </Button>
                </div>
              );
            })}
          </div>
        ) : (
          <div className="flex items-center gap-2 rounded-lg border border-success/30 bg-success-soft px-4 py-3 text-[13px] text-success">
            <CheckCircle2 className="size-4" /> Nothing needs your attention right now.
          </div>
        )}
      </section>

      <div className="mb-6 grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Stat label="Active users" value={s?.users_active} sub={s ? `${s.users_suspended} suspended` : undefined} href="/users" />
        <Stat
          label="MFA coverage"
          value={s ? `${Math.round(s.mfa_coverage * 100)}%` : undefined}
          sub="of active users"
          tone={s && s.mfa_coverage < 0.95 ? "warning" : "success"}
          href="/users?mfa=missing"
        />
        <Stat label="Sign-ins (24h)" value={s?.logins_24h} sub={s ? `${s.failed_logins_24h} failed` : undefined} href="/audit?type=auth.*" />
        <Stat
          label="Devices"
          value={s?.devices}
          sub={s ? (s.devices_non_compliant ? `${s.devices_non_compliant} not compliant` : "all compliant") : undefined}
          tone={s && s.devices_non_compliant ? "warning" : undefined}
          href={s?.devices_non_compliant ? "/devices?compliance=non_compliant" : "/devices"}
        />
      </div>

      <Card>
        <CardHeader
          title="Recent activity"
          actions={
            <Button asChild size="sm" variant="ghost">
              <Link href="/audit">
                Audit log <ArrowRight />
              </Link>
            </Button>
          }
        />
        {data?.recent_activity.length ? (
          <ActivityList events={data.recent_activity} compact />
        ) : (
          <EmptyState title="No activity yet" />
        )}
      </Card>
    </>
  );
}

function Stat({ label, value, sub, tone, href }: { label: string; value?: number | string; sub?: string; tone?: "warning" | "success"; href: string }) {
  return (
    <Link href={href} className="rounded-lg border border-border bg-bg p-4 shadow-card hover:border-border-strong">
      <p className="text-xs font-medium text-fg-muted">{label}</p>
      <div className={cn("mt-1 text-2xl font-semibold tabular", tone === "warning" && "text-warning")}>
        {value ?? <Skeleton className="h-7 w-12" />}
      </div>
      {sub ? <p className="mt-0.5 text-xs text-fg-subtle">{sub}</p> : null}
    </Link>
  );
}
