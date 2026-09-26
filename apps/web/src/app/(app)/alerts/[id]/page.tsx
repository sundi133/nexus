"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { BellOff, Check, ChevronLeft } from "lucide-react";
import Link from "next/link";
import { use, useState } from "react";
import { toast } from "sonner";
import { ActivityList } from "@/components/features/activity";
import { AlertStatus, SEVERITY_TONE } from "@/components/features/alert-bits";
import { Button } from "@/components/ui/button";
import { Select } from "@/components/ui/input";
import { Card, CardHeader, ErrorBanner, KeyValue, Skeleton, StatusPill } from "@/components/ui/misc";
import { api, unwrap } from "@/lib/api";
import { useCan, useMe } from "@/lib/queries";
import { formatDateTime, pluralize, timeAgo } from "@/lib/utils";

type Action =
  | { action: "acknowledge" }
  | { action: "resolve"; resolution: "true_positive" | "false_positive" | "benign"; note?: string }
  | { action: "snooze"; minutes: number }
  | { action: "unsnooze" }
  | { action: "assign"; user_id: string | null }
  | { action: "note"; body: string };

export default function AlertPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const qc = useQueryClient();
  const can = useCan();
  const me = useMe();
  const [note, setNote] = useState("");
  const [resolution, setResolution] = useState<"true_positive" | "false_positive" | "benign">("true_positive");
  const data = useQuery({ queryKey: ["alert", id], queryFn: () => unwrap(api.GET("/v1/alerts/{id}", { params: { path: { id } } })) });
  const act = useMutation({
    mutationFn: (body: Action) => unwrap(api.POST("/v1/alerts/{id}/actions", { params: { path: { id } }, body })),
    onSuccess: (d, v) => {
      qc.setQueryData(["alert", id], d);
      qc.invalidateQueries({ queryKey: ["alerts"] });
      if (v.action === "note") setNote("");
      else toast.success({ acknowledge: "Acknowledged", resolve: "Resolved", snooze: "Snoozed", unsnooze: "Back in the queue", assign: "Assigned" }[v.action]);
    },
  });

  if (data.isPending) return <Skeleton className="h-60" />;
  if (!data.data) return <ErrorBanner error={data.error} />;
  const { alert: a, events, notes, rule_description } = data.data;
  const triage = can("alerts:triage") && a.status !== "resolved";

  return (
    <>
      <Link href="/alerts" className="mb-3 inline-flex items-center gap-1 text-[13px] text-fg-muted hover:text-fg">
        <ChevronLeft className="size-4" /> Alerts
      </Link>
      <div className="mb-4 flex flex-wrap items-start gap-3">
        <div className="min-w-0 flex-1">
          <h1 className="flex flex-wrap items-center gap-2 text-xl font-semibold tracking-tight">
            <StatusPill tone={SEVERITY_TONE[a.severity]} dot={false}>
              <span className="capitalize">{a.severity}</span>
            </StatusPill>
            {a.title} <AlertStatus a={a} />
          </h1>
          <p className="mt-0.5 text-[13px] text-fg-muted">{rule_description}</p>
        </div>
        {triage ? (
          <div className="flex flex-wrap gap-2">
            {a.snoozed_until ? (
              <Button onClick={() => act.mutate({ action: "unsnooze" })}>Unsnooze</Button>
            ) : (
              <Button onClick={() => act.mutate({ action: "snooze", minutes: 240 })}>
                <BellOff /> Snooze 4 h
              </Button>
            )}
            {a.status === "open" ? (
              <Button variant="primary" loading={act.isPending} onClick={() => act.mutate({ action: "acknowledge" })}>
                <Check /> Acknowledge
              </Button>
            ) : null}
          </div>
        ) : null}
      </div>
      <ErrorBanner error={act.error} />
      <div className="grid gap-4 xl:grid-cols-3">
        <Card className="overflow-hidden xl:col-span-2">
          <CardHeader title={`What happened (${pluralize(a.count, "event")})`} description={a.count > events.length ? `The latest ${events.length} are shown.` : undefined} />
          <ActivityList events={events} compact />
        </Card>
        <div className="space-y-4">
          <Card>
            <CardHeader title="Details" />
            <div className="px-4 pb-4">
              <KeyValue
                items={[
                  ["Rule", a.rule.name],
                  ["About", a.subject || "—"],
                  ["First seen", formatDateTime(a.first_seen_at)],
                  ["Last seen", timeAgo(a.last_seen_at)],
                  ["Assigned to", a.assignee?.name ?? "Nobody"],
                  ["Acknowledged", a.acknowledged_at ? `${a.acknowledged_by}, ${timeAgo(a.acknowledged_at)}` : "—"],
                  ["Resolved", a.resolved_at ? `${a.resolved_by}, ${timeAgo(a.resolved_at)}` : "—"],
                  ["Paged", a.paged ? `${a.paged} on-call integration${a.paged > 1 ? "s" : ""}` : "No"],
                ]}
              />
              {triage && me.data && a.assignee?.id !== me.data.user.id ? (
                <Button size="sm" className="mt-3" onClick={() => act.mutate({ action: "assign", user_id: me.data!.user.id })}>
                  Assign to me
                </Button>
              ) : null}
            </div>
          </Card>
          {triage ? (
            <Card className="p-4">
              <p className="mb-2 text-[13px] font-medium">Resolve</p>
              <Select aria-label="Verdict" className="mb-2 w-full" value={resolution} onChange={(e) => setResolution(e.target.value as typeof resolution)}>
                <option value="true_positive">Real: handled</option>
                <option value="benign">Expected activity</option>
                <option value="false_positive">False alarm (tune the rule)</option>
              </Select>
              <Button variant="primary" className="w-full" loading={act.isPending} onClick={() => act.mutate({ action: "resolve", resolution, ...(note.trim() ? { note: note.trim() } : {}) })}>
                Resolve
              </Button>
            </Card>
          ) : null}
        </div>
      </div>
      <Card className="mt-4">
        <CardHeader title="Notes" />
        <div className="space-y-3 px-4 pb-4">
          {notes.map((n) => (
            <div key={n.id} className="text-[13px]">
              <p className="text-xs text-fg-muted">
                {n.author} · {timeAgo(n.at)}
              </p>
              <p className="whitespace-pre-wrap">{n.body}</p>
            </div>
          ))}
          {can("alerts:triage") ? (
            <div className="flex gap-2">
              <textarea aria-label="Note" className="h-16 flex-1 rounded-md border border-border bg-bg px-2.5 py-2 text-[13px]" value={note} onChange={(e) => setNote(e.target.value)} placeholder="What did you find?" maxLength={2000} />
              <Button disabled={!note.trim()} onClick={() => act.mutate({ action: "note", body: note.trim() })}>
                Add note
              </Button>
            </div>
          ) : null}
        </div>
      </Card>
    </>
  );
}
