"use client";

import type { Schemas } from "@nexus/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { BellRing, Plus, Siren } from "lucide-react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useState } from "react";
import { toast } from "sonner";
import { AlertStatus, SEVERITY_TONE } from "@/components/features/alert-bits";
import { useStepUp } from "@/components/step-up";
import { Button } from "@/components/ui/button";
import { CopyField } from "@/components/ui/copy";
import { Field, Input, Select } from "@/components/ui/input";
import { Card, EmptyState, ErrorBanner, PageHeader, Skeleton, StatusPill } from "@/components/ui/misc";
import { Dialog, DialogContent, Tabs, TabsContent, TabsList } from "@/components/ui/overlay";
import { api, unwrap } from "@/lib/api";
import { useCan } from "@/lib/queries";
import { cn, pluralize, timeAgo } from "@/lib/utils";

type Alert = Schemas["Alert"];
type Rule = Schemas["AlertRule"];
type Severity = Alert["severity"];

function AlertsView() {
  const params = useSearchParams();
  const router = useRouter();
  const tab = params.get("tab") ?? "queue";
  return (
    <>
      <PageHeader title="Alerts" description="Security events worth a look, deduplicated: a burst of matches is one alert with a count. Critical ones can page your on-call." />
      <Tabs value={tab} onValueChange={(v) => router.replace(v === "queue" ? "/alerts" : `/alerts?tab=${v}`)}>
        <TabsList
          tabs={[
            { value: "queue", label: "Queue" },
            { value: "rules", label: "Rules" },
            { value: "oncall", label: "On-call" },
          ]}
        />
        <TabsContent value="queue">
          <Queue />
        </TabsContent>
        <TabsContent value="rules">
          <Rules />
        </TabsContent>
        <TabsContent value="oncall">
          <Oncall />
        </TabsContent>
      </Tabs>
    </>
  );
}

function Queue() {
  const [status, setStatus] = useState<"active" | "snoozed" | "resolved" | "all">("active");
  const [severity, setSeverity] = useState<Severity | "">("");
  const list = useQuery({ queryKey: ["alerts", status, severity], queryFn: () => unwrap(api.GET("/v1/alerts", { params: { query: { status, severity: severity || undefined } } })), refetchInterval: 15_000 });
  const counts = list.data?.counts;
  return (
    <>
      <div className="mb-3 flex flex-wrap items-center gap-2">
        {(["active", "snoozed", "resolved", "all"] as const).map((s) => (
          <button key={s} onClick={() => setStatus(s)} className={cn("rounded-full border px-3 py-1 text-[13px] capitalize", status === s ? "border-primary bg-primary-soft/50 font-medium" : "border-border text-fg-muted hover:bg-bg-subtle")}>
            {s}
            {s === "active" && counts ? ` (${counts.open + counts.acknowledged})` : s === "snoozed" && counts?.snoozed ? ` (${counts.snoozed})` : ""}
          </button>
        ))}
        <Select aria-label="Severity" value={severity} onChange={(e) => setSeverity(e.target.value as Severity | "")}>
          <option value="">Any severity</option>
          {["critical", "high", "medium", "low"].map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </Select>
      </div>
      <Card className="overflow-hidden">
        {list.isPending ? (
          <Skeleton className="m-4 h-20" />
        ) : !list.data?.data.length ? (
          <EmptyState icon={<BellRing />} title={status === "active" ? "Nothing needs attention" : "No alerts"} description="Alerts appear here when a rule fires. Tune the rules so each alert is worth someone's time." />
        ) : (
          <ul className="divide-y divide-border">
            {list.data.data.map((a) => (
              <AlertRow key={a.id} a={a} />
            ))}
          </ul>
        )}
      </Card>
    </>
  );
}

function AlertRow({ a }: { a: Alert }) {
  return (
    <li>
      <Link href={`/alerts/${a.id}`} className="flex flex-wrap items-center gap-3 px-4 py-3 text-[13px] hover:bg-bg-subtle">
        <StatusPill tone={SEVERITY_TONE[a.severity]} dot={false}>
          <span className="capitalize">{a.severity}</span>
        </StatusPill>
        <div className="min-w-0 flex-1">
          <p className="truncate font-medium">{a.title}</p>
          <p className="text-xs text-fg-muted">
            {a.rule.name} · {pluralize(a.count, "event")} · first {timeAgo(a.first_seen_at)}, last {timeAgo(a.last_seen_at)}
            {a.assignee ? ` · ${a.assignee.name}` : ""}
            {a.paged ? " · paged" : ""}
          </p>
        </div>
        <AlertStatus a={a} />
      </Link>
    </li>
  );
}

// ---- Rules ----

const GROUP_LABEL = { none: "overall", actor: "per person or agent", target: "per target", ip: "per IP address" } as const;

function Rules() {
  const qc = useQueryClient();
  const can = useCan();
  const [editing, setEditing] = useState<Rule | "new" | null>(null);
  const rules = useQuery({ queryKey: ["alert-rules"], queryFn: () => unwrap(api.GET("/v1/alert-rules")) });
  const toggle = useMutation({
    mutationFn: (r: Rule) => unwrap(api.PATCH("/v1/alert-rules/{id}", { params: { path: { id: r.id } }, body: { enabled: !r.enabled } })),
    onSuccess: (d) => qc.setQueryData(["alert-rules"], d),
  });
  if (!rules.data) return <Skeleton className="h-40" />;
  return (
    <>
      <div className="mb-3 flex items-center gap-2">
        <p className="flex-1 text-[13px] text-fg-muted">Rules that fire often and get resolved as false positives are noise: raise their threshold or turn them off.</p>
        {can("alerts:manage") ? (
          <Button size="sm" variant="primary" onClick={() => setEditing("new")}>
            <Plus /> Add rule
          </Button>
        ) : null}
      </div>
      <Card className="overflow-hidden">
        <ul className="divide-y divide-border">
          {rules.data.data.map((r) => {
            const noisy = r.quality.false_positive_rate !== null && r.quality.false_positive_rate >= 0.5 && r.quality.fired_30d >= 3;
            return (
              <li key={r.id} className={cn("flex flex-wrap items-center gap-3 px-4 py-3 text-[13px]", !r.enabled && "opacity-60")}>
                <StatusPill tone={SEVERITY_TONE[r.severity]} dot={false}>
                  <span className="capitalize">{r.severity}</span>
                </StatusPill>
                <div className="min-w-0 flex-1">
                  <p className="font-medium">
                    {r.name} {r.builtin ? <span className="text-xs font-normal text-fg-subtle">default</span> : null} {noisy ? <StatusPill tone="warning">Noisy</StatusPill> : null}
                  </p>
                  <p className="text-xs text-fg-muted">
                    {r.threshold > 1 ? `${r.threshold} in ${r.window_minutes} min` : "Every time"} {GROUP_LABEL[r.group_by]} · {r.match.types.join(", ")}
                    {r.match.outcome ? ` (${r.match.outcome})` : ""}
                  </p>
                </div>
                <div className="w-56 text-right text-xs text-fg-muted">
                  {r.quality.fired_30d ? `${pluralize(r.quality.fired_30d, "alert")} in 30 days` : "Quiet in 30 days"}
                  {r.quality.false_positive_rate !== null ? ` · ${Math.round(r.quality.false_positive_rate * 100)}% false` : ""}
                  {r.quality.median_minutes_to_ack !== null ? ` · ack in ${r.quality.median_minutes_to_ack} min` : ""}
                </div>
                {can("alerts:manage") ? (
                  <>
                    <label className="flex items-center gap-1.5 text-xs">
                      <input type="checkbox" checked={r.enabled} onChange={() => toggle.mutate(r)} aria-label={`${r.name} enabled`} /> On
                    </label>
                    <Button size="sm" variant="ghost" onClick={() => setEditing(r)}>
                      Edit
                    </Button>
                  </>
                ) : null}
              </li>
            );
          })}
        </ul>
      </Card>
      {editing ? <RuleDialog rule={editing === "new" ? null : editing} onClose={() => setEditing(null)} /> : null}
    </>
  );
}

function RuleDialog({ rule, onClose }: { rule: Rule | null; onClose: () => void }) {
  const qc = useQueryClient();
  const [f, setF] = useState({
    name: rule?.name ?? "",
    severity: rule?.severity ?? ("medium" as Severity),
    types: rule?.match.types.join(", ") ?? "",
    outcome: rule?.match.outcome ?? "",
    group_by: rule?.group_by ?? ("actor" as Rule["group_by"]),
    threshold: rule?.threshold ?? 1,
    window_minutes: rule?.window_minutes ?? 5,
  });
  const save = useMutation({
    mutationFn: () => {
      const body = {
        name: f.name.trim(),
        severity: f.severity,
        match: { types: f.types.split(/[\s,]+/).filter(Boolean), ...(f.outcome ? { outcome: f.outcome as "success" | "failure" | "denied" } : {}), ...(rule?.match.details ? { details: rule.match.details } : {}) },
        group_by: f.group_by,
        threshold: f.threshold,
        window_minutes: f.window_minutes,
      };
      return rule ? unwrap(api.PATCH("/v1/alert-rules/{id}", { params: { path: { id: rule.id } }, body })) : unwrap(api.POST("/v1/alert-rules", { body }));
    },
    onSuccess: (d) => (qc.setQueryData(["alert-rules"], d), toast.success("Rule saved"), onClose()),
  });
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent title={rule ? `Edit ${rule.name}` : "Add an alert rule"} className="max-w-lg">
        <div className="space-y-3">
          <Field label="Name" htmlFor="ar-name">
            <Input id="ar-name" value={f.name} maxLength={100} onChange={(e) => setF({ ...f, name: e.target.value })} placeholder="Agent called a destructive tool" />
          </Field>
          <Field label="Event types" htmlFor="ar-types" hint="From the audit log, e.g. mcp.tool_denied, or a prefix like device.*">
            <Input id="ar-types" className="font-mono" value={f.types} disabled={!!rule?.builtin} onChange={(e) => setF({ ...f, types: e.target.value })} placeholder="mcp.tool_denied" />
          </Field>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Outcome" htmlFor="ar-outcome">
              <Select id="ar-outcome" className="w-full" value={f.outcome} disabled={!!rule?.builtin} onChange={(e) => setF({ ...f, outcome: e.target.value })}>
                <option value="">Any</option>
                <option value="success">Success</option>
                <option value="failure">Failure</option>
                <option value="denied">Denied</option>
              </Select>
            </Field>
            <Field label="Severity" htmlFor="ar-sev">
              <Select id="ar-sev" className="w-full" value={f.severity} onChange={(e) => setF({ ...f, severity: e.target.value as Severity })}>
                {["low", "medium", "high", "critical"].map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </Select>
            </Field>
            <Field label="Fire after" htmlFor="ar-th">
              <Input id="ar-th" type="number" min={1} max={10000} value={f.threshold} onChange={(e) => setF({ ...f, threshold: Number(e.target.value) || 1 })} />
            </Field>
            <Field label="Within (minutes)" htmlFor="ar-win">
              <Input id="ar-win" type="number" min={1} max={1440} value={f.window_minutes} onChange={(e) => setF({ ...f, window_minutes: Number(e.target.value) || 1 })} />
            </Field>
          </div>
          <Field label="Count" htmlFor="ar-group">
            <Select id="ar-group" className="w-full" value={f.group_by} onChange={(e) => setF({ ...f, group_by: e.target.value as Rule["group_by"] })}>
              {Object.entries(GROUP_LABEL).map(([k, l]) => (
                <option key={k} value={k}>
                  {l}
                </option>
              ))}
            </Select>
          </Field>
          <ErrorBanner error={save.error} />
          <div className="flex justify-end gap-2 border-t border-border pt-4">
            <Button variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button variant="primary" disabled={!f.name.trim() || !f.types.trim()} loading={save.isPending} onClick={() => save.mutate()}>
              Save rule
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

// ---- On-call ----

function Oncall() {
  const qc = useQueryClient();
  const can = useCan();
  const [adding, setAdding] = useState(false);
  const list = useQuery({ queryKey: ["oncall"], queryFn: () => unwrap(api.GET("/v1/oncall-integrations")) });
  const test = useMutation({
    mutationFn: (id: string) => unwrap(api.POST("/v1/oncall-integrations/{id}/test", { params: { path: { id } } })),
    onSuccess: (r) => (r.ok ? toast.success("Test page sent and resolved") : toast.error(r.error), qc.invalidateQueries({ queryKey: ["oncall"] })),
  });
  const remove = useMutation({
    mutationFn: (id: string) => unwrap(api.DELETE("/v1/oncall-integrations/{id}", { params: { path: { id } } })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["oncall"] }),
  });
  return (
    <>
      <div className="mb-3 flex items-center gap-2">
        <p className="flex-1 text-[13px] text-fg-muted">Page your on-call rotation for serious alerts. Acknowledging or resolving on either side updates the other.</p>
        {can("alerts:manage") ? (
          <Button size="sm" variant="primary" onClick={() => setAdding(true)}>
            <Plus /> Connect
          </Button>
        ) : null}
      </div>
      <Card className="overflow-hidden">
        {!list.data?.data.length ? (
          <EmptyState icon={<Siren />} title="No on-call paging" description="Connect PagerDuty or Opsgenie to be woken up for critical alerts only." />
        ) : (
          <ul className="divide-y divide-border">
            {list.data.data.map((i) => (
              <li key={i.id} className="flex flex-wrap items-center gap-3 px-4 py-3 text-[13px]">
                <div className="min-w-0 flex-1">
                  <p className="font-medium">
                    {i.name} <span className="font-normal text-fg-muted">· {i.kind === "pagerduty" ? "PagerDuty" : `Opsgenie (${i.region.toUpperCase()})`}</span>
                  </p>
                  <p className={cn("text-xs", i.last_error ? "text-danger" : "text-fg-muted")}>
                    Pages for {i.min_severity} alerts{i.min_severity !== "critical" ? " and above" : ""} · {i.last_error ? i.last_error : i.last_sent_at ? `last sent ${timeAgo(i.last_sent_at)}` : "nothing sent yet"}
                  </p>
                </div>
                {can("alerts:manage") ? (
                  <>
                    <Button size="sm" loading={test.isPending && test.variables === i.id} onClick={() => test.mutate(i.id)}>
                      Send test
                    </Button>
                    <Button size="sm" variant="ghost" onClick={() => remove.mutate(i.id)}>
                      Disconnect
                    </Button>
                  </>
                ) : null}
              </li>
            ))}
          </ul>
        )}
      </Card>
      {adding ? <ConnectDialog onClose={() => setAdding(false)} /> : null}
    </>
  );
}

function ConnectDialog({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient();
  const withStepUp = useStepUp();
  const [f, setF] = useState({ kind: "pagerduty" as "pagerduty" | "opsgenie", name: "PagerDuty", key: "", region: "us" as "us" | "eu", min_severity: "critical" as Severity });
  const [hook, setHook] = useState<string | null>(null);
  const connect = useMutation({
    mutationFn: () => withStepUp(() => unwrap(api.POST("/v1/oncall-integrations", { body: f }))),
    onSuccess: (r) => (qc.invalidateQueries({ queryKey: ["oncall"] }), setHook(r.webhook_url)),
  });
  if (hook) {
    return (
      <Dialog open onOpenChange={(o) => !o && onClose()}>
        <DialogContent title="One more step: acknowledgements back" description={f.kind === "pagerduty" ? "In PagerDuty, add a v3 webhook subscription for incident.acknowledged and incident.resolved on this service, pointing at:" : "In Opsgenie, add an outgoing Webhook integration for Acknowledge and Close actions, pointing at:"}>
          <CopyField label="Webhook URL (shown once)" value={hook} secret />
          <div className="mt-4 flex justify-end">
            <Button variant="primary" onClick={onClose}>
              Done
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    );
  }
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent title="Connect on-call paging" className="max-w-md">
        <div className="space-y-3">
          <Field label="Service" htmlFor="oc-kind">
            <Select id="oc-kind" className="w-full" value={f.kind} onChange={(e) => setF({ ...f, kind: e.target.value as typeof f.kind, name: e.target.value === "pagerduty" ? "PagerDuty" : "Opsgenie" })}>
              <option value="pagerduty">PagerDuty</option>
              <option value="opsgenie">Opsgenie</option>
            </Select>
          </Field>
          <Field label="Name" htmlFor="oc-name">
            <Input id="oc-name" value={f.name} maxLength={100} onChange={(e) => setF({ ...f, name: e.target.value })} />
          </Field>
          <Field label={f.kind === "pagerduty" ? "Integration key (Events API v2)" : "API integration key"} htmlFor="oc-key">
            <Input id="oc-key" type="password" autoComplete="off" value={f.key} onChange={(e) => setF({ ...f, key: e.target.value })} />
          </Field>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Page for" htmlFor="oc-sev">
              <Select id="oc-sev" className="w-full" value={f.min_severity} onChange={(e) => setF({ ...f, min_severity: e.target.value as Severity })}>
                <option value="critical">Critical only</option>
                <option value="high">High and critical</option>
                <option value="medium">Medium and above</option>
              </Select>
            </Field>
            {f.kind === "opsgenie" ? (
              <Field label="Region" htmlFor="oc-region">
                <Select id="oc-region" className="w-full" value={f.region} onChange={(e) => setF({ ...f, region: e.target.value as "us" | "eu" })}>
                  <option value="us">US</option>
                  <option value="eu">EU</option>
                </Select>
              </Field>
            ) : null}
          </div>
          <ErrorBanner error={connect.error} />
          <div className="flex justify-end gap-2 border-t border-border pt-4">
            <Button variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button variant="primary" disabled={f.key.length < 8 || !f.name.trim()} loading={connect.isPending} onClick={() => connect.mutate()}>
              Connect
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

export default function AlertsPage() {
  return (
    <Suspense>
      <AlertsView />
    </Suspense>
  );
}
