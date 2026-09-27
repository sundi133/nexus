"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Play, TerminalSquare } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { RowsTable } from "@/components/features/osquery-bits";
import { useStepUp } from "@/components/step-up";
import { Button } from "@/components/ui/button";
import { Field, Input, Select } from "@/components/ui/input";
import { Card, CardHeader, EmptyState, ErrorBanner, PageHeader, Skeleton, StatusPill } from "@/components/ui/misc";
import { Table, TD, TH, THead, TR } from "@/components/ui/table";
import { api, unwrap } from "@/lib/api";
import { useCan } from "@/lib/queries";
import { cn, pluralize, timeAgo } from "@/lib/utils";

const EXAMPLES: { label: string; sql: string }[] = [
  { label: "Who's signed in", sql: "SELECT user, host, type, time FROM logged_in_users;" },
  { label: "Processes listening on the network", sql: "SELECT DISTINCT p.name, l.port, l.address FROM listening_ports l JOIN processes p USING (pid) WHERE l.address NOT IN ('127.0.0.1', '::1');" },
  { label: "Chrome version", sql: "SELECT name, version FROM apps WHERE name LIKE 'Google Chrome%'\nUNION ALL SELECT name, version FROM programs WHERE name LIKE 'Google Chrome%';" },
  { label: "OS version", sql: "SELECT name, version, build FROM os_version;" },
  { label: "Local admins (macOS)", sql: "SELECT u.username FROM users u JOIN user_groups ug USING (uid) JOIN groups g USING (gid) WHERE g.groupname = 'admin';" },
];

export default function LiveQueryPage() {
  const can = useCan();
  const qc = useQueryClient();
  const withStepUp = useStepUp();
  const [sql, setSql] = useState(EXAMPLES[0]!.sql);
  const [reason, setReason] = useState("");
  const [target, setTarget] = useState<"all" | "group">("all");
  const [groupId, setGroupId] = useState("");
  const [current, setCurrent] = useState<string | null>(null);

  const groups = useQuery({ queryKey: ["groups", "live-query"], queryFn: () => unwrap(api.GET("/v1/groups", { params: { query: { limit: 200 } } })), enabled: target === "group" });
  const history = useQuery({ queryKey: ["live-queries"], queryFn: () => unwrap(api.GET("/v1/live-queries")), enabled: can("devices:query") });
  const run = useMutation({
    mutationFn: () =>
      withStepUp(() => unwrap(api.POST("/v1/live-queries", { body: { sql, reason, target: target === "all" ? { all: true } : { group_id: groupId } } }))),
    onSuccess: (r) => {
      setCurrent(r.id);
      qc.invalidateQueries({ queryKey: ["live-queries"] });
      toast.success(`Sent to ${pluralize(r.devices, "device")}`, { description: r.skipped_without_osquery ? `${pluralize(r.skipped_without_osquery, "device")} without osquery skipped.` : "Devices answer on their next check-in, within about a minute." });
    },
  });

  if (!can("devices:query"))
    return (
      <>
        <PageHeader title="Live query" />
        <Card>
          <EmptyState title="You can't run live queries" description="Live queries need the “Run live queries” permission (devices:query), which Owners, Admins and Security analysts have." />
        </Card>
      </>
    );

  return (
    <>
      <PageHeader
        title="Live query"
        description="Ask every device a question in SQL, with osquery. Each device runs it on its next check-in (about a minute) and returns up to 1,000 rows. Queries are signed with your organization's key, recorded in the audit log, and can't reach the network or read file contents."
      />
      <Card className="mb-5 p-4">
        <div className="mb-2 flex flex-wrap items-center gap-1.5">
          <span className="text-xs text-fg-muted">Examples:</span>
          {EXAMPLES.map((e) => (
            <button key={e.label} type="button" onClick={() => setSql(e.sql)} className="rounded-full border border-border px-2 py-0.5 text-xs text-fg-muted hover:bg-bg-subtle">
              {e.label}
            </button>
          ))}
        </div>
        <textarea
          aria-label="SQL"
          value={sql}
          onChange={(e) => setSql(e.target.value)}
          rows={5}
          spellCheck={false}
          className="w-full rounded-md border border-border bg-bg px-3 py-2 font-mono text-xs"
        />
        <p className="mt-1 text-xs text-fg-subtle">
          Tables: see the{" "}
          <a className="underline" href="https://osquery.io/schema/" target="_blank" rel="noreferrer">
            osquery schema
          </a>
          . One SELECT statement.
        </p>
        <div className="mt-3 grid gap-3 sm:grid-cols-[auto_1fr_auto] sm:items-end">
          <Field label="Devices">
            <div className="flex gap-2">
              <Select value={target} onChange={(e) => setTarget(e.target.value as "all" | "group")} aria-label="Target">
                <option value="all">All devices</option>
                <option value="group">A group&apos;s devices</option>
              </Select>
              {target === "group" ? (
                <Select value={groupId} onChange={(e) => setGroupId(e.target.value)} aria-label="Group">
                  <option value="">Choose a group</option>
                  {groups.data?.data.map((g) => (
                    <option key={g.id} value={g.id}>
                      {g.name}
                    </option>
                  ))}
                </Select>
              ) : null}
            </div>
          </Field>
          <Field label="Why (goes in the audit log)">
            <Input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="e.g. Checking who still runs Chrome 120 (CVE-2026-…)" />
          </Field>
          <Button variant="primary" loading={run.isPending} disabled={!sql.trim() || reason.trim().length < 3 || (target === "group" && !groupId)} onClick={() => run.mutate()}>
            <Play /> Run
          </Button>
        </div>
        {run.error ? (
          <div className="mt-3">
            <ErrorBanner error={run.error} />
          </div>
        ) : null}
      </Card>

      {current ? <Results id={current} /> : null}

      <Card className="mt-5 overflow-hidden">
        <CardHeader title="Recent queries" />
        {history.data?.data.length ? (
          <Table>
            <THead>
              <tr>
                <TH>Query</TH>
                <TH>By</TH>
                <TH className="text-right">Devices</TH>
                <TH>When</TH>
              </tr>
            </THead>
            <tbody>
              {history.data.data.map((h) => (
                <TR key={h.id} className={cn("cursor-pointer", current === h.id && "bg-primary-soft/40")} onClick={() => setCurrent(h.id)}>
                  <TD className="max-w-[32rem]">
                    <code className="block truncate font-mono text-xs">{h.sql}</code>
                    <span className="text-xs text-fg-subtle">{h.reason}</span>
                  </TD>
                  <TD className="text-fg-muted">{h.requested_by ?? "—"}</TD>
                  <TD className="text-right tabular-nums">
                    {h.done}/{h.devices}
                    {h.failed ? <span className="block text-xs text-danger">{h.failed} failed</span> : null}
                  </TD>
                  <TD className="whitespace-nowrap text-fg-muted">{timeAgo(h.created_at)}</TD>
                </TR>
              ))}
            </tbody>
          </Table>
        ) : (
          <EmptyState icon={<TerminalSquare className="size-5" />} title="No queries yet" />
        )}
      </Card>
    </>
  );
}

function Results({ id }: { id: string }) {
  const [view, setView] = useState<"rows" | "devices">("rows");
  const r = useQuery({
    queryKey: ["live-query", id],
    queryFn: () => unwrap(api.GET("/v1/live-queries/{id}", { params: { path: { id } } })),
    refetchInterval: (q) => (q.state.data && q.state.data.pending === 0 ? false : 3000),
  });
  if (r.isPending) return <Skeleton className="h-40" />;
  if (!r.data) return <ErrorBanner error={r.error} />;
  const d = r.data;
  return (
    <Card className="overflow-hidden">
      <CardHeader
        title="Results"
        description={
          <>
            {d.done} of {d.devices} answered{d.failed ? `, ${d.failed} failed` : ""}
            {d.pending ? ` · waiting for ${pluralize(d.pending, "device")} (they answer on their next check-in)` : ""}
          </>
        }
        actions={
          <div className="inline-flex shrink-0 rounded-md border border-border p-0.5" role="radiogroup" aria-label="View">
            {(["rows", "devices"] as const).map((v) => (
              <button key={v} type="button" role="radio" aria-checked={view === v} onClick={() => setView(v)} className={cn("whitespace-nowrap rounded px-2.5 py-1 text-xs font-medium", view === v ? "bg-primary text-white" : "text-fg-muted hover:bg-bg-subtle")}>
                {v === "rows" ? `Rows (${d.rows.length})` : `Devices (${d.devices})`}
              </button>
            ))}
          </div>
        }
      />
      {view === "rows" ? (
        <RowsTable rows={d.rows} columns={d.rows.length ? ["_device", ...d.columns] : undefined} file={`live-query-${id.slice(0, 8)}`} empty={d.pending ? "Waiting for devices…" : "No rows"} />
      ) : (
        <Table>
          <THead>
            <tr>
              <TH>Device</TH>
              <TH>Status</TH>
              <TH className="text-right">Rows</TH>
            </tr>
          </THead>
          <tbody>
            {d.results.map((x) => (
              <TR key={x.device_id}>
                <TD className="font-medium">{x.hostname}</TD>
                <TD>
                  <StatusPill tone={x.status === "done" ? "success" : x.status === "failed" || x.status === "expired" ? "danger" : "neutral"}>
                    {x.status === "done" ? "Answered" : x.status === "expired" ? "Didn't check in" : x.status === "failed" ? "Failed" : "Waiting"}
                  </StatusPill>
                  {x.message ? <p className="mt-0.5 text-xs text-fg-muted">{x.message}</p> : null}
                </TD>
                <TD className="text-right tabular-nums">
                  {x.rows}
                  {x.truncated ? " (first 1,000)" : ""}
                </TD>
              </TR>
            ))}
          </tbody>
        </Table>
      )}
    </Card>
  );
}
