"use client";

import type { Schemas } from "@nexus/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Play, Plus, TerminalSquare } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { useStepUp } from "@/components/step-up";
import { Button } from "@/components/ui/button";
import { Field, Input, Select } from "@/components/ui/input";
import { Card, CardHeader, EmptyState, ErrorBanner, PageHeader, StatusPill } from "@/components/ui/misc";
import { Dialog, DialogContent } from "@/components/ui/overlay";
import { api, unwrap } from "@/lib/api";
import { useCan } from "@/lib/queries";
import { timeAgo } from "@/lib/utils";

type Script = Schemas["DeviceScript"];
const SHELLS = [
  ["bash", "bash (macOS, Linux)"],
  ["zsh", "zsh (macOS, Linux)"],
  ["sh", "sh (macOS, Linux)"],
  ["powershell", "PowerShell (Windows)"],
] as const;

export default function ScriptsPage() {
  const can = useCan();
  const qc = useQueryClient();
  const scripts = useQuery({ queryKey: ["device-scripts"], queryFn: () => unwrap(api.GET("/v1/device-scripts")), enabled: can("devices:scripts") });
  const runs = useQuery({ queryKey: ["script-runs"], queryFn: () => unwrap(api.GET("/v1/script-runs")), enabled: can("devices:scripts"), refetchInterval: 15_000 });
  const [editing, setEditing] = useState<Partial<Script> | null>(null);
  const [running, setRunning] = useState<Script | null>(null);
  const [openRun, setOpenRun] = useState<string | null>(null);
  if (!can("devices:scripts")) return <PageHeader title="Scripts" description="Only owners and admins can run scripts on devices." />;
  return (
    <>
      <PageHeader
        title="Scripts"
        description="Run scripts on devices as root or SYSTEM: sent as commands signed with your organization's key (the agent refuses anything else), picked up at the next check-in (offline devices within a day), with each device's exit code and output back here. Every run is in the audit log."
        actions={
          <Button variant="primary" onClick={() => setEditing({ shell: "bash", name: "", body: "", description: "" })}>
            <Plus className="size-4" /> New script
          </Button>
        }
      />
      <div className="space-y-5">
        <Card className="overflow-hidden">
          <CardHeader title="Library" />
          {scripts.data?.data.length ? (
            <ul className="divide-y divide-border">
              {scripts.data.data.map((s) => (
                <li key={s.id} className="flex items-center justify-between gap-3 px-4 py-2.5 text-[13px]">
                  <button type="button" className="min-w-0 text-left" onClick={() => setEditing(s)}>
                    <span className="font-medium">{s.name}</span> <span className="text-xs text-fg-muted">{s.shell}</span>
                    {s.description ? <span className="block text-xs text-fg-muted">{s.description}</span> : null}
                  </button>
                  <Button size="sm" onClick={() => setRunning(s)}>
                    <Play className="size-3.5" /> Run
                  </Button>
                </li>
              ))}
            </ul>
          ) : (
            <EmptyState icon={<TerminalSquare className="size-5" />} title="No scripts yet" description="Save the scripts you run often: they're versioned by what runs (each run keeps its own copy)." />
          )}
        </Card>

        <Card className="overflow-hidden">
          <CardHeader title="Recent runs" />
          {runs.data?.data.length ? (
            <ul className="divide-y divide-border">
              {runs.data.data.map((r) => (
                <li key={r.id}>
                  <button type="button" className="flex w-full items-center justify-between gap-3 px-4 py-2.5 text-left text-[13px] hover:bg-bg-subtle" onClick={() => setOpenRun(r.id)}>
                    <span className="min-w-0">
                      <span className="font-medium">{r.name}</span> <span className="text-xs text-fg-muted">· {r.reason}</span>
                      <span className="block text-xs text-fg-muted">
                        {r.requested_by ?? "someone"} · {timeAgo(r.created_at)}
                      </span>
                    </span>
                    <span className="flex shrink-0 gap-1.5">
                      {r.succeeded ? <StatusPill tone="success">{r.succeeded} ok</StatusPill> : null}
                      {r.failed ? <StatusPill tone="danger">{r.failed} failed</StatusPill> : null}
                      {r.pending ? <StatusPill>{r.pending} waiting</StatusPill> : null}
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          ) : (
            <p className="px-4 pb-4 text-[13px] text-fg-muted">No runs yet.</p>
          )}
        </Card>
      </div>

      {editing ? <ScriptEditor script={editing} onClose={() => setEditing(null)} onSaved={() => (qc.invalidateQueries({ queryKey: ["device-scripts"] }), setEditing(null))} /> : null}
      {running ? <RunDialog script={running} onClose={() => setRunning(null)} onStarted={(id) => (qc.invalidateQueries({ queryKey: ["script-runs"] }), setRunning(null), setOpenRun(id))} /> : null}
      {openRun ? <RunResults id={openRun} onClose={() => setOpenRun(null)} /> : null}
    </>
  );
}

function ScriptEditor({ script, onClose, onSaved }: { script: Partial<Script>; onClose: () => void; onSaved: () => void }) {
  const [draft, setDraft] = useState({ name: script.name ?? "", description: script.description ?? "", shell: (script.shell ?? "bash") as Script["shell"], body: script.body ?? "" });
  const save = useMutation({
    mutationFn: () => (script.id ? unwrap(api.PUT("/v1/device-scripts/{id}", { params: { path: { id: script.id } }, body: draft })) : unwrap(api.POST("/v1/device-scripts", { body: draft }))),
    onSuccess: () => (toast.success("Saved"), onSaved()),
  });
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent title={script.id ? "Edit script" : "New script"} className="max-w-2xl">
        <form className="space-y-3" onSubmit={(e) => (e.preventDefault(), save.mutate())}>
          <ErrorBanner error={save.error} />
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="Name" htmlFor="name">
              <Input id="name" value={draft.name} onChange={(e) => setDraft({ ...draft, name: e.target.value })} autoFocus />
            </Field>
            <Field label="Shell" htmlFor="shell">
              <Select id="shell" value={draft.shell} onChange={(e) => setDraft({ ...draft, shell: e.target.value as Script["shell"] })}>
                {SHELLS.map(([v, l]) => (
                  <option key={v} value={v}>
                    {l}
                  </option>
                ))}
              </Select>
            </Field>
          </div>
          <Field label="Description" htmlFor="desc">
            <Input id="desc" value={draft.description} onChange={(e) => setDraft({ ...draft, description: e.target.value })} />
          </Field>
          <Field label="Script" htmlFor="body" hint="Runs as root (macOS, Linux) or SYSTEM (Windows). Output is kept up to 64 KB.">
            <textarea id="body" rows={12} spellCheck={false} className="w-full rounded-md border border-border bg-bg-subtle p-2.5 font-mono text-xs" value={draft.body} onChange={(e) => setDraft({ ...draft, body: e.target.value })} />
          </Field>
          <div className="flex justify-end gap-2">
            <Button type="button" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" variant="primary" loading={save.isPending} disabled={!draft.name || !draft.body}>
              Save
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function RunDialog({ script, onClose, onStarted }: { script: Script; onClose: () => void; onStarted: (id: string) => void }) {
  const withStepUp = useStepUp();
  const groups = useQuery({ queryKey: ["groups", {}], queryFn: () => unwrap(api.GET("/v1/groups")) });
  const [groupId, setGroupId] = useState("");
  const [reason, setReason] = useState("");
  const run = useMutation({
    mutationFn: () =>
      withStepUp(() => unwrap(api.POST("/v1/script-runs", { body: { script_id: script.id, reason, target: groupId ? { group_id: groupId } : { all: true }, timeout_seconds: 300 } }))),
    onSuccess: (r) => {
      toast.success(`Sent to ${r.devices} device${r.devices === 1 ? "" : "s"}${r.skipped_incompatible ? ` (${r.skipped_incompatible} can't run ${script.shell})` : ""}`);
      onStarted(r.id);
    },
  });
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent title={`Run ${script.name}`} description="It runs as root or SYSTEM on each device at its next check-in.">
        <form className="space-y-3" onSubmit={(e) => (e.preventDefault(), run.mutate())}>
          <ErrorBanner error={run.error} />
          <Field label="On" htmlFor="target">
            <Select id="target" value={groupId} onChange={(e) => setGroupId(e.target.value)}>
              <option value="">Every device that can run {script.shell}</option>
              {(groups.data?.data ?? []).map((g) => (
                <option key={g.id} value={g.id}>
                  Devices of people in {g.name}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="Reason" htmlFor="reason" hint="Saved to the audit log.">
            <Input id="reason" value={reason} onChange={(e) => setReason(e.target.value)} placeholder="e.g. Check free disk space before the upgrade" />
          </Field>
          <div className="flex justify-end gap-2">
            <Button type="button" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" variant="primary" loading={run.isPending} disabled={reason.trim().length < 3}>
              Run
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function RunResults({ id, onClose }: { id: string; onClose: () => void }) {
  const q = useQuery({ queryKey: ["script-run", id], queryFn: () => unwrap(api.GET("/v1/script-runs/{id}", { params: { path: { id } } })), refetchInterval: 10_000 });
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent title={q.data ? `${q.data.name}: ${q.data.succeeded} ok, ${q.data.failed} failed, ${q.data.pending} waiting` : "Loading…"} className="max-w-3xl">
        <div className="max-h-[70vh] space-y-3 overflow-y-auto">
          {q.data?.results.map((r) => (
            <div key={r.device_id} className="rounded-md border border-border">
              <div className="flex items-center justify-between px-3 py-2 text-[13px]">
                <span className="font-medium">{r.hostname}</span>
                <span className="text-xs text-fg-muted">
                  {r.status === "queued" || r.status === "sent" ? "waiting for the device" : `exit ${r.exit_code ?? "?"}${r.duration_ms !== null ? ` · ${(r.duration_ms / 1000).toFixed(1)} s` : ""}${r.finished_at ? ` · ${timeAgo(r.finished_at)}` : ""}`}
                </span>
              </div>
              {r.output ? (
                <pre className="max-h-64 overflow-auto border-t border-border bg-bg-subtle px-3 py-2 font-mono text-[11px] whitespace-pre-wrap">
                  {r.output}
                  {r.truncated ? "\n… (output truncated at 64 KB)" : ""}
                </pre>
              ) : null}
            </div>
          ))}
        </div>
      </DialogContent>
    </Dialog>
  );
}
