"use client";

import type { Schemas } from "@nexus/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, CheckCircle2, CircleSlash, Clock, Info, PackageCheck, Pause, Play, Rocket, SkipForward, Undo2, X } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { useStepUp } from "@/components/step-up";
import { Button } from "@/components/ui/button";
import { Field, Select } from "@/components/ui/input";
import { Card, CardHeader, EmptyState, ErrorBanner, PageHeader, Skeleton, StatusPill, type Tone } from "@/components/ui/misc";
import { Dialog, DialogContent } from "@/components/ui/overlay";
import { api, unwrap } from "@/lib/api";
import { useCan } from "@/lib/queries";
import { cn, formatDateTime, pluralize, timeAgo } from "@/lib/utils";

type Status = Schemas["AgentUpdateStatus"];
type Rollout = NonNullable<Status["rollout"]>;
const KEY = ["agent-updates"];

const STAGE_LABEL: Record<Rollout["stage"], string> = { canary: "Canary", early: "10% of devices", all: "Everyone" };
const STATUS: Record<Rollout["status"], { label: string; tone: Tone }> = {
  active: { label: "Rolling out", tone: "primary" },
  paused: { label: "Paused", tone: "warning" },
  halted: { label: "Halted", tone: "danger" },
  completed: { label: "Completed", tone: "success" },
  cancelled: { label: "Cancelled", tone: "neutral" },
};
const DEVICE_STATE: Record<Rollout["devices"][number]["state"], { label: string; tone: Tone }> = {
  updated: { label: "Updated", tone: "success" },
  offered: { label: "Updating", tone: "primary" },
  waiting: { label: "Waiting for its stage", tone: "neutral" },
  failed: { label: "Failed", tone: "danger" },
  rolled_back: { label: "Rolled back", tone: "danger" },
  unsupported: { label: "No build for this platform", tone: "neutral" },
};

export default function AgentUpdatesPage() {
  const status = useQuery({ queryKey: KEY, queryFn: () => unwrap(api.GET("/v1/agent-updates")), refetchInterval: 15_000 });
  const can = useCan();
  const editable = can("devices:updates");
  const [starting, setStarting] = useState(false);
  const s = status.data;
  const open = s?.rollout && ["active", "paused", "halted"].includes(s.rollout.status);
  const newer = s?.latest && (!s.rollout || s.rollout.version !== s.latest.version);

  return (
    <>
      <PageHeader
        title="Agent updates"
        description="Keep the Nexus agent current on every device: in stages, verified by signature, with automatic rollback."
        actions={
          editable && s?.latest ? (
            <Button variant={newer ? "primary" : "secondary"} onClick={() => setStarting(true)}>
              <Rocket /> {open ? "Start a new rollout" : `Roll out ${s.latest.version}`}
            </Button>
          ) : null
        }
      />
      {status.isPending ? (
        <Skeleton className="h-64" />
      ) : !s ? (
        <ErrorBanner error={status.error} />
      ) : (
        <div className="space-y-4">
          {!s.release_keys_configured ? (
            <Banner tone="warning" icon={<AlertTriangle />}>
              No release signing keys are configured on this server, so no releases are offered. Set <code className="font-mono text-xs">NEXUS_AGENT_RELEASE_KEYS</code>.
            </Banner>
          ) : null}

          <div className="grid gap-4 lg:grid-cols-3">
            <LatestRelease status={s} />
            <Fleet status={s} />
          </div>

          {s.rollout ? <RolloutCard rollout={s.rollout} editable={editable} /> : <NoRollout status={s} />}
          <Settings status={s} editable={editable} />
        </div>
      )}
      {starting && s ? <StartDialog status={s} onClose={() => setStarting(false)} /> : null}
    </>
  );
}

function Banner({ tone, icon, children }: { tone: "warning" | "danger" | "primary"; icon: React.ReactNode; children: React.ReactNode }) {
  const cls = { warning: "border-warning/30 bg-warning-soft", danger: "border-danger/30 bg-danger-soft", primary: "border-primary/20 bg-primary-soft" }[tone];
  const ic = { warning: "text-warning", danger: "text-danger", primary: "text-primary" }[tone];
  return (
    <div className={cn("flex items-start gap-2 rounded-lg border px-4 py-3 text-[13px]", cls)}>
      <span className={cn("mt-0.5 shrink-0 [&_svg]:size-4", ic)}>{icon}</span>
      <div>{children}</div>
    </div>
  );
}

function LatestRelease({ status: s }: { status: Status }) {
  return (
    <Card className="p-4 lg:col-span-1">
      <p className="text-xs font-medium uppercase tracking-wide text-fg-subtle">Latest release</p>
      {s.latest ? (
        <>
          <p className="mt-1 flex items-center gap-2 text-xl font-semibold">
            {s.latest.version} <PackageCheck className="size-4 text-success" aria-label="Signature verified" />
          </p>
          <p className="text-xs text-fg-muted">Published {timeAgo(s.latest.published_at)} · signature verified</p>
          {s.latest.notes ? <p className="mt-2 text-[13px]">{s.latest.notes}</p> : null}
          <p className="mt-2 text-xs text-fg-subtle">{s.latest.platforms.join(" · ")}</p>
        </>
      ) : (
        <p className="mt-2 text-[13px] text-fg-muted">No releases published yet.</p>
      )}
    </Card>
  );
}

function Fleet({ status: s }: { status: Status }) {
  const total = s.fleet.reduce((n, f) => n + f.devices, 0);
  return (
    <Card className="p-4 lg:col-span-2">
      <p className="text-xs font-medium uppercase tracking-wide text-fg-subtle">Agent versions in your fleet</p>
      {total === 0 ? (
        <p className="mt-2 text-[13px] text-fg-muted">No devices enrolled yet.</p>
      ) : (
        <div className="mt-3 space-y-2">
          {s.fleet.map((f) => {
            const current = s.latest && f.version === s.latest.version;
            return (
              <div key={f.version} className="flex items-center gap-3 text-[13px]">
                <span className="w-24 shrink-0 font-mono text-xs">{f.version}</span>
                <div className="h-2 flex-1 overflow-hidden rounded-full bg-bg-muted">
                  <div className={cn("h-full rounded-full", current ? "bg-success" : "bg-fg-subtle")} style={{ width: `${(f.devices / total) * 100}%` }} />
                </div>
                <span className="w-24 shrink-0 text-right text-xs text-fg-muted">{pluralize(f.devices, "device")}</span>
              </div>
            );
          })}
        </div>
      )}
    </Card>
  );
}

function NoRollout({ status: s }: { status: Status }) {
  return (
    <Card>
      <EmptyState
        icon={<Rocket />}
        title="No rollouts yet"
        description={
          s.settings.auto_rollout
            ? "New releases roll out by themselves: canary devices first, then 10% of the fleet, then everyone."
            : "Automatic rollouts are off. Start one when you're ready."
        }
      />
    </Card>
  );
}

function useAction(id: string) {
  const qc = useQueryClient();
  const withStepUp = useStepUp();
  return useMutation({
    mutationFn: (action: "pause" | "resume" | "advance" | "cancel") =>
      withStepUp(() => unwrap(api.POST("/v1/agent-updates/rollouts/{id}/actions", { params: { path: { id } }, body: { action } }))),
    onSuccess: (data, action) => {
      qc.setQueryData(KEY, data);
      toast.success({ pause: "Rollout paused", resume: "Rollout resumed", advance: "Rollout widened", cancel: "Rollout cancelled" }[action]);
    },
  });
}

function RolloutCard({ rollout: r, editable }: { rollout: Rollout; editable: boolean }) {
  const action = useAction(r.id);
  const st = STATUS[r.status];
  const open = ["active", "paused", "halted"].includes(r.status);
  const stageIdx = ["canary", "early", "all"].indexOf(r.stage);

  return (
    <Card>
      <CardHeader
        title={
          <span className="flex items-center gap-2">
            Rollout of {r.version} <StatusPill tone={st.tone}>{st.label}</StatusPill>
          </span>
        }
        description={`Started ${timeAgo(r.created_at)} by ${r.started_by}`}
        actions={
          editable && open ? (
            <div className="flex gap-1.5">
              {r.status === "active" ? (
                <Button size="sm" variant="secondary" loading={action.isPending && action.variables === "pause"} onClick={() => action.mutate("pause")}>
                  <Pause /> Pause
                </Button>
              ) : (
                <Button size="sm" variant="primary" loading={action.isPending && action.variables === "resume"} onClick={() => action.mutate("resume")}>
                  <Play /> Resume
                </Button>
              )}
              {r.stage !== "all" && r.status !== "halted" ? (
                <Button size="sm" variant="secondary" loading={action.isPending && action.variables === "advance"} onClick={() => action.mutate("advance")}>
                  <SkipForward /> Widen now
                </Button>
              ) : null}
              <Button size="sm" variant="ghost" loading={action.isPending && action.variables === "cancel"} onClick={() => action.mutate("cancel")}>
                <X /> Cancel
              </Button>
            </div>
          ) : null
        }
      />
      <div className="space-y-4 p-4">
        {r.status === "halted" ? (
          <Banner tone="danger" icon={<Undo2 />}>
            <p className="font-medium">Stopped spreading: {r.halted_reason}</p>
            <p className="text-fg-muted">
              The device kept (or restored) its previous version by itself, so it keeps working. Resume to continue with the other devices (the failed one won&apos;t be retried), or cancel and wait for a fixed
              release.
            </p>
          </Banner>
        ) : null}
        <ErrorBanner error={action.error} />

        <ol className="grid gap-2 sm:grid-cols-3">
          {r.stages.map((s, i) => {
            const current = i === stageIdx && open;
            const done = i < stageIdx || r.status === "completed";
            return (
              <li key={s.stage} className={cn("rounded-md border p-3", current ? "border-primary bg-primary-soft" : "border-border", !done && !current && "opacity-70")}>
                <p className="flex items-center gap-1.5 text-xs font-medium text-fg-muted">
                  {done ? <CheckCircle2 className="size-3.5 text-success" /> : current ? <Clock className="size-3.5 text-primary" /> : null}
                  {i + 1}. {STAGE_LABEL[s.stage]}
                </p>
                <p className="mt-1 text-[13px]">
                  <span className="font-semibold">{s.updated}</span> of {pluralize(s.devices, "device")} updated
                  {s.failed ? <span className="text-danger"> · {s.failed} failed</span> : null}
                </p>
              </li>
            );
          })}
        </ol>
        {r.status === "active" && r.stage !== "all" ? (
          <p className="text-xs text-fg-muted">
            {r.next_advance_at
              ? `Widens to ${STAGE_LABEL[(["early", "all"] as const)[stageIdx]!].toLowerCase()} ${new Date(r.next_advance_at) > new Date() ? `on ${formatDateTime(r.next_advance_at)}` : "at the next check-in"}, once a device in this stage has updated healthily. Any failure stops it.`
              : "Automatic widening is off: use “Widen now” when you're satisfied."}
          </p>
        ) : null}

        <div className="overflow-hidden rounded-md border border-border">
          <table className="w-full text-[13px]">
            <thead className="bg-bg-subtle text-left text-xs text-fg-muted">
              <tr>
                <th className="px-3 py-2 font-medium">Device</th>
                <th className="px-3 py-2 font-medium">Stage</th>
                <th className="px-3 py-2 font-medium">Agent</th>
                <th className="px-3 py-2 font-medium">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {r.devices.map((d) => (
                <tr key={d.id}>
                  <td className="px-3 py-2 font-medium">{d.hostname}</td>
                  <td className="px-3 py-2 text-fg-muted">{STAGE_LABEL[d.ring]}</td>
                  <td className="px-3 py-2 font-mono text-xs">{d.agent_version || "—"}</td>
                  <td className="px-3 py-2">
                    <StatusPill tone={DEVICE_STATE[d.state].tone}>{DEVICE_STATE[d.state].label}</StatusPill>
                    {d.error ? <p className="mt-1 text-xs text-fg-muted">{d.error}</p> : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </Card>
  );
}

function Settings({ status: s, editable }: { status: Status; editable: boolean }) {
  const qc = useQueryClient();
  const withStepUp = useStepUp();
  const save = useMutation({
    mutationFn: (body: Status["settings"]) => withStepUp(() => unwrap(api.PUT("/v1/agent-updates/settings", { body }))),
    onSuccess: (data) => {
      qc.setQueryData(KEY, data);
      toast.success("Update settings saved");
    },
  });
  const set = (patch: Partial<Status["settings"]>) => save.mutate({ ...s.settings, ...patch });
  return (
    <Card>
      <CardHeader title="Settings" description="How new agent releases reach your devices." />
      <div className="grid gap-4 p-4 sm:grid-cols-2">
        <label className="flex items-start gap-3">
          <input type="checkbox" className="mt-1" checked={s.settings.auto_rollout} disabled={!editable || save.isPending} onChange={(e) => set({ auto_rollout: e.target.checked })} />
          <span>
            <span className="block text-[13px] font-medium">Roll out new releases automatically</span>
            <span className="block text-xs text-fg-muted">Starts with canary devices as soon as a release is published. Off: you start each rollout.</span>
          </span>
        </label>
        <Field label="Widen each stage after" htmlFor="advance">
          <Select id="advance" className="w-full" value={String(s.settings.advance_after_hours)} disabled={!editable || save.isPending} onChange={(e) => set({ advance_after_hours: Number(e.target.value) })}>
            {[4, 12, 24, 48, 72, 168].map((hrs) => (
              <option key={hrs} value={hrs}>
                {hrs < 48 ? `${hrs} hours` : `${hrs / 24} days`} without failures
              </option>
            ))}
            <option value={0}>Never: I widen by hand</option>
          </Select>
        </Field>
      </div>
      <div className="px-4 pb-4">
        <ErrorBanner error={save.error} />
        <p className="flex items-start gap-1.5 text-xs text-fg-subtle">
          <Info className="mt-0.5 size-3.5 shrink-0" />
          Agents only install releases signed by the Nexus release key and refuse downgrades. A new version that crashes or can&apos;t check in within 10 minutes is rolled back on the device, and the rollout halts.
        </p>
      </div>
    </Card>
  );
}

function StartDialog({ status: s, onClose }: { status: Status; onClose: () => void }) {
  const qc = useQueryClient();
  const withStepUp = useStepUp();
  const [version, setVersion] = useState(s.latest?.version ?? "");
  const [canaries, setCanaries] = useState<string[]>([]);
  const devices = useQuery({ queryKey: ["devices", { limit: 200 }], queryFn: () => unwrap(api.GET("/v1/devices", { params: { query: { limit: 200 } } })) });
  const start = useMutation({
    mutationFn: () => withStepUp(() => unwrap(api.POST("/v1/agent-updates/rollouts", { body: { version, ...(canaries.length ? { canary_device_ids: canaries } : {}) } }))),
    onSuccess: (data) => {
      qc.setQueryData(KEY, data);
      toast.success(`Rolling out ${version}`, { description: "Canary devices get it at their next check-in." });
      onClose();
    },
  });
  const open = s.rollout && ["active", "paused", "halted"].includes(s.rollout.status);
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent title="Start a rollout" description="Canary devices update first. Widening to 10% and then everyone follows your settings, and stops at the first failure.">
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            start.mutate();
          }}
        >
          <Field label="Release" htmlFor="rel">
            <Select id="rel" className="w-full" value={version} onChange={(e) => setVersion(e.target.value)}>
              {s.releases.map((r) => (
                <option key={r.version} value={r.version}>
                  {r.version} · {timeAgo(r.published_at)}
                </option>
              ))}
            </Select>
          </Field>
          <fieldset>
            <legend className="mb-1 text-[13px] font-medium">Canary devices</legend>
            <p className="mb-2 text-xs text-fg-muted">Pick machines you can watch, such as IT&apos;s own. None picked: about 1% of the fleet, preferring devices online now.</p>
            <div className="max-h-44 overflow-y-auto rounded-md border border-border">
              {(devices.data?.data ?? []).map((d) => (
                <label key={d.id} className="flex cursor-pointer items-center gap-2 border-b border-border px-3 py-2 text-[13px] last:border-0 hover:bg-bg-subtle">
                  <input type="checkbox" checked={canaries.includes(d.id)} onChange={(e) => setCanaries(e.target.checked ? [...canaries, d.id] : canaries.filter((x) => x !== d.id))} />
                  <span className="flex-1">{d.hostname}</span>
                  <span className="text-[11px] text-fg-subtle">{d.os_name || d.platform}</span>
                </label>
              ))}
            </div>
          </fieldset>
          {open ? (
            <p className="flex items-start gap-1.5 text-xs text-warning">
              <CircleSlash className="mt-0.5 size-3.5 shrink-0" /> This replaces the current rollout of {s.rollout!.version}.
            </p>
          ) : null}
          <ErrorBanner error={start.error} />
          <div className="flex justify-end gap-2 border-t border-border pt-4">
            <Button type="button" variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" variant="primary" loading={start.isPending} disabled={!version}>
              Start rollout
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
