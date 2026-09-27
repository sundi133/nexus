"use client";

import type { Schemas } from "@nexus/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Download, RefreshCcwDot, Settings2 } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { toast } from "sonner";
import { useStepUp } from "@/components/step-up";
import { Button } from "@/components/ui/button";
import { Field, Input, Select } from "@/components/ui/input";
import { Card, CardHeader, EmptyState, ErrorBanner, PageHeader, Skeleton, StatusPill } from "@/components/ui/misc";
import { Dialog, DialogContent } from "@/components/ui/overlay";
import { Table, TD, TH, THead, TR } from "@/components/ui/table";
import { api, unwrap } from "@/lib/api";
import { useCan } from "@/lib/queries";
import { pluralize, timeAgo } from "@/lib/utils";

type Policy = Schemas["PatchPolicy"];
type Row = Schemas["DeviceUpdatesRow"];
const hour = (h: number) => `${String(h).padStart(2, "0")}:00`;
const INSTALL: Record<string, { label: string; tone: "success" | "danger" | "neutral" | "warning" }> = {
  queued: { label: "install queued", tone: "neutral" },
  sent: { label: "installing", tone: "warning" },
  done: { label: "installed", tone: "success" },
  failed: { label: "install failed", tone: "danger" },
  expired: { label: "install expired", tone: "neutral" },
  canceled: { label: "install canceled", tone: "neutral" },
};

export default function UpdatesPage() {
  const can = useCan();
  const fleet = useQuery({ queryKey: ["device-updates"], queryFn: () => unwrap(api.GET("/v1/device-updates")), refetchInterval: 30_000 });
  const [editing, setEditing] = useState(false);
  const [installing, setInstalling] = useState<Row[] | "all" | null>(null);
  const [open, setOpen] = useState<Row | null>(null);
  const s = fleet.data?.summary;
  const p = fleet.data?.policy;

  return (
    <>
      <PageHeader
        title="OS updates"
        description="Pending operating-system updates on each device (Software Update, Windows Update, apt or dnf), checked by the agent every few hours. Install them now, or let the patch policy install them once they've waited past its deadline, inside a maintenance window."
        actions={
          can("devices:updates") ? (
            <Button variant="primary" onClick={() => setInstalling("all")} disabled={!s?.with_security && !fleet.data?.data.some((d) => d.pending || d.apps_pending)}>
              <Download className="size-4" /> Install updates
            </Button>
          ) : null
        }
      />
      {fleet.isPending ? (
        <Skeleton className="h-64" />
      ) : !fleet.data || !s || !p ? (
        <ErrorBanner error={fleet.error} />
      ) : (
        <div className="space-y-5">
          <div className="grid gap-3 sm:grid-cols-3 lg:grid-cols-5">
            <Tile label="Up to date" value={s.up_to_date} of={s.reporting} />
            <Tile label="Security updates pending" value={s.with_security} tone={s.with_security ? "warning" : undefined} />
            <Tile label="Apps out of date" value={s.apps_outdated} tone={s.apps_outdated ? "warning" : undefined} hint="Chrome, Zoom, Slack…" />
            <Tile label="Past the deadline" value={s.overdue} tone={s.overdue ? "danger" : undefined} hint={p.enabled ? `${pluralize(p.deadline_days, "day")} for ${p.scope === "security" ? "security updates" : "all updates"}` : "no patch policy"} />
            <Tile label="Not reporting" value={s.devices - s.reporting + s.failing_checks} hint={s.failing_checks ? `${s.failing_checks} failing to check` : "need agent 0.2 or later"} />
          </div>

          <Card>
            <CardHeader
              title="Patch policy"
              description={
                p.enabled
                  ? `Installs ${p.scope === "security" ? "security updates" : "all updates"}${p.third_party ? " and app updates" : ""} pending more than ${pluralize(p.deadline_days, "day")}, on online devices between ${hour(p.window_start)} and ${hour(p.window_end)} (${p.timezone})${p.window_start === p.window_end ? ", any time" : ""}. ${p.restart === "if_needed" ? "Restarts when the update needs it, after warning the signed-in person." : "Never restarts: people restart when they're ready."}`
                  : "Off: updates are installed only when someone clicks Install updates."
              }
              actions={
                can("devices:updates") ? (
                  <Button size="sm" onClick={() => setEditing(true)}>
                    <Settings2 className="size-3.5" /> Change
                  </Button>
                ) : null
              }
            />
          </Card>

          <Card className="overflow-hidden">
            {fleet.data.data.length ? (
              <Table>
                <THead>
                  <tr>
                    <TH>Device</TH>
                    <TH className="text-right">Security</TH>
                    <TH className="text-right">All</TH>
                    <TH className="text-right">Apps</TH>
                    <TH>Pending since</TH>
                    <TH>Last checked</TH>
                    <TH>Last install</TH>
                  </tr>
                </THead>
                <tbody>
                  {fleet.data.data.map((d) => (
                    <TR key={d.device_id} className="cursor-pointer" onClick={() => setOpen(d)}>
                      <TD>
                        <Link href={`/devices/${d.device_id}`} className="font-medium hover:underline" onClick={(e) => e.stopPropagation()}>
                          {d.hostname}
                        </Link>
                        <span className="block text-xs text-fg-muted">
                          {d.platform} {d.os_version}
                        </span>
                      </TD>
                      <TD className="text-right tabular-nums">{d.checked_at ? d.security_pending : "–"}</TD>
                      <TD className="text-right tabular-nums">{d.checked_at ? d.pending : "–"}</TD>
                      <TD className="text-right tabular-nums">{d.checked_at ? d.apps_pending : "–"}</TD>
                      <TD>
                        {(p.scope === "security" ? d.security_since : d.pending_since) ? (
                          <span className="flex items-center gap-1.5">
                            {timeAgo((p.scope === "security" ? d.security_since : d.pending_since)!)}
                            {d.overdue ? <StatusPill tone="danger">overdue</StatusPill> : null}
                          </span>
                        ) : (
                          <span className="text-fg-muted">–</span>
                        )}
                      </TD>
                      <TD className="text-fg-muted">
                        {d.error ? <StatusPill tone="warning">check failed</StatusPill> : d.checked_at ? timeAgo(d.checked_at) : "not reporting"}
                      </TD>
                      <TD>{d.last_install ? <StatusPill tone={INSTALL[d.last_install.status]?.tone ?? "neutral"}>{INSTALL[d.last_install.status]?.label ?? d.last_install.status}</StatusPill> : <span className="text-fg-muted">–</span>}</TD>
                    </TR>
                  ))}
                </tbody>
              </Table>
            ) : (
              <EmptyState icon={<RefreshCcwDot className="size-5" />} title="No devices yet" description="Enroll devices with the Nexus agent: each reports its pending OS updates." />
            )}
          </Card>
        </div>
      )}

      {editing && p ? <PolicyEditor policy={p} onClose={() => setEditing(false)} /> : null}
      {installing ? <InstallDialog rows={installing === "all" ? null : installing} onClose={() => setInstalling(null)} /> : null}
      {open ? <DeviceUpdates row={open} canInstall={can("devices:updates")} onInstall={() => (setInstalling([open]), setOpen(null))} onClose={() => setOpen(null)} /> : null}
    </>
  );
}

function Tile({ label, value, of, tone, hint }: { label: string; value: number; of?: number; tone?: "warning" | "danger"; hint?: string }) {
  return (
    <Card className="px-4 py-3">
      <p className="text-xs text-fg-muted">{label}</p>
      <p className={`mt-1 text-2xl font-semibold tabular-nums ${tone === "danger" ? "text-danger" : tone === "warning" ? "text-warning" : ""}`}>
        {value}
        {of !== undefined ? <span className="text-sm font-normal text-fg-muted"> / {of}</span> : null}
      </p>
      {hint ? <p className="text-xs text-fg-subtle">{hint}</p> : null}
    </Card>
  );
}

function PolicyEditor({ policy, onClose }: { policy: Policy; onClose: () => void }) {
  const qc = useQueryClient();
  const withStepUp = useStepUp();
  const [draft, setDraft] = useState<Policy>(policy);
  const save = useMutation({
    mutationFn: () => withStepUp(() => unwrap(api.PUT("/v1/patch-policy", { body: draft }))),
    onSuccess: () => (toast.success("Patch policy saved"), qc.invalidateQueries({ queryKey: ["device-updates"] }), onClose()),
  });
  const hours = Array.from({ length: 24 }, (_, h) => h);
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent title="Patch policy" description="Installs run as signed commands on online devices, inside the window. A failed install is retried after 12 hours.">
        <form className="space-y-3" onSubmit={(e) => (e.preventDefault(), save.mutate())}>
          <ErrorBanner error={save.error} />
          <label className="flex items-center gap-2 text-[13px]">
            <input type="checkbox" checked={draft.enabled} onChange={(e) => setDraft({ ...draft, enabled: e.target.checked })} /> Install updates automatically
          </label>
          <label className="flex items-center gap-2 text-[13px]">
            <input type="checkbox" checked={draft.third_party} onChange={(e) => setDraft({ ...draft, third_party: e.target.checked })} /> Also keep apps up to date (Chrome, Zoom, Slack… on Windows and macOS)
          </label>
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="What" htmlFor="scope">
              <Select id="scope" value={draft.scope} onChange={(e) => setDraft({ ...draft, scope: e.target.value as Policy["scope"] })}>
                <option value="security">Security updates</option>
                <option value="all">All updates</option>
              </Select>
            </Field>
            <Field label="After waiting (days)" htmlFor="deadline" hint="0 installs as soon as they're seen">
              <Input id="deadline" type="number" min={0} max={90} value={draft.deadline_days} onChange={(e) => setDraft({ ...draft, deadline_days: Number(e.target.value) })} />
            </Field>
            <Field label="Window from" htmlFor="ws">
              <Select id="ws" value={draft.window_start} onChange={(e) => setDraft({ ...draft, window_start: Number(e.target.value) })}>
                {hours.map((h) => (
                  <option key={h} value={h}>
                    {hour(h)}
                  </option>
                ))}
              </Select>
            </Field>
            <Field label="Window to" htmlFor="we" hint="Same as from: any time">
              <Select id="we" value={draft.window_end} onChange={(e) => setDraft({ ...draft, window_end: Number(e.target.value) })}>
                {hours.map((h) => (
                  <option key={h} value={h}>
                    {hour(h)}
                  </option>
                ))}
              </Select>
            </Field>
            <Field label="Time zone" htmlFor="tz" hint="e.g. America/New_York">
              <Input id="tz" value={draft.timezone} onChange={(e) => setDraft({ ...draft, timezone: e.target.value })} />
            </Field>
            <Field label="Restart" htmlFor="restart">
              <Select id="restart" value={draft.restart} onChange={(e) => setDraft({ ...draft, restart: e.target.value as Policy["restart"] })}>
                <option value="never">Never</option>
                <option value="if_needed">When the update needs it</option>
              </Select>
            </Field>
          </div>
          <div className="flex justify-end gap-2">
            <Button type="button" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" variant="primary" loading={save.isPending}>
              Save
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function InstallDialog({ rows, onClose }: { rows: Row[] | null; onClose: () => void }) {
  const qc = useQueryClient();
  const withStepUp = useStepUp();
  const groups = useQuery({ queryKey: ["groups", {}], queryFn: () => unwrap(api.GET("/v1/groups")), enabled: !rows });
  const [groupId, setGroupId] = useState("");
  const [scope, setScope] = useState<"security" | "all">("security");
  const [restart, setRestart] = useState<"never" | "if_needed">("never");
  const [apps, setApps] = useState(true);
  const [reason, setReason] = useState("");
  const install = useMutation({
    mutationFn: () =>
      withStepUp(() =>
        unwrap(api.POST("/v1/device-updates/install", { body: { scope, restart, apps, reason, target: rows ? { device_ids: rows.map((r) => r.device_id) } : groupId ? { group_id: groupId } : { all: true } } })),
      ),
    onSuccess: (r) => {
      const skipped = [r.skipped_up_to_date ? `${r.skipped_up_to_date} up to date` : "", r.skipped_in_progress ? `${r.skipped_in_progress} already installing` : "", r.skipped_not_reporting ? `${r.skipped_not_reporting} not reporting` : ""].filter(Boolean).join(", ");
      toast.success(`Installing on ${pluralize(r.queued, "device")}`, { description: skipped || undefined });
      qc.invalidateQueries({ queryKey: ["device-updates"] });
      onClose();
    },
  });
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent title={rows?.length === 1 ? `Install updates on ${rows[0]!.hostname}` : "Install updates"} description="Each device installs at its next check-in (offline devices within a day).">
        <form className="space-y-3" onSubmit={(e) => (e.preventDefault(), install.mutate())}>
          <ErrorBanner error={install.error} />
          {!rows ? (
            <Field label="On" htmlFor="target">
              <Select id="target" value={groupId} onChange={(e) => setGroupId(e.target.value)}>
                <option value="">Every device with updates pending</option>
                {(groups.data?.data ?? []).map((g) => (
                  <option key={g.id} value={g.id}>
                    Devices of people in {g.name}
                  </option>
                ))}
              </Select>
            </Field>
          ) : null}
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="What" htmlFor="iscope">
              <Select id="iscope" value={scope} onChange={(e) => setScope(e.target.value as "security" | "all")}>
                <option value="security">Security updates</option>
                <option value="all">All updates</option>
              </Select>
            </Field>
            <Field label="Restart" htmlFor="irestart">
              <Select id="irestart" value={restart} onChange={(e) => setRestart(e.target.value as "never" | "if_needed")}>
                <option value="never">Never</option>
                <option value="if_needed">When needed</option>
              </Select>
            </Field>
          </div>
          <label className="flex items-center gap-2 text-[13px]">
            <input type="checkbox" checked={apps} onChange={(e) => setApps(e.target.checked)} /> Also update apps (Chrome, Zoom, Slack…). Open apps are skipped.
          </label>
          <Field label="Reason" htmlFor="ireason" hint="Saved to the audit log.">
            <Input id="ireason" value={reason} onChange={(e) => setReason(e.target.value)} placeholder="e.g. Patch the OpenSSH advisory" />
          </Field>
          <div className="flex justify-end gap-2">
            <Button type="button" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" variant="primary" loading={install.isPending} disabled={reason.trim().length < 3}>
              Install
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function DeviceUpdates({ row, canInstall, onInstall, onClose }: { row: Row; canInstall: boolean; onInstall: () => void; onClose: () => void }) {
  const q = useQuery({ queryKey: ["device-updates", row.device_id], queryFn: () => unwrap(api.GET("/v1/devices/{id}/updates", { params: { path: { id: row.device_id } } })) });
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent title={`${row.hostname}: ${pluralize(row.pending, "update")} pending`} description={row.checked_at ? `Checked ${timeAgo(row.checked_at)}` : "This device hasn't reported updates yet."} className="max-w-2xl">
        <div className="max-h-[65vh] space-y-4 overflow-y-auto">
          {row.error ? <p className="rounded-md bg-warning-soft px-3 py-2 text-[13px]">The last check failed: {row.error}</p> : null}
          {q.data?.available.length ? (
            <ul className="divide-y divide-border rounded-md border border-border text-[13px]">
              {q.data.available.map((u) => (
                <li key={`${u.name}-${u.version}`} className="flex items-center justify-between gap-2 px-3 py-1.5">
                  <span className="min-w-0 truncate">
                    {u.name}{" "}
                    {u.version ? (
                      <code className="font-mono text-xs text-fg-muted">
                        {u.current ? `${u.current} → ` : ""}
                        {u.version}
                      </code>
                    ) : null}
                  </span>
                  <span className="flex shrink-0 gap-1">
                    {u.upgrade ? <StatusPill>major upgrade, not installed by patching</StatusPill> : null}
                    {u.third_party ? <StatusPill>app</StatusPill> : null}
                    {u.security ? <StatusPill tone="warning">security</StatusPill> : null}
                    {u.restart ? <StatusPill>restart</StatusPill> : null}
                  </span>
                </li>
              ))}
            </ul>
          ) : q.data ? (
            <p className="text-[13px] text-fg-muted">Nothing pending.</p>
          ) : (
            <Skeleton className="h-24" />
          )}
          {q.data?.installs.length ? (
            <div>
              <p className="mb-1 text-xs font-medium text-fg-muted">Installs</p>
              <ul className="space-y-1 text-[13px]">
                {q.data.installs.map((i) => (
                  <li key={i.created_at} className="flex flex-wrap items-center gap-2">
                    <StatusPill tone={INSTALL[i.status]?.tone ?? "neutral"}>{INSTALL[i.status]?.label ?? i.status}</StatusPill>
                    <span className="text-fg-muted">
                      {i.automatic ? "patch policy" : (i.requested_by ?? "someone")} · {timeAgo(i.created_at)}
                    </span>
                    {i.output ? <span className="text-xs text-fg-subtle">{i.output}</span> : null}
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
        </div>
        {canInstall && row.pending ? (
          <div className="mt-3 flex justify-end">
            <Button variant="primary" onClick={onInstall}>
              <Download className="size-4" /> Install updates
            </Button>
          </div>
        ) : null}
      </DialogContent>
    </Dialog>
  );
}
