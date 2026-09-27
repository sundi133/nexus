"use client";

import type { Schemas } from "@nexus/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { PackagePlus, Plus, Trash2, Users } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { toast } from "sonner";
import { useStepUp } from "@/components/step-up";
import { Button } from "@/components/ui/button";
import { Field, Input, Select } from "@/components/ui/input";
import { Card, EmptyState, ErrorBanner, PageHeader, Skeleton, StatusPill } from "@/components/ui/misc";
import { Dialog, DialogContent } from "@/components/ui/overlay";
import { api, unwrap } from "@/lib/api";
import { useCan } from "@/lib/queries";
import { timeAgo } from "@/lib/utils";

type Pkg = Schemas["SoftwarePackage"];
type Kind = Pkg["kind"];
const KINDS: { kind: Kind; label: string; ref: string; placeholder: string; download: boolean }[] = [
  { kind: "winget", label: "Windows · winget", ref: "winget package ID", placeholder: "Zoom.Zoom", download: false },
  { kind: "msi", label: "Windows · MSI", ref: "ProductCode", placeholder: "{12345678-1234-1234-1234-123456789012}", download: true },
  { kind: "pkg", label: "macOS · .pkg", ref: "Package receipt ID (pkgutil --pkgs)", placeholder: "us.zoom.pkg.videomeeting", download: true },
  { kind: "apt", label: "Linux · apt", ref: "Package name", placeholder: "htop", download: false },
  { kind: "dnf", label: "Linux · dnf", ref: "Package name", placeholder: "htop", download: false },
];
const kindOf = (k: Kind) => KINDS.find((x) => x.kind === k)!;
const STATUS: Record<string, { label: string; tone: "success" | "danger" | "neutral" | "warning" }> = {
  installed: { label: "installed", tone: "success" },
  absent: { label: "not installed", tone: "neutral" },
  failed: { label: "failed", tone: "danger" },
  unsupported: { label: "unsupported", tone: "warning" },
  pending: { label: "waiting for the device", tone: "neutral" },
};

export default function AppDeploymentPage() {
  const can = useCan();
  const pkgs = useQuery({ queryKey: ["software-packages"], queryFn: () => unwrap(api.GET("/v1/software-packages")), refetchInterval: 30_000 });
  const [editing, setEditing] = useState<Partial<Pkg> | null>(null);
  const [assigning, setAssigning] = useState<Pkg | null>(null);
  const [open, setOpen] = useState<Pkg | null>(null);
  const manage = can("devices:software");

  return (
    <>
      <PageHeader
        title="App deployment"
        description="Install and remove apps on devices: winget and MSI on Windows, .pkg on macOS, apt and dnf on Linux. Each device gets its apps in its signed policy, installs them as root/SYSTEM in the background, re-checks hourly (so a removed app comes back), and reports back here. Downloads must match the SHA-256 you give."
        actions={
          manage ? (
            <Button variant="primary" onClick={() => setEditing({ kind: "winget", name: "", ref: "", url: "", sha256: "", args: [], description: "" })}>
              <Plus className="size-4" /> Add app
            </Button>
          ) : null
        }
      />
      {pkgs.isPending ? (
        <Skeleton className="h-64" />
      ) : !pkgs.data ? (
        <ErrorBanner error={pkgs.error} />
      ) : !pkgs.data.data.length ? (
        <Card>
          <EmptyState icon={<PackagePlus className="size-5" />} title="No apps yet" description="Add the apps your teams need, then assign them to everyone or to a group." />
        </Card>
      ) : (
        <Card className="overflow-hidden">
          <ul className="divide-y divide-border">
            {pkgs.data.data.map((p) => (
              <li key={p.id} className="flex flex-wrap items-center justify-between gap-3 px-4 py-3 text-[13px]">
                <button type="button" className="min-w-0 text-left" onClick={() => setOpen(p)}>
                  <span className="font-medium">{p.name}</span> <span className="text-xs text-fg-muted">{kindOf(p.kind).label}</span>
                  <span className="block font-mono text-xs text-fg-subtle">{p.ref}</span>
                  <span className="mt-1 flex flex-wrap gap-1.5">
                    {p.assignments.length ? (
                      p.assignments.map((a) => (
                        <span key={a.id} className="rounded bg-bg-subtle px-1.5 py-0.5 text-xs text-fg-muted">
                          {a.action === "install" ? "Install" : "Remove"} · {a.group_name ?? `every ${p.platform === "macos" ? "Mac" : p.platform === "windows" ? "Windows PC" : "Linux device"}`}
                        </span>
                      ))
                    ) : (
                      <span className="text-xs text-fg-subtle">Not assigned</span>
                    )}
                  </span>
                </button>
                <span className="flex shrink-0 flex-wrap items-center gap-1.5">
                  {p.counts.installed ? <StatusPill tone="success">{p.counts.installed} installed</StatusPill> : null}
                  {p.counts.absent ? <StatusPill>{p.counts.absent} not installed</StatusPill> : null}
                  {p.counts.failed ? <StatusPill tone="danger">{p.counts.failed} failed</StatusPill> : null}
                  {p.counts.unsupported ? <StatusPill tone="warning">{p.counts.unsupported} unsupported</StatusPill> : null}
                  {p.counts.pending ? <StatusPill>{p.counts.pending} waiting</StatusPill> : null}
                  {manage ? (
                    <>
                      <Button size="sm" onClick={() => setAssigning(p)}>
                        <Users className="size-3.5" /> Assign
                      </Button>
                      <Button size="sm" onClick={() => setEditing(p)}>
                        Edit
                      </Button>
                    </>
                  ) : null}
                </span>
              </li>
            ))}
          </ul>
        </Card>
      )}
      {editing ? <PackageEditor pkg={editing} onClose={() => setEditing(null)} /> : null}
      {assigning ? <AssignDialog pkg={assigning} onClose={() => setAssigning(null)} /> : null}
      {open ? <PackageDevices pkg={open} manage={manage} onClose={() => setOpen(null)} /> : null}
    </>
  );
}

function PackageEditor({ pkg, onClose }: { pkg: Partial<Pkg>; onClose: () => void }) {
  const qc = useQueryClient();
  const withStepUp = useStepUp();
  const [d, setD] = useState({ name: pkg.name ?? "", description: pkg.description ?? "", kind: (pkg.kind ?? "winget") as Kind, ref: pkg.ref ?? "", url: pkg.url ?? "", sha256: pkg.sha256 ?? "", args: (pkg.args ?? []).join("\n") });
  const k = kindOf(d.kind);
  const body = () => ({ name: d.name, description: d.description, kind: d.kind, ref: d.ref, url: k.download ? d.url : "", sha256: k.download ? d.sha256 : "", args: d.args.split("\n").map((a) => a.trim()).filter(Boolean) });
  const save = useMutation({
    mutationFn: () => withStepUp(() => (pkg.id ? unwrap(api.PUT("/v1/software-packages/{id}", { params: { path: { id: pkg.id } }, body: body() })) : unwrap(api.POST("/v1/software-packages", { body: body() })))),
    onSuccess: () => (toast.success("Saved", { description: "Devices pick it up at their next check-in." }), qc.invalidateQueries({ queryKey: ["software-packages"] }), onClose()),
  });
  const del = useMutation({
    mutationFn: () => withStepUp(() => unwrap(api.DELETE("/v1/software-packages/{id}", { params: { path: { id: pkg.id! } } }))),
    onSuccess: () => (toast.success("Removed from the catalog", { description: "Devices keep what they installed." }), qc.invalidateQueries({ queryKey: ["software-packages"] }), onClose()),
  });
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent title={pkg.id ? `Edit ${pkg.name}` : "Add app"} className="max-w-xl">
        <form className="space-y-3" onSubmit={(e) => (e.preventDefault(), save.mutate())}>
          <ErrorBanner error={save.error ?? del.error} />
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="Name" htmlFor="name">
              <Input id="name" value={d.name} onChange={(e) => setD({ ...d, name: e.target.value })} autoFocus />
            </Field>
            <Field label="Type" htmlFor="kind">
              <Select id="kind" value={d.kind} onChange={(e) => setD({ ...d, kind: e.target.value as Kind })}>
                {KINDS.map((x) => (
                  <option key={x.kind} value={x.kind}>
                    {x.label}
                  </option>
                ))}
              </Select>
            </Field>
          </div>
          <Field label={k.ref} htmlFor="ref" hint="How the agent tells whether it's installed.">
            <Input id="ref" className="font-mono" value={d.ref} placeholder={k.placeholder} onChange={(e) => setD({ ...d, ref: e.target.value })} />
          </Field>
          {k.download ? (
            <>
              <Field label="Installer URL" htmlFor="url" hint="https only.">
                <Input id="url" value={d.url} placeholder="https://downloads.example.com/app.msi" onChange={(e) => setD({ ...d, url: e.target.value })} />
              </Field>
              <Field label="SHA-256" htmlFor="sha" hint="shasum -a 256 (macOS) or Get-FileHash (Windows). The agent won't install a download that doesn't match.">
                <Input id="sha" className="font-mono text-xs" value={d.sha256} onChange={(e) => setD({ ...d, sha256: e.target.value.trim() })} />
              </Field>
            </>
          ) : null}
          <Field label="Extra installer arguments" htmlFor="args" hint="One per line, e.g. ALLUSERS=1 for an MSI. Optional.">
            <textarea id="args" rows={2} spellCheck={false} className="w-full rounded-md border border-border bg-bg-subtle p-2 font-mono text-xs" value={d.args} onChange={(e) => setD({ ...d, args: e.target.value })} />
          </Field>
          <div className="flex items-center justify-between gap-2">
            {pkg.id ? (
              <Button type="button" variant="danger-outline" loading={del.isPending} onClick={() => del.mutate()}>
                <Trash2 className="size-3.5" /> Remove from catalog
              </Button>
            ) : (
              <span />
            )}
            <div className="flex gap-2">
              <Button type="button" onClick={onClose}>
                Cancel
              </Button>
              <Button type="submit" variant="primary" loading={save.isPending} disabled={!d.name || !d.ref}>
                Save
              </Button>
            </div>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function AssignDialog({ pkg, onClose }: { pkg: Pkg; onClose: () => void }) {
  const qc = useQueryClient();
  const withStepUp = useStepUp();
  const groups = useQuery({ queryKey: ["groups", {}], queryFn: () => unwrap(api.GET("/v1/groups")) });
  const [groupId, setGroupId] = useState("");
  const [action, setAction] = useState<"install" | "remove">("install");
  const refresh = () => qc.invalidateQueries({ queryKey: ["software-packages"] });
  const add = useMutation({
    mutationFn: () => withStepUp(() => unwrap(api.POST("/v1/software-packages/{id}/assignments", { params: { path: { id: pkg.id } }, body: { action, group_id: groupId || null } }))),
    onSuccess: () => (toast.success(`${pkg.name} assigned`), refresh(), onClose()),
  });
  const drop = useMutation({
    mutationFn: (aid: string) => withStepUp(() => unwrap(api.DELETE("/v1/software-packages/{id}/assignments/{assignment_id}", { params: { path: { id: pkg.id, assignment_id: aid } } }))),
    onSuccess: () => (toast.success("Assignment removed", { description: "Installed copies stay." }), refresh(), onClose()),
  });
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent title={`Assign ${pkg.name}`} description="A group's devices are the ones whose primary user is in the group. Where install and remove both apply, install wins.">
        <form className="space-y-3" onSubmit={(e) => (e.preventDefault(), add.mutate())}>
          <ErrorBanner error={add.error ?? drop.error} />
          {pkg.assignments.length ? (
            <ul className="divide-y divide-border rounded-md border border-border text-[13px]">
              {pkg.assignments.map((a) => (
                <li key={a.id} className="flex items-center justify-between px-3 py-1.5">
                  <span>
                    {a.action === "install" ? "Install on" : "Remove from"} {a.group_name ? `devices of people in ${a.group_name}` : "every device"} <span className="text-xs text-fg-muted">· {timeAgo(a.created_at)}</span>
                  </span>
                  <Button type="button" size="sm" variant="ghost" aria-label="Remove assignment" onClick={() => drop.mutate(a.id)}>
                    <Trash2 className="size-3.5" />
                  </Button>
                </li>
              ))}
            </ul>
          ) : null}
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="Action" htmlFor="action">
              <Select id="action" value={action} onChange={(e) => setAction(e.target.value as "install" | "remove")}>
                <option value="install">Install</option>
                {pkg.kind !== "pkg" ? <option value="remove">Remove</option> : null}
              </Select>
            </Field>
            <Field label="On" htmlFor="group">
              <Select id="group" value={groupId} onChange={(e) => setGroupId(e.target.value)}>
                <option value="">Every device</option>
                {(groups.data?.data ?? []).map((g) => (
                  <option key={g.id} value={g.id}>
                    People in {g.name}
                  </option>
                ))}
              </Select>
            </Field>
          </div>
          <div className="flex justify-end gap-2">
            <Button type="button" onClick={onClose}>
              Close
            </Button>
            <Button type="submit" variant="primary" loading={add.isPending}>
              Assign
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function PackageDevices({ pkg, manage, onClose }: { pkg: Pkg; manage: boolean; onClose: () => void }) {
  const q = useQuery({ queryKey: ["software-package-devices", pkg.id], queryFn: () => unwrap(api.GET("/v1/software-packages/{id}/devices", { params: { path: { id: pkg.id } } })) });
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent title={pkg.name} description={`${kindOf(pkg.kind).label} · ${pkg.ref}`} className="max-w-2xl">
        <div className="max-h-[65vh] overflow-y-auto">
          {q.data?.data.length ? (
            <ul className="divide-y divide-border rounded-md border border-border text-[13px]">
              {q.data.data.map((d) => (
                <li key={d.device_id} className="flex flex-wrap items-center justify-between gap-2 px-3 py-1.5">
                  <span className="min-w-0">
                    <Link href={`/devices/${d.device_id}`} className="font-medium hover:underline">
                      {d.hostname}
                    </Link>{" "}
                    <span className="text-xs text-fg-muted">{d.action === "install" ? "should have it" : "shouldn't have it"}</span>
                    {d.detail ? <span className="block text-xs text-fg-subtle">{d.detail}</span> : null}
                  </span>
                  <span className="flex items-center gap-2">
                    <StatusPill tone={STATUS[d.status]?.tone ?? "neutral"}>{STATUS[d.status]?.label ?? d.status}</StatusPill>
                    {d.updated_at ? <span className="text-xs text-fg-subtle">{timeAgo(d.updated_at)}</span> : null}
                  </span>
                </li>
              ))}
            </ul>
          ) : q.data ? (
            <p className="text-[13px] text-fg-muted">{pkg.assignments.length ? "No devices match its assignments yet." : manage ? "Not assigned yet: use Assign." : "Not assigned yet."}</p>
          ) : (
            <Skeleton className="h-24" />
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}
