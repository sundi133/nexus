"use client";

import type { paths, Schemas } from "@nexus/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, CheckCircle2, Eye, FolderSync, MoreHorizontal, Plus, RefreshCw, ShieldAlert } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { useStepUp } from "@/components/step-up";
import { Button } from "@/components/ui/button";
import { Field, Input, Select } from "@/components/ui/input";
import { Card, EmptyState, ErrorBanner, PageHeader, Skeleton, StatusPill, type Tone } from "@/components/ui/misc";
import { Dialog, DialogContent, Menu, MenuContent, MenuItem, MenuSeparator, MenuTrigger } from "@/components/ui/overlay";
import { api, unwrap } from "@/lib/api";
import { useCan } from "@/lib/queries";
import { cn, pluralize, timeAgo } from "@/lib/utils";

type Conn = Schemas["DirectoryConnection"];
type Probe = Schemas["DirectoryProbe"];
type ConnPatch = NonNullable<paths["/v1/directory/connections/{id}"]["patch"]["requestBody"]>["content"]["application/json"];
const KEY = ["directory-connections"];
const people = (n: number, adj = "") => `${n.toLocaleString()} ${adj}${n === 1 ? "person" : "people"}`;

const STATUS: Record<Conn["last_status"], { label: string; tone: Tone }> = {
  never: { label: "Not synced yet", tone: "neutral" },
  ok: { label: "Healthy", tone: "success" },
  error: { label: "Failing", tone: "danger" },
  needs_approval: { label: "Needs your approval", tone: "warning" },
};

export default function DirectorySyncPage() {
  const conns = useQuery({
    queryKey: KEY,
    queryFn: () => unwrap(api.GET("/v1/directory/connections")),
    refetchInterval: (q) => (q.state.data?.data.some((c) => c.syncing) ? 2000 : 30_000),
  });
  const can = useCan();
  const editable = can("directory:sync");
  const [connecting, setConnecting] = useState(false);
  const [preview, setPreview] = useState<Conn | null>(null);

  return (
    <>
      <PageHeader
        title="Directory sync"
        description="Keep people and groups in step with Google Workspace or Microsoft Entra ID: joiners get accounts, leavers are suspended."
        actions={
          editable ? (
            <Button variant="primary" onClick={() => setConnecting(true)}>
              <Plus /> Connect a directory
            </Button>
          ) : null
        }
      />
      {conns.isPending ? (
        <Skeleton className="h-48" />
      ) : conns.data?.data.length ? (
        <div className="space-y-4">
          {conns.data.data.map((c) => (
            <ConnectionCard key={c.id} conn={c} editable={editable} onPreview={() => setPreview(c)} />
          ))}
        </div>
      ) : (
        <Card>
          <EmptyState
            icon={<FolderSync />}
            title="No directory connected"
            description="Connect Google Workspace or Microsoft Entra ID and Nexus creates accounts for new hires, keeps names, titles and groups current, and suspends people the moment they leave."
            action={
              editable ? (
                <Button variant="primary" onClick={() => setConnecting(true)}>
                  <Plus /> Connect a directory
                </Button>
              ) : undefined
            }
          />
        </Card>
      )}
      {connecting ? <ConnectDialog onClose={() => setConnecting(false)} onSaved={(c) => (setConnecting(false), setPreview(c))} /> : null}
      {preview ? <PreviewDialog conn={preview} onClose={() => setPreview(null)} /> : null}
    </>
  );
}

function useSync(conn: Conn) {
  const qc = useQueryClient();
  const withStepUp = useStepUp();
  return useMutation({
    mutationFn: (approved?: number) =>
      withStepUp(() => unwrap(api.POST("/v1/directory/connections/{id}/sync", { params: { path: { id: conn.id } }, body: approved === undefined ? {} : { approved_suspensions: approved } }))),
    onSuccess: (r, approved) => {
      qc.setQueryData(KEY, r);
      toast.success(approved === undefined ? `Syncing ${conn.name}` : `Approved: syncing ${conn.name}`);
    },
  });
}

function usePatch(conn: Conn) {
  const qc = useQueryClient();
  const withStepUp = useStepUp();
  return useMutation({
    mutationFn: (body: ConnPatch) =>
      withStepUp(() => unwrap(api.PATCH("/v1/directory/connections/{id}", { params: { path: { id: conn.id } }, body }))),
    onSuccess: (r) => qc.setQueryData(KEY, r),
  });
}

function ConnectionCard({ conn: c, editable, onPreview }: { conn: Conn; editable: boolean; onPreview: () => void }) {
  const qc = useQueryClient();
  const withStepUp = useStepUp();
  const sync = useSync(c);
  const patch = usePatch(c);
  const [settings, setSettings] = useState(false);
  const remove = useMutation({
    mutationFn: () => withStepUp(() => unwrap(api.DELETE("/v1/directory/connections/{id}", { params: { path: { id: c.id } } }))),
    onSuccess: (r) => {
      qc.setQueryData(KEY, r);
      toast.success(`Disconnected ${c.name}`, { description: "People and groups stay; they're just no longer synced." });
    },
  });
  const st = STATUS[c.last_status];
  const summary = (c.last_result as { summary?: Record<string, number> }).summary;
  const held = c.last_status === "needs_approval" ? (c.last_result as { guard: { suspensions: number; threshold: number }; suspend_users: { email: string; reason: string }[] }) : null;
  const skipped = ((c.last_result as { skipped?: { email: string; reason: string }[] }).skipped ?? []).slice(0, 5);

  return (
    <Card>
      <div className="flex flex-wrap items-start gap-3 border-b border-border px-4 py-3">
        <ProviderMark provider={c.provider} />
        <div className="min-w-0 flex-1">
          <p className="flex flex-wrap items-center gap-2 text-[13px] font-semibold">
            {c.name} <StatusPill tone={st.tone}>{st.label}</StatusPill>
            {!c.enabled ? <StatusPill>Scheduled sync off</StatusPill> : null}
            {c.syncing ? (
              <span className="inline-flex items-center gap-1 text-xs font-normal text-primary">
                <RefreshCw className="size-3 animate-spin" /> Syncing…
              </span>
            ) : null}
          </p>
          <p className="text-xs text-fg-muted">
            {c.provider_name} · {c.account} · {people(c.linked_users)} and {pluralize(c.linked_groups, "group")} synced
          </p>
          <p className="text-xs text-fg-subtle">
            {c.last_sync_at ? `Last sync ${timeAgo(c.last_sync_at)}` : "Never synced"}
            {c.enabled && c.next_sync_at ? ` · next ${timeAgo(c.next_sync_at)}` : ""} · every {c.interval_minutes >= 60 ? `${c.interval_minutes / 60} h` : `${c.interval_minutes} min`}
          </p>
        </div>
        {editable ? (
          <div className="flex items-center gap-1.5">
            <Button size="sm" variant="secondary" onClick={onPreview}>
              <Eye /> Preview
            </Button>
            <Button size="sm" variant="secondary" loading={sync.isPending} disabled={c.syncing} onClick={() => sync.mutate(undefined)}>
              <RefreshCw /> Sync now
            </Button>
            <Menu>
              <MenuTrigger asChild>
                <Button size="sm" variant="ghost" aria-label={`Actions for ${c.name}`}>
                  <MoreHorizontal />
                </Button>
              </MenuTrigger>
              <MenuContent>
                <MenuItem onSelect={() => patch.mutate({ enabled: !c.enabled }, { onSuccess: () => toast.success(c.enabled ? "Scheduled sync turned off" : "Scheduled sync turned on") })}>
                  {c.enabled ? "Turn off scheduled sync" : "Turn on scheduled sync"}
                </MenuItem>
                <MenuItem onSelect={() => setSettings(true)}>Settings</MenuItem>
                <MenuSeparator />
                <MenuItem danger onSelect={() => remove.mutate()}>
                  Disconnect
                </MenuItem>
              </MenuContent>
            </Menu>
          </div>
        ) : null}
      </div>
      <div className="space-y-3 p-4">
        <ErrorBanner error={sync.error ?? patch.error ?? remove.error} />
        {c.last_status === "error" ? (
          <div className="flex items-start gap-2 rounded-md border border-danger/30 bg-danger-soft px-3 py-2 text-[13px]">
            <AlertTriangle className="mt-0.5 size-4 shrink-0 text-danger" />
            <div>
              <p className="font-medium">The last sync couldn&apos;t read {c.provider_name}</p>
              <p className="text-fg-muted">{c.last_error}</p>
              <p className="mt-1 text-xs text-fg-muted">Nothing was changed. Check the credentials in Settings, then sync again.</p>
            </div>
          </div>
        ) : null}
        {held ? (
          <div className="rounded-md border border-warning/40 bg-warning-soft px-3 py-3 text-[13px]">
            <p className="flex items-center gap-2 font-medium">
              <ShieldAlert className="size-4 text-warning" /> This sync would suspend {people(held.guard.suspensions)}, more than the safety limit of {held.guard.threshold}.
            </p>
            <p className="mt-1 text-fg-muted">Nothing was changed. If a group or license change upstream caused this, fix it there and sync again. Otherwise approve these suspensions:</p>
            <ul className="mt-2 max-h-40 space-y-0.5 overflow-y-auto rounded border border-border bg-bg px-3 py-2 text-xs">
              {held.suspend_users.map((u) => (
                <li key={u.email} className="flex justify-between gap-3">
                  <span className="font-medium">{u.email}</span>
                  <span className="text-fg-muted">{u.reason}</span>
                </li>
              ))}
            </ul>
            {editable ? (
              <Button size="sm" variant="primary" className="mt-3" loading={sync.isPending} onClick={() => sync.mutate(held.guard.suspensions)}>
                Approve {pluralize(held.guard.suspensions, "suspension")} and sync
              </Button>
            ) : null}
          </div>
        ) : null}
        {summary && c.last_status === "ok" ? (
          <p className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-fg-muted">
            <CheckCircle2 className="size-3.5 text-success" /> Last run:
            <Stat n={summary.create_users} label="created" />
            <Stat n={summary.update_users} label="updated" />
            <Stat n={summary.suspend_users} label="suspended" />
            <Stat n={summary.reactivate_users} label="reactivated" />
            <Stat n={summary.membership_changes} label="group membership changes" />
            {summary.skipped ? <Stat n={summary.skipped} label="skipped" tone="warning" /> : null}
          </p>
        ) : null}
        {skipped.length ? (
          <details className="text-xs text-fg-muted">
            <summary className="cursor-pointer">Why were some people skipped?</summary>
            <ul className="mt-1 space-y-0.5 pl-4">
              {skipped.map((s) => (
                <li key={s.email}>
                  <span className="font-medium text-fg">{s.email}</span>: {s.reason}
                </li>
              ))}
            </ul>
          </details>
        ) : null}
      </div>
      {settings ? <SettingsDialog conn={c} onClose={() => setSettings(false)} /> : null}
    </Card>
  );
}

function Stat({ n, label, tone }: { n: number | undefined; label: string; tone?: "warning" }) {
  return (
    <span className={cn(tone === "warning" && n ? "text-warning" : "")}>
      <span className="font-semibold text-fg">{n ?? 0}</span> {label}
    </span>
  );
}

function ProviderMark({ provider }: { provider: Conn["provider"] }) {
  return (
    <div className={cn("flex size-9 shrink-0 items-center justify-center rounded-md text-xs font-bold text-white", provider === "google" ? "bg-[#1a73e8]" : "bg-[#0078d4]")} aria-hidden>
      {provider === "google" ? "G" : "E"}
    </div>
  );
}

// ---- connect ----------------------------------------------------------------------

const SETUP = {
  google: [
    "In Google Cloud, create a service account and a JSON key for it.",
    "In the Google Admin console → Security → API controls → Domain-wide delegation, add the service account's client ID with these read-only scopes: admin.directory.user.readonly, admin.directory.group.readonly, admin.directory.group.member.readonly.",
    "Enter the email of a Workspace admin for the service account to act as.",
  ],
  entra: [
    "In Microsoft Entra admin center → App registrations, register an app for Nexus.",
    "Under API permissions, add Microsoft Graph application permissions User.Read.All, Group.Read.All and GroupMember.Read.All, then grant admin consent.",
    "Under Certificates & secrets, create a client secret.",
  ],
};

function ConnectDialog({ onClose, onSaved }: { onClose: () => void; onSaved: (c: Conn) => void }) {
  const qc = useQueryClient();
  const withStepUp = useStepUp();
  const [provider, setProvider] = useState<"google" | "entra">("google");
  const [name, setName] = useState("Google Workspace");
  const [adminEmail, setAdminEmail] = useState("");
  const [key, setKey] = useState("");
  const [tenant, setTenant] = useState("");
  const [clientId, setClientId] = useState("");
  const [secret, setSecret] = useState("");
  const [probe, setProbe] = useState<Probe | null>(null);
  const [scope, setScope] = useState<"all" | "groups">("all");
  const [filter, setFilter] = useState<string[]>([]);
  const [syncGroups, setSyncGroups] = useState(true);
  const [deprovision, setDeprovision] = useState<"suspend" | "none">("suspend");
  const [invite, setInvite] = useState(true);

  const creds =
    provider === "google"
      ? ({ provider, admin_email: adminEmail.trim(), service_account_key: key } as const)
      : ({ provider, tenant_id: tenant.trim(), client_id: clientId.trim(), client_secret: secret } as const);
  const test = useMutation({
    mutationFn: () => unwrap(api.POST("/v1/directory/test", { body: creds })),
    onSuccess: setProbe,
    onError: () => setProbe(null),
  });
  const save = useMutation({
    mutationFn: () =>
      withStepUp(() =>
        unwrap(
          api.POST("/v1/directory/connections", {
            body: { ...creds, name: name.trim(), enabled: false, sync_groups: syncGroups, group_filter: scope === "groups" ? filter : [], deprovision, invite_new_users: invite, interval_minutes: 60 },
          }),
        ),
      ),
    onSuccess: (r) => {
      qc.setQueryData(KEY, r);
      const created = r.data.find((c) => c.name === name.trim());
      toast.success(`${name.trim()} connected`, { description: "Nothing has changed yet. Review the preview, then sync." });
      if (created) onSaved(created);
      else onClose();
    },
  });
  const pick = (p: "google" | "entra") => {
    setProvider(p);
    setName(p === "google" ? "Google Workspace" : "Microsoft Entra ID");
    setProbe(null);
    test.reset();
  };

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent title="Connect a directory" description="Nexus only reads your directory. You'll see a preview before anything changes." className="max-w-xl">
        <div className="max-h-[70vh] space-y-5 overflow-y-auto pr-1">
          <div className="grid grid-cols-2 gap-2">
            {(["google", "entra"] as const).map((p) => (
              <button
                key={p}
                type="button"
                onClick={() => pick(p)}
                className={cn("flex items-center gap-2 rounded-md border p-3 text-left text-[13px] font-medium", provider === p ? "border-primary bg-primary-soft" : "border-border hover:bg-bg-subtle")}
              >
                <ProviderMark provider={p} /> {p === "google" ? "Google Workspace" : "Microsoft Entra ID"}
              </button>
            ))}
          </div>

          <ol className="list-decimal space-y-1 pl-5 text-xs text-fg-muted">
            {SETUP[provider].map((s) => (
              <li key={s}>{s}</li>
            ))}
          </ol>

          {provider === "google" ? (
            <>
              <Field label="Admin email" htmlFor="ds-admin" hint="The service account reads the directory as this admin">
                <Input id="ds-admin" type="email" value={adminEmail} onChange={(e) => (setAdminEmail(e.target.value), setProbe(null))} placeholder="it-admin@yourcompany.com" />
              </Field>
              <Field label="Service account key (JSON)" htmlFor="ds-key">
                <textarea
                  id="ds-key"
                  value={key}
                  onChange={(e) => (setKey(e.target.value), setProbe(null))}
                  rows={4}
                  spellCheck={false}
                  placeholder='{"type": "service_account", …}'
                  className="w-full rounded-md border border-border bg-bg px-3 py-2 font-mono text-xs shadow-card focus:border-ring focus:outline-none"
                />
              </Field>
            </>
          ) : (
            <div className="grid gap-3 sm:grid-cols-2">
              <Field label="Tenant ID" htmlFor="ds-tenant">
                <Input id="ds-tenant" value={tenant} onChange={(e) => (setTenant(e.target.value), setProbe(null))} placeholder="00000000-0000-0000-0000-000000000000" />
              </Field>
              <Field label="Application (client) ID" htmlFor="ds-client">
                <Input id="ds-client" value={clientId} onChange={(e) => (setClientId(e.target.value), setProbe(null))} />
              </Field>
              <div className="sm:col-span-2">
                <Field label="Client secret" htmlFor="ds-secret">
                  <Input id="ds-secret" type="password" autoComplete="off" value={secret} onChange={(e) => (setSecret(e.target.value), setProbe(null))} />
                </Field>
              </div>
            </div>
          )}

          <div className="flex items-center gap-3">
            <Button type="button" variant="secondary" loading={test.isPending} onClick={() => test.mutate()}>
              Test connection
            </Button>
            {probe ? (
              <span className="flex items-center gap-1.5 text-[13px] text-success">
                <CheckCircle2 className="size-4" /> Connected: {people(probe.active_users, "active ")} ({probe.users} total), {pluralize(probe.groups.length, "group")}
              </span>
            ) : null}
          </div>
          <ErrorBanner error={test.error} />

          {probe ? (
            <>
              <fieldset className="space-y-2">
                <legend className="mb-1 text-[13px] font-medium">Who to sync</legend>
                <label className="flex items-center gap-2 text-[13px]">
                  <input type="radio" checked={scope === "all"} onChange={() => setScope("all")} /> Everyone in the directory
                </label>
                <label className="flex items-center gap-2 text-[13px]">
                  <input type="radio" checked={scope === "groups"} onChange={() => setScope("groups")} /> Only members of these groups
                </label>
                {scope === "groups" ? (
                  <div className="max-h-40 overflow-y-auto rounded-md border border-border">
                    {probe.groups.map((g) => (
                      <label key={g.id} className="flex cursor-pointer items-center gap-2 border-b border-border px-3 py-1.5 text-[13px] last:border-0 hover:bg-bg-subtle">
                        <input type="checkbox" checked={filter.includes(g.id)} onChange={(e) => setFilter(e.target.checked ? [...filter, g.id] : filter.filter((x) => x !== g.id))} />
                        <span className="flex-1">{g.name}</span>
                        <span className="text-[11px] text-fg-subtle">{pluralize(g.members, "member")}</span>
                      </label>
                    ))}
                  </div>
                ) : null}
              </fieldset>
              <div className="space-y-2 text-[13px]">
                <label className="flex items-start gap-2">
                  <input type="checkbox" className="mt-0.5" checked={syncGroups} onChange={(e) => setSyncGroups(e.target.checked)} />
                  <span>
                    Sync groups and their members <span className="block text-xs text-fg-muted">Use them to assign apps and policies. Their membership follows the directory.</span>
                  </span>
                </label>
                <label className="flex items-start gap-2">
                  <input type="checkbox" className="mt-0.5" checked={deprovision === "suspend"} onChange={(e) => setDeprovision(e.target.checked ? "suspend" : "none")} />
                  <span>
                    Suspend people who leave <span className="block text-xs text-fg-muted">When someone is suspended or removed upstream, their Nexus account is suspended and signed out everywhere.</span>
                  </span>
                </label>
                <label className="flex items-start gap-2">
                  <input type="checkbox" className="mt-0.5" checked={invite} onChange={(e) => setInvite(e.target.checked)} />
                  <span>
                    Email new people an invitation <span className="block text-xs text-fg-muted">Otherwise they stay staged until you invite them.</span>
                  </span>
                </label>
              </div>
              <Field label="Name" htmlFor="ds-name">
                <Input id="ds-name" value={name} onChange={(e) => setName(e.target.value)} maxLength={100} />
              </Field>
            </>
          ) : null}
          <ErrorBanner error={save.error} />
          <div className="flex justify-end gap-2 border-t border-border pt-4">
            <Button type="button" variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button type="button" variant="primary" disabled={!probe || !name.trim() || (scope === "groups" && filter.length === 0)} loading={save.isPending} onClick={() => save.mutate()}>
              Save and preview
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

// ---- preview / settings -----------------------------------------------------------

function PreviewDialog({ conn, onClose }: { conn: Conn; onClose: () => void }) {
  const patch = usePatch(conn);
  const sync = useSync(conn);
  const plan = useQuery({
    queryKey: ["directory-preview", conn.id],
    queryFn: () => unwrap(api.POST("/v1/directory/connections/{id}/preview", { params: { path: { id: conn.id } } })),
    staleTime: 0,
    gcTime: 0,
  });
  const p = plan.data;
  const start = async () => {
    if (!conn.enabled) await patch.mutateAsync({ enabled: true });
    await sync.mutateAsync(p?.guard.tripped ? p.guard.suspensions : undefined);
    onClose();
  };
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent title={`Preview: ${conn.name}`} description="What a sync would change right now. Nothing has been changed yet." className="max-w-2xl">
        {plan.isPending ? (
          <Skeleton className="h-48" />
        ) : !p ? (
          <ErrorBanner error={plan.error} />
        ) : (
          <div className="max-h-[65vh] space-y-4 overflow-y-auto pr-1 text-[13px]">
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
              <Tile n={p.summary.create_users ?? 0} label="new people" />
              <Tile n={(p.summary.update_users ?? 0) + (p.summary.link_users ?? 0)} label="updated or linked" />
              <Tile n={p.summary.suspend_users ?? 0} label="suspended" tone={p.summary.suspend_users ? "warning" : undefined} />
              <Tile n={p.summary.membership_changes ?? 0} label="group changes" />
            </div>
            {p.guard.tripped ? (
              <p className="flex items-start gap-2 rounded-md border border-warning/40 bg-warning-soft px-3 py-2">
                <ShieldAlert className="mt-0.5 size-4 shrink-0 text-warning" />
                {people(p.guard.suspensions)} would be suspended, more than the safety limit of {p.guard.threshold}. Starting this sync approves exactly that many.
              </p>
            ) : null}
            <Section title="New people" items={p.create_users.map((u) => [u.email, u.name])} />
            <Section title="Existing Nexus accounts that will be linked" items={p.link_users.map((u) => [u.email, ""])} />
            <Section
              title="Updates"
              items={p.update_users.map((u) => [u.email, Object.entries(u.changes).map(([k, v]) => `${k.replace("_", " ")}: “${v.from}” → “${v.to}”`).join("; ")])}
            />
            <Section title="Will be suspended" items={p.suspend_users.map((u) => [u.email, u.reason])} tone="warning" />
            <Section title="Will be reactivated" items={p.reactivate_users.map((u) => [u.email, ""])} />
            <Section
              title="Groups"
              items={p.groups.map((g) => [g.name, g.action === "members" ? `+${g.add} / −${g.remove} members` : { create: "new group", link: "link existing group", update: "renamed or described" }[g.action]])}
            />
            <Section title="Skipped" items={p.skipped.map((s) => [s.email, s.reason])} tone="warning" />
          </div>
        )}
        <ErrorBanner error={patch.error ?? sync.error} />
        <div className="mt-4 flex justify-end gap-2 border-t border-border pt-4">
          <Button variant="ghost" onClick={onClose}>
            Close
          </Button>
          {p ? (
            <Button variant="primary" loading={patch.isPending || sync.isPending} onClick={() => void start()}>
              {conn.enabled ? "Sync now" : "Turn on and sync now"}
            </Button>
          ) : null}
        </div>
      </DialogContent>
    </Dialog>
  );
}

function Tile({ n, label, tone }: { n: number; label: string; tone?: "warning" }) {
  return (
    <div className={cn("rounded-md border p-3", tone === "warning" ? "border-warning/40 bg-warning-soft" : "border-border")}>
      <p className="text-lg font-semibold">{n}</p>
      <p className="text-xs text-fg-muted">{label}</p>
    </div>
  );
}

function Section({ title, items, tone }: { title: string; items: [string, string][]; tone?: "warning" }) {
  if (!items.length) return null;
  return (
    <div>
      <p className={cn("mb-1 text-xs font-medium uppercase tracking-wide", tone === "warning" ? "text-warning" : "text-fg-subtle")}>
        {title} ({items.length})
      </p>
      <ul className="divide-y divide-border rounded-md border border-border">
        {items.map(([a, b], i) => (
          <li key={`${a}-${i}`} className="flex justify-between gap-3 px-3 py-1.5 text-xs">
            <span className="font-medium">{a}</span>
            <span className="text-right text-fg-muted">{b}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function SettingsDialog({ conn, onClose }: { conn: Conn; onClose: () => void }) {
  const patch = usePatch(conn);
  const [deprovision, setDeprovision] = useState(conn.deprovision);
  const [invite, setInvite] = useState(conn.invite_new_users);
  const [syncGroups, setSyncGroups] = useState(conn.sync_groups);
  const [every, setEvery] = useState(conn.interval_minutes);
  const [adminEmail, setAdminEmail] = useState(conn.provider === "google" ? conn.account : "");
  const [key, setKey] = useState("");
  const [tenant, setTenant] = useState(conn.provider === "entra" ? conn.account : "");
  const [clientId, setClientId] = useState("");
  const [secret, setSecret] = useState("");
  const replacing = conn.provider === "google" ? key.trim() !== "" : secret !== "";
  const credentials = !replacing
    ? undefined
    : conn.provider === "google"
      ? ({ provider: "google", admin_email: adminEmail.trim(), service_account_key: key } as const)
      : ({ provider: "entra", tenant_id: tenant.trim(), client_id: clientId.trim(), client_secret: secret } as const);
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent title={`${conn.name} settings`}>
        <div className="space-y-3 text-[13px]">
          <label className="flex items-center gap-2">
            <input type="checkbox" checked={syncGroups} onChange={(e) => setSyncGroups(e.target.checked)} /> Sync groups and their members
          </label>
          <label className="flex items-center gap-2">
            <input type="checkbox" checked={deprovision === "suspend"} onChange={(e) => setDeprovision(e.target.checked ? "suspend" : "none")} /> Suspend people who leave
          </label>
          <label className="flex items-center gap-2">
            <input type="checkbox" checked={invite} onChange={(e) => setInvite(e.target.checked)} /> Email new people an invitation
          </label>
          <Field label="Sync every" htmlFor="ds-int">
            <Select id="ds-int" className="w-full" value={String(every)} onChange={(e) => setEvery(Number(e.target.value))}>
              {[15, 30, 60, 240, 720, 1440].map((m) => (
                <option key={m} value={m}>
                  {m < 60 ? `${m} minutes` : m === 60 ? "hour" : `${m / 60} hours`}
                </option>
              ))}
            </Select>
          </Field>
          {conn.group_filter.length ? <p className="text-xs text-fg-muted">Scoped to {pluralize(conn.group_filter.length, "directory group")}.</p> : null}
          <details className="rounded-md border border-border px-3 py-2">
            <summary className="cursor-pointer text-[13px] font-medium">Replace credentials</summary>
            <div className="mt-3 space-y-3">
              {conn.provider === "google" ? (
                <>
                  <Field label="Admin email" htmlFor="st-admin">
                    <Input id="st-admin" type="email" value={adminEmail} onChange={(e) => setAdminEmail(e.target.value)} />
                  </Field>
                  <Field label="New service account key (JSON)" htmlFor="st-key">
                    <textarea
                      id="st-key"
                      rows={3}
                      spellCheck={false}
                      value={key}
                      onChange={(e) => setKey(e.target.value)}
                      className="w-full rounded-md border border-border bg-bg px-3 py-2 font-mono text-xs shadow-card focus:border-ring focus:outline-none"
                    />
                  </Field>
                </>
              ) : (
                <>
                  <Field label="Tenant ID" htmlFor="st-tenant">
                    <Input id="st-tenant" value={tenant} onChange={(e) => setTenant(e.target.value)} />
                  </Field>
                  <Field label="Application (client) ID" htmlFor="st-client">
                    <Input id="st-client" value={clientId} onChange={(e) => setClientId(e.target.value)} />
                  </Field>
                  <Field label="New client secret" htmlFor="st-secret">
                    <Input id="st-secret" type="password" autoComplete="off" value={secret} onChange={(e) => setSecret(e.target.value)} />
                  </Field>
                </>
              )}
              <p className="text-xs text-fg-muted">The current credentials are never shown. Saving replaces them.</p>
            </div>
          </details>
          <ErrorBanner error={patch.error} />
          <div className="flex justify-end gap-2 border-t border-border pt-4">
            <Button variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button
              variant="primary"
              loading={patch.isPending}
              onClick={() =>
                patch.mutate({ deprovision, invite_new_users: invite, sync_groups: syncGroups, interval_minutes: every, ...(credentials ? { credentials } : {}) }, { onSuccess: () => (toast.success("Settings saved"), onClose()) })
              }
            >
              Save
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
