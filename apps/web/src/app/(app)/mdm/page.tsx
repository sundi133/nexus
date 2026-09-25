"use client";

import type { Schemas } from "@nexus/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, MoreHorizontal, Plus, RefreshCw, Server } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { toast } from "sonner";
import { useStepUp } from "@/components/step-up";
import { Button } from "@/components/ui/button";
import { Field, Input } from "@/components/ui/input";
import { Card, EmptyState, ErrorBanner, PageHeader, Skeleton, StatusPill } from "@/components/ui/misc";
import { Dialog, DialogContent, Menu, MenuContent, MenuItem, MenuSeparator, MenuTrigger } from "@/components/ui/overlay";
import { api, unwrap } from "@/lib/api";
import { useCan } from "@/lib/queries";
import { cn, pluralize, timeAgo } from "@/lib/utils";

type Conn = Schemas["MdmConnection"];
const KEY = ["mdm-connections"];

const SETUP = {
  intune: [
    "In the Microsoft Entra admin center → App registrations, register an app for Nexus (or reuse the one for directory sync).",
    "API permissions → Microsoft Graph → Application: DeviceManagementManagedDevices.Read.All. Grant admin consent.",
    "Certificates & secrets → New client secret. Enter the tenant ID, client ID and secret below.",
  ],
  jamf: [
    "In Jamf Pro → Settings → API roles and clients, create a role with “Read Computers”.",
    "Create an API client with that role, enable it, and generate a client secret.",
    "Enter your Jamf Pro URL, the client ID and the secret below.",
  ],
};

export default function MdmPage() {
  const list = useQuery({ queryKey: KEY, queryFn: () => unwrap(api.GET("/v1/mdm/connections")), refetchInterval: (q) => (q.state.data?.data.some((c) => c.syncing) ? 2000 : 30_000) });
  const can = useCan();
  const [adding, setAdding] = useState(false);
  return (
    <>
      <PageHeader
        title="Device management"
        description="Bring in what your MDM knows: Nexus reads Microsoft Intune or Jamf Pro, matches their devices to Nexus devices by serial number, and can require devices to be managed and compliant there."
        actions={
          can("devices:write") ? (
            <Button variant="primary" onClick={() => setAdding(true)}>
              <Plus /> Connect an MDM
            </Button>
          ) : null
        }
      />
      {list.isPending ? (
        <Skeleton className="h-40" />
      ) : !list.data ? (
        <ErrorBanner error={list.error} />
      ) : list.data.data.length ? (
        <div className="space-y-3">
          {list.data.data.map((c) => (
            <ConnectionCard key={c.id} conn={c} editable={can("devices:write")} />
          ))}
          <p className="text-xs text-fg-muted">
            To make MDM compliance count, turn on <Link className="text-primary hover:underline" href="/device-policies">Managed and compliant in your MDM</Link> in device policies.
          </p>
        </div>
      ) : (
        <Card>
          <EmptyState
            icon={<Server />}
            title="No MDM connected"
            description="If you use Intune or Jamf, connect it so device policies and conditional access can use its verdict, and so you can see which managed devices still lack the Nexus agent."
          />
        </Card>
      )}
      {adding ? <ConnectDialog onClose={() => setAdding(false)} /> : null}
    </>
  );
}

function Mark({ provider }: { provider: Conn["provider"] }) {
  return (
    <div className={cn("flex size-9 shrink-0 items-center justify-center rounded-md text-xs font-bold text-white", provider === "intune" ? "bg-[#0078d4]" : "bg-[#4a4a55]")} aria-hidden>
      {provider === "intune" ? "In" : "J"}
    </div>
  );
}

function ConnectionCard({ conn: c, editable }: { conn: Conn; editable: boolean }) {
  const qc = useQueryClient();
  const withStepUp = useStepUp();
  const [gap, setGap] = useState(false);
  const sync = useMutation({
    mutationFn: () => unwrap(api.POST("/v1/mdm/connections/{id}/sync", { params: { path: { id: c.id } } })),
    onSuccess: (r) => (qc.setQueryData(KEY, r), toast.success(`Reading ${c.name}`)),
  });
  const patch = useMutation({
    mutationFn: (enabled: boolean) => withStepUp(() => unwrap(api.PATCH("/v1/mdm/connections/{id}", { params: { path: { id: c.id } }, body: { enabled } }))),
    onSuccess: (r, enabled) => (qc.setQueryData(KEY, r), toast.success(enabled ? `${c.name} is on` : `${c.name} is off: its signals no longer count`)),
  });
  const remove = useMutation({
    mutationFn: () => withStepUp(() => unwrap(api.DELETE("/v1/mdm/connections/{id}", { params: { path: { id: c.id } } }))),
    onSuccess: (r) => (qc.setQueryData(KEY, r), toast.success(`Disconnected ${c.name}`)),
  });
  const devices = useQuery({
    queryKey: ["mdm-gap", c.id],
    queryFn: () => unwrap(api.GET("/v1/mdm/connections/{id}/devices", { params: { path: { id: c.id }, query: { without_agent: "true", limit: 200 } } })),
    enabled: gap,
  });
  return (
    <Card>
      <div className="flex flex-wrap items-start gap-3 px-4 py-3">
        <Mark provider={c.provider} />
        <div className="min-w-0 flex-1">
          <p className="flex flex-wrap items-center gap-2 text-[13px] font-semibold">
            {c.name}
            {!c.enabled ? <StatusPill>Off</StatusPill> : c.last_status === "error" ? <StatusPill tone="danger">Failing</StatusPill> : c.last_status === "ok" ? <StatusPill tone="success">Connected</StatusPill> : <StatusPill>Not read yet</StatusPill>}
            {c.syncing ? (
              <span className="inline-flex items-center gap-1 text-xs font-normal text-primary">
                <RefreshCw className="size-3 animate-spin" /> Reading…
              </span>
            ) : null}
          </p>
          <p className="text-xs text-fg-muted">
            {c.provider_name} · <span className="font-mono">{c.account}</span>
          </p>
          <p className="text-xs text-fg-subtle">
            {c.last_sync_at ? `Read ${timeAgo(c.last_sync_at)}` : "Never read"} · every {c.interval_minutes >= 60 ? `${c.interval_minutes / 60} h` : `${c.interval_minutes} min`}
          </p>
        </div>
        {editable ? (
          <div className="flex items-center gap-1.5">
            <Button size="sm" variant="secondary" loading={sync.isPending} disabled={c.syncing} onClick={() => sync.mutate()}>
              <RefreshCw /> Read now
            </Button>
            <Menu>
              <MenuTrigger asChild>
                <Button size="sm" variant="ghost" aria-label={`Actions for ${c.name}`}>
                  <MoreHorizontal />
                </Button>
              </MenuTrigger>
              <MenuContent>
                <MenuItem onSelect={() => patch.mutate(!c.enabled)}>{c.enabled ? "Turn off" : "Turn on"}</MenuItem>
                <MenuSeparator />
                <MenuItem danger onSelect={() => remove.mutate()}>
                  Disconnect
                </MenuItem>
              </MenuContent>
            </Menu>
          </div>
        ) : null}
      </div>
      <div className="space-y-3 border-t border-border px-4 py-3">
        <ErrorBanner error={sync.error ?? patch.error ?? remove.error} />
        {c.last_status === "error" ? (
          <p className="flex items-start gap-2 rounded-md border border-danger/30 bg-danger-soft px-3 py-2 text-[13px]">
            <AlertTriangle className="mt-0.5 size-4 shrink-0 text-danger" /> {c.last_error}
          </p>
        ) : null}
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <Stat n={c.devices} label={`devices in ${c.provider_name}`} />
          <Stat n={c.matched} label="with the Nexus agent" />
          <Stat n={c.without_agent} label="without the agent" tone={c.without_agent ? "warning" : undefined} />
          <Stat n={c.noncompliant} label="non-compliant or unmanaged" tone={c.noncompliant ? "warning" : undefined} />
        </div>
        {c.without_agent ? (
          <details className="text-[13px]" onToggle={(e) => setGap((e.target as HTMLDetailsElement).open)}>
            <summary className="cursor-pointer text-fg-muted">Devices without the Nexus agent: deploy it from {c.provider_name} to cover them</summary>
            <ul className="mt-2 max-h-64 divide-y divide-border overflow-y-auto rounded-md border border-border text-xs">
              {devices.data?.data.map((d) => (
                <li key={d.external_id} className="flex flex-wrap items-center gap-x-3 gap-y-0.5 px-3 py-2">
                  <span className="font-medium">{d.name || "Unnamed"}</span>
                  <span className="font-mono text-fg-muted">{d.serial || "no serial"}</span>
                  <span className="text-fg-muted">
                    {d.platform} {d.os_version}
                  </span>
                  <span className="text-fg-muted">{d.user_email}</span>
                  <span className="flex-1" />
                  {d.compliant === false || !d.managed ? <StatusPill tone="warning">{!d.managed ? "Unmanaged" : "Non-compliant"}</StatusPill> : null}
                </li>
              ))}
            </ul>
          </details>
        ) : null}
      </div>
    </Card>
  );
}

function Stat({ n, label, tone }: { n: number; label: string; tone?: "warning" }) {
  return (
    <div className="rounded-md bg-bg-subtle px-3 py-2">
      <p className={cn("text-lg font-semibold tabular-nums", tone === "warning" && "text-warning")}>{n.toLocaleString()}</p>
      <p className="text-xs text-fg-muted">{label}</p>
    </div>
  );
}

function ConnectDialog({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient();
  const withStepUp = useStepUp();
  const [provider, setProvider] = useState<Conn["provider"]>("intune");
  const [name, setName] = useState("Intune");
  const [tenant, setTenant] = useState("");
  const [url, setUrl] = useState("");
  const [clientId, setClientId] = useState("");
  const [secret, setSecret] = useState("");
  const create = useMutation({
    mutationFn: () =>
      withStepUp(() =>
        unwrap(
          api.POST("/v1/mdm/connections", {
            body: {
              name: name.trim(),
              credentials:
                provider === "intune"
                  ? { provider, tenant_id: tenant.trim(), client_id: clientId.trim(), client_secret: secret }
                  : { provider, base_url: url.trim(), client_id: clientId.trim(), client_secret: secret },
            },
          }),
        ),
      ),
    onSuccess: (r) => {
      qc.setQueryData(KEY, { data: r.data });
      toast.success(`${name.trim()} connected`, { description: `Found ${pluralize(r.found, "device")}. Matching them to Nexus devices now.` });
      onClose();
    },
  });
  const ready = !!name.trim() && !!clientId.trim() && !!secret && (provider === "intune" ? !!tenant.trim() : !!url.trim());
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent title="Connect an MDM" description="Read-only: Nexus reads which devices are managed and compliant. The credentials are tried before saving." className="max-w-xl">
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-2">
            {(["intune", "jamf"] as const).map((p) => (
              <button
                key={p}
                type="button"
                onClick={() => (setProvider(p), setName(p === "intune" ? "Intune" : "Jamf"))}
                className={cn("flex items-center gap-2 rounded-md border p-3 text-left text-[13px] font-medium", provider === p ? "border-primary bg-primary-soft" : "border-border hover:bg-bg-subtle")}
              >
                <Mark provider={p} /> {p === "intune" ? "Microsoft Intune" : "Jamf Pro"}
              </button>
            ))}
          </div>
          <ol className="list-decimal space-y-1 rounded-md bg-bg-subtle py-2 pl-7 pr-3 text-xs text-fg-muted">
            {SETUP[provider].map((s) => (
              <li key={s}>{s}</li>
            ))}
          </ol>
          <Field label="Name" htmlFor="mdm-name">
            <Input id="mdm-name" value={name} onChange={(e) => setName(e.target.value)} maxLength={100} />
          </Field>
          {provider === "intune" ? (
            <Field label="Directory (tenant) ID" htmlFor="mdm-tenant">
              <Input id="mdm-tenant" value={tenant} onChange={(e) => setTenant(e.target.value)} className="font-mono text-xs" />
            </Field>
          ) : (
            <Field label="Jamf Pro URL" htmlFor="mdm-url">
              <Input id="mdm-url" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://acme.jamfcloud.com" />
            </Field>
          )}
          <div className="grid grid-cols-2 gap-3">
            <Field label={provider === "intune" ? "Application (client) ID" : "Client ID"} htmlFor="mdm-client">
              <Input id="mdm-client" value={clientId} onChange={(e) => setClientId(e.target.value)} className="font-mono text-xs" />
            </Field>
            <Field label="Client secret" htmlFor="mdm-secret">
              <Input id="mdm-secret" type="password" autoComplete="off" value={secret} onChange={(e) => setSecret(e.target.value)} />
            </Field>
          </div>
          <ErrorBanner error={create.error} />
          <div className="flex justify-end gap-2 border-t border-border pt-4">
            <Button variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button variant="primary" loading={create.isPending} disabled={!ready} onClick={() => create.mutate()}>
              Connect
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
