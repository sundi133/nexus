"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { useStepUp } from "@/components/step-up";
import { Button } from "@/components/ui/button";
import { CopyField } from "@/components/ui/copy";
import { Field, Input, Select } from "@/components/ui/input";
import { Card, CardHeader, ErrorBanner, PageHeader, Skeleton } from "@/components/ui/misc";
import { Dialog, DialogContent } from "@/components/ui/overlay";
import { api, unwrap } from "@/lib/api";
import { useCan } from "@/lib/queries";
import { timeAgo } from "@/lib/utils";

type Shown = { title: string; fields: [string, string][] } | null;

export default function DirectoryServicesPage() {
  const can = useCan();
  const editable = can("org:manage");
  const qc = useQueryClient();
  const withStepUp = useStepUp();
  const q = useQuery({ queryKey: ["directory-services"], queryFn: () => unwrap(api.GET("/v1/directory-services")), enabled: editable });
  const [shown, setShown] = useState<Shown>(null);
  const [adding, setAdding] = useState<"account" | "client" | null>(null);
  const refresh = () => qc.invalidateQueries({ queryKey: ["directory-services"] });
  const save = useMutation({
    mutationFn: (body: { ldap_enabled: boolean; radius_enabled: boolean; radius_mfa: "required" | "if_enrolled" | "off" }) => withStepUp(() => unwrap(api.PUT("/v1/directory-services", { body }))),
    onSuccess: () => (refresh(), toast.success("Saved")),
    onError: (e) => toast.error(e instanceof Error ? e.message : "Couldn't save"),
  });
  const revokeAccount = useMutation({ mutationFn: (id: string) => unwrap(api.DELETE("/v1/directory-services/ldap/service-accounts/{id}", { params: { path: { id } } })), onSuccess: refresh });
  const removeClient = useMutation({ mutationFn: (id: string) => unwrap(api.DELETE("/v1/directory-services/radius/clients/{id}", { params: { path: { id } } })), onSuccess: refresh });

  if (!editable) return <PageHeader title="LDAP & RADIUS" description="Only owners and admins can manage these." />;
  if (q.isPending) return <Skeleton className="h-64" />;
  if (!q.data) return <ErrorBanner error={q.error} />;
  const d = q.data;
  const settings = { ldap_enabled: d.ldap_enabled, radius_enabled: d.radius_enabled, radius_mfa: d.radius_mfa };

  return (
    <>
      <PageHeader
        title="LDAP & RADIUS"
        description="For what can't use SAML or OIDC: legacy apps, NAS boxes and printers read people and groups over LDAP; VPNs and Wi-Fi check passwords (and authenticator-app codes) over RADIUS. Both follow Nexus: suspended people are refused at once."
      />
      <div className="space-y-5">
        <Card>
          <CardHeader
            title="LDAP directory"
            description="Read-only, over LDAPS. Apps bind as a service account to search, then as the person with their Nexus password. People see only their own entry and groups."
            actions={
              <label className="flex items-center gap-2 text-[13px]">
                <input type="checkbox" checked={d.ldap_enabled} onChange={(e) => save.mutate({ ...settings, ldap_enabled: e.target.checked })} /> On
              </label>
            }
          />
          <div className="grid gap-3 px-4 pb-4 md:grid-cols-2">
            <CopyField label="Address" value={d.ldap.address ?? "Not offered by this deployment (NEXUS_LDAP_PORT)"} />
            <CopyField label="Base DN" value={d.ldap.base_dn} />
            <CopyField label="People" value={d.ldap.users_dn} />
            <CopyField label="Groups" value={d.ldap.groups_dn} />
          </div>
          <div className="border-t border-border px-4 py-3">
            <div className="mb-2 flex items-center justify-between">
              <span className="text-[13px] font-medium">Service accounts</span>
              <Button size="sm" onClick={() => setAdding("account")}>
                <Plus className="size-3.5" /> Add
              </Button>
            </div>
            {d.ldap.service_accounts.length ? (
              <ul className="divide-y divide-border text-[13px]">
                {d.ldap.service_accounts.map((a) => (
                  <li key={a.id} className="flex items-center justify-between gap-3 py-2">
                    <span className="min-w-0">
                      <span className="block truncate font-mono text-xs">{a.dn}</span>
                      <span className="text-xs text-fg-muted">{a.last_used_at ? `Last used ${timeAgo(a.last_used_at)}` : "Not used yet"}</span>
                    </span>
                    <Button size="sm" variant="danger-outline" onClick={() => revokeAccount.mutate(a.id)}>
                      Revoke
                    </Button>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-xs text-fg-muted">One per app, so each can be revoked on its own.</p>
            )}
          </div>
        </Card>

        <Card>
          <CardHeader
            title="RADIUS"
            description="PAP over UDP, for VPN concentrators and Wi-Fi controllers. Each is registered by the address it sends from, with its own shared secret; requests must carry a Message-Authenticator. Accepted sign-ins carry the person's groups (Class = group:<name>) for the device's own policies."
            actions={
              <label className="flex items-center gap-2 text-[13px]">
                <input type="checkbox" checked={d.radius_enabled} onChange={(e) => save.mutate({ ...settings, radius_enabled: e.target.checked })} /> On
              </label>
            }
          />
          <div className="grid gap-3 px-4 pb-3 md:grid-cols-2">
            <CopyField label="Address (UDP)" value={d.radius.address ?? "Not offered by this deployment (NEXUS_RADIUS_PORT)"} />
            <label className="text-xs font-medium text-fg-muted">
              Authenticator-app code
              <Select className="mt-1 w-full" value={d.radius_mfa} onChange={(e) => save.mutate({ ...settings, radius_mfa: e.target.value as "required" })}>
                <option value="required">Always (people without one can't sign in)</option>
                <option value="if_enrolled">When the person has MFA</option>
                <option value="off">Never (password only)</option>
              </Select>
            </label>
          </div>
          <div className="border-t border-border px-4 py-3">
            <div className="mb-2 flex items-center justify-between">
              <span className="text-[13px] font-medium">Clients</span>
              <Button size="sm" onClick={() => setAdding("client")}>
                <Plus className="size-3.5" /> Add
              </Button>
            </div>
            {d.radius.clients.length ? (
              <ul className="divide-y divide-border text-[13px]">
                {d.radius.clients.map((c) => (
                  <li key={c.id} className="flex items-center justify-between gap-3 py-2">
                    <span>
                      {c.name} <span className="font-mono text-xs text-fg-muted">{c.address}</span>
                      <span className="block text-xs text-fg-muted">{c.last_used_at ? `Last request ${timeAgo(c.last_used_at)}` : "No requests yet"}</span>
                    </span>
                    <Button size="sm" variant="danger-outline" onClick={() => removeClient.mutate(c.id)}>
                      Remove
                    </Button>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-xs text-fg-muted">None yet.</p>
            )}
          </div>
        </Card>
      </div>

      {adding ? (
        <AddDialog
          kind={adding}
          onClose={() => setAdding(null)}
          onCreated={(s) => {
            setAdding(null);
            refresh();
            setShown(s);
          }}
        />
      ) : null}
      <Dialog open={!!shown} onOpenChange={(o) => !o && setShown(null)}>
        <DialogContent title={shown?.title ?? ""} description="Copy it now: it isn't shown again.">
          <div className="space-y-3">
            {shown?.fields.map(([label, value]) => (
              <CopyField key={label} label={label} value={value} secret={label !== "Bind DN" && label !== "Address"} />
            ))}
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
}

function AddDialog({ kind, onClose, onCreated }: { kind: "account" | "client"; onClose: () => void; onCreated: (s: NonNullable<Shown>) => void }) {
  const withStepUp = useStepUp();
  const [name, setName] = useState("");
  const [address, setAddress] = useState("");
  const create = useMutation({
    mutationFn: async () => {
      if (kind === "account") {
        const r = await withStepUp(() => unwrap(api.POST("/v1/directory-services/ldap/service-accounts", { body: { name } })));
        return { title: `Service account ${r.name}`, fields: [["Bind DN", r.dn], ["Password", r.password]] as [string, string][] };
      }
      const r = await withStepUp(() => unwrap(api.POST("/v1/directory-services/radius/clients", { body: { name, address } })));
      return { title: `RADIUS client ${r.name}`, fields: [["Address", r.address], ["Shared secret", r.secret]] as [string, string][] };
    },
    onSuccess: onCreated,
  });
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent title={kind === "account" ? "Add an LDAP service account" : "Add a RADIUS client"}>
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            create.mutate();
          }}
        >
          <ErrorBanner error={create.error} />
          <Field label="Name" htmlFor="name" hint={kind === "account" ? "Lowercase, e.g. jenkins" : "e.g. Office VPN"}>
            <Input id="name" value={name} onChange={(e) => setName(e.target.value)} autoFocus />
          </Field>
          {kind === "client" ? (
            <Field label="Address it sends from" htmlFor="address" hint="An IP, or a range no broader than /16">
              <Input id="address" className="font-mono" value={address} onChange={(e) => setAddress(e.target.value)} placeholder="203.0.113.10" />
            </Field>
          ) : null}
          <div className="flex justify-end gap-2">
            <Button type="button" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" variant="primary" loading={create.isPending} disabled={!name || (kind === "client" && !address)}>
              Create
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
