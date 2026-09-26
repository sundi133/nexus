"use client";

import type { Schemas } from "@nexus/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { KeyRound, Plus } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { useStepUp } from "@/components/step-up";
import { Button } from "@/components/ui/button";
import { CopyField } from "@/components/ui/copy";
import { Field, Input, Select } from "@/components/ui/input";
import { Card, EmptyState, ErrorBanner, PageHeader, Skeleton, StatusPill } from "@/components/ui/misc";
import { Dialog, DialogContent } from "@/components/ui/overlay";
import { api, unwrap } from "@/lib/api";
import { useCan } from "@/lib/queries";
import { formatDateTime, timeAgo } from "@/lib/utils";

type Key = Schemas["ApiKey"];
const KEY = ["api-keys"];

// Human names for scopes, grouped the way admins think about them.
const SCOPE_LABELS: Record<string, string> = {
  "users:read": "Read people",
  "users:write": "Create and edit people",
  "users:lifecycle": "Suspend, offboard and contain people",
  "groups:read": "Read groups",
  "groups:write": "Manage groups",
  "audit:read": "Read the audit log",
  "apps:read": "Read apps",
  "apps:write": "Configure apps",
  "apps:assign": "Assign apps",
  "devices:read": "Read devices",
  "devices:write": "Manage devices and device policies",
  "devices:updates": "Roll out agent updates",
  "policies:write": "Manage conditional access",
  "directory:sync": "Manage directory sync",
  "org:manage": "Change organization settings",
};

export default function ApiKeysPage() {
  const keys = useQuery({ queryKey: KEY, queryFn: () => unwrap(api.GET("/v1/api-keys")) });
  const can = useCan();
  const qc = useQueryClient();
  const [creating, setCreating] = useState(false);
  const [shown, setShown] = useState<{ name: string; key: string } | null>(null);
  const revoke = useMutation({
    mutationFn: (k: Key) => unwrap(api.DELETE("/v1/api-keys/{id}", { params: { path: { id: k.id } } })),
    onSuccess: (_r, k) => {
      qc.invalidateQueries({ queryKey: KEY });
      toast.success(`Revoked “${k.name}”`, { description: "It stopped working immediately." });
    },
  });

  return (
    <>
      <PageHeader
        title="API keys"
        description="Keys for scripts and integrations: HR offboarding, reporting, config as code. Each has only the scopes you give it, and expires."
        actions={
          can("api_keys:manage") ? (
            <Button variant="primary" onClick={() => setCreating(true)}>
              <Plus /> Create key
            </Button>
          ) : null
        }
      />
      <ErrorBanner error={revoke.error} />
      {keys.isPending ? (
        <Skeleton className="h-40" />
      ) : keys.data?.data.length ? (
        <Card className="overflow-hidden">
          <table className="w-full text-[13px]">
            <thead className="bg-bg-subtle text-left text-xs text-fg-muted">
              <tr>
                <th className="px-4 py-2 font-medium">Key</th>
                <th className="px-4 py-2 font-medium">Scopes</th>
                <th className="px-4 py-2 font-medium">Last used</th>
                <th className="px-4 py-2 font-medium">Expires</th>
                <th />
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {keys.data.data.map((k) => (
                <tr key={k.id} className={k.status !== "active" ? "opacity-60" : ""}>
                  <td className="px-4 py-2.5">
                    <p className="font-medium">{k.name}</p>
                    <p className="font-mono text-xs text-fg-muted">{k.prefix}…</p>
                    <p className="text-xs text-fg-subtle">Created by {k.created_by ?? "a removed user"}</p>
                  </td>
                  <td className="px-4 py-2.5 text-xs text-fg-muted">{k.scopes.map((s) => SCOPE_LABELS[s] ?? s).join(" · ")}</td>
                  <td className="px-4 py-2.5 text-xs text-fg-muted">
                    {k.last_used_at ? timeAgo(k.last_used_at) : "Never"}
                    {k.last_used_ip ? <span className="block text-fg-subtle">from {k.last_used_ip}</span> : null}
                  </td>
                  <td className="px-4 py-2.5 text-xs">
                    {k.status === "active" ? <span className="text-fg-muted">{formatDateTime(k.expires_at)}</span> : <StatusPill tone={k.status === "revoked" ? "danger" : "neutral"}>{k.status === "revoked" ? "Revoked" : "Expired"}</StatusPill>}
                  </td>
                  <td className="px-4 py-2.5 text-right">
                    {k.status === "active" && can("api_keys:manage") ? (
                      <Button size="sm" variant="danger-outline" loading={revoke.isPending && revoke.variables?.id === k.id} onClick={() => revoke.mutate(k)}>
                        Revoke
                      </Button>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      ) : (
        <Card>
          <EmptyState icon={<KeyRound />} title="No API keys" description="Create one for each script or integration, with only the scopes it needs." />
        </Card>
      )}
      {creating && keys.data ? <CreateKey grantable={keys.data.grantable_scopes} onClose={() => setCreating(false)} onCreated={(name, key) => (setCreating(false), setShown({ name, key }))} /> : null}
      {shown ? (
        <Dialog open onOpenChange={(o) => !o && setShown(null)}>
          <DialogContent title={`Your key for “${shown.name}”`} description="Copy it now: it won't be shown again. Send it as Authorization: Bearer <key>.">
            <CopyField value={shown.key} />
            <div className="mt-4 flex justify-end">
              <Button variant="primary" onClick={() => setShown(null)}>
                I've stored it safely
              </Button>
            </div>
          </DialogContent>
        </Dialog>
      ) : null}
    </>
  );
}

function CreateKey({ grantable, onClose, onCreated }: { grantable: Key["scopes"]; onClose: () => void; onCreated: (name: string, key: string) => void }) {
  const qc = useQueryClient();
  const withStepUp = useStepUp();
  const [name, setName] = useState("");
  const [scopes, setScopes] = useState<Key["scopes"]>([]);
  const [days, setDays] = useState(90);
  const create = useMutation({
    mutationFn: () => withStepUp(() => unwrap(api.POST("/v1/api-keys", { body: { name: name.trim(), scopes, expires_in_days: days } }))),
    onSuccess: (r) => {
      qc.invalidateQueries({ queryKey: KEY });
      onCreated(r.api_key.name, r.key);
    },
  });
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent title="Create an API key" description="Grant only what this integration needs. Keys can't manage admins, keys or event streams.">
        <div className="space-y-4">
          <Field label="Name" htmlFor="key-name" hint="What uses it, e.g. “Workday offboarding”">
            <Input id="key-name" value={name} onChange={(e) => setName(e.target.value)} maxLength={100} />
          </Field>
          <fieldset>
            <legend className="mb-1 text-[13px] font-medium">Scopes</legend>
            <div className="max-h-52 overflow-y-auto rounded-md border border-border">
              {grantable.map((s) => (
                <label key={s} className="flex cursor-pointer items-center gap-2 border-b border-border px-3 py-1.5 text-[13px] last:border-0 hover:bg-bg-subtle">
                  <input type="checkbox" checked={scopes.includes(s)} onChange={(e) => setScopes(e.target.checked ? [...scopes, s] : scopes.filter((x) => x !== s))} />
                  <span className="flex-1">{SCOPE_LABELS[s] ?? s}</span>
                  <span className="font-mono text-[11px] text-fg-subtle">{s}</span>
                </label>
              ))}
            </div>
          </fieldset>
          <Field label="Expires after" htmlFor="key-exp">
            <Select id="key-exp" className="w-full" value={String(days)} onChange={(e) => setDays(Number(e.target.value))}>
              {[7, 30, 90, 180, 365].map((d) => (
                <option key={d} value={d}>
                  {d} days
                </option>
              ))}
            </Select>
          </Field>
          <ErrorBanner error={create.error} />
          <div className="flex justify-end gap-2 border-t border-border pt-4">
            <Button variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button variant="primary" loading={create.isPending} disabled={!name.trim() || scopes.length === 0} onClick={() => create.mutate()}>
              Create key
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
