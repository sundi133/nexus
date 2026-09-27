"use client";

import type { Schemas } from "@nexus/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { KeyRound, Plus, Trash2 } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { useStepUp } from "@/components/step-up";
import { Button } from "@/components/ui/button";
import { Field, Input } from "@/components/ui/input";
import { Avatar, Card, CardHeader, EmptyState, ErrorBanner, StatusPill } from "@/components/ui/misc";
import { Dialog, DialogContent } from "@/components/ui/overlay";
import { api, unwrap } from "@/lib/api";
import { useCan } from "@/lib/queries";
import { timeAgo } from "@/lib/utils";

type Account = Schemas["DeviceAccount"];
export const ACCOUNT_STATUS: Record<string, { label: string; tone: "success" | "danger" | "neutral" | "warning" }> = {
  pending: { label: "waiting for the device", tone: "neutral" },
  waiting_password: { label: "waiting for a Nexus sign-in", tone: "warning" },
  active: { label: "active", tone: "success" },
  disabled: { label: "disabled", tone: "neutral" },
  failed: { label: "failed", tone: "danger" },
};

/** People's local accounts on a device (sign in to the laptop with the company password). */
export function DeviceAccounts({ deviceId, hostname }: { deviceId: string; hostname: string }) {
  const can = useCan();
  const qc = useQueryClient();
  const withStepUp = useStepUp();
  const list = useQuery({ queryKey: ["device-accounts", deviceId], queryFn: () => unwrap(api.GET("/v1/devices/{id}/accounts", { params: { path: { id: deviceId } } })), refetchInterval: 30_000 });
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState<Account | null>(null);
  const remove = useMutation({
    mutationFn: (userId: string) => withStepUp(() => unwrap(api.DELETE("/v1/devices/{id}/accounts/{user_id}", { params: { path: { id: deviceId, user_id: userId } } }))),
    onSuccess: () => (toast.success("No longer managed", { description: "The agent disables the account; its files stay." }), qc.invalidateQueries({ queryKey: ["device-accounts", deviceId] })),
  });
  const manage = can("devices:write");
  return (
    <Card className="overflow-hidden">
      <CardHeader
        title="Local accounts"
        description="People sign in here with their Nexus password, synced encrypted whenever they sign in to Nexus or change it."
        actions={
          manage ? (
            <Button size="sm" onClick={() => setAdding(true)}>
              <Plus className="size-3.5" /> Add person
            </Button>
          ) : null
        }
      />
      <ErrorBanner error={remove.error} />
      {list.data?.data.length ? (
        <ul className="divide-y divide-border">
          {list.data.data.map((a) => (
            <li key={a.user_id} className="flex flex-wrap items-center justify-between gap-3 px-4 py-2.5 text-[13px]">
              <span className="flex min-w-0 items-center gap-2.5">
                <Avatar name={a.name} size={24} />
                <span className="min-w-0">
                  <span className="font-medium">{a.name}</span> <code className="font-mono text-xs text-fg-muted">{a.username}</code>
                  {a.admin ? <span className="ml-1.5 rounded bg-bg-subtle px-1.5 py-0.5 text-xs text-fg-muted">admin</span> : null}
                  <span className="block text-xs text-fg-subtle">{a.detail || (a.reported_at ? `Reported ${timeAgo(a.reported_at)}` : "Not reported yet")}</span>
                </span>
              </span>
              <span className="flex items-center gap-1.5">
                <StatusPill tone={ACCOUNT_STATUS[a.status]?.tone ?? "neutral"}>{ACCOUNT_STATUS[a.status]?.label ?? a.status}</StatusPill>
                {a.status === "active" ? (
                  <StatusPill tone={a.password_synced ? "success" : "neutral"}>
                    <KeyRound className="size-3" /> {a.password_synced ? "password synced" : "password not synced yet"}
                  </StatusPill>
                ) : null}
                {manage ? (
                  <>
                    <Button size="sm" variant="ghost" onClick={() => setEditing(a)}>
                      Edit
                    </Button>
                    <Button size="sm" variant="ghost" aria-label={`Stop managing ${a.username}`} loading={remove.isPending && remove.variables === a.user_id} onClick={() => remove.mutate(a.user_id)}>
                      <Trash2 className="size-3.5" />
                    </Button>
                  </>
                ) : null}
              </span>
            </li>
          ))}
        </ul>
      ) : (
        <EmptyState title="No local accounts" description={`Add people to give them an account on ${hostname} with their company password.`} />
      )}
      {adding ? <AccountDialog deviceId={deviceId} hostname={hostname} onClose={() => setAdding(false)} /> : null}
      {editing ? <AccountDialog deviceId={deviceId} hostname={hostname} account={editing} onClose={() => setEditing(null)} /> : null}
    </Card>
  );
}

function AccountDialog({ deviceId, hostname, account, onClose }: { deviceId: string; hostname: string; account?: Account; onClose: () => void }) {
  const can = useCan();
  const qc = useQueryClient();
  const withStepUp = useStepUp();
  const [q, setQ] = useState("");
  const [person, setPerson] = useState<{ id: string; name: string; email: string } | null>(account ? { id: account.user_id, name: account.name, email: account.email } : null);
  const [username, setUsername] = useState(account?.username ?? "");
  const [admin, setAdmin] = useState(account?.admin ?? false);
  const [takeOver, setTakeOver] = useState(account?.take_over ?? false);
  const users = useQuery({ queryKey: ["users", { q, deviceAccount: true }], queryFn: () => unwrap(api.GET("/v1/users", { params: { query: { q: q || undefined, limit: 10, status: "active" } } })), enabled: !person });
  const save = useMutation({
    mutationFn: () =>
      withStepUp(() =>
        unwrap(api.PUT("/v1/devices/{id}/accounts/{user_id}", { params: { path: { id: deviceId, user_id: person!.id } }, body: { admin, take_over: takeOver, ...(username.trim() ? { username: username.trim() } : {}) } })),
      ),
    onSuccess: (a) => {
      toast.success(`${a.username} on ${hostname}`, { description: a.password_synced ? "Ready." : "The account stays locked until they sign in to Nexus once." });
      qc.invalidateQueries({ queryKey: ["device-accounts", deviceId] });
      onClose();
    },
  });
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent title={account ? `${account.name} on ${hostname}` : `Add a person to ${hostname}`} description="The agent creates the account (or takes over an existing one). Their password arrives when they next sign in to Nexus.">
        <form className="space-y-3" onSubmit={(e) => (e.preventDefault(), save.mutate())}>
          <ErrorBanner error={save.error} />
          {person ? (
            <p className="flex items-center gap-2 text-[13px]">
              <Avatar name={person.name} size={24} /> {person.name} <span className="text-fg-subtle">{person.email}</span>
              {!account ? (
                <Button type="button" size="sm" variant="ghost" onClick={() => setPerson(null)}>
                  Change
                </Button>
              ) : null}
            </p>
          ) : (
            <>
              <Input autoFocus placeholder="Search people" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search people" />
              <ul className="max-h-56 divide-y divide-border overflow-y-auto rounded-md border border-border">
                {users.data?.data.map((u) => (
                  <li key={u.id}>
                    <button type="button" className="flex w-full items-center gap-3 px-3 py-2 text-left text-[13px] hover:bg-bg-subtle" onClick={() => setPerson({ id: u.id, name: u.display_name, email: u.email })}>
                      <Avatar name={u.display_name} size={24} /> {u.display_name} <span className="text-fg-subtle">{u.email}</span>
                    </button>
                  </li>
                ))}
              </ul>
            </>
          )}
          <Field label="Account name" htmlFor="username" hint="Leave empty to use the start of their email address. Lower-case, up to 20 characters.">
            <Input id="username" className="font-mono" value={username} placeholder={person?.email.split("@")[0]?.toLowerCase().slice(0, 20)} onChange={(e) => setUsername(e.target.value)} />
          </Field>
          <label className="flex items-start gap-2 text-[13px]">
            <input type="checkbox" className="mt-0.5" checked={admin} disabled={!can("devices:scripts")} onChange={(e) => setAdmin(e.target.checked)} />
            <span>
              Administrator on this device
              <span className="block text-xs text-fg-muted">{can("devices:scripts") ? "They can do anything on it, like root." : "Only owners and admins can grant this."}</span>
            </span>
          </label>
          <label className="flex items-start gap-2 text-[13px]">
            <input type="checkbox" className="mt-0.5" checked={takeOver} onChange={(e) => setTakeOver(e.target.checked)} />
            <span>
              Take over an existing account with this name
              <span className="block text-xs text-fg-muted">It keeps its files; from their next Nexus sign-in it uses their company password.</span>
            </span>
          </label>
          <div className="flex justify-end gap-2">
            <Button type="button" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" variant="primary" loading={save.isPending} disabled={!person}>
              Save
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

/** For the person: their accounts on devices, and whether each has their current password. */
export function MyDeviceAccounts() {
  const q = useQuery({ queryKey: ["me-device-accounts"], queryFn: () => unwrap(api.GET("/v1/me/device-accounts")) });
  if (!q.data?.data.length) return null;
  return (
    <Card className="overflow-hidden">
      <CardHeader title="Sign in to your devices" description="Use your Nexus password. After you change it, your devices pick up the new one within a minute or two, as long as they're online." />
      <ul className="divide-y divide-border">
        {q.data.data.map((a) => (
          <li key={a.device_id} className="flex flex-wrap items-center justify-between gap-2 px-4 py-2.5 text-[13px]">
            <span>
              <span className="font-medium">{a.hostname}</span> · account <code className="font-mono text-xs">{a.username}</code>
              {a.admin ? <span className="text-xs text-fg-muted"> (administrator)</span> : null}
            </span>
            <StatusPill tone={a.status === "active" && a.password_synced ? "success" : a.status === "failed" ? "danger" : "warning"}>
              {a.status === "active" && a.password_synced ? "ready" : a.status === "disabled" ? "disabled" : a.status === "failed" ? "needs IT" : "waiting for the device"}
            </StatusPill>
          </li>
        ))}
      </ul>
    </Card>
  );
}
