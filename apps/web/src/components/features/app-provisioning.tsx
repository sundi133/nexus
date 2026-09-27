"use client";

import type { Schemas } from "@nexus/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, CheckCircle2, RefreshCw, RotateCcw } from "lucide-react";
import { useEffect, useState } from "react";
import { toast } from "sonner";
import { useStepUp } from "@/components/step-up";
import { Button } from "@/components/ui/button";
import { Field, Input } from "@/components/ui/input";
import { Card, CardHeader, EmptyState, ErrorBanner, Skeleton, StatusPill, type Tone } from "@/components/ui/misc";
import { api, unwrap } from "@/lib/api";
import { useCan } from "@/lib/queries";
import { cn, pluralize, timeAgo } from "@/lib/utils";

type Prov = Schemas["AppProvisioning"];
const STATE: Record<Prov["accounts"][number]["state"], { label: string; tone: Tone }> = {
  active: { label: "Active", tone: "success" },
  inactive: { label: "Deactivated", tone: "neutral" },
  error: { label: "Error", tone: "danger" },
  pending: { label: "Syncing", tone: "primary" },
};

/** SCIM provisioning for one app (SCIM-01/02): settings, then every account's state. */
export function AppProvisioning({ appId, appName }: { appId: string; appName: string }) {
  const key = ["provisioning", appId];
  const qc = useQueryClient();
  const withStepUp = useStepUp();
  const can = useCan();
  const editable = can("apps:write");
  const prov = useQuery({
    queryKey: key,
    queryFn: () => unwrap(api.GET("/v1/apps/{id}/provisioning", { params: { path: { id: appId } } })),
    refetchInterval: (q) => (q.state.data?.counts.pending ? 2000 : 30_000),
  });
  const p = prov.data;
  const [baseUrl, setBaseUrl] = useState("");
  const [token, setToken] = useState("");
  const [pushGroups, setPushGroups] = useState(true);
  const [onUnassign, setOnUnassign] = useState<"deactivate" | "delete">("deactivate");
  const [tested, setTested] = useState(false);
  useEffect(() => {
    if (!p) return;
    setBaseUrl(p.base_url);
    setPushGroups(p.push_groups);
    setOnUnassign(p.on_unassign);
  }, [p]);

  const test = useMutation({
    mutationFn: () => unwrap(api.POST("/v1/apps/{id}/provisioning/test", { params: { path: { id: appId } }, body: { base_url: baseUrl.trim(), ...(token ? { token } : {}) } })),
    onSuccess: () => setTested(true),
    onError: () => setTested(false),
  });
  const save = useMutation({
    mutationFn: (enabled: boolean) =>
      withStepUp(() =>
        unwrap(api.PUT("/v1/apps/{id}/provisioning", { params: { path: { id: appId } }, body: { base_url: baseUrl.trim(), enabled, push_groups: pushGroups, on_unassign: onUnassign, ...(token ? { token } : {}) } })),
      ),
    onSuccess: (r, enabled) => {
      qc.setQueryData(key, r);
      setToken("");
      toast.success(enabled ? `Provisioning to ${appName} is on` : "Provisioning settings saved", {
        description: enabled ? "Everyone assigned gets an account; people who lose access are deactivated." : undefined,
      });
    },
  });
  const sync = useMutation({
    mutationFn: () => unwrap(api.POST("/v1/apps/{id}/provisioning/sync", { params: { path: { id: appId } } })),
    onSuccess: (r) => qc.setQueryData(key, r),
  });
  const retry = useMutation({
    mutationFn: (userId: string) => unwrap(api.POST("/v1/apps/{id}/provisioning/accounts/{userId}/retry", { params: { path: { id: appId, userId } } })),
    onSuccess: (r) => qc.setQueryData(key, r),
  });

  if (prov.isPending) return <Skeleton className="h-64" />;
  if (!p) return <ErrorBanner error={prov.error} />;

  return (
    <div className="grid gap-5 lg:grid-cols-5">
      <Card className="lg:col-span-2">
        <CardHeader title="Automatic provisioning (SCIM)" description={`Create, update and deactivate accounts in ${appName} as people join, move and leave.`} />
        <div className="space-y-4 p-4">
          {p.enabled ? (
            <p className="flex items-center gap-2 text-[13px] text-success">
              <CheckCircle2 className="size-4" /> On{p.last_success_at ? ` · last change pushed ${timeAgo(p.last_success_at)}` : ""}
            </p>
          ) : null}
          {p.last_error ? (
            <div className="flex items-start gap-2 rounded-md border border-danger/30 bg-danger-soft px-3 py-2 text-[13px]">
              <AlertTriangle className="mt-0.5 size-4 shrink-0 text-danger" />
              <div>
                <p className="font-medium">{p.last_error}</p>
                <p className="text-xs text-fg-muted">{p.last_error_at ? `Since ${timeAgo(p.last_error_at)}. ` : ""}Paste a new token below, save, then retry the failed accounts.</p>
              </div>
            </div>
          ) : null}
          <Field label="SCIM base URL" htmlFor="scim-url" hint={`From ${appName}'s admin settings, e.g. https://api.example.com/scim/v2`}>
            <Input id="scim-url" value={baseUrl} disabled={!editable} onChange={(e) => (setBaseUrl(e.target.value), setTested(false))} placeholder="https://" />
          </Field>
          <Field label={p.configured ? "Bearer token (leave empty to keep the current one)" : "Bearer token"} htmlFor="scim-token">
            <Input id="scim-token" type="password" autoComplete="off" value={token} disabled={!editable} onChange={(e) => (setToken(e.target.value), setTested(false))} />
          </Field>
          <label className="flex items-start gap-2 text-[13px]">
            <input type="checkbox" className="mt-0.5" checked={pushGroups} disabled={!editable} onChange={(e) => setPushGroups(e.target.checked)} />
            <span>
              Push assigned groups <span className="block text-xs text-fg-muted">Groups assigned to this app are created in it, with their members.</span>
            </span>
          </label>
          <fieldset className="space-y-1 text-[13px]">
            <legend className="mb-1 font-medium">When someone loses access</legend>
            <label className="flex items-center gap-2">
              <input type="radio" disabled={!editable} checked={onUnassign === "deactivate"} onChange={() => setOnUnassign("deactivate")} /> Deactivate their account (recommended: keeps their data)
            </label>
            <label className="flex items-center gap-2">
              <input type="radio" disabled={!editable} checked={onUnassign === "delete"} onChange={() => setOnUnassign("delete")} /> Delete their account
            </label>
          </fieldset>
          <ErrorBanner error={test.error ?? save.error} />
          {editable ? (
            <div className="flex flex-wrap items-center gap-2 border-t border-border pt-4">
              <Button variant="secondary" loading={test.isPending} disabled={!baseUrl.trim() || (!p.configured && !token)} onClick={() => test.mutate()}>
                Test connection
              </Button>
              {tested ? (
                <span className="flex items-center gap-1 text-xs text-success">
                  <CheckCircle2 className="size-3.5" /> Connected
                </span>
              ) : null}
              <span className="flex-1" />
              {p.enabled ? (
                <>
                  <Button variant="ghost" loading={save.isPending && save.variables === false} onClick={() => save.mutate(false)}>
                    Turn off
                  </Button>
                  <Button variant="primary" loading={save.isPending && save.variables === true} onClick={() => save.mutate(true)}>
                    Save
                  </Button>
                </>
              ) : (
                <Button variant="primary" loading={save.isPending} disabled={!tested && !p.configured} onClick={() => save.mutate(true)}>
                  Turn on provisioning
                </Button>
              )}
            </div>
          ) : null}
        </div>
      </Card>

      <Card className="lg:col-span-3">
        <CardHeader
          title="Accounts"
          description={
            p.configured ? `${pluralize(p.counts.active, "active account")} · ${p.counts.inactive} deactivated${p.counts.error ? ` · ${p.counts.error} failing` : ""}${p.counts.pending ? ` · ${p.counts.pending} syncing` : ""}` : undefined
          }
          actions={
            editable && p.enabled ? (
              <Button size="sm" variant="secondary" loading={sync.isPending} onClick={() => sync.mutate()}>
                <RefreshCw /> Re-check all
              </Button>
            ) : null
          }
        />
        {p.accounts.length ? (
          <table className="w-full text-[13px]">
            <thead className="bg-bg-subtle text-left text-xs text-fg-muted">
              <tr>
                <th className="px-4 py-2 font-medium">Person</th>
                <th className="px-4 py-2 font-medium">Account</th>
                <th className="px-4 py-2 font-medium">Last change</th>
                <th />
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {p.accounts.map((a) => (
                <tr key={a.user_id} className={cn(a.state === "error" && "bg-danger-soft/40")}>
                  <td className="px-4 py-2">
                    <p className="font-medium">{a.display_name}</p>
                    <p className="text-xs text-fg-muted">{a.email}</p>
                  </td>
                  <td className="px-4 py-2">
                    <StatusPill tone={STATE[a.state].tone}>{STATE[a.state].label}</StatusPill>
                    {a.last_error ? <p className="mt-1 max-w-xs text-xs text-danger">{a.last_error}</p> : null}
                  </td>
                  <td className="px-4 py-2 text-xs text-fg-muted">{a.last_synced_at ? timeAgo(a.last_synced_at) : "—"}</td>
                  <td className="px-4 py-2 text-right">
                    {editable && a.state === "error" ? (
                      <Button size="sm" variant="ghost" loading={retry.isPending && retry.variables === a.user_id} onClick={() => retry.mutate(a.user_id)}>
                        <RotateCcw /> Retry
                      </Button>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <EmptyState title={p.enabled ? "No accounts yet" : "Provisioning is off"} description={p.enabled ? "Assign people or groups to this app and their accounts appear here." : "Turn it on to create accounts for everyone assigned."} />
        )}
        {p.groups.length ? (
          <p className="border-t border-border px-4 py-3 text-xs text-fg-muted">Groups pushed: {p.groups.map((g) => g.display_name).join(", ")}</p>
        ) : null}
        <ErrorBanner error={sync.error ?? retry.error} />
      </Card>
    </div>
  );
}
