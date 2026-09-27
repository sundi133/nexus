"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, Download, RefreshCw, Upload } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { useStepUp } from "@/components/step-up";
import { Button } from "@/components/ui/button";
import { Field, Input } from "@/components/ui/input";
import { Card, CardHeader, ErrorBanner, StatusPill } from "@/components/ui/misc";
import { api, unwrap } from "@/lib/api";
import { useCan } from "@/lib/queries";
import { formatDateTime, timeAgo } from "@/lib/utils";

function saveFile(name: string, text: string) {
  const url = URL.createObjectURL(new Blob([text], { type: "application/x-pem-file" }));
  const a = Object.assign(document.createElement("a"), { href: url, download: name });
  a.click();
  URL.revokeObjectURL(url);
}

/** Zero-touch enrollment through Apple Business Manager. */
export function AdeCard() {
  const can = useCan();
  const qc = useQueryClient();
  const withStepUp = useStepUp();
  const s = useQuery({ queryKey: ["apple-ade"], queryFn: () => unwrap(api.GET("/v1/apple-mdm/ade")) });
  const devices = useQuery({ queryKey: ["apple-ade-devices"], queryFn: () => unwrap(api.GET("/v1/apple-mdm/ade/devices")), enabled: !!s.data?.connected });
  const [token, setToken] = useState("");
  const [profile, setProfile] = useState({ profile_name: "Votal Nexus", support_email_address: "", support_phone_number: "", is_mdm_removable: false });
  const refresh = () => (qc.invalidateQueries({ queryKey: ["apple-ade"] }), qc.invalidateQueries({ queryKey: ["apple-ade-devices"] }));
  const key = useMutation({ mutationFn: () => withStepUp(() => unwrap(api.POST("/v1/apple-mdm/ade/public-key"))), onSuccess: (r) => (saveFile("nexus-abm-public-key.pem", r.certificate), refresh()) });
  const connect = useMutation({
    mutationFn: () => withStepUp(() => unwrap(api.PUT("/v1/apple-mdm/ade/token", { body: { token, profile: { ...profile, department: "", skip_setup_items: ["Siri", "Diagnostics", "ScreenTime", "AppleID", "Payment"], auto_assign: true } } }))),
    onSuccess: () => (toast.success("Connected to Apple Business Manager"), setToken(""), refresh()),
  });
  const sync = useMutation({ mutationFn: () => unwrap(api.POST("/v1/apple-mdm/ade/sync")), onSuccess: (r) => (toast.success(`Synced: ${r.changes} changes, ${r.assigned} assigned`), refresh()) });
  const d = s.data;
  if (!d) return null;
  const manage = can("org:manage");
  return (
    <Card>
      <CardHeader
        title="Apple Business Manager (zero-touch)"
        description={
          d.connected ? (
            <span className="flex flex-wrap items-center gap-2">
              <CheckCircle2 className="size-4 text-success" /> {d.server_name} · {d.abm_org_name} · {d.devices} Macs assigned
              {d.last_sync_at ? ` · synced ${timeAgo(d.last_sync_at)}` : ""}
              {d.token_expires_at ? ` · token until ${formatDateTime(d.token_expires_at)}` : ""}
            </span>
          ) : (
            "Macs bought through Apple or a reseller enroll themselves in Setup Assistant, before anyone signs in."
          )
        }
        actions={
          d.connected && can("devices:write") ? (
            <Button size="sm" loading={sync.isPending} onClick={() => sync.mutate()}>
              <RefreshCw className="size-3.5" /> Sync now
            </Button>
          ) : null
        }
      />
      <div className="space-y-3 px-4 pb-4 text-[13px]">
        <ErrorBanner error={key.error ?? connect.error ?? sync.error} />
        {d.last_error ? <p className="rounded-md bg-warning-soft px-3 py-2">{d.last_error}</p> : null}
        {!d.connected && manage ? (
          <ol className="list-decimal space-y-3 pl-5">
            <li>
              Download Nexus's public key.{" "}
              <Button size="sm" loading={key.isPending} onClick={() => key.mutate()}>
                <Download className="size-3.5" /> {d.key_ready ? "Make a new key" : "Download public key"}
              </Button>
            </li>
            <li>In Apple Business Manager: your name → Preferences → Your MDM Servers → Add (or edit a server), upload that key, save, then Download Token (a .p7m file).</li>
            <li>
              Upload the token and choose what people see in Setup Assistant:
              <div className="mt-2 grid gap-2 sm:grid-cols-2">
                <Field label="Server token (.p7m)" htmlFor="ade-token">
                  <Input id="ade-token" type="file" accept=".p7m" onChange={async (e) => setToken((await e.target.files?.[0]?.text()) ?? "")} />
                </Field>
                <Field label="Profile name" htmlFor="ade-name">
                  <Input id="ade-name" value={profile.profile_name} onChange={(e) => setProfile({ ...profile, profile_name: e.target.value })} />
                </Field>
                <Field label="IT support email" htmlFor="ade-email">
                  <Input id="ade-email" value={profile.support_email_address} onChange={(e) => setProfile({ ...profile, support_email_address: e.target.value })} />
                </Field>
                <Field label="IT support phone" htmlFor="ade-phone">
                  <Input id="ade-phone" value={profile.support_phone_number} onChange={(e) => setProfile({ ...profile, support_phone_number: e.target.value })} />
                </Field>
              </div>
              <label className="mt-2 flex items-center gap-2">
                <input type="checkbox" checked={profile.is_mdm_removable} onChange={(e) => setProfile({ ...profile, is_mdm_removable: e.target.checked })} /> Let people remove device management
              </label>
              <Button className="mt-2" variant="primary" size="sm" loading={connect.isPending} disabled={!token || !d.key_ready} onClick={() => connect.mutate()}>
                <Upload className="size-3.5" /> Connect
              </Button>
            </li>
          </ol>
        ) : null}
        {d.connected && devices.data?.data.length ? (
          <ul className="max-h-56 divide-y divide-border overflow-y-auto rounded-md border border-border">
            {devices.data.data.map((m) => (
              <li key={m.serial} className="flex items-center justify-between px-3 py-1.5">
                <span>
                  <code className="font-mono text-xs">{m.serial}</code> <span className="text-xs text-fg-muted">{m.model || m.description}</span>
                </span>
                <StatusPill tone={m.enrolled ? "success" : "neutral"}>{m.enrolled ? "enrolled" : m.profile_status || "waiting"}</StatusPill>
              </li>
            ))}
          </ul>
        ) : null}
      </div>
    </Card>
  );
}
