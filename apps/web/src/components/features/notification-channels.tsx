"use client";

import type { Schemas } from "@nexus/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Bell, Hash, Mail, Moon } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { useStepUp } from "@/components/step-up";
import { Button } from "@/components/ui/button";
import { Field, Input, Select } from "@/components/ui/input";
import { Card, CardHeader, ErrorBanner, StatusPill } from "@/components/ui/misc";
import { api, unwrap } from "@/lib/api";
import { useCan } from "@/lib/queries";

const LEVELS = [
  { value: "all", label: "Everything" },
  { value: "important", label: "Warnings and critical alerts" },
  { value: "critical", label: "Critical alerts only" },
] as const;
type Level = (typeof LEVELS)[number]["value"];

type Prefs = Schemas["NotificationPreferences"];
const browserZone = () => {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
  } catch {
    return "UTC";
  }
};

/** NTF-07: what reaches your phone and inbox, and when. Critical alerts always do, right away. */
export function NotificationPrefsCard() {
  const qc = useQueryClient();
  const prefs = useQuery({ queryKey: ["notification-prefs"], queryFn: () => unwrap(api.GET("/v1/me/notification-preferences")) });
  const save = useMutation({
    mutationFn: (body: Partial<Prefs>) => unwrap(api.PUT("/v1/me/notification-preferences", { body })),
    onSuccess: (r) => (qc.setQueryData(["notification-prefs"], r), toast.success("Notification settings saved")),
  });
  const p = prefs.data;
  // Turning on a time-based setting also records where you are, so "22:00" means your 22:00.
  const zone = (patch: Partial<Prefs>) => save.mutate(p && p.timezone === "UTC" && browserZone() !== "UTC" ? { ...patch, timezone: browserZone() } : patch);
  return (
    <Card>
      <CardHeader
        title={
          <span className="flex items-center gap-2">
            <Bell className="size-4 text-fg-muted" /> Notifications
          </span>
        }
        description="Everything lands in your Nexus inbox. Choose what also reaches your phone (Nexus Mobile) and email, and when. Critical security alerts always do, right away."
      />
      {p ? (
        <div className="grid gap-4 p-4 sm:grid-cols-2">
          {(["push", "email"] as const).map((ch) => (
            <Field key={ch} label={ch === "push" ? "Phone (Nexus Mobile)" : "Email"} htmlFor={`pref-${ch}`}>
              <Select id={`pref-${ch}`} className="w-full" value={p[ch]} disabled={save.isPending} onChange={(e) => save.mutate({ [ch]: e.target.value as Level })}>
                {LEVELS.map((l) => (
                  <option key={l.value} value={l.value}>
                    {l.label}
                  </option>
                ))}
              </Select>
            </Field>
          ))}
          <div className="space-y-2 rounded-md border border-border p-3 sm:col-span-2">
            <label className="flex items-center gap-2 text-[13px] font-medium">
              <input type="checkbox" checked={p.quiet_hours.enabled} disabled={save.isPending} onChange={(e) => zone({ quiet_hours: { ...p.quiet_hours, enabled: e.target.checked } })} />
              <Moon className="size-3.5 text-fg-muted" /> Quiet hours
            </label>
            <div className="flex flex-wrap items-center gap-2 text-[13px] text-fg-muted">
              From
              <TimeInput label="Quiet hours start" value={p.quiet_hours.start} disabled={save.isPending || !p.quiet_hours.enabled} onChange={(start) => save.mutate({ quiet_hours: { ...p.quiet_hours, start } })} />
              to
              <TimeInput label="Quiet hours end" value={p.quiet_hours.end} disabled={save.isPending || !p.quiet_hours.enabled} onChange={(end) => save.mutate({ quiet_hours: { ...p.quiet_hours, end } })} />
            </div>
            <p className="text-xs text-fg-subtle">Other notifications wait, then arrive as one summary when quiet hours end.</p>
          </div>
          <div className="space-y-2 rounded-md border border-border p-3 sm:col-span-2">
            <label className="flex items-center gap-2 text-[13px] font-medium">
              <input type="checkbox" checked={p.digest.enabled} disabled={save.isPending} onChange={(e) => zone({ digest: { ...p.digest, enabled: e.target.checked } })} />
              <Mail className="size-3.5 text-fg-muted" /> Daily email digest
            </label>
            <div className="flex flex-wrap items-center gap-2 text-[13px] text-fg-muted">
              One email a day at
              <TimeInput label="Digest time" value={p.digest.time} disabled={save.isPending || !p.digest.enabled} onChange={(time) => save.mutate({ digest: { ...p.digest, time } })} />
              instead of one per notification.
            </div>
          </div>
          <div className="sm:col-span-2">
            <ErrorBanner error={save.error} />
            <p className="text-xs text-fg-subtle">
              Times are in {p.timezone.replace(/_/g, " ")}
              {p.timezone !== browserZone() ? (
                <>
                  {" "}
                  ·{" "}
                  <button type="button" className="text-primary hover:underline" onClick={() => save.mutate({ timezone: browserZone() })}>
                    Use {browserZone().replace(/_/g, " ")}
                  </button>
                </>
              ) : null}
              . Phone notifications never contain details: they say “Security alert” and open the app, which shows the rest after you unlock it.
            </p>
          </div>
        </div>
      ) : null}
    </Card>
  );
}

function TimeInput({ label, value, disabled, onChange }: { label: string; value: string; disabled?: boolean; onChange: (v: string) => void }) {
  return (
    <Input
      type="time"
      aria-label={label}
      className="w-36"
      defaultValue={value}
      key={value}
      disabled={disabled}
      onBlur={(e) => e.target.value && e.target.value !== value && onChange(e.target.value)}
    />
  );
}

/** NTF-06: org-wide alerts to the security team's Slack channel. */
export function AlertChannelsCard() {
  const qc = useQueryClient();
  const withStepUp = useStepUp();
  const can = useCan();
  const ch = useQuery({ queryKey: ["alert-channels"], queryFn: () => unwrap(api.GET("/v1/org/alert-channels")), enabled: can("org:manage") });
  const [url, setUrl] = useState("");
  const [severity, setSeverity] = useState<"info" | "warning" | "critical" | null>(null);
  const save = useMutation({
    mutationFn: (body: { slack_webhook_url?: string | null; slack_min_severity: "info" | "warning" | "critical" }) => withStepUp(() => unwrap(api.PUT("/v1/org/alert-channels", { body }))),
    onSuccess: (r, body) => {
      qc.setQueryData(["alert-channels"], r);
      setUrl("");
      toast.success(body.slack_webhook_url === null ? "Slack alerts turned off" : "Slack alerts saved");
    },
  });
  const test = useMutation({
    mutationFn: () => unwrap(api.POST("/v1/org/alert-channels/test", {})),
    onSuccess: () => toast.success("Test alert sent to Slack"),
  });
  if (!can("org:manage") || !ch.data) return null;
  const sev = severity ?? ch.data.slack_min_severity;
  return (
    <Card>
      <CardHeader
        title={
          <span className="flex items-center gap-2">
            <Hash className="size-4 text-fg-muted" /> Alerts to Slack
          </span>
        }
        description="Security alerts for admins (contained accounts, halted rollouts, failing syncs…) also go to a Slack channel, once per alert."
        actions={ch.data.slack_configured ? <StatusPill tone="success">Connected</StatusPill> : null}
      />
      <div className="grid gap-4 p-4 sm:grid-cols-[1fr_220px]">
        <Field label={ch.data.slack_configured ? "Replace the incoming webhook URL" : "Slack incoming webhook URL"} htmlFor="slack-url" hint="In Slack: Apps → Incoming Webhooks → Add to a channel, then paste the URL.">
          <Input id="slack-url" type="password" autoComplete="off" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://hooks.slack.com/services/…" />
        </Field>
        <Field label="Send alerts from" htmlFor="slack-sev">
          <Select id="slack-sev" className="w-full" value={sev} onChange={(e) => setSeverity(e.target.value as typeof sev)}>
            <option value="critical">Critical only</option>
            <option value="warning">Warning and critical</option>
            <option value="info">Everything</option>
          </Select>
        </Field>
        <div className="flex flex-wrap items-center gap-2 sm:col-span-2">
          <Button variant="primary" loading={save.isPending} disabled={!ch.data.slack_configured && !url} onClick={() => save.mutate({ ...(url ? { slack_webhook_url: url } : {}), slack_min_severity: sev })}>
            Save
          </Button>
          {ch.data.slack_configured ? (
            <>
              <Button variant="secondary" loading={test.isPending} onClick={() => test.mutate()}>
                Send test alert
              </Button>
              <Button variant="ghost" onClick={() => save.mutate({ slack_webhook_url: null, slack_min_severity: sev })}>
                Disconnect
              </Button>
            </>
          ) : null}
        </div>
        <div className="sm:col-span-2">
          <ErrorBanner error={save.error ?? test.error} />
        </div>
      </div>
    </Card>
  );
}
