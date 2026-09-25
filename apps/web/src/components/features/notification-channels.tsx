"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Bell, Hash } from "lucide-react";
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

/** NTF-07: what reaches your phone and inbox. Critical alerts always do. */
export function NotificationPrefsCard() {
  const qc = useQueryClient();
  const prefs = useQuery({ queryKey: ["notification-prefs"], queryFn: () => unwrap(api.GET("/v1/me/notification-preferences")) });
  const save = useMutation({
    mutationFn: (body: { email: Level; push: Level }) => unwrap(api.PUT("/v1/me/notification-preferences", { body })),
    onSuccess: (r) => (qc.setQueryData(["notification-prefs"], r), toast.success("Notification settings saved")),
  });
  const p = prefs.data;
  return (
    <Card>
      <CardHeader
        title={
          <span className="flex items-center gap-2">
            <Bell className="size-4 text-fg-muted" /> Notifications
          </span>
        }
        description="Everything lands in your Nexus inbox. Choose what also reaches your phone (Nexus Mobile) and email. Critical security alerts always do."
      />
      {p ? (
        <div className="grid gap-4 p-4 sm:grid-cols-2">
          {(["push", "email"] as const).map((ch) => (
            <Field key={ch} label={ch === "push" ? "Phone (Nexus Mobile)" : "Email"} htmlFor={`pref-${ch}`}>
              <Select id={`pref-${ch}`} className="w-full" value={p[ch]} disabled={save.isPending} onChange={(e) => save.mutate({ ...p, [ch]: e.target.value as Level })}>
                {LEVELS.map((l) => (
                  <option key={l.value} value={l.value}>
                    {l.label}
                  </option>
                ))}
              </Select>
            </Field>
          ))}
          <div className="sm:col-span-2">
            <ErrorBanner error={save.error} />
            <p className="text-xs text-fg-subtle">Phone notifications never contain details: they say “Security alert” and open the app, which shows the rest after you unlock it.</p>
          </div>
        </div>
      ) : null}
    </Card>
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
