"use client";

import type { Schemas } from "@nexus/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Globe, Plus, Trash2 } from "lucide-react";
import { useEffect, useState } from "react";
import { toast } from "sonner";
import { useStepUp } from "@/components/step-up";
import { Button } from "@/components/ui/button";
import { CopyField } from "@/components/ui/copy";
import { Input, Select } from "@/components/ui/input";
import { Card, CardHeader, EmptyState, ErrorBanner, PageHeader, Skeleton, StatusPill, type Tone } from "@/components/ui/misc";
import { Tabs, TabsContent, TabsList } from "@/components/ui/overlay";
import { Table, TD, TH, THead, TR } from "@/components/ui/table";
import { api, unwrap } from "@/lib/api";
import { useCan } from "@/lib/queries";
import { formatDateTime, pluralize, timeAgo } from "@/lib/utils";

type Policy = Schemas["BrowserPolicy"];
type Draft = { apps: Record<string, "allow" | "warn" | "block">; detectors: Record<string, "off" | "monitor" | "warn" | "block">; custom: Policy["dlp"]["custom"]; uploads: Policy["uploads"]; message: string };

const DETECTORS: [string, string][] = [
  ["secret", "API keys, tokens and passwords"],
  ["private_key", "Private keys"],
  ["credit_card", "Payment card numbers"],
  ["us_ssn", "US Social Security numbers"],
  ["iban", "Bank account numbers (IBAN)"],
  ["email_list", "Lists of email addresses (10 or more)"],
];
const ACTION_TONE: Record<string, Tone> = { blocked: "danger", warned: "warning", continued: "warning", monitored: "neutral", allowed: "success" };

const toDraft = (p: Policy): Draft => ({
  apps: Object.fromEntries(p.apps.map((a) => [a.key, a.action])),
  detectors: { ...p.dlp.detectors } as Draft["detectors"],
  custom: p.dlp.custom,
  uploads: p.uploads,
  message: p.message,
});

export default function AIBrowsersPage() {
  const can = useCan();
  const editable = can("devices:enforce");
  const qc = useQueryClient();
  const withStepUp = useStepUp();
  const policy = useQuery({ queryKey: ["browser-policy"], queryFn: () => unwrap(api.GET("/v1/browser/policy")) });
  const usage = useQuery({ queryKey: ["browser-usage"], queryFn: () => unwrap(api.GET("/v1/browser/usage")), refetchInterval: 60_000 });
  const events = useQuery({ queryKey: ["browser-events"], queryFn: () => unwrap(api.GET("/v1/browser/events", { params: { query: { limit: 200 } } })), refetchInterval: 30_000 });
  const [draft, setDraft] = useState<Draft | null>(null);
  useEffect(() => {
    if (policy.data) setDraft(toDraft(policy.data));
  }, [policy.data]);
  const dirty = !!draft && !!policy.data && JSON.stringify(draft) !== JSON.stringify(toDraft(policy.data));
  const save = useMutation({
    mutationFn: () =>
      withStepUp(() =>
        unwrap(
          api.PUT("/v1/browser/policy", {
            body: { apps: Object.fromEntries(Object.entries(draft!.apps).filter(([, v]) => v !== "allow")), dlp: { detectors: draft!.detectors, custom: draft!.custom }, uploads: draft!.uploads, message: draft!.message },
          }),
        ),
      ),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["browser-policy"] });
      toast.success("Saved. Browsers pick it up within a minute.");
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : "Couldn't save"),
  });

  const byApp = new Map((usage.data?.data ?? []).map((u) => [u.app, u]));
  const saveBar =
    editable && dirty ? (
      <div className="flex items-center justify-end gap-2">
        <Button onClick={() => setDraft(toDraft(policy.data!))}>Discard</Button>
        <Button variant="primary" onClick={() => save.mutate()} loading={save.isPending}>
          Save changes
        </Button>
      </div>
    ) : null;

  return (
    <>
      <PageHeader
        title="AI in browsers"
        description="The Nexus browser extension (Chrome and Edge) shows which AI apps people use, blocks or warns about the ones you don't approve, and stops company data they paste, send or upload. Text is checked in the browser and never sent to Nexus."
        actions={usage.data ? <span className="text-xs text-fg-muted">{pluralize(usage.data.browsers.people, "person")} reporting in the last 30 days{usage.data.browsers.last_seen_at ? `; latest ${timeAgo(usage.data.browsers.last_seen_at)}` : ""}</span> : null}
      />
      {policy.isPending || !draft ? (
        policy.error ? <ErrorBanner error={policy.error} /> : <Skeleton className="h-64" />
      ) : (
        <Tabs defaultValue="apps">
          <TabsList tabs={[{ value: "apps", label: "Apps" }, { value: "data", label: "Data protection" }, { value: "events", label: "Events" }, { value: "setup", label: "Setup" }]} />

          <TabsContent value="apps" className="space-y-4">
            <Card className="overflow-hidden">
              <CardHeader title="AI apps" description="Allow is the default: you see who uses what. Warn shows a page asking people to check first (they can continue for an hour). Block replaces the app with a page saying it's blocked." />
              <Table>
                <THead>
                  <TR>
                    <TH>App</TH>
                    <TH className="text-right">People (30 days)</TH>
                    <TH className="text-right">Visits</TH>
                    <TH className="text-right">Sensitive data</TH>
                    <TH>Action</TH>
                  </TR>
                </THead>
                <tbody>
                  {policy.data!.apps.map((a) => {
                    const u = byApp.get(a.key);
                    return (
                      <TR key={a.key}>
                        <TD>
                          <span className="font-medium">{a.name}</span> <span className="text-xs text-fg-muted">{a.vendor}</span>
                          <span className="block font-mono text-[11px] text-fg-subtle">{a.hosts.join(", ")}</span>
                        </TD>
                        <TD className="text-right tabular-nums">{u?.people ?? 0}</TD>
                        <TD className="text-right tabular-nums">{u?.visits ?? 0}</TD>
                        <TD className="text-right tabular-nums">{u?.sensitive ? <span className="font-medium text-danger">{u.sensitive}</span> : 0}</TD>
                        <TD>
                          <Select aria-label={`${a.name} action`} disabled={!editable} value={draft.apps[a.key] ?? "allow"} onChange={(e) => setDraft({ ...draft, apps: { ...draft.apps, [a.key]: e.target.value as "allow" } })}>
                            <option value="allow">Allow</option>
                            <option value="warn">Warn</option>
                            <option value="block">Block</option>
                          </Select>
                        </TD>
                      </TR>
                    );
                  })}
                </tbody>
              </Table>
            </Card>
            {saveBar}
          </TabsContent>

          <TabsContent value="data" className="space-y-4">
            <Card>
              <CardHeader title="Sensitive data" description="Checked when people paste into an AI app, press Enter or Send, or upload a file. Monitor records it; Warn asks them to confirm; Block stops it. Only what kind of data it was (and a masked hint like “•••• 4242”) reaches Nexus." />
              <div className="divide-y divide-border">
                {DETECTORS.map(([id, label]) => (
                  <div key={id} className="flex items-center justify-between gap-3 px-4 py-2.5 text-[13px]">
                    <span>{label}</span>
                    <Select aria-label={label} disabled={!editable} value={draft.detectors[id] ?? "off"} onChange={(e) => setDraft({ ...draft, detectors: { ...draft.detectors, [id]: e.target.value as "off" } })}>
                      <option value="off">Off</option>
                      <option value="monitor">Monitor</option>
                      <option value="warn">Warn</option>
                      <option value="block">Block</option>
                    </Select>
                  </div>
                ))}
                <div className="flex items-center justify-between gap-3 px-4 py-2.5 text-[13px]">
                  <span>
                    File uploads
                    <span className="block text-xs text-fg-muted">The attach button, drag and drop, and pasted images</span>
                  </span>
                  <Select aria-label="File uploads" disabled={!editable} value={draft.uploads} onChange={(e) => setDraft({ ...draft, uploads: e.target.value as "allow" })}>
                    <option value="allow">Allow</option>
                    <option value="warn">Warn</option>
                    <option value="block">Block</option>
                  </Select>
                </div>
              </div>
            </Card>
            <Card>
              <CardHeader
                title="Your own patterns"
                description="Project code names, customer IDs, internal hostnames: regular expressions, matched without regard to case."
                actions={
                  editable ? (
                    <Button size="sm" onClick={() => setDraft({ ...draft, custom: [...draft.custom, { id: `p${Date.now().toString(36)}`, name: "", pattern: "", action: "warn" }] })}>
                      <Plus className="size-3.5" /> Add pattern
                    </Button>
                  ) : null
                }
              />
              {draft.custom.length ? (
                <div className="divide-y divide-border">
                  {draft.custom.map((c, i) => {
                    const set = (patch: Partial<(typeof draft.custom)[number]>) => setDraft({ ...draft, custom: draft.custom.map((x, j) => (j === i ? { ...x, ...patch } : x)) });
                    return (
                      <div key={c.id} className="grid gap-2 px-4 py-2.5 sm:grid-cols-[1fr_1.5fr_auto_auto]">
                        <Input aria-label="Name" placeholder="Name, e.g. Project Falcon" disabled={!editable} value={c.name} onChange={(e) => set({ name: e.target.value })} />
                        <Input aria-label="Pattern" className="font-mono text-xs" placeholder="project\s+falcon" disabled={!editable} value={c.pattern} onChange={(e) => set({ pattern: e.target.value })} />
                        <Select aria-label="Action" disabled={!editable} value={c.action} onChange={(e) => set({ action: e.target.value as "warn" })}>
                          <option value="monitor">Monitor</option>
                          <option value="warn">Warn</option>
                          <option value="block">Block</option>
                        </Select>
                        {editable ? (
                          <Button aria-label="Remove pattern" onClick={() => setDraft({ ...draft, custom: draft.custom.filter((_, j) => j !== i) })}>
                            <Trash2 className="size-3.5" />
                          </Button>
                        ) : null}
                      </div>
                    );
                  })}
                </div>
              ) : (
                <p className="px-4 pb-4 text-[13px] text-fg-muted">None yet.</p>
              )}
            </Card>
            <Card>
              <CardHeader title="Message to people" description="Shown on warnings and blocks: a link to your AI policy, or who to ask." />
              <div className="p-4">
                <Input aria-label="Message" disabled={!editable} maxLength={500} placeholder="e.g. Use Claude Enterprise for company work: go/ai-policy" value={draft.message} onChange={(e) => setDraft({ ...draft, message: e.target.value })} />
              </div>
            </Card>
            {saveBar}
          </TabsContent>

          <TabsContent value="events">
            <Card className="overflow-hidden">
              {events.data?.data.length ? (
                <Table>
                  <THead>
                    <TR>
                      <TH>When</TH>
                      <TH>Person</TH>
                      <TH>App</TH>
                      <TH>What</TH>
                      <TH>Outcome</TH>
                    </TR>
                  </THead>
                  <tbody>
                    {events.data.data.map((e) => (
                      <TR key={e.id}>
                        <TD className="whitespace-nowrap text-xs text-fg-muted">{formatDateTime(e.at)}</TD>
                        <TD className="text-[13px]">{e.user_email || "—"}</TD>
                        <TD className="text-[13px]">{e.app_name || e.host}</TD>
                        <TD className="text-[13px]">{e.kind === "visit" ? "Opened the app" : e.kind === "upload" ? `Upload: ${e.detail}` : e.detail || e.detector}</TD>
                        <TD>
                          <StatusPill tone={ACTION_TONE[e.action] ?? "neutral"}>{e.action === "continued" ? "went ahead after a warning" : e.action}</StatusPill>
                        </TD>
                      </TR>
                    ))}
                  </tbody>
                </Table>
              ) : (
                <EmptyState icon={<Globe className="size-5" />} title="Nothing reported yet" description="Events appear once browsers with the extension use AI apps. See Setup." />
              )}
            </Card>
          </TabsContent>

          <TabsContent value="setup">
            <SetupTab editable={editable} server={policy.data!.server} />
          </TabsContent>
        </Tabs>
      )}
    </>
  );
}

function SetupTab({ editable, server }: { editable: boolean; server: string }) {
  const qc = useQueryClient();
  const withStepUp = useStepUp();
  const tokens = useQuery({ queryKey: ["browser-tokens"], queryFn: () => unwrap(api.GET("/v1/browser/tokens")), enabled: editable });
  const [created, setCreated] = useState<string | null>(null);
  const create = useMutation({
    mutationFn: () => withStepUp(() => unwrap(api.POST("/v1/browser/tokens", { body: { name: `Browsers ${new Date().toISOString().slice(0, 10)}` } }))),
    onSuccess: (t) => {
      setCreated(t.token);
      qc.invalidateQueries({ queryKey: ["browser-tokens"] });
    },
  });
  const revoke = useMutation({
    mutationFn: (id: string) => unwrap(api.DELETE("/v1/browser/tokens/{id}", { params: { path: { id } } })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["browser-tokens"] }),
  });
  const managed = JSON.stringify({ server: { Value: server }, token: { Value: created ?? "nxb_…" } }, null, 2);
  return (
    <div className="space-y-4">
      <Card>
        <CardHeader
          title="1. An extension token"
          description="Browsers use it to reach Nexus. It identifies your organization, not a person: people are recognized by their managed browser profile's email, and what browsers report is self-reported."
          actions={editable ? <Button size="sm" onClick={() => create.mutate()} loading={create.isPending}>Create token</Button> : null}
        />
        {created ? (
          <div className="px-4 pb-4">
            <CopyField label="Copy it now: it isn't shown again" value={created} secret />
          </div>
        ) : null}
        {tokens.data?.data.length ? (
          <ul className="divide-y divide-border border-t border-border">
            {tokens.data.data.map((t) => (
              <li key={t.id} className="flex items-center justify-between gap-3 px-4 py-2.5 text-[13px]">
                <span>
                  {t.name}
                  <span className="block text-xs text-fg-muted">
                    Created {formatDateTime(t.created_at)}
                    {t.created_by ? ` by ${t.created_by}` : ""} · {t.revoked_at ? `revoked ${timeAgo(t.revoked_at)}` : t.last_used_at ? `last used ${timeAgo(t.last_used_at)}` : "not used yet"}
                  </span>
                </span>
                {editable && !t.revoked_at ? (
                  <Button size="sm" variant="danger-outline" onClick={() => revoke.mutate(t.id)}>
                    Revoke
                  </Button>
                ) : null}
              </li>
            ))}
          </ul>
        ) : null}
      </Card>
      <Card>
        <CardHeader title="2. Install it on managed browsers" description="Force-install the Votal Nexus extension with your browser management, and give it this configuration. Chrome and Edge read it as the extension's managed policy." />
        <div className="space-y-3 px-4 pb-4 text-[13px]">
          <p>
            <span className="font-medium">Google Admin console:</span> Devices → Chrome → Apps &amp; extensions → Users &amp; browsers → add the extension, set it to <em>Force install</em>, and paste this under <em>Policy for extensions</em>:
          </p>
          <pre className="overflow-x-auto rounded-md border border-border bg-bg-subtle p-3 font-mono text-[11px]">{managed}</pre>
          <p>
            <span className="font-medium">Intune or Group Policy (Windows):</span> add the extension to <code className="font-mono">ExtensionInstallForcelist</code>, and set <code className="font-mono">server</code> and <code className="font-mono">token</code> under{" "}
            <code className="font-mono">HKLM\Software\Policies\Google\Chrome\3rdparty\extensions\&lt;extension ID&gt;\policy</code> (Edge: <code className="font-mono">…\Microsoft\Edge\3rdparty…</code>).
          </p>
          <p>
            <span className="font-medium">macOS (Jamf, Intune, Kandji):</span> a configuration profile for <code className="font-mono">com.google.Chrome.extensions.&lt;extension ID&gt;</code> with the same two keys.
          </p>
          <p className="text-xs text-fg-muted">For a pilot, load the extension unpacked (apps/browser-extension/dist) and set the configuration from its service worker console; docs/BROWSER-EXTENSION.md has the steps.</p>
        </div>
      </Card>
    </div>
  );
}
