"use client";

import type { Schemas } from "@nexus/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Ban, Globe, Plus, Trash2 } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { toast } from "sonner";
import { ConfirmAction } from "@/components/features/confirm-action";
import { EventsTable } from "@/components/features/enforcement-bits";
import { useStepUp } from "@/components/step-up";
import { Button } from "@/components/ui/button";
import { Field, Input, Select } from "@/components/ui/input";
import { Badge, Card, CardHeader, EmptyState, ErrorBanner, PageHeader, Skeleton, StatusPill } from "@/components/ui/misc";
import { Dialog, DialogContent } from "@/components/ui/overlay";
import { Table, TD, TH, THead, TR } from "@/components/ui/table";
import { api, unwrap } from "@/lib/api";
import { useCan } from "@/lib/queries";
import { pluralize, timeAgo } from "@/lib/utils";

type Rule = Schemas["EnforcementRule"];
const MATCH: Record<Rule["match"], string> = { name: "Program name", path: "Path or folder", sha256: "SHA-256", domain: "Domain" };
export default function BlockRulesPage() {
  const can = useCan();
  const qc = useQueryClient();
  const withStepUp = useStepUp();
  const rules = useQuery({ queryKey: ["enforcement-rules"], queryFn: () => unwrap(api.GET("/v1/enforcement/rules")) });
  const events = useQuery({ queryKey: ["enforcement-events"], queryFn: () => unwrap(api.GET("/v1/enforcement/events", { params: { query: { limit: 100 } } })), refetchInterval: 30_000 });
  const groups = useQuery({ queryKey: ["groups", "block-rules"], queryFn: () => unwrap(api.GET("/v1/groups", { params: { query: { limit: 200 } } })) });
  const [adding, setAdding] = useState(false);
  const [removing, setRemoving] = useState<Rule | null>(null);
  const [enforcing, setEnforcing] = useState<Rule | null>(null);
  const editable = can("devices:enforce");
  const groupName = (id: string) => groups.data?.data.find((g) => g.id === id)?.name ?? "a group";
  const patch = useMutation({
    mutationFn: ({ id, body }: { id: string; body: Record<string, unknown> }) => withStepUp(() => unwrap(api.PATCH("/v1/enforcement/rules/{id}", { params: { path: { id } }, body }))),
    onSuccess: (r) => (qc.invalidateQueries({ queryKey: ["enforcement-rules"] }), toast.success(`${r.name} saved`, { description: "Devices apply it on their next check-in, within about a minute." })),
  });

  return (
    <>
      <PageHeader
        title="Block rules"
        description="Stop apps and domains on devices. App rules end a matching program within seconds of launch; domain rules make a domain unreachable through the hosts file. New app rules start in monitor mode, so you see what they'd stop first."
        actions={
          editable ? (
            <Button variant="primary" onClick={() => setAdding(true)}>
              <Plus /> Add rule
            </Button>
          ) : null
        }
      />
      <Card className="mb-5 overflow-hidden">
        {rules.isPending ? (
          <Skeleton className="h-32" />
        ) : !rules.data ? (
          <ErrorBanner error={rules.error} />
        ) : rules.data.data.length ? (
          <Table>
            <THead>
              <tr>
                <TH>Rule</TH>
                <TH>Matches</TH>
                <TH>Applies to</TH>
                <TH>Mode</TH>
                <TH className="text-right">Last 7 days</TH>
                <TH />
              </tr>
            </THead>
            <tbody>
              {rules.data.data.map((r) => (
                <TR key={r.id} className={r.enabled ? undefined : "opacity-60"}>
                  <TD className="min-w-[13rem]">
                    <span className="flex items-center gap-1.5 font-medium">
                      {r.kind === "domain" ? <Globe className="size-3.5 text-fg-muted" aria-hidden /> : <Ban className="size-3.5 text-fg-muted" aria-hidden />}
                      {r.name}
                      {!r.enabled ? <Badge>off</Badge> : null}
                    </span>
                    {r.reason ? <span className="text-xs text-fg-subtle">{r.reason}</span> : null}
                  </TD>
                  <TD>
                    <span className="text-xs text-fg-muted">{MATCH[r.match]}</span>
                    <code className="block max-w-[22rem] truncate font-mono text-xs" title={r.value}>
                      {r.value}
                    </code>
                  </TD>
                  <TD className="text-fg-muted">
                    {r.target.all ? "All devices" : (r.target.group_ids ?? []).map(groupName).join(", ")}
                    {r.platforms.length < 3 ? <span className="block text-xs text-fg-subtle">{r.platforms.join(", ")}</span> : null}
                  </TD>
                  <TD>
                    {r.mode === "block" ? <StatusPill tone="danger">Blocking</StatusPill> : <StatusPill tone="warning">Monitor</StatusPill>}
                    {editable && r.kind === "app" && r.mode === "monitor" ? (
                      <button type="button" className="mt-1 block text-xs text-primary hover:underline" onClick={() => setEnforcing(r)}>
                        Start blocking
                      </button>
                    ) : null}
                  </TD>
                  <TD className="text-right tabular-nums">
                    {r.stats.events_7d}
                    <span className="block text-xs text-fg-subtle">{pluralize(r.stats.devices, "device")}</span>
                  </TD>
                  <TD className="whitespace-nowrap text-right">
                    {editable ? (
                      <>
                        <Button size="sm" variant="ghost" onClick={() => patch.mutate({ id: r.id, body: { enabled: !r.enabled } })}>
                          {r.enabled ? "Turn off" : "Turn on"}
                        </Button>
                        <Button size="sm" variant="ghost" aria-label={`Remove ${r.name}`} onClick={() => setRemoving(r)}>
                          <Trash2 />
                        </Button>
                      </>
                    ) : null}
                  </TD>
                </TR>
              ))}
            </tbody>
          </Table>
        ) : (
          <EmptyState icon={<Ban className="size-5" />} title="No block rules" description="Add a rule to stop an app (e.g. an unapproved AI tool) or make a domain unreachable on devices." />
        )}
      </Card>

      <Card className="overflow-hidden">
        <CardHeader title="What devices stopped" description="Reported by agents on their next check-in. Repeats of the same app are counted." />
        <EventsTable events={events.data?.data ?? []} showDevice />
      </Card>

      {adding ? <AddRuleDialog onClose={() => setAdding(false)} groups={groups.data?.data ?? []} /> : null}
      <ConfirmAction
        open={!!enforcing}
        onOpenChange={(v) => !v && setEnforcing(null)}
        title={`Start blocking with “${enforcing?.name ?? ""}”?`}
        effects={[
          `Matching programs are ended within seconds of starting, on ${enforcing?.target.all ? "every device" : "the devices of the chosen groups"}.`,
          enforcing ? `In monitor mode it matched ${pluralize(enforcing.stats.events_7d, "time")} on ${pluralize(enforcing.stats.devices, "device")} in the last 7 days.` : "",
          "People lose unsaved work in a program that's ended. Tell them first.",
        ]}
        confirmLabel="Start blocking"
        danger
        askReason={false}
        onConfirm={async () => {
          await patch.mutateAsync({ id: enforcing!.id, body: { mode: "block" } });
          setEnforcing(null);
        }}
      />
      <ConfirmAction
        open={!!removing}
        onOpenChange={(v) => !v && setRemoving(null)}
        title={`Remove “${removing?.name ?? ""}”?`}
        effects={["Devices stop enforcing it on their next check-in.", "Its past events stay in the audit log."]}
        confirmLabel="Remove rule"
        danger
        askReason={false}
        onConfirm={async () => {
          await withStepUp(() => unwrap(api.DELETE("/v1/enforcement/rules/{id}", { params: { path: { id: removing!.id } } })));
          qc.invalidateQueries({ queryKey: ["enforcement-rules"] });
          toast.success(`${removing!.name} removed`);
          setRemoving(null);
        }}
      />
    </>
  );
}

function AddRuleDialog({ onClose, groups }: { onClose: () => void; groups: { id: string; name: string }[] }) {
  const qc = useQueryClient();
  const withStepUp = useStepUp();
  const [kind, setKind] = useState<"app" | "domain">("app");
  const [match, setMatch] = useState<Rule["match"]>("path");
  const [name, setName] = useState("");
  const [value, setValue] = useState("");
  const [reason, setReason] = useState("");
  const [target, setTarget] = useState<"all" | string>("all");
  const [platforms, setPlatforms] = useState<("macos" | "windows" | "linux")[]>(["macos", "windows", "linux"]);
  const create = useMutation({
    mutationFn: () =>
      withStepUp(() =>
        unwrap(
          api.POST("/v1/enforcement/rules", {
            body: { name, kind, match: kind === "domain" ? "domain" : match, value, reason, mode: "monitor", platforms, target: target === "all" ? { all: true } : { group_ids: [target] } },
          }),
        ),
      ),
    onSuccess: (r) => {
      qc.invalidateQueries({ queryKey: ["enforcement-rules"] });
      toast.success(`${r.name} added`, { description: r.kind === "app" ? "Monitoring first: devices report what it would stop." : "Devices block it on their next check-in." });
      onClose();
    },
  });
  const placeholder = kind === "domain" ? "chat.example.com" : match === "path" ? "/Applications/Example.app/ or C:\\Program Files\\Example\\" : match === "name" ? "Example or example.exe" : "64 hexadecimal characters";
  return (
    <Dialog open onOpenChange={(v) => !v && onClose()}>
      <DialogContent title="Add a block rule" description={kind === "app" ? "App rules start in monitor mode. Switch to blocking once you've seen what they match." : "Domain rules block at once: the domain resolves to nothing on the device."}>
        <div className="space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <Field label="Block">
              <Select value={kind} onChange={(e) => setKind(e.target.value as "app" | "domain")}>
                <option value="app">An app</option>
                <option value="domain">A domain</option>
              </Select>
            </Field>
            {kind === "app" ? (
              <Field label="Match by">
                <Select value={match} onChange={(e) => setMatch(e.target.value as Rule["match"])}>
                  <option value="path">Path or folder (ends with / or \)</option>
                  <option value="name">Program name</option>
                  <option value="sha256">SHA-256 of the program</option>
                </Select>
              </Field>
            ) : null}
          </div>
          <Field label="Name">
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Unapproved AI assistant" />
          </Field>
          <Field label={kind === "domain" ? "Domain" : MATCH[match]} hint={kind === "domain" ? "Exact name; subdomains need their own rule." : undefined}>
            <Input className="font-mono text-xs" value={value} onChange={(e) => setValue(e.target.value)} placeholder={placeholder} />
          </Field>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Devices">
              <Select value={target} onChange={(e) => setTarget(e.target.value)}>
                <option value="all">All devices</option>
                {groups.map((g) => (
                  <option key={g.id} value={g.id}>
                    {g.name}&apos;s devices
                  </option>
                ))}
              </Select>
            </Field>
            <Field label="Platforms">
              <div className="flex gap-3 pt-1.5 text-[13px]">
                {(["macos", "windows", "linux"] as const).map((pl) => (
                  <label key={pl} className="flex items-center gap-1">
                    <input type="checkbox" checked={platforms.includes(pl)} onChange={(e) => setPlatforms(e.target.checked ? [...platforms, pl] : platforms.filter((x) => x !== pl))} />
                    {pl === "macos" ? "macOS" : pl === "windows" ? "Windows" : "Linux"}
                  </label>
                ))}
              </div>
            </Field>
          </div>
          <Field label="Why (people and auditors see this)">
            <Input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="e.g. Not approved for company data (ticket SEC-142)" />
          </Field>
          {create.error ? <ErrorBanner error={create.error} /> : null}
          <div className="flex justify-end gap-2">
            <Button variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button variant="primary" loading={create.isPending} disabled={!name.trim() || !value.trim() || !platforms.length} onClick={() => create.mutate()}>
              Add rule
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
