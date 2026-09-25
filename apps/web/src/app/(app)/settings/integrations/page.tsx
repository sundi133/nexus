"use client";

import type { Schemas } from "@nexus/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, Archive, CheckCircle2, MoreHorizontal, Plus, Radio, Send, ShieldCheck, Webhook } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { useStepUp } from "@/components/step-up";
import { Button } from "@/components/ui/button";
import { CopyField } from "@/components/ui/copy";
import { Field, Input, Select } from "@/components/ui/input";
import { Card, EmptyState, ErrorBanner, PageHeader, Skeleton, StatusPill, type Tone } from "@/components/ui/misc";
import { Dialog, DialogContent, Menu, MenuContent, MenuItem, MenuSeparator, MenuTrigger } from "@/components/ui/overlay";
import { api, unwrap } from "@/lib/api";
import { useCan } from "@/lib/queries";
import { cn, pluralize, timeAgo } from "@/lib/utils";

type Dest = Schemas["EventDestination"];
const KEY = ["event-destinations"];
const KINDS = {
  webhook: { label: "Webhook", help: "A signed POST for every event, to your endpoint", icon: Webhook },
  splunk_hec: { label: "Splunk", help: "HTTP Event Collector, batched", icon: Radio },
  datadog: { label: "Datadog", help: "Logs intake, batched", icon: Radio },
  sentinel: { label: "Microsoft Sentinel", help: "Azure Monitor Logs Ingestion API", icon: ShieldCheck },
  s3: { label: "Amazon S3", help: "Archive to your bucket for long-term retention", icon: Archive },
  gcs: { label: "Google Cloud Storage", help: "Archive to your bucket for long-term retention", icon: Archive },
} as const;
const isArchive = (k: Dest["kind"]) => k === "s3" || k === "gcs";
/** Where events go, as people write it: s3://bucket/prefix for archives, else the URL. */
function where(d: Dest) {
  if (!isArchive(d.kind)) return d.url;
  const prefix = d.config.prefix?.replace(/^\/+|\/+$/g, "");
  return `${d.kind === "gcs" ? "gs" : "s3"}://${d.config.bucket}/${prefix ? `${prefix}/` : ""}`;
}
const STATUS: Record<Dest["status"], { label: string; tone: Tone }> = {
  healthy: { label: "Delivering", tone: "success" },
  waiting: { label: "Waiting for events", tone: "neutral" },
  failing: { label: "Retrying", tone: "warning" },
  off: { label: "Off", tone: "neutral" },
};
const DATADOG_SITES = ["datadoghq.com", "us3.datadoghq.com", "us5.datadoghq.com", "datadoghq.eu", "ap1.datadoghq.com"];

export default function IntegrationsPage() {
  const dests = useQuery({ queryKey: KEY, queryFn: () => unwrap(api.GET("/v1/event-destinations")), refetchInterval: 15_000 });
  const can = useCan();
  const [adding, setAdding] = useState(false);
  const [secret, setSecret] = useState<string | null>(null);
  return (
    <>
      <PageHeader
        title="Integrations"
        description="Stream every audit event, in order and without gaps, to your SIEM, your storage or your own systems."
        actions={
          can("integrations:manage") ? (
            <Button variant="primary" onClick={() => setAdding(true)}>
              <Plus /> Add a destination
            </Button>
          ) : null
        }
      />
      {dests.isPending ? (
        <Skeleton className="h-40" />
      ) : !dests.data ? (
        <ErrorBanner error={dests.error} />
      ) : dests.data.data.length ? (
        <div className="space-y-3">
          {dests.data.data.map((d) => (
            <DestinationCard key={d.id} dest={d} />
          ))}
        </div>
      ) : (
        <Card>
          <EmptyState icon={<Radio />} title="Nothing is streaming yet" description="Send sign-ins, admin changes, device and policy events to Splunk, Datadog, Microsoft Sentinel or a webhook, or archive them to S3 or Google Cloud Storage. Outages are retried; nothing is lost." />
        </Card>
      )}
      {adding ? <AddDestination onClose={() => setAdding(false)} onSecret={setSecret} /> : null}
      {secret ? (
        <Dialog open onOpenChange={(o) => !o && setSecret(null)}>
          <DialogContent title="Webhook signing secret" description="Copy it now: it won't be shown again. Verify each request's Nexus-Signature header with it (HMAC-SHA256 of “<t>.<body>”).">
            <CopyField value={secret} />
            <div className="mt-4 flex justify-end">
              <Button variant="primary" onClick={() => setSecret(null)}>
                Done
              </Button>
            </div>
          </DialogContent>
        </Dialog>
      ) : null}
    </>
  );
}

function DestinationCard({ dest: d }: { dest: Dest }) {
  const qc = useQueryClient();
  const withStepUp = useStepUp();
  const can = useCan();
  const [log, setLog] = useState(false);
  const patch = useMutation({
    mutationFn: (enabled: boolean) => withStepUp(() => unwrap(api.PATCH("/v1/event-destinations/{id}", { params: { path: { id: d.id } }, body: { enabled } }))),
    onSuccess: (r, enabled) => (qc.setQueryData(KEY, r), toast.success(enabled ? `${d.name} is on: resuming where it stopped` : `${d.name} is off`)),
  });
  const remove = useMutation({
    mutationFn: () => withStepUp(() => unwrap(api.DELETE("/v1/event-destinations/{id}", { params: { path: { id: d.id } } }))),
    onSuccess: (r) => (qc.setQueryData(KEY, r), toast.success(`Deleted ${d.name}`)),
  });
  const test = useMutation({
    mutationFn: () => unwrap(api.POST("/v1/event-destinations/{id}/test", { params: { path: { id: d.id } } })),
    onSuccess: (r) => (r.ok ? toast.success("Test event delivered") : toast.error(`Test failed: ${r.error}`)),
  });
  const deliveries = useQuery({
    queryKey: ["deliveries", d.id],
    queryFn: () => unwrap(api.GET("/v1/event-destinations/{id}/deliveries", { params: { path: { id: d.id } } })),
    enabled: log,
  });
  const Icon = KINDS[d.kind].icon;
  const st = STATUS[d.status];
  return (
    <Card>
      <div className="flex flex-wrap items-start gap-3 px-4 py-3">
        <div className="rounded-md bg-bg-muted p-2 text-fg-muted">
          <Icon className="size-4" />
        </div>
        <div className="min-w-0 flex-1">
          <p className="flex flex-wrap items-center gap-2 text-[13px] font-semibold">
            {d.name} <StatusPill tone={st.tone}>{st.label}</StatusPill>
          </p>
          <p className="truncate text-xs text-fg-muted">
            {KINDS[d.kind].label} · {d.format === "ocsf" ? "OCSF" : "Nexus JSON"} · {d.event_filter.length ? d.event_filter.join(", ") : "all events"} · <span className="font-mono">{where(d)}</span>
          </p>
          <p className="text-xs text-fg-subtle">
            {d.last_delivered_at ? `Last delivery ${timeAgo(d.last_delivered_at)}` : "Nothing delivered yet"}
            {d.backlog ? ` · ${d.backlog >= 10000 ? "10,000+" : pluralize(d.backlog, "event")} waiting` : " · up to date"}
          </p>
        </div>
        {can("integrations:manage") ? (
          <div className="flex items-center gap-1.5">
            <Button size="sm" variant="secondary" loading={test.isPending} onClick={() => test.mutate()}>
              <Send /> Send test
            </Button>
            <Menu>
              <MenuTrigger asChild>
                <Button size="sm" variant="ghost" aria-label={`Actions for ${d.name}`}>
                  <MoreHorizontal />
                </Button>
              </MenuTrigger>
              <MenuContent>
                <MenuItem onSelect={() => setLog(!log)}>{log ? "Hide" : "Show"} delivery log</MenuItem>
                <MenuItem onSelect={() => patch.mutate(!d.enabled)}>{d.enabled ? "Turn off" : "Turn on"}</MenuItem>
                <MenuSeparator />
                <MenuItem danger onSelect={() => remove.mutate()}>
                  Delete
                </MenuItem>
              </MenuContent>
            </Menu>
          </div>
        ) : null}
      </div>
      {d.status === "failing" || d.disabled_reason ? (
        <div className="mx-4 mb-3 flex items-start gap-2 rounded-md border border-warning/40 bg-warning-soft px-3 py-2 text-[13px]">
          <AlertTriangle className="mt-0.5 size-4 shrink-0 text-warning" />
          <div>
            <p className="font-medium">{d.disabled_reason || d.last_error}</p>
            <p className="text-xs text-fg-muted">
              {d.disabled_reason ? "Events are kept. Fix the endpoint, then turn it back on to resume where it stopped." : `${pluralize(d.consecutive_failures, "failed attempt")} in a row. Retrying with backoff; nothing is lost.`}
            </p>
          </div>
        </div>
      ) : null}
      <div className="px-4">
        <ErrorBanner error={patch.error ?? remove.error ?? test.error} />
      </div>
      {log ? (
        <div className="border-t border-border px-4 py-3">
          {deliveries.data?.data.length ? (
            <ul className="space-y-1 text-xs">
              {deliveries.data.data.slice(0, 20).map((x, i) => (
                <li key={i} className="flex items-center gap-2">
                  {x.ok ? <CheckCircle2 className="size-3.5 text-success" /> : <AlertTriangle className="size-3.5 text-warning" />}
                  <span className="w-28 text-fg-muted">{timeAgo(x.at)}</span>
                  <span className={cn("w-40", !x.ok && "text-warning")}>{x.ok ? `${pluralize(x.events, "event")} delivered` : x.error}</span>
                  <span className="text-fg-subtle">
                    {x.http_status ? `HTTP ${x.http_status} · ` : ""}
                    {x.duration_ms} ms
                  </span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-xs text-fg-muted">No deliveries yet.</p>
          )}
        </div>
      ) : null}
    </Card>
  );
}

function AddDestination({ onClose, onSecret }: { onClose: () => void; onSecret: (s: string) => void }) {
  const qc = useQueryClient();
  const withStepUp = useStepUp();
  const [kind, setKind] = useState<Dest["kind"]>("splunk_hec");
  const [name, setName] = useState("Splunk");
  const [url, setUrl] = useState("");
  const [site, setSite] = useState(DATADOG_SITES[0]!);
  const [secret, setSecret] = useState("");
  const [format, setFormat] = useState<Dest["format"]>("ocsf");
  const [filter, setFilter] = useState("");
  const [index, setIndex] = useState("");
  const [tags, setTags] = useState("");
  const [bucket, setBucket] = useState("");
  const [region, setRegion] = useState("us-east-1");
  const [prefix, setPrefix] = useState("");
  const [endpoint, setEndpoint] = useState("");
  const [accessKeyId, setAccessKeyId] = useState("");
  const [tenantId, setTenantId] = useState("");
  const [clientId, setClientId] = useState("");
  const [dcrId, setDcrId] = useState("");
  const [stream, setStream] = useState("Custom-VotalNexus_CL");
  const [backfill, setBackfill] = useState(false);
  const pick = (k: Dest["kind"]) => {
    setKind(k);
    setName(KINDS[k].label);
    setFormat(k === "webhook" || isArchive(k) ? "nexus" : "ocsf");
  };
  const finalUrl = kind === "datadog" ? url || `https://http-intake.logs.${site}/api/v2/logs` : url;
  const opt = (o: Record<string, string>) => Object.fromEntries(Object.entries(o).map(([k, v]) => [k, v.trim()]).filter(([, v]) => v));
  const config =
    kind === "splunk_hec"
      ? opt({ index })
      : kind === "datadog"
        ? opt({ tags })
        : kind === "s3"
          ? opt({ bucket, region, prefix, endpoint, access_key_id: accessKeyId })
          : kind === "gcs"
            ? opt({ bucket, prefix, access_key_id: accessKeyId })
            : kind === "sentinel"
              ? opt({ tenant_id: tenantId, client_id: clientId, dcr_id: dcrId, stream })
              : {};
  const ready =
    !!name.trim() &&
    (kind === "webhook" || !!secret) &&
    (isArchive(kind) ? !!bucket.trim() && !!accessKeyId.trim() && (kind === "gcs" || !!region.trim() || !!endpoint.trim()) : !!finalUrl.trim()) &&
    (kind !== "sentinel" || (!!tenantId.trim() && !!clientId.trim() && !!dcrId.trim() && !!stream.trim()));
  const create = useMutation({
    mutationFn: () =>
      withStepUp(() =>
        unwrap(
          api.POST("/v1/event-destinations", {
            body: {
              kind,
              name: name.trim(),
              ...(isArchive(kind) ? {} : { url: finalUrl.trim() }),
              ...(secret ? { secret } : {}),
              format,
              event_filter: filter.split(",").map((f) => f.trim()).filter(Boolean),
              config,
              start: backfill ? "last_24h" : "now",
            },
          }),
        ),
      ),
    onSuccess: (r) => {
      qc.setQueryData(KEY, { data: r.data });
      toast.success(`${name.trim()} added`, { description: backfill ? "Sending the last 24 hours, then everything new." : "New events will stream from now on." });
      if (r.signing_secret) onSecret(r.signing_secret);
      onClose();
    },
  });
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent title="Add a destination" className="max-w-lg">
        <div className="max-h-[70vh] space-y-4 overflow-y-auto pr-1">
          <div className="grid grid-cols-3 gap-2">
            {(["splunk_hec", "datadog", "sentinel", "webhook", "s3", "gcs"] as const).map((k) => (
              <button key={k} type="button" onClick={() => pick(k)} className={cn("rounded-md border p-2.5 text-left text-[13px]", kind === k ? "border-primary bg-primary-soft" : "border-border hover:bg-bg-subtle")}>
                <span className="block font-medium">{KINDS[k].label}</span>
                <span className="block text-[11px] text-fg-muted">{KINDS[k].help}</span>
              </button>
            ))}
          </div>
          <Field label="Name" htmlFor="d-name">
            <Input id="d-name" value={name} onChange={(e) => setName(e.target.value)} maxLength={100} />
          </Field>
          {kind === "datadog" ? (
            <Field label="Datadog site" htmlFor="d-site">
              <Select id="d-site" className="w-full" value={site} onChange={(e) => setSite(e.target.value)}>
                {DATADOG_SITES.map((s) => (
                  <option key={s}>{s}</option>
                ))}
              </Select>
            </Field>
          ) : isArchive(kind) ? (
            <ArchiveFields kind={kind} {...{ bucket, setBucket, region, setRegion, prefix, setPrefix, endpoint, setEndpoint, accessKeyId, setAccessKeyId }} />
          ) : (
            <Field
              label={kind === "splunk_hec" ? "HEC URL" : kind === "sentinel" ? "Data collection endpoint" : "Endpoint URL"}
              htmlFor="d-url"
              hint={
                kind === "splunk_hec"
                  ? "e.g. https://splunk.example.com:8088/services/collector/event"
                  : kind === "sentinel"
                    ? "Logs ingestion URL of your data collection endpoint, e.g. https://nexus-abcd.eastus-1.ingest.monitor.azure.com"
                    : "Must be https"
              }
            >
              <Input id="d-url" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://" />
            </Field>
          )}
          {kind === "sentinel" ? <SentinelFields {...{ tenantId, setTenantId, clientId, setClientId, dcrId, setDcrId, stream, setStream }} /> : null}
          {kind !== "webhook" ? (
            <Field label={SECRET_LABEL[kind]} htmlFor="d-secret">
              <Input id="d-secret" type="password" autoComplete="off" value={secret} onChange={(e) => setSecret(e.target.value)} />
            </Field>
          ) : (
            <p className="text-xs text-fg-muted">A signing secret is generated for you and shown once after you add it.</p>
          )}
          {kind === "splunk_hec" ? (
            <Field label="Index (optional)" htmlFor="d-index">
              <Input id="d-index" value={index} onChange={(e) => setIndex(e.target.value)} placeholder="security" />
            </Field>
          ) : null}
          {kind === "datadog" ? (
            <Field label="Tags (optional)" htmlFor="d-tags">
              <Input id="d-tags" value={tags} onChange={(e) => setTags(e.target.value)} placeholder="env:prod,team:secops" />
            </Field>
          ) : null}
          {isArchive(kind) ? (
            <p className="text-xs text-fg-muted">
              Written as gzipped JSON lines, one file per 1,000 events or every 5 minutes, under <span className="font-mono">year=/month=/day=</span> folders, ready for Athena, BigQuery or Snowflake. Turn on
              Object Lock or a retention policy on the bucket for tamper-proof retention.
            </p>
          ) : null}
          <Field label="Format" htmlFor="d-format">
            <Select id="d-format" className="w-full" value={format} onChange={(e) => setFormat(e.target.value as Dest["format"])}>
              <option value="ocsf">OCSF 1.3 (recommended for SIEMs)</option>
              <option value="nexus">Nexus JSON</option>
            </Select>
          </Field>
          <Field label="Only these events (optional)" htmlFor="d-filter" hint="Comma-separated types or prefixes, e.g. user., auth*, sso.login. Empty sends everything.">
            <Input id="d-filter" value={filter} onChange={(e) => setFilter(e.target.value)} />
          </Field>
          <label className="flex items-center gap-2 text-[13px]">
            <input type="checkbox" checked={backfill} onChange={(e) => setBackfill(e.target.checked)} /> Also send the last 24 hours
          </label>
          <ErrorBanner error={create.error} />
          <div className="flex justify-end gap-2 border-t border-border pt-4">
            <Button variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button variant="primary" loading={create.isPending} disabled={!ready} onClick={() => create.mutate()}>
              Add destination
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

const SECRET_LABEL: Record<Exclude<Dest["kind"], "webhook">, string> = {
  splunk_hec: "HEC token",
  datadog: "API key",
  sentinel: "Client secret",
  s3: "Secret access key",
  gcs: "HMAC key secret",
};

type Setter = (v: string) => void;

function ArchiveFields(p: {
  kind: "s3" | "gcs";
  bucket: string;
  setBucket: Setter;
  region: string;
  setRegion: Setter;
  prefix: string;
  setPrefix: Setter;
  endpoint: string;
  setEndpoint: Setter;
  accessKeyId: string;
  setAccessKeyId: Setter;
}) {
  const s3 = p.kind === "s3";
  return (
    <>
      <div className="grid grid-cols-2 gap-3">
        <Field label="Bucket" htmlFor="d-bucket">
          <Input id="d-bucket" value={p.bucket} onChange={(e) => p.setBucket(e.target.value.toLowerCase())} placeholder="acme-audit-logs" />
        </Field>
        {s3 ? (
          <Field label="Region" htmlFor="d-region">
            <Input id="d-region" value={p.region} onChange={(e) => p.setRegion(e.target.value)} placeholder="us-east-1" />
          </Field>
        ) : (
          <Field label="Folder (optional)" htmlFor="d-prefix">
            <Input id="d-prefix" value={p.prefix} onChange={(e) => p.setPrefix(e.target.value)} placeholder="nexus/" />
          </Field>
        )}
      </div>
      {s3 ? (
        <Field label="Folder (optional)" htmlFor="d-prefix">
          <Input id="d-prefix" value={p.prefix} onChange={(e) => p.setPrefix(e.target.value)} placeholder="nexus/" />
        </Field>
      ) : null}
      <Field
        label={s3 ? "Access key ID" : "HMAC access ID"}
        htmlFor="d-akid"
        hint={
          s3
            ? "An IAM user whose only permission is s3:PutObject on this bucket (and folder)."
            : "Cloud Storage → Settings → Interoperability: an HMAC key for a service account with Storage Object Creator on this bucket."
        }
      >
        <Input id="d-akid" value={p.accessKeyId} onChange={(e) => p.setAccessKeyId(e.target.value)} autoComplete="off" />
      </Field>
      {s3 ? (
        <details className="text-[13px]">
          <summary className="cursor-pointer text-fg-muted">S3-compatible storage</summary>
          <div className="mt-2">
            <Field label="Endpoint (optional)" htmlFor="d-endpoint" hint="For MinIO, Wasabi, Cloudflare R2 and others. Leave empty for Amazon S3.">
              <Input id="d-endpoint" value={p.endpoint} onChange={(e) => p.setEndpoint(e.target.value)} placeholder="https://" />
            </Field>
          </div>
        </details>
      ) : null}
    </>
  );
}

function SentinelFields(p: {
  tenantId: string;
  setTenantId: Setter;
  clientId: string;
  setClientId: Setter;
  dcrId: string;
  setDcrId: Setter;
  stream: string;
  setStream: Setter;
}) {
  return (
    <>
      <div className="grid grid-cols-2 gap-3">
        <Field label="Directory (tenant) ID" htmlFor="d-tenant">
          <Input id="d-tenant" value={p.tenantId} onChange={(e) => p.setTenantId(e.target.value)} className="font-mono text-xs" />
        </Field>
        <Field label="Application (client) ID" htmlFor="d-client">
          <Input id="d-client" value={p.clientId} onChange={(e) => p.setClientId(e.target.value)} className="font-mono text-xs" />
        </Field>
        <Field label="Data collection rule ID" htmlFor="d-dcr" hint="The rule's immutable ID">
          <Input id="d-dcr" value={p.dcrId} onChange={(e) => p.setDcrId(e.target.value)} placeholder="dcr-…" className="font-mono text-xs" />
        </Field>
        <Field label="Stream" htmlFor="d-stream">
          <Input id="d-stream" value={p.stream} onChange={(e) => p.setStream(e.target.value)} className="font-mono text-xs" />
        </Field>
      </div>
      <details className="text-[13px]">
        <summary className="cursor-pointer text-fg-muted">How to set this up in Azure</summary>
        <ol className="mt-2 list-decimal space-y-1 pl-5 text-xs text-fg-muted">
          <li>
            In your Sentinel workspace, create a custom table <span className="font-mono">VotalNexus_CL</span> with columns <span className="font-mono">TimeGenerated</span> (datetime),{" "}
            <span className="font-mono">EventId</span> (string), <span className="font-mono">EventType</span> (string) and <span className="font-mono">Event</span> (dynamic).
          </li>
          <li>Create a data collection endpoint and a data collection rule that sends the stream above to that table.</li>
          <li>Register an app in Microsoft Entra ID, add a client secret, and give it the Monitoring Metrics Publisher role on the rule.</li>
        </ol>
      </details>
    </>
  );
}
