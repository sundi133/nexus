"use client";

import type { Schemas } from "@nexus/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ChevronLeft, Fingerprint, KeyRound, Pencil, Play, Plus, Power, Trash2, Workflow, X } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { use, useState } from "react";
import { toast } from "sonner";
import { ActivityList } from "@/components/features/activity";
import { AgentStatus, RISK_TONE } from "@/components/features/agent-bits";
import { ConfirmAction } from "@/components/features/confirm-action";
import { useStepUp } from "@/components/step-up";
import { Button } from "@/components/ui/button";
import { CopyField } from "@/components/ui/copy";
import { Field, Input, Select } from "@/components/ui/input";
import { Card, CardHeader, EmptyState, ErrorBanner, KeyValue, Skeleton, StatusPill } from "@/components/ui/misc";
import { Dialog, DialogContent } from "@/components/ui/overlay";
import { api, unwrap } from "@/lib/api";
import { useCan } from "@/lib/queries";
import { formatDateTime, timeAgo } from "@/lib/utils";

type Agent = Schemas["Agent"];
type Credential = Schemas["AgentCredential"];

export default function AgentPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const qc = useQueryClient();
  const router = useRouter();
  const can = useCan();
  const withStepUp = useStepUp();
  const [killing, setKilling] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [editing, setEditing] = useState(false);
  const [adding, setAdding] = useState(false);
  const data = useQuery({ queryKey: ["agent", id], queryFn: () => unwrap(api.GET("/v1/agents/{id}", { params: { path: { id } } })) });
  const activity = useQuery({ queryKey: ["agent", id, "activity"], queryFn: () => unwrap(api.GET("/v1/audit/events", { params: { query: { subject_id: id, limit: 30 } } })), enabled: can("audit:read") });
  const refresh = () => {
    qc.invalidateQueries({ queryKey: ["agent", id] });
    qc.invalidateQueries({ queryKey: ["agents"] });
  };
  const activate = useMutation({
    mutationFn: () => withStepUp(() => unwrap(api.POST("/v1/agents/{id}/activate", { params: { path: { id } } }))),
    onSuccess: () => (refresh(), toast.success("Agent reactivated. Its old tokens stay invalid; it will get new ones.")),
  });
  const revoke = useMutation({
    mutationFn: (credentialId: string) => unwrap(api.DELETE("/v1/agents/{id}/credentials/{credentialId}", { params: { path: { id, credentialId } } })),
    onSuccess: () => (refresh(), toast.success("Credential revoked")),
  });

  if (data.isPending) return <Skeleton className="h-60" />;
  if (!data.data) return <ErrorBanner error={data.error} />;
  const { agent: a, credentials, endpoints } = data.data;

  return (
    <>
      <Link href="/agents" className="mb-3 inline-flex items-center gap-1 text-[13px] text-fg-muted hover:text-fg">
        <ChevronLeft className="size-4" /> Agents
      </Link>
      <div className="mb-5 flex flex-wrap items-start gap-3">
        <div className="min-w-0 flex-1">
          <h1 className="flex flex-wrap items-center gap-2 text-xl font-semibold tracking-tight">
            {a.name} <AgentStatus a={a} />
          </h1>
          <p className="mt-0.5 text-[13px] text-fg-muted">{a.description || "No description"}</p>
          {a.status === "suspended" ? <p className="mt-1 text-[13px] text-danger">Suspended{a.status_reason ? `: ${a.status_reason}` : ""}. Its tokens don't work.</p> : null}
        </div>
        <div className="flex flex-wrap gap-2">
          {can("agents:manage") ? (
            <Button variant="danger-outline" onClick={() => setDeleting(true)}>
              <Trash2 /> Delete
            </Button>
          ) : null}
          {a.status === "active" && can("agents:suspend") ? (
            <Button variant="danger" onClick={() => setKilling(true)}>
              <Power /> Suspend now
            </Button>
          ) : a.status === "suspended" && can("agents:manage") ? (
            <Button variant="primary" loading={activate.isPending} onClick={() => activate.mutate()}>
              <Play /> Reactivate
            </Button>
          ) : null}
        </div>
      </div>
      <ErrorBanner error={activate.error} />

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader
            title="Details"
            actions={
              can("agents:manage") ? (
                <Button size="sm" variant="ghost" onClick={() => setEditing(true)}>
                  <Pencil /> Edit
                </Button>
              ) : null
            }
          />
          <div className="px-4 pb-4">
            <KeyValue
              items={[
                ["Owner", a.owner ? <span className={a.owner.active ? "" : "text-warning"}>{a.owner.name}{a.owner.type === "group" ? " (group)" : ""}{a.owner.active ? "" : " (inactive)"}</span> : <span className="text-warning">None</span>],
                ["Environment", <span className="capitalize">{a.environment}</span>],
                ["Runtime / model", [a.runtime, a.model].filter(Boolean).join(" · ") || "—"],
                ["Risk tier", <StatusPill tone={RISK_TONE[a.risk_tier]} dot={false}><span className="capitalize">{a.risk_tier}</span></StatusPill>],
                ["Tags", a.tags.length ? a.tags.map((t) => `#${t}`).join(" ") : "—"],
                ["Token lifetime", `${a.token_ttl_minutes} minutes`],
                ["Last seen", a.last_seen_at ? `${timeAgo(a.last_seen_at)}${a.stale ? " (stale)" : ""}` : "Never"],
              ]}
            />
          </div>
        </Card>
        <Card>
          <CardHeader title="Connect" description="The agent gets a token with the client credentials grant, then calls MCP servers through the gateway." />
          <div className="space-y-3 px-4 pb-4">
            <CopyField label="Client ID" value={a.client_id} />
            <CopyField label="Token endpoint" value={endpoints.token_endpoint} />
            <CopyField label="MCP gateway" value={endpoints.gateway} />
            <pre className="overflow-x-auto rounded-md border border-border bg-bg-subtle p-3 font-mono text-[11px] leading-relaxed text-fg-muted">
              {`curl -s ${endpoints.token_endpoint} \\
  -u "${a.client_id}:$AGENT_SECRET" \\
  -d grant_type=client_credentials \\
  -d resource=${endpoints.gateway}/<server>`}
            </pre>
          </div>
        </Card>
      </div>

      <Card className="mt-4">
        <CardHeader
          title="Credentials"
          description="Prefer workload identity: the agent proves itself with its platform's token, and no secret exists to leak."
          actions={
            can("agents:manage") ? (
              <Button size="sm" onClick={() => setAdding(true)}>
                <Plus /> Add credential
              </Button>
            ) : null
          }
        />
        {credentials.length ? (
          <ul className="divide-y divide-border border-t border-border">
            {credentials.map((c) => (
              <CredentialRow key={c.id} c={c} onRevoke={can("agents:manage") ? () => revoke.mutate(c.id) : undefined} />
            ))}
          </ul>
        ) : (
          <EmptyState icon={<KeyRound />} title="No credentials" description="Without a credential the agent can't get tokens." />
        )}
      </Card>

      {can("audit:read") ? (
        <Card className="mt-4 overflow-hidden">
          <CardHeader title="Activity" description="Tokens issued, tool calls and refusals, and changes to this agent." />
          {activity.data?.data.length ? <ActivityList events={activity.data.data} compact /> : <p className="px-4 pb-4 text-[13px] text-fg-muted">Nothing yet.</p>}
        </Card>
      ) : null}

      {editing ? <EditDialog a={a} onClose={() => setEditing(false)} onSaved={refresh} /> : null}
      {adding ? <AddCredentialDialog agentId={id} issuer={endpoints.issuer} onClose={() => setAdding(false)} onAdded={refresh} /> : null}
      <ConfirmAction
        open={killing}
        onOpenChange={setKilling}
        title={`Suspend ${a.name}?`}
        effects={["Every token it holds stops working at once, including calls in progress at the gateway", "It can't get new tokens until someone reactivates it", a.owner?.type === "user" ? `${a.owner.name} is notified` : "Its owner is notified"]}
        confirmLabel="Suspend now"
        danger
        onConfirm={async (reason) => {
          await unwrap(api.POST("/v1/agents/{id}/suspend", { params: { path: { id } }, body: { reason: reason ?? "" } }));
          refresh();
          toast.success(`${a.name} suspended`);
        }}
      />
      <ConfirmAction
        open={deleting}
        onOpenChange={setDeleting}
        title={`Delete ${a.name}?`}
        effects={["Its credentials and tokens stop working", "Tool permissions that name it are removed", "Its audit trail stays"]}
        confirmLabel="Delete agent"
        danger
        askReason={false}
        onConfirm={async () => {
          await withStepUp(() => unwrap(api.DELETE("/v1/agents/{id}", { params: { path: { id } } })));
          qc.invalidateQueries({ queryKey: ["agents"] });
          toast.success("Agent deleted");
          router.push("/agents");
        }}
      />
    </>
  );
}

const KIND = {
  secret: { icon: KeyRound, label: "Client secret" },
  public_key: { icon: Fingerprint, label: "Public key (private_key_jwt)" },
  federated: { icon: Workflow, label: "Workload identity" },
} as const;

function CredentialRow({ c, onRevoke }: { c: Credential; onRevoke?: () => void }) {
  const K = KIND[c.kind];
  const expired = c.expires_at && new Date(c.expires_at) < new Date();
  return (
    <li className="flex flex-wrap items-center gap-3 px-4 py-3 text-[13px]">
      <K.icon className="size-4 text-fg-muted" />
      <div className="min-w-0 flex-1">
        <p className="font-medium">
          {c.name || K.label} {c.name ? <span className="font-normal text-fg-muted">· {K.label}</span> : null}
        </p>
        <p className="truncate text-xs text-fg-muted">
          {c.kind === "secret" ? `…${c.hint}` : c.kind === "public_key" ? `Key ${c.hint}` : `${c.issuer} · ${c.subject}`}
          {" · "}
          {c.last_used_at ? `last used ${timeAgo(c.last_used_at)}` : "never used"}
          {c.expires_at ? ` · ${expired ? "expired" : "expires"} ${formatDateTime(c.expires_at)}` : ""}
        </p>
      </div>
      {expired ? <StatusPill tone="warning">Expired</StatusPill> : null}
      {onRevoke ? (
        <Button size="sm" variant="ghost" onClick={onRevoke} aria-label={`Revoke ${c.name || K.label}`}>
          <X /> Revoke
        </Button>
      ) : null}
    </li>
  );
}

function EditDialog({ a, onClose, onSaved }: { a: Agent; onClose: () => void; onSaved: () => void }) {
  const users = useQuery({ queryKey: ["users", "all-for-picker"], queryFn: () => unwrap(api.GET("/v1/users", { params: { query: { limit: 200 } } })) });
  const [f, setF] = useState({ description: a.description, owner: a.owner?.type === "user" ? a.owner.id : "", environment: a.environment, runtime: a.runtime, model: a.model, risk_tier: a.risk_tier, tags: a.tags.join(", "), ttl: a.token_ttl_minutes });
  const save = useMutation({
    mutationFn: () =>
      unwrap(
        api.PATCH("/v1/agents/{id}", {
          params: { path: { id: a.id } },
          body: {
            description: f.description,
            ...(f.owner ? { owner_user_id: f.owner } : {}),
            environment: f.environment,
            runtime: f.runtime,
            model: f.model,
            risk_tier: f.risk_tier,
            tags: f.tags.split(/[\s,]+/).map((t) => t.replace(/^#/, "").toLowerCase()).filter(Boolean),
            token_ttl_minutes: f.ttl,
          },
        }),
      ),
    onSuccess: () => (onSaved(), toast.success("Saved"), onClose()),
  });
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent title={`Edit ${a.name}`} className="max-w-lg">
        <div className="space-y-3">
          <Field label="What it does" htmlFor="e-desc">
            <Input id="e-desc" value={f.description} maxLength={1000} onChange={(e) => setF({ ...f, description: e.target.value })} />
          </Field>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Owner" htmlFor="e-owner">
              <Select id="e-owner" className="w-full" value={f.owner} onChange={(e) => setF({ ...f, owner: e.target.value })}>
                {!f.owner ? <option value="">{a.owner?.name ?? "Choose…"}</option> : null}
                {(users.data?.data ?? [])
                  .filter((u) => u.status === "active")
                  .map((u) => (
                    <option key={u.id} value={u.id}>
                      {u.display_name}
                    </option>
                  ))}
              </Select>
            </Field>
            <Field label="Environment" htmlFor="e-env">
              <Select id="e-env" className="w-full" value={f.environment} onChange={(e) => setF({ ...f, environment: e.target.value as Agent["environment"] })}>
                <option value="production">Production</option>
                <option value="staging">Staging</option>
                <option value="development">Development</option>
              </Select>
            </Field>
            <Field label="Runtime" htmlFor="e-runtime">
              <Input id="e-runtime" value={f.runtime} maxLength={100} onChange={(e) => setF({ ...f, runtime: e.target.value })} />
            </Field>
            <Field label="Model" htmlFor="e-model">
              <Input id="e-model" value={f.model} maxLength={100} onChange={(e) => setF({ ...f, model: e.target.value })} />
            </Field>
            <Field label="Risk tier" htmlFor="e-risk">
              <Select id="e-risk" className="w-full" value={f.risk_tier} onChange={(e) => setF({ ...f, risk_tier: e.target.value as Agent["risk_tier"] })}>
                {["low", "medium", "high", "critical"].map((r) => (
                  <option key={r} value={r} className="capitalize">
                    {r}
                  </option>
                ))}
              </Select>
            </Field>
            <Field label="Token lifetime" htmlFor="e-ttl">
              <Select id="e-ttl" className="w-full" value={String(f.ttl)} onChange={(e) => setF({ ...f, ttl: Number(e.target.value) })}>
                {[5, 10, 15, 30, 60].map((m) => (
                  <option key={m} value={m}>
                    {m} minutes
                  </option>
                ))}
              </Select>
            </Field>
          </div>
          <Field label="Tags" htmlFor="e-tags">
            <Input id="e-tags" value={f.tags} onChange={(e) => setF({ ...f, tags: e.target.value })} />
          </Field>
          <ErrorBanner error={save.error} />
          <div className="flex justify-end gap-2 border-t border-border pt-4">
            <Button variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button variant="primary" loading={save.isPending} onClick={() => save.mutate()}>
              Save
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

const PRESETS = {
  github: { label: "GitHub Actions", issuer: "https://token.actions.githubusercontent.com", subject: "repo:ORG/REPO:ref:refs/heads/main" },
  gitlab: { label: "GitLab CI", issuer: "https://gitlab.com", subject: "project_path:GROUP/PROJECT:ref_type:branch:ref:main" },
  kubernetes: { label: "Kubernetes", issuer: "https://oidc.eks.REGION.amazonaws.com/id/CLUSTER", subject: "system:serviceaccount:NAMESPACE:SERVICEACCOUNT" },
  gcp: { label: "Google Cloud", issuer: "https://accounts.google.com", subject: "SERVICE_ACCOUNT_UNIQUE_ID" },
  custom: { label: "Other OIDC issuer", issuer: "", subject: "" },
} as const;

function AddCredentialDialog({ agentId, issuer, onClose, onAdded }: { agentId: string; issuer: string; onClose: () => void; onAdded: () => void }) {
  const withStepUp = useStepUp();
  const [kind, setKind] = useState<"federated" | "public_key" | "secret">("federated");
  const [name, setName] = useState("");
  const [preset, setPreset] = useState<keyof typeof PRESETS>("github");
  const [fed, setFed] = useState<{ issuer: string; subject: string; audience: string }>({ issuer: PRESETS.github.issuer, subject: "", audience: "" });
  const [jwk, setJwk] = useState("");
  const [days, setDays] = useState(180);
  const [secret, setSecret] = useState<string | null>(null);
  const add = useMutation({
    mutationFn: () => {
      const body =
        kind === "secret"
          ? { kind, name, expires_in_days: days }
          : kind === "public_key"
            ? { kind, name, jwk: JSON.parse(jwk) as Record<string, unknown> }
            : { kind, name, issuer: fed.issuer.trim(), subject: fed.subject.trim(), ...(fed.audience.trim() ? { audience: fed.audience.trim() } : {}) };
      return withStepUp(() => unwrap(api.POST("/v1/agents/{id}/credentials", { params: { path: { id: agentId } }, body })));
    },
    onSuccess: (r) => {
      onAdded();
      if (r.secret) setSecret(r.secret);
      else (toast.success("Credential added"), onClose());
    },
  });
  let jwkError = "";
  if (kind === "public_key" && jwk.trim()) {
    try {
      JSON.parse(jwk);
    } catch {
      jwkError = "Paste a JSON Web Key";
    }
  }
  const ready = kind === "secret" || (kind === "public_key" ? !!jwk.trim() && !jwkError : !!fed.issuer.trim() && !!fed.subject.trim());

  if (secret) {
    return (
      <Dialog open onOpenChange={(o) => !o && onClose()}>
        <DialogContent title="Copy the secret now" description="It's shown once. Store it in the agent's secret manager.">
          <CopyField label="Client secret" value={secret} secret />
          <div className="mt-4 flex justify-end">
            <Button variant="primary" onClick={onClose}>
              Done
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    );
  }
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent title="Add a credential" className="max-w-lg">
        <div className="space-y-3">
          <div className="grid grid-cols-3 gap-2" role="radiogroup" aria-label="Kind">
            {(Object.keys(KIND) as (keyof typeof KIND)[]).reverse().map((k) => {
              const K = KIND[k];
              return (
                <button
                  key={k}
                  type="button"
                  role="radio"
                  aria-checked={kind === k}
                  onClick={() => setKind(k)}
                  className={`rounded-md border px-3 py-2 text-left text-xs ${kind === k ? "border-primary bg-primary-soft/40" : "border-border hover:bg-bg-subtle"}`}
                >
                  <K.icon className="mb-1 size-4" />
                  <span className="font-medium">{K.label}</span>
                  {k === "federated" ? <span className="block text-fg-muted">Recommended</span> : null}
                </button>
              );
            })}
          </div>
          <Field label="Name" htmlFor="c-name">
            <Input id="c-name" value={name} maxLength={100} onChange={(e) => setName(e.target.value)} placeholder={kind === "federated" ? "Production deploy workflow" : "Production"} />
          </Field>
          {kind === "federated" ? (
            <>
              <Field label="Platform" htmlFor="c-preset">
                <Select
                  id="c-preset"
                  className="w-full"
                  value={preset}
                  onChange={(e) => {
                    const p = e.target.value as keyof typeof PRESETS;
                    setPreset(p);
                    setFed({ ...fed, issuer: PRESETS[p].issuer });
                  }}
                >
                  {Object.entries(PRESETS).map(([k, p]) => (
                    <option key={k} value={k}>
                      {p.label}
                    </option>
                  ))}
                </Select>
              </Field>
              <Field label="Issuer" htmlFor="c-issuer">
                <Input id="c-issuer" value={fed.issuer} onChange={(e) => setFed({ ...fed, issuer: e.target.value })} placeholder="https://…" />
              </Field>
              <Field label="Subject (exact match)" htmlFor="c-subject" hint="Only tokens for exactly this workload are accepted">
                <Input id="c-subject" value={fed.subject} onChange={(e) => setFed({ ...fed, subject: e.target.value })} placeholder={PRESETS[preset].subject} />
              </Field>
              <Field label="Audience" htmlFor="c-aud" hint={`Leave empty to use ${issuer}`}>
                <Input id="c-aud" value={fed.audience} onChange={(e) => setFed({ ...fed, audience: e.target.value })} placeholder={issuer} />
              </Field>
            </>
          ) : kind === "public_key" ? (
            <Field label="Public key (JWK)" htmlFor="c-jwk" hint="EC P-256/P-384, Ed25519 or RSA 2048+. The private key never leaves the agent." error={jwkError}>
              <textarea
                id="c-jwk"
                className="h-28 w-full rounded-md border border-border bg-bg px-2.5 py-2 font-mono text-xs"
                value={jwk}
                onChange={(e) => setJwk(e.target.value)}
                placeholder='{"kty":"EC","crv":"P-256","x":"…","y":"…","kid":"agent-1"}'
              />
            </Field>
          ) : (
            <Field label="Expires in" htmlFor="c-days">
              <Select id="c-days" className="w-full" value={String(days)} onChange={(e) => setDays(Number(e.target.value))}>
                {[30, 90, 180, 365].map((d) => (
                  <option key={d} value={d}>
                    {d} days
                  </option>
                ))}
              </Select>
            </Field>
          )}
          <ErrorBanner error={add.error} />
          <div className="flex justify-end gap-2 border-t border-border pt-4">
            <Button variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button variant="primary" disabled={!ready} loading={add.isPending} onClick={() => add.mutate()}>
              Add credential
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
