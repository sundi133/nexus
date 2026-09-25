"use client";

import type { Schemas } from "@nexus/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, CheckCircle2, LogIn, MoreHorizontal, Plus, ShieldCheck, X } from "lucide-react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useState } from "react";
import { toast } from "sonner";
import { useStepUp } from "@/components/step-up";
import { Button } from "@/components/ui/button";
import { CopyField } from "@/components/ui/copy";
import { Field, Input, Select } from "@/components/ui/input";
import { Card, EmptyState, ErrorBanner, PageHeader, Skeleton, StatusPill } from "@/components/ui/misc";
import { Dialog, DialogContent, Menu, MenuContent, MenuItem, MenuSeparator, MenuTrigger } from "@/components/ui/overlay";
import { api, bffAuth, unwrap } from "@/lib/api";
import { useCan } from "@/lib/queries";
import { cn, pluralize, timeAgo } from "@/lib/utils";

type Idp = Schemas["IdentityProvider"];
type Sp = Schemas["FederationServiceProvider"];
type Mfa = Idp["mfa"];
const KEY = ["identity-providers"];

const MFA: { value: Mfa; label: string; help: string }[] = [
  { value: "when_signalled", label: "Trust the IdP's MFA when it reports it", help: "Recommended. Entra ID and Okta say when MFA was used; otherwise Nexus asks for its own." },
  { value: "always", label: "Always trust the IdP", help: "For IdPs that enforce MFA but don't report it (e.g. Google Workspace with 2-Step Verification enforced)." },
  { value: "never", label: "Always ask for Nexus MFA too", help: "Passkey, push or code after every IdP sign-in." },
];

export default function IdentityProvidersPage() {
  return (
    <Suspense>
      <Providers />
    </Suspense>
  );
}

function Providers() {
  const list = useQuery({ queryKey: KEY, queryFn: () => unwrap(api.GET("/v1/identity-providers")) });
  const can = useCan();
  const params = useSearchParams();
  const [adding, setAdding] = useState(false);
  const test = params.get("test") && params.get("idp") ? { idp: params.get("idp")!, state: params.get("test")! } : null;
  return (
    <>
      <PageHeader
        title="Single sign-on"
        description="Let people sign in to Nexus with the identity provider you already use: Okta, Microsoft Entra ID, Google Workspace, or any OIDC or SAML IdP."
        actions={
          can("org:manage") ? (
            <Button variant="primary" onClick={() => setAdding(true)}>
              <Plus /> Connect an identity provider
            </Button>
          ) : null
        }
      />
      {test ? <TestResult idpId={test.idp} state={test.state} providers={list.data?.data ?? []} /> : null}
      {list.isPending ? (
        <Skeleton className="h-40" />
      ) : !list.data ? (
        <ErrorBanner error={list.error} />
      ) : list.data.data.length ? (
        <div className="space-y-3">
          {list.data.data.map((d) => (
            <ProviderCard key={d.id} idp={d} sp={list.data.service_provider} />
          ))}
        </div>
      ) : (
        <Card>
          <EmptyState
            icon={<LogIn />}
            title="People sign in with Nexus passwords and passkeys"
            description="Connect your identity provider so people use the account they already have. Nexus still adds device trust, conditional access and its own MFA on top."
          />
        </Card>
      )}
      {adding && list.data ? <AddProvider sp={list.data.service_provider} onClose={() => setAdding(false)} /> : null}
    </>
  );
}

function ProviderCard({ idp: d, sp }: { idp: Idp; sp: Sp }) {
  const qc = useQueryClient();
  const withStepUp = useStepUp();
  const can = useCan();
  const [editing, setEditing] = useState(false);
  const patch = useMutation({
    mutationFn: (body: { required?: boolean; enabled?: boolean }) => withStepUp(() => unwrap(api.PATCH("/v1/identity-providers/{id}", { params: { path: { id: d.id } }, body }))),
    onSuccess: (r, body) => {
      qc.setQueryData(KEY, r);
      if (body.required !== undefined) toast.success(body.required ? `${d.name} is now required for ${d.domains.join(", ")}` : `Passwords and passkeys work again for ${d.domains.join(", ")}`);
      if (body.enabled !== undefined) toast.success(body.enabled ? `${d.name} is on` : `${d.name} is off`);
    },
  });
  const remove = useMutation({
    mutationFn: () => withStepUp(() => unwrap(api.DELETE("/v1/identity-providers/{id}", { params: { path: { id: d.id } } }))),
    onSuccess: (r) => (qc.setQueryData(KEY, r), toast.success(`Disconnected ${d.name}`)),
  });
  const test = useMutation({
    mutationFn: () => bffAuth<{ redirect_url: string }>("federation/test", { idp_id: d.id }),
    onSuccess: (r) => window.location.assign(r.redirect_url),
  });
  const status = !d.enabled ? <StatusPill>Off</StatusPill> : d.required ? <StatusPill tone="success">Required</StatusPill> : <StatusPill tone="primary">Available</StatusPill>;
  return (
    <Card>
      <div className="flex flex-wrap items-start gap-3 px-4 py-3">
        <div className="rounded-md bg-bg-muted p-2 text-fg-muted">
          <ShieldCheck className="size-4" />
        </div>
        <div className="min-w-0 flex-1">
          <p className="flex flex-wrap items-center gap-2 text-[13px] font-semibold">
            {d.name} {status}
            <span className="rounded bg-bg-muted px-1.5 py-0.5 text-[11px] font-medium uppercase text-fg-muted">{d.protocol}</span>
          </p>
          <p className="truncate text-xs text-fg-muted">
            Signs in {d.domains.map((x) => `@${x}`).join(", ")} · <span className="font-mono">{d.protocol === "oidc" ? d.issuer : d.idp_entity_id}</span>
          </p>
          <p className="text-xs text-fg-subtle">
            {pluralize(d.linked_users, "person")} linked · {d.last_login_at ? `last sign-in ${timeAgo(d.last_login_at)}` : "no sign-ins yet"} ·{" "}
            {d.jit_provisioning ? "creates accounts on first sign-in" : "existing accounts only"} ·{" "}
            {d.last_test_ok_at ? `tested ${timeAgo(d.last_test_ok_at)}` : <span className="text-warning">not tested yet</span>}
          </p>
        </div>
        {can("org:manage") ? (
          <div className="flex items-center gap-1.5">
            <Button size="sm" variant="secondary" loading={test.isPending} onClick={() => test.mutate()}>
              <LogIn /> Test sign-in
            </Button>
            <Menu>
              <MenuTrigger asChild>
                <Button size="sm" variant="ghost" aria-label={`Actions for ${d.name}`}>
                  <MoreHorizontal />
                </Button>
              </MenuTrigger>
              <MenuContent>
                {d.required ? (
                  <MenuItem onSelect={() => patch.mutate({ required: false })}>Stop requiring it</MenuItem>
                ) : (
                  <MenuItem disabled={!d.last_test_ok_at || !d.enabled} onSelect={() => patch.mutate({ required: true })}>
                    Require it {!d.last_test_ok_at ? "(test first)" : ""}
                  </MenuItem>
                )}
                <MenuItem onSelect={() => patch.mutate({ enabled: !d.enabled })}>{d.enabled ? "Turn off" : "Turn on"}</MenuItem>
                <MenuItem onSelect={() => setEditing(true)}>Edit</MenuItem>
                <MenuSeparator />
                <MenuItem danger onSelect={() => remove.mutate()}>
                  Disconnect
                </MenuItem>
              </MenuContent>
            </Menu>
          </div>
        ) : null}
      </div>
      {d.required ? (
        <p className="mx-4 mb-3 rounded-md bg-bg-subtle px-3 py-2 text-xs text-fg-muted">
          People at {d.domains.join(", ")} can only sign in through {d.name}: no Nexus passwords, passkey sign-in or password resets. Break-glass accounts still can, in case {d.name} is down.
        </p>
      ) : null}
      <div className="px-4">
        <ErrorBanner error={patch.error ?? remove.error ?? test.error} />
      </div>
      {editing ? <EditProvider idp={d} sp={sp} onClose={() => setEditing(false)} /> : null}
    </Card>
  );
}

/** What to enter at the IdP when creating the app for Nexus. */
function SpValues({ protocol, sp }: { protocol: Idp["protocol"]; sp: Sp }) {
  return (
    <div className="space-y-2 rounded-md border border-border bg-bg-subtle p-3">
      <p className="text-xs font-medium text-fg-muted">At your IdP, create an app for Nexus with:</p>
      {protocol === "oidc" ? (
        <Field label="Sign-in redirect URI" htmlFor="sp-redirect">
          <CopyField value={sp.oidc_redirect_uri} />
        </Field>
      ) : (
        <>
          <Field label="Entity ID (audience)" htmlFor="sp-entity">
            <CopyField value={sp.saml_entity_id} />
          </Field>
          <Field label="ACS URL (reply URL)" htmlFor="sp-acs">
            <CopyField value={sp.saml_acs_url} />
          </Field>
          <p className="text-xs text-fg-muted">
            Or import our metadata:{" "}
            <a className="text-primary hover:underline" href={sp.saml_metadata_url} target="_blank" rel="noreferrer">
              {sp.saml_metadata_url}
            </a>
            . Send the email as the NameID or an email attribute, and sign assertions with SHA-256.
          </p>
        </>
      )}
    </div>
  );
}

function DomainPicker({ value, onChange }: { value: string[]; onChange: (v: string[]) => void }) {
  const domains = useQuery({ queryKey: ["org-domains"], queryFn: () => unwrap(api.GET("/v1/org/domains")) });
  const verified = domains.data?.data.filter((d) => d.status !== "pending") ?? [];
  if (domains.data && !verified.length) {
    return (
      <p className="rounded-md border border-warning/40 bg-warning-soft px-3 py-2 text-[13px]">
        Verify your email domain first, in{" "}
        <Link className="font-medium text-primary hover:underline" href="/settings/organization">
          Organization → Domains
        </Link>
        . An IdP can only sign in people from domains you've proven you own.
      </p>
    );
  }
  return (
    <div className="flex flex-wrap gap-2">
      {verified.map((d) => (
        <label key={d.id} className={cn("flex items-center gap-2 rounded-md border px-2.5 py-1.5 text-[13px]", value.includes(d.domain) ? "border-primary bg-primary-soft" : "border-border")}>
          <input type="checkbox" checked={value.includes(d.domain)} onChange={(e) => onChange(e.target.checked ? [...value, d.domain] : value.filter((x) => x !== d.domain))} />@{d.domain}
        </label>
      ))}
    </div>
  );
}

function Behaviour(p: { jit: boolean; setJit: (v: boolean) => void; mfa: Mfa; setMfa: (v: Mfa) => void }) {
  return (
    <>
      <label className="flex items-start gap-2 text-[13px]">
        <input type="checkbox" className="mt-0.5" checked={p.jit} onChange={(e) => p.setJit(e.target.checked)} />
        <span>
          Create accounts on first sign-in
          <span className="block text-xs text-fg-muted">Otherwise only people already in Nexus (invited, synced or imported) can sign in.</span>
        </span>
      </label>
      <Field label="MFA" htmlFor="idp-mfa" hint={MFA.find((m) => m.value === p.mfa)?.help}>
        <Select id="idp-mfa" className="w-full" value={p.mfa} onChange={(e) => p.setMfa(e.target.value as Mfa)}>
          {MFA.map((m) => (
            <option key={m.value} value={m.value}>
              {m.label}
            </option>
          ))}
        </Select>
      </Field>
    </>
  );
}

function AddProvider({ sp, onClose }: { sp: Sp; onClose: () => void }) {
  const qc = useQueryClient();
  const withStepUp = useStepUp();
  const [protocol, setProtocol] = useState<Idp["protocol"]>("oidc");
  const [name, setName] = useState("Okta");
  const [issuer, setIssuer] = useState("");
  const [clientId, setClientId] = useState("");
  const [clientSecret, setClientSecret] = useState("");
  const [metadata, setMetadata] = useState("");
  const [domains, setDomains] = useState<string[]>([]);
  const [jit, setJit] = useState(true);
  const [mfa, setMfa] = useState<Mfa>("when_signalled");
  const create = useMutation({
    mutationFn: () =>
      withStepUp(() =>
        unwrap(
          api.POST("/v1/identity-providers", {
            body:
              protocol === "oidc"
                ? { protocol, name: name.trim(), issuer: issuer.trim(), client_id: clientId.trim(), client_secret: clientSecret, domains, jit_provisioning: jit, mfa }
                : { protocol, name: name.trim(), metadata_xml: metadata, domains, jit_provisioning: jit, mfa },
          }),
        ),
      ),
    onSuccess: (r) => {
      qc.setQueryData(KEY, r);
      toast.success(`${name.trim()} connected`, { description: "Run a test sign-in, then people can use it." });
      onClose();
    },
  });
  const ready = !!name.trim() && domains.length > 0 && (protocol === "oidc" ? !!issuer.trim() && !!clientId.trim() && !!clientSecret : !!metadata.trim());
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent title="Connect an identity provider" className="max-w-xl">
        <div className="max-h-[72vh] space-y-4 overflow-y-auto pr-1">
          <div className="grid grid-cols-2 gap-2">
            {(
              [
                ["oidc", "OpenID Connect", "Okta, Entra ID, Google, Auth0, Ping"],
                ["saml", "SAML 2.0", "ADFS, Entra ID, Okta, Ping, OneLogin"],
              ] as const
            ).map(([k, label, help]) => (
              <button
                key={k}
                type="button"
                onClick={() => (setProtocol(k), setName(k === "oidc" ? "Okta" : "ADFS"))}
                className={cn("rounded-md border p-2.5 text-left text-[13px]", protocol === k ? "border-primary bg-primary-soft" : "border-border hover:bg-bg-subtle")}
              >
                <span className="block font-medium">{label}</span>
                <span className="block text-[11px] text-fg-muted">{help}</span>
              </button>
            ))}
          </div>
          <SpValues protocol={protocol} sp={sp} />
          <Field label="Name" htmlFor="idp-name" hint="Shown on the sign-in page: “Continue with …”">
            <Input id="idp-name" value={name} onChange={(e) => setName(e.target.value)} maxLength={100} />
          </Field>
          {protocol === "oidc" ? (
            <>
              <Field
                label="Issuer URL"
                htmlFor="idp-issuer"
                hint="Okta: https://acme.okta.com · Entra ID: https://login.microsoftonline.com/<tenant ID>/v2.0 · Google: https://accounts.google.com"
              >
                <Input id="idp-issuer" value={issuer} onChange={(e) => setIssuer(e.target.value)} placeholder="https://" />
              </Field>
              <div className="grid grid-cols-2 gap-3">
                <Field label="Client ID" htmlFor="idp-client">
                  <Input id="idp-client" value={clientId} onChange={(e) => setClientId(e.target.value)} autoComplete="off" />
                </Field>
                <Field label="Client secret" htmlFor="idp-secret">
                  <Input id="idp-secret" type="password" value={clientSecret} onChange={(e) => setClientSecret(e.target.value)} autoComplete="off" />
                </Field>
              </div>
            </>
          ) : (
            <Field label="IdP metadata (XML)" htmlFor="idp-metadata" hint="Download it from your IdP's app page (Federation metadata) and paste it here.">
              <textarea
                id="idp-metadata"
                value={metadata}
                onChange={(e) => setMetadata(e.target.value)}
                rows={5}
                spellCheck={false}
                className="w-full rounded-md border border-border bg-bg px-3 py-2 font-mono text-xs"
                placeholder='<md:EntityDescriptor entityID="…">'
              />
            </Field>
          )}
          <Field label="Signs in people at" htmlFor="idp-domains">
            <DomainPicker value={domains} onChange={setDomains} />
          </Field>
          <Behaviour jit={jit} setJit={setJit} mfa={mfa} setMfa={setMfa} />
          <ErrorBanner error={create.error} />
          <div className="flex justify-end gap-2 border-t border-border pt-4">
            <Button variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button variant="primary" loading={create.isPending} disabled={!ready} onClick={() => create.mutate()}>
              Connect
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

function EditProvider({ idp: d, sp, onClose }: { idp: Idp; sp: Sp; onClose: () => void }) {
  const qc = useQueryClient();
  const withStepUp = useStepUp();
  const [name, setName] = useState(d.name);
  const [domains, setDomains] = useState(d.domains);
  const [jit, setJit] = useState(d.jit_provisioning);
  const [mfa, setMfa] = useState<Mfa>(d.mfa);
  const [secret, setSecret] = useState("");
  const [metadata, setMetadata] = useState("");
  const save = useMutation({
    mutationFn: () =>
      withStepUp(() =>
        unwrap(
          api.PATCH("/v1/identity-providers/{id}", {
            params: { path: { id: d.id } },
            body: { name: name.trim(), domains, jit_provisioning: jit, mfa, ...(secret ? { client_secret: secret } : {}), ...(metadata.trim() ? { metadata_xml: metadata } : {}) },
          }),
        ),
      ),
    onSuccess: (r) => (qc.setQueryData(KEY, r), toast.success(`${name.trim()} saved`), onClose()),
  });
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent title={`Edit ${d.name}`} className="max-w-xl">
        <div className="max-h-[72vh] space-y-4 overflow-y-auto pr-1">
          <SpValues protocol={d.protocol} sp={sp} />
          <Field label="Name" htmlFor="e-name">
            <Input id="e-name" value={name} onChange={(e) => setName(e.target.value)} maxLength={100} />
          </Field>
          {d.protocol === "oidc" ? (
            <Field label="New client secret (optional)" htmlFor="e-secret" hint="Changing it needs a new test sign-in before the IdP can be required again.">
              <Input id="e-secret" type="password" value={secret} onChange={(e) => setSecret(e.target.value)} autoComplete="off" />
            </Field>
          ) : (
            <>
              <div className="space-y-1 text-xs text-fg-muted">
                {d.certificates.map((c) => (
                  <p key={c.fingerprint_sha256}>
                    Signing certificate {c.subject} · expires {new Date(c.not_after).toLocaleDateString()}
                  </p>
                ))}
              </div>
              <Field label="Replace metadata (optional)" htmlFor="e-metadata" hint="For a new signing certificate or sign-in URL.">
                <textarea id="e-metadata" value={metadata} onChange={(e) => setMetadata(e.target.value)} rows={4} spellCheck={false} className="w-full rounded-md border border-border bg-bg px-3 py-2 font-mono text-xs" />
              </Field>
            </>
          )}
          <Field label="Signs in people at" htmlFor="e-domains">
            <DomainPicker value={domains} onChange={setDomains} />
          </Field>
          <Behaviour jit={jit} setJit={setJit} mfa={mfa} setMfa={setMfa} />
          <ErrorBanner error={save.error} />
          <div className="flex justify-end gap-2 border-t border-border pt-4">
            <Button variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button variant="primary" loading={save.isPending} disabled={!name.trim() || !domains.length} onClick={() => save.mutate()}>
              Save
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

type TestData = {
  ok: boolean;
  code?: string;
  error?: string;
  claims?: { subject: string; email: string; given_name: string; family_name: string; groups: string[]; mfa: boolean };
  account?: { outcome: "signs_in" | "created" | "refused"; email: string; status: string | null; linked: boolean };
  session_mfa?: "satisfied_by_idp" | "nexus_mfa";
  raw?: Record<string, unknown>;
};

/** What came back from a test sign-in, and what Nexus would do with it. */
function TestResult({ idpId, state, providers }: { idpId: string; state: string; providers: Idp[] }) {
  const router = useRouter();
  const [raw, setRaw] = useState(false);
  const r = useQuery({
    queryKey: ["idp-test", state],
    queryFn: () => unwrap(api.GET("/v1/identity-providers/{id}/tests/{state}", { params: { path: { id: idpId, state } } })),
    refetchInterval: (q) => (q.state.data?.done ? false : 1000),
  });
  const qc = useQueryClient();
  const name = providers.find((p) => p.id === idpId)?.name ?? "The IdP";
  const t = r.data?.result as TestData | null | undefined;
  const close = () => (router.replace("/settings/identity-providers"), qc.invalidateQueries({ queryKey: KEY }));
  if (!r.data?.done || !t) return r.error ? <ErrorBanner error={r.error} /> : <Skeleton className="mb-3 h-24" />;
  const outcome = {
    signs_in: `signs in as ${t.account?.email}${t.account?.linked ? "" : " (linked on first sign-in)"}`,
    created: `gets a new Nexus account for ${t.account?.email}`,
    refused: t.account?.status ? `is refused: the account is ${t.account.status}` : `is refused: there's no Nexus account and new accounts aren't created`,
  };
  return (
    <Card className={cn("mb-4 border", t.ok ? "border-success/40" : "border-warning/40")}>
      <div className="flex items-start gap-3 px-4 py-3">
        {t.ok ? <CheckCircle2 className="mt-0.5 size-5 text-success" /> : <AlertTriangle className="mt-0.5 size-5 text-warning" />}
        <div className="min-w-0 flex-1 space-y-2 text-[13px]">
          <p className="font-semibold">{t.ok ? `Test sign-in with ${name} worked` : `Test sign-in with ${name} failed`}</p>
          {t.ok && t.claims ? (
            <>
              <dl className="grid grid-cols-[140px_1fr] gap-x-3 gap-y-1 text-xs">
                <dt className="text-fg-muted">Email</dt>
                <dd>{t.claims.email}</dd>
                <dt className="text-fg-muted">Name</dt>
                <dd>{`${t.claims.given_name} ${t.claims.family_name}`.trim() || "—"}</dd>
                <dt className="text-fg-muted">Subject</dt>
                <dd className="truncate font-mono">{t.claims.subject}</dd>
                <dt className="text-fg-muted">Groups</dt>
                <dd>{t.claims.groups.length ? t.claims.groups.join(", ") : "—"}</dd>
                <dt className="text-fg-muted">MFA at the IdP</dt>
                <dd>{t.claims.mfa ? "Reported" : "Not reported"}</dd>
              </dl>
              <p>
                In a real sign-in, this person {outcome[t.account!.outcome]}.{" "}
                {t.session_mfa === "satisfied_by_idp" ? "The IdP's sign-in counts as MFA." : "Nexus asks for its own MFA when the organization requires it."}
              </p>
              <button type="button" className="text-xs text-primary hover:underline" onClick={() => setRaw(!raw)}>
                {raw ? "Hide" : "Show"} everything the IdP sent
              </button>
              {raw ? <pre className="max-h-64 overflow-auto rounded-md bg-bg-subtle p-2 text-[11px]">{JSON.stringify(t.raw, null, 2)}</pre> : null}
            </>
          ) : (
            <p className="text-fg-muted">{t.error}</p>
          )}
        </div>
        <Button size="sm" variant="ghost" aria-label="Dismiss" onClick={close}>
          <X />
        </Button>
      </div>
    </Card>
  );
}
