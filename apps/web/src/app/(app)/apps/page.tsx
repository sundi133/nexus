"use client";

import type { Schemas } from "@nexus/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AppWindow, Plus, TriangleAlert } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { AppIcon } from "@/components/features/app-icon";
import { Button } from "@/components/ui/button";
import { CopyField } from "@/components/ui/copy";
import { SamlIdpValues } from "@/components/features/saml-values";
import { Field, Input } from "@/components/ui/input";
import { Badge, Card, EmptyState, ErrorBanner, PageHeader, Skeleton, StatusPill } from "@/components/ui/misc";
import { Dialog, DialogContent } from "@/components/ui/overlay";
import { Table, TD, TH, THead, TR } from "@/components/ui/table";
import { api, fieldErrors, unwrap } from "@/lib/api";
import { useCan } from "@/lib/queries";
import { pluralize } from "@/lib/utils";

export default function AppsPage() {
  const router = useRouter();
  const can = useCan();
  const [creating, setCreating] = useState(false);
  const apps = useQuery({ queryKey: ["apps"], queryFn: () => unwrap(api.GET("/v1/apps")) });

  return (
    <>
      <PageHeader
        title="Applications"
        description="Apps your people sign in to with Nexus. Only assigned users and groups can use each app."
        actions={
          can("apps:write") ? (
            <Button variant="primary" onClick={() => setCreating(true)}>
              <Plus /> Add app
            </Button>
          ) : null
        }
      />
      <Card className="overflow-hidden">
        {apps.isPending ? (
          <Skeleton className="m-4 h-24" />
        ) : !apps.data?.data.length ? (
          <EmptyState
            icon={<AppWindow />}
            title="No applications yet"
            description="Connect an app over OpenID Connect so your team signs in with Nexus, including MFA and device checks."
            action={can("apps:write") ? <Button onClick={() => setCreating(true)}>Add your first app</Button> : undefined}
          />
        ) : (
          <Table>
            <THead>
              <tr>
                <TH>Application</TH>
                <TH>Protocol</TH>
                <TH>Access</TH>
                <TH>Status</TH>
              </tr>
            </THead>
            <tbody>
              {apps.data.data.map((a) => (
                <TR key={a.id} className="cursor-pointer" onClick={() => router.push(`/apps/${a.id}`)}>
                  <TD>
                    <Link href={`/apps/${a.id}`} className="flex items-center gap-3" onClick={(e) => e.stopPropagation()}>
                      <AppIcon name={a.name} size={30} />
                      <span className="font-medium">{a.name}</span>
                    </Link>
                  </TD>
                  <TD>
                    <Badge>{a.protocol.toUpperCase()}</Badge>
                  </TD>
                  <TD className="text-fg-muted">
                    {a.assignment_count ? (
                      pluralize(a.assignment_count, "assignment")
                    ) : (
                      <span className="inline-flex items-center gap-1 text-warning">
                        <TriangleAlert className="size-3.5" /> Nobody assigned
                      </span>
                    )}
                  </TD>
                  <TD>{a.status === "active" ? <StatusPill tone="success">Active</StatusPill> : <StatusPill>Disabled</StatusPill>}</TD>
                </TR>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
      <CreateAppDialog open={creating} onOpenChange={setCreating} />
    </>
  );
}

function CreateAppDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (v: boolean) => void }) {
  const qc = useQueryClient();
  const router = useRouter();
  const empty = {
    protocol: "saml" as "oidc" | "saml",
    name: "",
    redirects: "",
    launch_url: "",
    client_type: "confidential" as "confidential" | "public",
    saml_mode: "metadata" as "metadata" | "manual",
    metadata_xml: "",
    entity_id: "",
    acs_url: "",
  };
  const [form, setForm] = useState(empty);
  const [created, setCreated] = useState<Schemas["ApplicationCreated"] | null>(null);
  const set = (k: keyof typeof empty) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => setForm({ ...form, [k]: e.target.value });
  const create = useMutation({
    mutationFn: () =>
      unwrap(
        api.POST("/v1/apps", {
          body:
            form.protocol === "oidc"
              ? { name: form.name, protocol: "oidc", client_type: form.client_type, redirect_uris: form.redirects.split(/\s+/).filter(Boolean), launch_url: form.launch_url }
              : form.saml_mode === "metadata"
                ? { name: form.name, protocol: "saml", metadata_xml: form.metadata_xml, name_id_format: "email", sign: "assertion", launch_url: "" }
                : { name: form.name, protocol: "saml", entity_id: form.entity_id, acs_url: form.acs_url, name_id_format: "email", sign: "assertion", launch_url: "" },
        }),
      ),
    onSuccess: (r) => {
      qc.invalidateQueries({ queryKey: ["apps"] });
      setCreated(r);
    },
    onError: () => {},
  });
  const errs = fieldErrors(create.error);
  const close = () => {
    onOpenChange(false);
    if (created) router.push(`/apps/${created.app.id}?tab=access`);
    setCreated(null);
    setForm(empty);
  };
  const textarea = "w-full rounded-md border border-border bg-bg px-2.5 py-1.5 font-mono text-xs shadow-card focus:border-ring focus:outline-none";

  return (
    <Dialog open={open} onOpenChange={(v) => (v ? onOpenChange(true) : close())}>
      <DialogContent title={created ? `${created.app.name} is ready` : "Add an application"} className="max-w-lg">
        {created ? (
          <div className="space-y-3">
            <p className="text-[13px] text-fg-muted">Enter these values in the app&apos;s SSO settings.</p>
            {created.app.oidc ? (
              <>
                <CopyField label="Issuer" value={created.app.oidc.issuer} />
                <CopyField label="Discovery URL" value={created.app.oidc.discovery_url} />
                <CopyField label="Client ID" value={created.app.oidc.client_id} />
                {created.client_secret ? (
                  <>
                    <CopyField label="Client secret" value={created.client_secret} secret />
                    <p className="flex items-start gap-1.5 text-xs text-warning">
                      <TriangleAlert className="mt-px size-3.5 shrink-0" /> This is the only time the secret is shown. Store it in the app now; you can rotate it later.
                    </p>
                  </>
                ) : null}
              </>
            ) : null}
            {created.app.saml ? <SamlIdpValues saml={created.app.saml} /> : null}
            <div className="flex justify-end pt-2">
              <Button variant="primary" onClick={close}>
                Next: choose who gets access
              </Button>
            </div>
          </div>
        ) : (
          <form
            className="space-y-3"
            onSubmit={(e) => {
              e.preventDefault();
              create.mutate();
            }}
          >
            <div className="grid grid-cols-2 gap-2" role="radiogroup" aria-label="Protocol">
              {(["saml", "oidc"] as const).map((p) => (
                <button
                  key={p}
                  type="button"
                  role="radio"
                  aria-checked={form.protocol === p}
                  onClick={() => setForm({ ...form, protocol: p })}
                  className={`rounded-lg border p-3 text-left ${form.protocol === p ? "border-primary bg-primary-soft" : "border-border hover:bg-bg-subtle"}`}
                >
                  <span className="block text-[13px] font-medium">{p === "saml" ? "SAML 2.0" : "OpenID Connect"}</span>
                  <span className="block text-xs text-fg-muted">{p === "saml" ? "Most enterprise apps (Slack, GitHub, AWS…)" : "Modern apps and your own software"}</span>
                </button>
              ))}
            </div>
            {!Object.keys(errs).length ? <ErrorBanner error={create.error} /> : null}
            <Field label="Name" htmlFor="app-name" error={errs.name}>
              <Input id="app-name" autoFocus required value={form.name} onChange={set("name")} placeholder={form.protocol === "saml" ? "HR Portal" : "Grafana"} />
            </Field>
            {form.protocol === "saml" ? (
              <>
                <div className="flex gap-4 text-[13px]">
                  <label className="flex items-center gap-1.5">
                    <input type="radio" checked={form.saml_mode === "metadata"} onChange={() => setForm({ ...form, saml_mode: "metadata" })} /> Paste the app&apos;s metadata
                  </label>
                  <label className="flex items-center gap-1.5">
                    <input type="radio" checked={form.saml_mode === "manual"} onChange={() => setForm({ ...form, saml_mode: "manual" })} /> Enter values
                  </label>
                </div>
                {form.saml_mode === "metadata" ? (
                  <Field label="Service provider metadata (XML)" htmlFor="app-md" hint="Usually found in the app's SSO settings as “SP metadata”.">
                    <textarea id="app-md" required rows={5} value={form.metadata_xml} onChange={set("metadata_xml")} placeholder="<EntityDescriptor entityID=…" className={textarea} />
                  </Field>
                ) : (
                  <>
                    <Field label="Entity ID (Audience)" htmlFor="app-entity">
                      <Input id="app-entity" required value={form.entity_id} onChange={set("entity_id")} placeholder="https://app.example.com/saml/metadata" />
                    </Field>
                    <Field label="ACS URL" htmlFor="app-acs" hint="Where Nexus posts the signed sign-in response. HTTPS only.">
                      <Input id="app-acs" type="url" required value={form.acs_url} onChange={set("acs_url")} placeholder="https://app.example.com/saml/acs" />
                    </Field>
                  </>
                )}
              </>
            ) : (
              <>
                <Field
                  label="Redirect URIs"
                  htmlFor="app-redirects"
                  hint="One per line, exactly as the app sends them. HTTPS only (http is allowed for localhost)."
                  error={Object.entries(errs).find(([k]) => k.startsWith("redirect_uris"))?.[1]}
                >
                  <textarea id="app-redirects" required rows={3} value={form.redirects} onChange={set("redirects")} placeholder="https://grafana.example.com/login/generic_oauth" className={textarea} />
                </Field>
                <Field label="Launch URL" htmlFor="app-launch" hint="Optional: where the app launcher sends people to start signing in." error={errs.launch_url}>
                  <Input id="app-launch" type="url" value={form.launch_url} onChange={set("launch_url")} placeholder="https://grafana.example.com/login" />
                </Field>
                <fieldset>
                  <legend className="mb-1 text-[13px] font-medium">Client type</legend>
                  <label className="flex items-center gap-2 text-[13px]">
                    <input type="radio" checked={form.client_type === "confidential"} onChange={() => setForm({ ...form, client_type: "confidential" })} /> Web app with a server
                    <span className="text-fg-subtle">(client secret)</span>
                  </label>
                  <label className="flex items-center gap-2 text-[13px]">
                    <input type="radio" checked={form.client_type === "public"} onChange={() => setForm({ ...form, client_type: "public" })} /> Single-page or mobile app
                    <span className="text-fg-subtle">(PKCE, no secret)</span>
                  </label>
                </fieldset>
              </>
            )}
            <div className="flex justify-end gap-2 pt-2">
              <Button type="button" onClick={close}>
                Cancel
              </Button>
              <Button type="submit" variant="primary" loading={create.isPending}>
                Create app
              </Button>
            </div>
          </form>
        )}
      </DialogContent>
    </Dialog>
  );
}
