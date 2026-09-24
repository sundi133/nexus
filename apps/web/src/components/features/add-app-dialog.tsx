"use client";

import type { Schemas } from "@nexus/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, Code2, Search, TriangleAlert } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { CopyField } from "@/components/ui/copy";
import { Field, Input } from "@/components/ui/input";
import { Badge, ErrorBanner } from "@/components/ui/misc";
import { Dialog, DialogContent } from "@/components/ui/overlay";
import { api, fieldErrors, unwrap } from "@/lib/api";
import { AppIcon } from "./app-icon";
import { SamlIdpValues } from "./saml-values";

type Entry = Schemas["CatalogEntry"];
type Result = { app: Schemas["Application"]; client_secret: string | null; setup_steps?: string[] };
type Stage = { kind: "pick" } | { kind: "catalog"; entry: Entry } | { kind: "custom"; protocol: "saml" | "oidc" } | { kind: "done"; result: Result };

/** Add an app: pick from the catalog (guided) or configure a custom SAML/OIDC app. */
export function AddAppDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (v: boolean) => void }) {
  const router = useRouter();
  const [stage, setStage] = useState<Stage>({ kind: "pick" });
  const close = () => {
    onOpenChange(false);
    if (stage.kind === "done") router.push(`/apps/${stage.result.app.id}?tab=access`);
    setStage({ kind: "pick" });
  };
  const title = {
    pick: "Add an application",
    catalog: stage.kind === "catalog" ? `Add ${stage.entry.name}` : "",
    custom: stage.kind === "custom" ? (stage.protocol === "saml" ? "Custom SAML app" : "Custom OpenID Connect app") : "",
    done: stage.kind === "done" ? `${stage.result.app.name} is ready` : "",
  }[stage.kind];

  return (
    <Dialog open={open} onOpenChange={(v) => (v ? onOpenChange(true) : close())}>
      <DialogContent title={title} className={stage.kind === "pick" ? "max-w-2xl" : "max-w-lg"}>
        {stage.kind === "pick" ? <Picker onPick={setStage} /> : null}
        {stage.kind === "catalog" ? <CatalogForm entry={stage.entry} onBack={() => setStage({ kind: "pick" })} onDone={(result) => setStage({ kind: "done", result })} /> : null}
        {stage.kind === "custom" ? <CustomForm protocol={stage.protocol} onBack={() => setStage({ kind: "pick" })} onDone={(result) => setStage({ kind: "done", result })} /> : null}
        {stage.kind === "done" ? <Done result={stage.result} onClose={close} /> : null}
      </DialogContent>
    </Dialog>
  );
}

function Picker({ onPick }: { onPick: (s: Stage) => void }) {
  const [q, setQ] = useState("");
  const catalog = useQuery({ queryKey: ["app-catalog"], queryFn: () => unwrap(api.GET("/v1/app-catalog")), staleTime: Infinity });
  const list = (catalog.data?.data ?? []).filter((e) => `${e.name} ${e.category}`.toLowerCase().includes(q.toLowerCase()));
  return (
    <div className="space-y-3">
      <div className="relative">
        <Search className="pointer-events-none absolute left-2.5 top-2 size-4 text-fg-subtle" />
        <Input autoFocus placeholder="Search apps" value={q} onChange={(e) => setQ(e.target.value)} className="pl-8" aria-label="Search the app catalog" />
      </div>
      <ul className="grid max-h-80 grid-cols-2 gap-2 overflow-y-auto sm:grid-cols-3">
        {list.map((e) => (
          <li key={e.key}>
            <button
              type="button"
              onClick={() => onPick({ kind: "catalog", entry: e })}
              className="flex w-full items-center gap-2.5 rounded-lg border border-border p-2.5 text-left hover:border-primary hover:bg-bg-subtle"
            >
              <AppIcon name={e.name} size={30} />
              <span className="min-w-0">
                <span className="block truncate text-[13px] font-medium">{e.name}</span>
                <span className="block text-[11px] text-fg-muted">
                  {e.category} · {e.protocol.toUpperCase()}
                </span>
              </span>
            </button>
          </li>
        ))}
      </ul>
      <div className="grid gap-2 border-t border-border pt-3 sm:grid-cols-2">
        {(["saml", "oidc"] as const).map((p) => (
          <button
            key={p}
            type="button"
            onClick={() => onPick({ kind: "custom", protocol: p })}
            className="flex items-center gap-2.5 rounded-lg border border-dashed border-border-strong p-2.5 text-left hover:bg-bg-subtle"
          >
            <Code2 className="size-4 text-fg-muted" />
            <span>
              <span className="block text-[13px] font-medium">{p === "saml" ? "Custom SAML 2.0 app" : "Custom OpenID Connect app"}</span>
              <span className="block text-[11px] text-fg-muted">{p === "saml" ? "Paste metadata or enter URLs" : "Your own software or any OIDC app"}</span>
            </span>
          </button>
        ))}
      </div>
    </div>
  );
}

function CatalogForm({ entry, onBack, onDone }: { entry: Entry; onBack: () => void; onDone: (r: Result) => void }) {
  const qc = useQueryClient();
  const [name, setName] = useState(entry.name);
  const [values, setValues] = useState<Record<string, string>>({});
  const install = useMutation({
    mutationFn: () => unwrap(api.POST("/v1/app-catalog/{key}/install", { params: { path: { key: entry.key } }, body: { name, fields: values } })),
    onSuccess: (r) => {
      qc.invalidateQueries({ queryKey: ["apps"] });
      onDone(r);
    },
    onError: () => {},
  });
  const errs = fieldErrors(install.error);
  return (
    <form
      className="space-y-3"
      onSubmit={(e) => {
        e.preventDefault();
        install.mutate();
      }}
    >
      <div className="flex items-center gap-3 rounded-lg bg-bg-subtle p-3">
        <AppIcon name={entry.name} size={36} />
        <div className="min-w-0 flex-1">
          <p className="text-[13px] text-fg-muted">{entry.description}</p>
        </div>
        <Badge>{entry.protocol.toUpperCase()}</Badge>
      </div>
      {!Object.keys(errs).length ? <ErrorBanner error={install.error} /> : null}
      <Field label="Name in Nexus" htmlFor="cat-name">
        <Input id="cat-name" value={name} onChange={(e) => setName(e.target.value)} required />
      </Field>
      {entry.fields.map((f) => {
        const v = values[f.key] ?? "";
        const bad = v !== "" && !new RegExp(f.pattern).test(v);
        return (
          <Field key={f.key} label={f.label} htmlFor={`f-${f.key}`} hint={f.help} error={errs[`fields.${f.key}`] ?? (bad ? `${f.label} doesn't look right` : undefined)}>
            <Input id={`f-${f.key}`} required placeholder={f.placeholder} value={v} aria-invalid={bad} onChange={(e) => setValues({ ...values, [f.key]: e.target.value.trim() })} />
          </Field>
        );
      })}
      <div className="flex justify-between gap-2 pt-2">
        <Button type="button" variant="ghost" onClick={onBack}>
          <ArrowLeft /> Back
        </Button>
        <Button type="submit" variant="primary" loading={install.isPending}>
          Add {entry.name}
        </Button>
      </div>
    </form>
  );
}

function CustomForm({ protocol, onBack, onDone }: { protocol: "saml" | "oidc"; onBack: () => void; onDone: (r: Result) => void }) {
  const qc = useQueryClient();
  const [form, setForm] = useState({ name: "", redirects: "", launch_url: "", client_type: "confidential" as "confidential" | "public", saml_mode: "metadata" as "metadata" | "manual", metadata_xml: "", entity_id: "", acs_url: "" });
  const set = (k: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => setForm({ ...form, [k]: e.target.value });
  const create = useMutation({
    mutationFn: () =>
      unwrap(
        api.POST("/v1/apps", {
          body:
            protocol === "oidc"
              ? { name: form.name, protocol: "oidc", client_type: form.client_type, redirect_uris: form.redirects.split(/\s+/).filter(Boolean), launch_url: form.launch_url }
              : form.saml_mode === "metadata"
                ? { name: form.name, protocol: "saml", metadata_xml: form.metadata_xml, name_id_format: "email", sign: "assertion", launch_url: "" }
                : { name: form.name, protocol: "saml", entity_id: form.entity_id, acs_url: form.acs_url, name_id_format: "email", sign: "assertion", launch_url: "" },
        }),
      ),
    onSuccess: (r) => {
      qc.invalidateQueries({ queryKey: ["apps"] });
      onDone(r);
    },
    onError: () => {},
  });
  const errs = fieldErrors(create.error);
  const textarea = "w-full rounded-md border border-border bg-bg px-2.5 py-1.5 font-mono text-xs shadow-card focus:border-ring focus:outline-none";
  return (
    <form
      className="space-y-3"
      onSubmit={(e) => {
        e.preventDefault();
        create.mutate();
      }}
    >
      {!Object.keys(errs).length ? <ErrorBanner error={create.error} /> : null}
      <Field label="Name" htmlFor="app-name" error={errs.name}>
        <Input id="app-name" autoFocus required value={form.name} onChange={set("name")} placeholder={protocol === "saml" ? "HR Portal" : "Internal dashboard"} />
      </Field>
      {protocol === "saml" ? (
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
          <Field label="Redirect URIs" htmlFor="app-redirects" hint="One per line, exactly as the app sends them. HTTPS only (http is allowed for localhost)." error={Object.entries(errs).find(([k]) => k.startsWith("redirect_uris"))?.[1]}>
            <textarea id="app-redirects" required rows={3} value={form.redirects} onChange={set("redirects")} placeholder="https://app.example.com/oauth/callback" className={textarea} />
          </Field>
          <Field label="Launch URL" htmlFor="app-launch" hint="Optional: where the app launcher sends people to start signing in." error={errs.launch_url}>
            <Input id="app-launch" type="url" value={form.launch_url} onChange={set("launch_url")} placeholder="https://app.example.com/login" />
          </Field>
          <fieldset>
            <legend className="mb-1 text-[13px] font-medium">Client type</legend>
            <label className="flex items-center gap-2 text-[13px]">
              <input type="radio" checked={form.client_type === "confidential"} onChange={() => setForm({ ...form, client_type: "confidential" })} /> Web app with a server <span className="text-fg-subtle">(client secret)</span>
            </label>
            <label className="flex items-center gap-2 text-[13px]">
              <input type="radio" checked={form.client_type === "public"} onChange={() => setForm({ ...form, client_type: "public" })} /> Single-page or mobile app <span className="text-fg-subtle">(PKCE, no secret)</span>
            </label>
          </fieldset>
        </>
      )}
      <div className="flex justify-between gap-2 pt-2">
        <Button type="button" variant="ghost" onClick={onBack}>
          <ArrowLeft /> Back
        </Button>
        <Button type="submit" variant="primary" loading={create.isPending}>
          Create app
        </Button>
      </div>
    </form>
  );
}

function Done({ result, onClose }: { result: Result; onClose: () => void }) {
  return (
    <div className="space-y-3">
      {result.app.oidc ? (
        <>
          <CopyField label="Issuer" value={result.app.oidc.issuer} />
          <CopyField label="Client ID" value={result.app.oidc.client_id} />
          {result.client_secret ? (
            <>
              <CopyField label="Client secret" value={result.client_secret} secret />
              <p className="flex items-start gap-1.5 text-xs text-warning">
                <TriangleAlert className="mt-px size-3.5 shrink-0" /> This is the only time the secret is shown. Store it in the app now; you can rotate it later.
              </p>
            </>
          ) : null}
        </>
      ) : null}
      {result.app.saml ? <SamlIdpValues saml={result.app.saml} /> : null}
      {result.setup_steps?.length ? (
        <div className="rounded-lg border border-border bg-bg-subtle p-3">
          <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-fg-muted">Finish in {result.app.name}</p>
          <ol className="list-decimal space-y-1.5 pl-4 text-[13px]">
            {result.setup_steps.map((s, i) => (
              <li key={i} className="break-words">
                <StepText text={s} />
              </li>
            ))}
          </ol>
        </div>
      ) : null}
      <div className="flex justify-end pt-1">
        <Button variant="primary" onClick={onClose}>
          Next: choose who gets access
        </Button>
      </div>
    </div>
  );
}

/** Renders URLs inside setup instructions as copyable code, the rest as prose. */
function StepText({ text }: { text: string }) {
  return (
    <>
      {/* A URL never ends in sentence punctuation, so "…/saml." copies as "…/saml". */}
      {text.split(/((?:https?:\/\/|urn:)[^\s,]*[^\s,.;:)])/g).map((part, i) =>
        i % 2 ? (
          <code key={i} className="rounded bg-bg px-1 font-mono text-xs">
            {part}
          </code>
        ) : (
          part
        ),
      )}
    </>
  );
}
