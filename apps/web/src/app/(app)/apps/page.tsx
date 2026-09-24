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
  const [form, setForm] = useState({ name: "", redirects: "", launch_url: "", client_type: "confidential" as "confidential" | "public" });
  const [created, setCreated] = useState<Schemas["ApplicationCreated"] | null>(null);
  const create = useMutation({
    mutationFn: () =>
      unwrap(
        api.POST("/v1/apps", {
          body: {
            name: form.name,
            protocol: "oidc",
            client_type: form.client_type,
            redirect_uris: form.redirects.split(/\s+/).filter(Boolean),
            launch_url: form.launch_url,
          },
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
    setForm({ name: "", redirects: "", launch_url: "", client_type: "confidential" });
  };

  return (
    <Dialog open={open} onOpenChange={(v) => (v ? onOpenChange(true) : close())}>
      <DialogContent title={created ? `${created.app.name} is ready` : "Add an OpenID Connect app"} className="max-w-lg">
        {created ? (
          <div className="space-y-3">
            <p className="text-[13px] text-fg-muted">Enter these values in the app&apos;s SSO settings. Most apps only need the issuer (or discovery URL), client ID and secret.</p>
            <CopyField label="Issuer" value={created.app.oidc!.issuer} />
            <CopyField label="Discovery URL" value={created.app.oidc!.discovery_url} />
            <CopyField label="Client ID" value={created.app.oidc!.client_id} />
            {created.client_secret ? (
              <>
                <CopyField label="Client secret" value={created.client_secret} secret />
                <p className="flex items-start gap-1.5 text-xs text-warning">
                  <TriangleAlert className="mt-px size-3.5 shrink-0" /> This is the only time the secret is shown. Store it in the app now; you can rotate it later.
                </p>
              </>
            ) : null}
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
            {!Object.keys(errs).length ? <ErrorBanner error={create.error} /> : null}
            <Field label="Name" htmlFor="app-name" error={errs.name}>
              <Input id="app-name" autoFocus required value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="Grafana" />
            </Field>
            <Field
              label="Redirect URIs"
              htmlFor="app-redirects"
              hint="One per line, exactly as the app sends them. HTTPS only (http is allowed for localhost)."
              error={Object.entries(errs).find(([k]) => k.startsWith("redirect_uris"))?.[1]}
            >
              <textarea
                id="app-redirects"
                required
                rows={3}
                value={form.redirects}
                onChange={(e) => setForm({ ...form, redirects: e.target.value })}
                placeholder="https://grafana.example.com/login/generic_oauth"
                className="w-full rounded-md border border-border bg-bg px-2.5 py-1.5 font-mono text-xs shadow-card focus:border-ring focus:outline-none"
              />
            </Field>
            <Field label="Launch URL" htmlFor="app-launch" hint="Optional: where the app launcher sends people to start signing in." error={errs.launch_url}>
              <Input id="app-launch" type="url" value={form.launch_url} onChange={(e) => setForm({ ...form, launch_url: e.target.value })} placeholder="https://grafana.example.com/login" />
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
