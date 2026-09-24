"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ChevronLeft, KeyRound, Trash2, UserPlus, UsersRound, X } from "lucide-react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, use, useState } from "react";
import { toast } from "sonner";
import { ActivityList } from "@/components/features/activity";
import { AppIcon } from "@/components/features/app-icon";
import { SamlIdpValues } from "@/components/features/saml-values";
import { SamlAttributesEditor } from "@/components/features/saml-attributes";
import { ConfirmAction } from "@/components/features/confirm-action";
import { Button } from "@/components/ui/button";
import { CopyField } from "@/components/ui/copy";
import { Input } from "@/components/ui/input";
import { Avatar, Badge, Card, CardHeader, EmptyState, ErrorBanner, KeyValue, Skeleton, StatusPill } from "@/components/ui/misc";
import { Dialog, DialogContent, Tabs, TabsContent, TabsList } from "@/components/ui/overlay";
import { api, unwrap } from "@/lib/api";
import { useCan } from "@/lib/queries";
import { formatDateTime } from "@/lib/utils";

function AppDetail({ id }: { id: string }) {
  const qc = useQueryClient();
  const router = useRouter();
  const params = useSearchParams();
  const can = useCan();
  const [secret, setSecret] = useState<string | null>(null);
  const [rotating, setRotating] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [assigning, setAssigning] = useState(false);

  const app = useQuery({ queryKey: ["app", id], queryFn: () => unwrap(api.GET("/v1/apps/{id}", { params: { path: { id } } })) });
  const assignments = useQuery({ queryKey: ["app", id, "assignments"], queryFn: () => unwrap(api.GET("/v1/apps/{id}/assignments", { params: { path: { id } } })) });
  const activity = useQuery({
    queryKey: ["audit", { subject_id: id }],
    queryFn: () => unwrap(api.GET("/v1/audit/events", { params: { query: { subject_id: id, limit: 50 } } })),
  });
  const refresh = () => {
    qc.invalidateQueries({ queryKey: ["app", id] });
    qc.invalidateQueries({ queryKey: ["apps"] });
    qc.invalidateQueries({ queryKey: ["audit"] });
  };
  const setStatus = useMutation({
    mutationFn: (status: "active" | "disabled") => unwrap(api.PATCH("/v1/apps/{id}", { params: { path: { id } }, body: { status } })),
    onSuccess: (a) => {
      refresh();
      toast.success(a.status === "active" ? "Sign-in enabled" : "Sign-in disabled");
    },
  });
  const unassign = useMutation({
    mutationFn: (p: { type: "user" | "group"; id: string }) =>
      unwrap(api.DELETE("/v1/apps/{id}/assignments/{type}/{principalId}", { params: { path: { id, type: p.type, principalId: p.id } } })),
    onSuccess: () => {
      refresh();
      toast.success("Access removed");
    },
  });

  if (app.isPending) return <Skeleton className="h-40" />;
  if (!app.data) return <ErrorBanner error={app.error} />;
  const a = app.data;

  return (
    <>
      <Link href="/apps" className="mb-3 inline-flex items-center gap-1 text-[13px] text-fg-muted hover:text-fg">
        <ChevronLeft className="size-4" /> Applications
      </Link>
      <div className="mb-5 flex flex-wrap items-center gap-4">
        <AppIcon name={a.name} size={48} />
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-semibold tracking-tight">{a.name}</h1>
            <Badge>{a.protocol.toUpperCase()}</Badge>
            {a.status === "active" ? <StatusPill tone="success">Active</StatusPill> : <StatusPill>Disabled</StatusPill>}
          </div>
          <p className="mt-0.5 text-[13px] text-fg-muted">Created {formatDateTime(a.created_at)}</p>
        </div>
        {can("apps:write") ? (
          <div className="flex gap-2">
            <Button onClick={() => setStatus.mutate(a.status === "active" ? "disabled" : "active")} loading={setStatus.isPending}>
              {a.status === "active" ? "Disable sign-in" : "Enable sign-in"}
            </Button>
            <Button variant="danger-outline" onClick={() => setDeleting(true)}>
              <Trash2 /> Delete
            </Button>
          </div>
        ) : null}
      </div>

      <Tabs defaultValue={params.get("tab") ?? "setup"}>
        <TabsList
          tabs={[
            { value: "setup", label: "Setup" },
            { value: "access", label: `Access (${a.assignment_count})` },
            { value: "activity", label: "Activity" },
          ]}
        />
        <TabsContent value="setup" className="grid gap-5 lg:grid-cols-2">
          {a.oidc ? (
            <Card>
              <CardHeader title="Values for the app" description="Paste these into the app's OpenID Connect / SSO settings." />
              <div className="space-y-3 p-4">
                <CopyField label="Issuer" value={a.oidc.issuer} />
                <CopyField label="Discovery URL" value={a.oidc.discovery_url} />
                <CopyField label="Client ID" value={a.oidc.client_id} />
                {a.oidc.client_type === "confidential" ? (
                  secret ? (
                    <CopyField label="New client secret (shown once)" value={secret} secret />
                  ) : (
                    <div>
                      <p className="mb-1 text-xs font-medium text-fg-muted">Client secret</p>
                      <div className="flex items-center justify-between rounded-md border border-border px-2.5 py-1.5 text-xs text-fg-muted">
                        Hidden: secrets are only shown when created
                        {can("apps:write") ? (
                          <Button size="sm" variant="ghost" onClick={() => setRotating(true)}>
                            <KeyRound /> Rotate
                          </Button>
                        ) : null}
                      </div>
                    </div>
                  )
                ) : (
                  <p className="text-xs text-fg-muted">Public client: uses PKCE, no secret.</p>
                )}
                <KeyValue items={[["Scopes", "openid, email, profile, groups"], ["Signing", "RS256"], ["Token lifetime", "1 hour"]]} />
              </div>
            </Card>
          ) : null}
          {a.saml ? (
            <Card>
              <CardHeader title="Values for the app" description="Paste these into the app's SAML / SSO settings." />
              <div className="p-4">
                <SamlIdpValues saml={a.saml} />
              </div>
            </Card>
          ) : null}
          <Card>
            <CardHeader title="Settings" />
            <div className="p-4">
              {a.saml ? (
                <KeyValue
                  items={[
                    ["Entity ID", <code key="e" className="break-all font-mono text-xs">{a.saml.entity_id}</code>],
                    ["ACS URL", <code key="a" className="break-all font-mono text-xs">{a.saml.acs_url}</code>],
                    ["NameID", a.saml.name_id_format === "email" ? "Email address" : "Persistent (user ID)"],
                    ["Signing", a.saml.sign === "assertion" ? "Assertion" : "Response and assertion"],
                    ["Launch", <code key="l" className="break-all font-mono text-xs">{a.launch_url}</code>],
                  ]}
                />
              ) : (
                <KeyValue
                  items={[
                    [
                      "Redirect URIs",
                      <ul key="r" className="space-y-1">
                        {a.oidc?.redirect_uris.map((u) => (
                          <li key={u}>
                            <code className="break-all font-mono text-xs">{u}</code>
                          </li>
                        ))}
                      </ul>,
                    ],
                    ["Launch URL", a.launch_url ? <code key="l" className="break-all font-mono text-xs">{a.launch_url}</code> : "Not set (hidden from the app launcher)"],
                    ["Client type", a.oidc?.client_type === "public" ? "Public (PKCE)" : "Confidential (secret)"],
                  ]}
                />
              )}
            </div>
          </Card>
          {a.saml ? <SamlAttributesEditor key={a.updated_at} appId={a.id} attributes={a.saml.attributes} editable={can("apps:write")} /> : null}
        </TabsContent>

        <TabsContent value="access">
          <Card className="overflow-hidden">
            <CardHeader
              title="Who can sign in"
              description="Assign groups rather than individuals where you can: access then follows team membership automatically."
              actions={
                can("apps:assign") ? (
                  <Button variant="primary" onClick={() => setAssigning(true)}>
                    <UserPlus /> Assign
                  </Button>
                ) : null
              }
            />
            {assignments.data?.data.length ? (
              <ul className="divide-y divide-border">
                {assignments.data.data.map((x) => (
                  <li key={`${x.principal_type}:${x.principal_id}`} className="flex items-center gap-3 px-4 py-2.5 text-[13px]">
                    {x.principal_type === "group" ? (
                      <span className="flex size-7 items-center justify-center rounded-full bg-bg-muted text-fg-muted">
                        <UsersRound className="size-3.5" />
                      </span>
                    ) : (
                      <Avatar name={x.display} />
                    )}
                    <Link href={x.principal_type === "group" ? `/groups/${x.principal_id}` : `/users/${x.principal_id}`} className="min-w-0 flex-1 hover:underline">
                      <span className="block font-medium">{x.display}</span>
                      <span className="block text-xs text-fg-muted">{x.principal_type === "group" ? `Group · ${x.detail}` : x.detail}</span>
                    </Link>
                    {can("apps:assign") ? (
                      <Button size="sm" variant="ghost" onClick={() => unassign.mutate({ type: x.principal_type, id: x.principal_id })} aria-label={`Remove ${x.display}`}>
                        <X /> Remove
                      </Button>
                    ) : null}
                  </li>
                ))}
              </ul>
            ) : (
              <EmptyState title="Nobody can sign in yet" description="Assign a group or individual people to give them access." />
            )}
          </Card>
        </TabsContent>

        <TabsContent value="activity">
          <Card className="overflow-hidden">
            {activity.data?.data.length ? <ActivityList events={activity.data.data} /> : <EmptyState title="No sign-ins yet" />}
          </Card>
        </TabsContent>
      </Tabs>

      <ConfirmAction
        open={rotating}
        onOpenChange={setRotating}
        title={`Rotate the client secret for ${a.name}?`}
        effects={["Generate a new secret and show it once", "The current secret stops working immediately: update the app right away"]}
        confirmLabel="Rotate secret"
        danger
        askReason={false}
        onConfirm={async () => {
          const r = await unwrap(api.POST("/v1/apps/{id}/secret", { params: { path: { id } } }));
          setSecret(r.client_secret);
          refresh();
        }}
      />
      <ConfirmAction
        open={deleting}
        onOpenChange={setDeleting}
        title={`Delete ${a.name}?`}
        effects={["Nobody can sign in to it through Nexus any more", "Tokens already issued expire within an hour"]}
        confirmLabel="Delete app"
        danger
        typeToConfirm={a.name}
        askReason={false}
        onConfirm={async () => {
          await unwrap(api.DELETE("/v1/apps/{id}", { params: { path: { id } } }));
          qc.invalidateQueries({ queryKey: ["apps"] });
          toast.success("App deleted");
          router.push("/apps");
        }}
      />
      <AssignDialog appId={id} open={assigning} onOpenChange={setAssigning} onDone={refresh} />
    </>
  );
}

function AssignDialog({ appId, open, onOpenChange, onDone }: { appId: string; open: boolean; onOpenChange: (v: boolean) => void; onDone: () => void }) {
  const [q, setQ] = useState("");
  const [picked, setPicked] = useState<Map<string, { type: "user" | "group"; id: string }>>(new Map());
  const groups = useQuery({ queryKey: ["groups", q, "assign"], queryFn: () => unwrap(api.GET("/v1/groups", { params: { query: { q: q || undefined, limit: 20 } } })), enabled: open });
  const users = useQuery({ queryKey: ["users", { q, assign: true }], queryFn: () => unwrap(api.GET("/v1/users", { params: { query: { q: q || undefined, limit: 20, status: "active" } } })), enabled: open });
  const save = useMutation({
    mutationFn: () => unwrap(api.POST("/v1/apps/{id}/assignments", { params: { path: { id: appId } }, body: { principals: [...picked.values()] } })),
    onSuccess: () => {
      onDone();
      toast.success("Access granted");
      setPicked(new Map());
      onOpenChange(false);
    },
  });
  const toggle = (type: "user" | "group", id: string) => {
    const next = new Map(picked);
    if (next.has(id)) next.delete(id);
    else next.set(id, { type, id });
    setPicked(next);
  };
  const row = (type: "user" | "group", id: string, title: string, detail: string) => (
    <li key={id}>
      <label className="flex cursor-pointer items-center gap-3 px-3 py-2 text-[13px] hover:bg-bg-subtle">
        <input type="checkbox" checked={picked.has(id)} onChange={() => toggle(type, id)} />
        {type === "group" ? <UsersRound className="size-4 text-fg-muted" /> : <Avatar name={title} size={22} />}
        <span className="min-w-0 flex-1 truncate">
          {title} <span className="text-fg-subtle">{detail}</span>
        </span>
      </label>
    </li>
  );
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent title="Give access" description="Pick groups (recommended) or individual people.">
        <Input autoFocus placeholder="Search groups and people" value={q} onChange={(e) => setQ(e.target.value)} />
        <div className="mt-3 max-h-80 overflow-y-auto rounded-md border border-border">
          {groups.data?.data.length ? (
            <>
              <p className="bg-bg-subtle px-3 py-1 text-[11px] font-medium uppercase tracking-wide text-fg-subtle">Groups</p>
              <ul>{groups.data.data.map((g) => row("group", g.id, g.name, `${g.member_count} members`))}</ul>
            </>
          ) : null}
          {users.data?.data.length ? (
            <>
              <p className="bg-bg-subtle px-3 py-1 text-[11px] font-medium uppercase tracking-wide text-fg-subtle">People</p>
              <ul>{users.data.data.map((u) => row("user", u.id, u.display_name, u.email))}</ul>
            </>
          ) : null}
        </div>
        <div className="mt-4 flex justify-end gap-2">
          <Button onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button variant="primary" disabled={!picked.size} loading={save.isPending} onClick={() => save.mutate()}>
            Give access{picked.size ? ` (${picked.size})` : ""}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}

export default function AppPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  return (
    <Suspense>
      <AppDetail id={id} />
    </Suspense>
  );
}
