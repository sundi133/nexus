"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, Server } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { toast } from "sonner";
import { useStepUp } from "@/components/step-up";
import { Button } from "@/components/ui/button";
import { Field, Input, Select } from "@/components/ui/input";
import { Card, EmptyState, ErrorBanner, PageHeader, Skeleton, StatusPill } from "@/components/ui/misc";
import { Dialog, DialogContent } from "@/components/ui/overlay";
import { Table, TD, TH, THead, TR } from "@/components/ui/table";
import { api, fieldErrors, unwrap } from "@/lib/api";
import { useCan } from "@/lib/queries";
import { timeAgo } from "@/lib/utils";

export default function McpServersPage() {
  const router = useRouter();
  const can = useCan();
  const [adding, setAdding] = useState(false);
  const list = useQuery({ queryKey: ["mcp-servers"], queryFn: () => unwrap(api.GET("/v1/mcp/servers")) });
  return (
    <>
      <PageHeader
        title="MCP servers"
        description="Agents reach tools through the Nexus gateway: only approved tools, only for permitted agents, every call recorded. Upstream credentials stay in Nexus."
        actions={
          can("mcp:manage") ? (
            <Button variant="primary" onClick={() => setAdding(true)}>
              <Plus /> Add server
            </Button>
          ) : null
        }
      />
      <Card className="overflow-hidden">
        {list.isPending ? (
          <div className="space-y-2 p-4">
            <Skeleton className="h-9" />
          </div>
        ) : !list.data?.data.length ? (
          <EmptyState icon={<Server />} title="No MCP servers yet" description="Add the MCP servers your agents use (GitHub, Jira, Linear, internal tools). Nexus discovers their tools for you to approve." action={can("mcp:manage") ? <Button onClick={() => setAdding(true)}>Add a server</Button> : undefined} />
        ) : (
          <Table>
            <THead>
              <tr>
                <TH>Server</TH>
                <TH>Tools</TH>
                <TH>Status</TH>
                <TH className="text-right">Checked</TH>
              </tr>
            </THead>
            <tbody>
              {list.data.data.map((s) => (
                <TR key={s.id} className="cursor-pointer" onClick={() => router.push(`/mcp/${s.id}`)}>
                  <TD>
                    <Link href={`/mcp/${s.id}`} className="font-medium" onClick={(e) => e.stopPropagation()}>
                      {s.name}
                    </Link>
                    <p className="truncate font-mono text-xs text-fg-muted">{s.url}</p>
                  </TD>
                  <TD>
                    <span className="tabular">{s.tools.usable}</span> <span className="text-fg-muted">of {s.tools.total} in use</span>
                    {s.tools.pending ? (
                      <span className="ml-2">
                        <StatusPill tone="warning">{s.tools.pending} to review</StatusPill>
                      </span>
                    ) : null}
                  </TD>
                  <TD>{s.status === "disabled" ? <StatusPill>Disabled</StatusPill> : s.last_sync_error ? <StatusPill tone="danger">Unreachable</StatusPill> : <StatusPill tone="success">Active</StatusPill>}</TD>
                  <TD className="text-right text-fg-muted">{s.last_synced_at ? timeAgo(s.last_synced_at) : "Never"}</TD>
                </TR>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
      {adding ? <AddServerDialog onClose={() => setAdding(false)} /> : null}
    </>
  );
}

function AddServerDialog({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient();
  const router = useRouter();
  const withStepUp = useStepUp();
  const [f, setF] = useState({ name: "", slug: "", url: "", description: "", authKind: "bearer" as "none" | "bearer" | "header", header: "X-API-Key", secret: "", autoRead: false, perMinute: 120 });
  const [slugTouched, setSlugTouched] = useState(false);
  const slug = slugTouched ? f.slug : f.name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 40);
  const add = useMutation({
    mutationFn: () =>
      withStepUp(() =>
        unwrap(
          api.POST("/v1/mcp/servers", {
            body: {
              name: f.name.trim(),
              slug,
              url: f.url.trim(),
              description: f.description,
              auth: f.authKind === "none" ? { kind: "none" } : f.authKind === "bearer" ? { kind: "bearer", token: f.secret } : { kind: "header", header: f.header, value: f.secret },
              auto_approve_read: f.autoRead,
              calls_per_minute: f.perMinute,
            },
          }),
        ),
      ),
    onSuccess: (r) => {
      qc.invalidateQueries({ queryKey: ["mcp-servers"] });
      if (r.server.last_sync_error) toast.error(`Added, but Nexus couldn't read its tools: ${r.server.last_sync_error}`);
      else toast.success(`${r.server.name}: found ${r.server.tools.total} tools to review`);
      router.push(`/mcp/${r.server.id}`);
    },
  });
  const errors = fieldErrors(add.error);
  const ready = !!f.name.trim() && !!slug && !!f.url.trim() && (f.authKind === "none" || !!f.secret);
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent title="Add an MCP server" description="Streamable HTTP. Nexus connects with the credential you give it; agents never see it." className="max-w-lg">
        <div className="space-y-3">
          {!Object.keys(errors).length ? <ErrorBanner error={add.error} /> : null}
          <div className="grid grid-cols-2 gap-3">
            <Field label="Name" htmlFor="s-name" error={errors.name}>
              <Input id="s-name" autoFocus value={f.name} maxLength={100} onChange={(e) => setF({ ...f, name: e.target.value })} placeholder="GitHub" />
            </Field>
            <Field label="Short name" htmlFor="s-slug" hint="In the gateway URL" error={errors.slug}>
              <Input
                id="s-slug"
                value={slug}
                maxLength={40}
                onChange={(e) => {
                  setSlugTouched(true);
                  setF({ ...f, slug: e.target.value.toLowerCase() });
                }}
                placeholder="github"
              />
            </Field>
          </div>
          <Field label="Server URL" htmlFor="s-url" error={errors.url}>
            <Input id="s-url" value={f.url} onChange={(e) => setF({ ...f, url: e.target.value })} placeholder="https://api.githubcopilot.com/mcp/" />
          </Field>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Authentication" htmlFor="s-auth">
              <Select id="s-auth" className="w-full" value={f.authKind} onChange={(e) => setF({ ...f, authKind: e.target.value as typeof f.authKind })}>
                <option value="bearer">Bearer token</option>
                <option value="header">API key header</option>
                <option value="none">None</option>
              </Select>
            </Field>
            {f.authKind === "header" ? (
              <Field label="Header" htmlFor="s-header">
                <Input id="s-header" value={f.header} onChange={(e) => setF({ ...f, header: e.target.value })} />
              </Field>
            ) : null}
          </div>
          {f.authKind !== "none" ? (
            <Field label={f.authKind === "bearer" ? "Token" : "Key"} htmlFor="s-secret" hint="Stored encrypted. Use a token scoped to what agents should reach.">
              <Input id="s-secret" type="password" autoComplete="off" value={f.secret} onChange={(e) => setF({ ...f, secret: e.target.value })} />
            </Field>
          ) : null}
          <div className="grid grid-cols-2 gap-3">
            <Field label="Rate limit" htmlFor="s-rate" hint="Calls a minute, per agent">
              <Input id="s-rate" type="number" min={1} max={10000} value={f.perMinute} onChange={(e) => setF({ ...f, perMinute: Number(e.target.value) || 1 })} />
            </Field>
            <label className="mt-6 flex items-start gap-2 text-[13px]">
              <input type="checkbox" checked={f.autoRead} onChange={(e) => setF({ ...f, autoRead: e.target.checked })} className="mt-0.5" />
              <span>Approve new read-only tools automatically</span>
            </label>
          </div>
          <div className="flex justify-end gap-2 border-t border-border pt-4">
            <Button variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button variant="primary" disabled={!ready} loading={add.isPending} onClick={() => add.mutate()}>
              Add and discover tools
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
