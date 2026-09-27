"use client";

import type { Schemas } from "@nexus/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Bot, Plus } from "lucide-react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useState } from "react";
import { toast } from "sonner";
import { AgentStatus, RISK_TONE } from "@/components/features/agent-bits";
import { Button } from "@/components/ui/button";
import { Field, Input, Select } from "@/components/ui/input";
import { Card, EmptyState, ErrorBanner, PageHeader, Skeleton, StatusPill } from "@/components/ui/misc";
import { Dialog, DialogContent } from "@/components/ui/overlay";
import { Table, TD, TH, THead, TR } from "@/components/ui/table";
import { api, fieldErrors, unwrap } from "@/lib/api";
import { useCan, useMe } from "@/lib/queries";
import { timeAgo } from "@/lib/utils";

type Agent = Schemas["Agent"];

function AgentsView() {
  const params = useSearchParams();
  const router = useRouter();
  const can = useCan();
  const status = params.get("status") as "active" | "suspended" | null;
  const [q, setQ] = useState("");
  const [registering, setRegistering] = useState(false);
  const list = useQuery({ queryKey: ["agents", { status, q }], queryFn: () => unwrap(api.GET("/v1/agents", { params: { query: { status: status ?? undefined, q: q || undefined } } })) });

  return (
    <>
      <PageHeader
        title="Agents"
        description="AI agents are identities too: each has an owner, its own credentials and short-lived tokens for the MCP gateway, and a kill switch."
        actions={
          can("agents:manage") ? (
            <Button variant="primary" onClick={() => setRegistering(true)}>
              <Plus /> Register agent
            </Button>
          ) : null
        }
      />
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <Input placeholder="Search by name or tag" className="w-64" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search agents" />
        <Select aria-label="Status" value={status ?? ""} onChange={(e) => router.replace(e.target.value ? `/agents?status=${e.target.value}` : "/agents")}>
          <option value="">All</option>
          <option value="active">Active</option>
          <option value="suspended">Suspended</option>
        </Select>
      </div>
      <Card className="overflow-hidden">
        {list.isPending ? (
          <div className="space-y-2 p-4">
            <Skeleton className="h-9" />
            <Skeleton className="h-9" />
          </div>
        ) : !list.data?.data.length ? (
          <EmptyState
            icon={<Bot />}
            title={q || status ? "No agents match" : "No agents yet"}
            description="Register each agent that calls tools for your company: support bots, coding agents, n8n or LangGraph workflows. They get tokens from Nexus instead of shared API keys."
            action={can("agents:manage") && !q && !status ? <Button onClick={() => setRegistering(true)}>Register an agent</Button> : undefined}
          />
        ) : (
          <Table>
            <THead>
              <tr>
                <TH>Agent</TH>
                <TH>Owner</TH>
                <TH>Risk</TH>
                <TH>Status</TH>
                <TH className="text-right">Last seen</TH>
              </tr>
            </THead>
            <tbody>
              {list.data.data.map((a) => (
                <TR key={a.id} className="cursor-pointer" onClick={() => router.push(`/agents/${a.id}`)}>
                  <TD>
                    <Link href={`/agents/${a.id}`} className="font-medium" onClick={(e) => e.stopPropagation()}>
                      {a.name}
                    </Link>
                    <p className="text-xs text-fg-muted">
                      <span className="capitalize">{a.environment}</span>
                      {a.runtime ? ` · ${a.runtime}` : ""}
                      {a.model ? ` · ${a.model}` : ""}
                      {a.tags.length ? ` · ${a.tags.map((t) => `#${t}`).join(" ")}` : ""}
                    </p>
                  </TD>
                  <TD className="text-fg-muted">{a.owner ? a.owner.name : <span className="text-warning">No owner</span>}</TD>
                  <TD>
                    <StatusPill tone={RISK_TONE[a.risk_tier]} dot={false}>
                      <span className="capitalize">{a.risk_tier}</span>
                    </StatusPill>
                  </TD>
                  <TD>
                    <AgentStatus a={a} />
                  </TD>
                  <TD className="text-right text-fg-muted">{a.last_seen_at ? timeAgo(a.last_seen_at) : "Never"}</TD>
                </TR>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
      {registering ? <RegisterDialog onClose={() => setRegistering(false)} /> : null}
    </>
  );
}

function RegisterDialog({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient();
  const router = useRouter();
  const me = useMe();
  const users = useQuery({ queryKey: ["users", "all-for-picker"], queryFn: () => unwrap(api.GET("/v1/users", { params: { query: { limit: 200 } } })) });
  const [f, setF] = useState({ name: "", description: "", owner: "", environment: "production" as Agent["environment"], runtime: "", model: "", risk_tier: "medium" as Agent["risk_tier"], tags: "" });
  const owner = f.owner || me.data?.user.id || "";
  const register = useMutation({
    mutationFn: () =>
      unwrap(
        api.POST("/v1/agents", {
          body: {
            name: f.name.trim(),
            description: f.description,
            owner_user_id: owner,
            environment: f.environment,
            runtime: f.runtime,
            model: f.model,
            risk_tier: f.risk_tier,
            tags: f.tags
              .split(/[\s,]+/)
              .map((t) => t.replace(/^#/, "").toLowerCase())
              .filter(Boolean),
          },
        }),
      ),
    onSuccess: (a) => {
      qc.invalidateQueries({ queryKey: ["agents"] });
      toast.success(`${a.name} registered. Add a credential so it can get tokens.`);
      router.push(`/agents/${a.id}`);
    },
  });
  const errors = fieldErrors(register.error);
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent title="Register an agent" description="Every agent has one accountable owner. If they leave, the agent is suspended until someone takes it over." className="max-w-lg">
        <form
          className="space-y-3"
          onSubmit={(e) => {
            e.preventDefault();
            register.mutate();
          }}
        >
          {!Object.keys(errors).length ? <ErrorBanner error={register.error} /> : null}
          <Field label="Name" htmlFor="a-name" error={errors.name}>
            <Input id="a-name" autoFocus required maxLength={100} value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} placeholder="Support triage bot" />
          </Field>
          <Field label="What it does" htmlFor="a-desc">
            <Input id="a-desc" maxLength={1000} value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} placeholder="Labels and answers new support tickets" />
          </Field>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Owner" htmlFor="a-owner">
              <Select id="a-owner" className="w-full" value={owner} onChange={(e) => setF({ ...f, owner: e.target.value })}>
                {(users.data?.data ?? [])
                  .filter((u) => u.status === "active")
                  .map((u) => (
                    <option key={u.id} value={u.id}>
                      {u.display_name}
                    </option>
                  ))}
              </Select>
            </Field>
            <Field label="Environment" htmlFor="a-env">
              <Select id="a-env" className="w-full" value={f.environment} onChange={(e) => setF({ ...f, environment: e.target.value as Agent["environment"] })}>
                <option value="production">Production</option>
                <option value="staging">Staging</option>
                <option value="development">Development</option>
              </Select>
            </Field>
            <Field label="Runtime" htmlFor="a-runtime">
              <Input id="a-runtime" maxLength={100} value={f.runtime} onChange={(e) => setF({ ...f, runtime: e.target.value })} placeholder="Claude Agent SDK" />
            </Field>
            <Field label="Model" htmlFor="a-model">
              <Input id="a-model" maxLength={100} value={f.model} onChange={(e) => setF({ ...f, model: e.target.value })} placeholder="claude-sonnet-5" />
            </Field>
            <Field label="Risk tier" htmlFor="a-risk">
              <Select id="a-risk" className="w-full" value={f.risk_tier} onChange={(e) => setF({ ...f, risk_tier: e.target.value as Agent["risk_tier"] })}>
                <option value="low">Low: read-only, internal data</option>
                <option value="medium">Medium</option>
                <option value="high">High: changes things</option>
                <option value="critical">Critical: money, prod, customer data</option>
              </Select>
            </Field>
            <Field label="Tags" htmlFor="a-tags" hint="Tool permissions can target tags" error={errors.tags}>
              <Input id="a-tags" value={f.tags} onChange={(e) => setF({ ...f, tags: e.target.value })} placeholder="support, tier1" />
            </Field>
          </div>
          <div className="flex justify-end gap-2 border-t border-border pt-4">
            <Button type="button" variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" variant="primary" loading={register.isPending} disabled={!f.name.trim() || !owner}>
              Register agent
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

export default function AgentsPage() {
  return (
    <Suspense>
      <AgentsView />
    </Suspense>
  );
}
