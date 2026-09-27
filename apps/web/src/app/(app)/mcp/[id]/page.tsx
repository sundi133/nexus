"use client";

import type { Schemas } from "@nexus/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, ChevronLeft, ChevronRight, Ban, Plus, RefreshCw, Trash2, X } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { use, useState } from "react";
import { toast } from "sonner";
import { MCP_RISK_TONE } from "@/components/features/agent-bits";
import { ConfirmAction } from "@/components/features/confirm-action";
import { Button } from "@/components/ui/button";
import { CopyField } from "@/components/ui/copy";
import { Field, Input, Select } from "@/components/ui/input";
import { Card, CardHeader, EmptyState, ErrorBanner, Skeleton, StatusPill } from "@/components/ui/misc";
import { Dialog, DialogContent, Tabs, TabsContent, TabsList } from "@/components/ui/overlay";
import { api, unwrap } from "@/lib/api";
import { useCan } from "@/lib/queries";
import { cn, timeAgo, toggled } from "@/lib/utils";

type Tool = Schemas["McpTool"];
type Permission = Schemas["McpPermission"];
type Risk = Tool["risk"];
const RISKS: Risk[] = ["read", "write", "external", "destructive"];
const RISK_HELP: Record<Risk, string> = { read: "Reads data", write: "Changes data", external: "Reaches outside (email, web, messages)", destructive: "Deletes or can't be undone" };

export default function McpServerPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const qc = useQueryClient();
  const router = useRouter();
  const can = useCan();
  const manage = can("mcp:manage");
  const [deleting, setDeleting] = useState(false);
  const data = useQuery({ queryKey: ["mcp-server", id], queryFn: () => unwrap(api.GET("/v1/mcp/servers/{id}", { params: { path: { id } } })) });
  const refresh = () => {
    qc.invalidateQueries({ queryKey: ["mcp-server", id] });
    qc.invalidateQueries({ queryKey: ["mcp-servers"] });
  };
  const sync = useMutation({
    mutationFn: () => unwrap(api.POST("/v1/mcp/servers/{id}/sync", { params: { path: { id } } })),
    onSuccess: (r) => {
      refresh();
      if (!r.ok) toast.error(r.error);
      else if (r.added.length || r.changed.length || r.removed.length) toast.success(`${r.added.length} new, ${r.changed.length} changed, ${r.removed.length} removed`);
      else toast.success("No changes");
    },
  });
  const setStatus = useMutation({
    mutationFn: (status: "active" | "disabled") => unwrap(api.PATCH("/v1/mcp/servers/{id}", { params: { path: { id } }, body: { status } })),
    onSuccess: (s) => (refresh(), toast.success(s.status === "active" ? "Enabled" : "Disabled: agents can't reach it")),
  });

  if (data.isPending) return <Skeleton className="h-60" />;
  if (!data.data) return <ErrorBanner error={data.error} />;
  const { server: s, tools, permissions } = data.data;
  const pending = tools.filter((t) => t.status === "pending");

  return (
    <>
      <Link href="/mcp" className="mb-3 inline-flex items-center gap-1 text-[13px] text-fg-muted hover:text-fg">
        <ChevronLeft className="size-4" /> MCP servers
      </Link>
      <div className="mb-4 flex flex-wrap items-start gap-3">
        <div className="min-w-0 flex-1">
          <h1 className="flex flex-wrap items-center gap-2 text-xl font-semibold tracking-tight">
            {s.name} {s.status === "disabled" ? <StatusPill>Disabled</StatusPill> : s.last_sync_error ? <StatusPill tone="danger">Unreachable</StatusPill> : <StatusPill tone="success">Active</StatusPill>}
          </h1>
          <p className="mt-0.5 font-mono text-xs text-fg-muted">{s.url}</p>
          <p className="mt-0.5 text-[13px] text-fg-muted">
            {s.tools.usable} of {s.tools.total} tools in use · {s.calls_per_minute} calls a minute per agent · checked {s.last_synced_at ? timeAgo(s.last_synced_at) : "never"}
          </p>
        </div>
        {manage ? (
          <div className="flex flex-wrap gap-2">
            <Button variant="danger-outline" onClick={() => setDeleting(true)}>
              <Trash2 /> Remove
            </Button>
            <Button loading={setStatus.isPending} onClick={() => setStatus.mutate(s.status === "active" ? "disabled" : "active")}>
              {s.status === "active" ? "Disable" : "Enable"}
            </Button>
            <Button loading={sync.isPending} onClick={() => sync.mutate()}>
              <RefreshCw /> Check tools
            </Button>
          </div>
        ) : null}
      </div>
      {s.last_sync_error ? (
        <div className="mb-4 rounded-md border border-danger/30 bg-danger-soft px-3 py-2 text-[13px] text-danger">Nexus couldn't read the tools: {s.last_sync_error}</div>
      ) : null}
      <Card className="mb-4 p-4">
        <CopyField label="Agents connect to" value={s.endpoint} />
        <p className="mt-2 text-xs text-fg-muted">Streamable HTTP. Agents send a Nexus token (client credentials, audience this URL or the gateway). Tools they're not allowed to use don't appear.</p>
      </Card>

      <Tabs defaultValue={pending.length ? "tools" : permissions.length ? "tools" : "permissions"}>
        <TabsList
          tabs={[
            { value: "tools", label: <>Tools{pending.length ? <span className="ml-1.5"><StatusPill tone="warning">{pending.length}</StatusPill></span> : null}</> },
            { value: "permissions", label: `Permissions (${permissions.length})` },
            { value: "try", label: "Try a call" },
          ]}
        />
        <TabsContent value="tools">
          <ToolsTab serverId={id} tools={tools} manage={manage} onChanged={refresh} />
        </TabsContent>
        <TabsContent value="permissions">
          <PermissionsTab serverId={id} tools={tools} permissions={permissions} manage={manage} onChanged={refresh} />
        </TabsContent>
        <TabsContent value="try">
          <TryTab serverId={id} tools={tools} />
        </TabsContent>
      </Tabs>

      <ConfirmAction
        open={deleting}
        onOpenChange={setDeleting}
        title={`Remove ${s.name}?`}
        effects={["Agents can no longer reach it through Nexus", "Its tool approvals and permissions are deleted", "The audit trail stays"]}
        confirmLabel="Remove server"
        danger
        askReason={false}
        onConfirm={async () => {
          await unwrap(api.DELETE("/v1/mcp/servers/{id}", { params: { path: { id } } }));
          qc.invalidateQueries({ queryKey: ["mcp-servers"] });
          toast.success("Server removed");
          router.push("/mcp");
        }}
      />
    </>
  );
}

// ---- Tools ----

function ToolsTab({ serverId, tools, manage, onChanged }: { serverId: string; tools: Tool[]; manage: boolean; onChanged: () => void }) {
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [open, setOpen] = useState<string | null>(null);
  const shown = tools.filter((t) => t.status !== "removed");
  const review = useMutation({
    mutationFn: (decision: "approve" | "block") => unwrap(api.POST("/v1/mcp/servers/{id}/tools/review", { params: { path: { id: serverId } }, body: { names: [...selected], decision } })),
    onSuccess: (_, decision) => (onChanged(), toast.success(`${selected.size} tool${selected.size === 1 ? "" : "s"} ${decision === "approve" ? "approved" : "blocked"}`), setSelected(new Set())),
  });
  const setRisk = useMutation({
    mutationFn: (v: { toolId: string; risk: Risk }) => unwrap(api.PATCH("/v1/mcp/servers/{id}/tools/{toolId}", { params: { path: { id: serverId, toolId: v.toolId } }, body: { risk: v.risk } })),
    onSuccess: () => (onChanged(), toast.success("Risk class set")),
  });
  const toggle = (n: string) => setSelected((s) => toggled(s, n));
  if (!shown.length) return <Card><EmptyState title="No tools" description="The server didn't report any tools. Check the URL and credential, then check again." /></Card>;
  return (
    <>
      {manage ? (
        <div className="mb-3 flex flex-wrap items-center gap-2 text-[13px]">
          <label className="flex items-center gap-2">
            <input type="checkbox" checked={selected.size === shown.length} onChange={(e) => setSelected(e.target.checked ? new Set(shown.map((t) => t.name)) : new Set())} /> Select all
          </label>
          <Button size="sm" variant="secondary" disabled={!shown.some((t) => t.status === "pending")} onClick={() => setSelected(new Set(shown.filter((t) => t.status === "pending").map((t) => t.name)))}>
            Select to review
          </Button>
          {selected.size ? (
            <>
              <Button size="sm" variant="primary" loading={review.isPending} onClick={() => review.mutate("approve")}>
                <Check /> Approve {selected.size}
              </Button>
              <Button size="sm" variant="danger-outline" loading={review.isPending} onClick={() => review.mutate("block")}>
                <Ban /> Block {selected.size}
              </Button>
            </>
          ) : null}
        </div>
      ) : null}
      <ErrorBanner error={review.error ?? setRisk.error} />
      <Card className="overflow-hidden">
        <ul className="divide-y divide-border">
          {shown.map((t) => (
            <li key={t.id} className={cn(selected.has(t.name) && "bg-primary-soft/30")}>
              <div className="flex flex-wrap items-center gap-3 px-4 py-2.5 text-[13px]">
                {manage ? <input type="checkbox" checked={selected.has(t.name)} onChange={() => toggle(t.name)} aria-label={`Select ${t.name}`} /> : null}
                <button onClick={() => setOpen(open === t.id ? null : t.id)} className="flex min-w-0 flex-1 items-center gap-2 text-left" aria-expanded={open === t.id}>
                  <ChevronRight className={cn("size-3.5 shrink-0 text-fg-subtle transition-transform", open === t.id && "rotate-90")} />
                  <span className="min-w-0">
                    <span className="font-mono font-medium">{t.name}</span>
                    {t.change === "changed" ? <span className="ml-2"><StatusPill tone="danger">Changed</StatusPill></span> : t.change === "new" ? <span className="ml-2"><StatusPill tone="primary">New</StatusPill></span> : null}
                    <span className="block truncate text-xs text-fg-muted">{t.description}</span>
                  </span>
                </button>
                {manage ? (
                  <Select aria-label={`Risk of ${t.name}`} value={t.risk} onChange={(e) => setRisk.mutate({ toolId: t.id, risk: e.target.value as Risk })} title={t.risk_source === "admin" ? "Set by an admin" : t.risk_source === "annotations" ? "From the server's annotations" : "Guessed from the name"}>
                    {RISKS.map((r) => (
                      <option key={r} value={r}>
                        {r}
                      </option>
                    ))}
                  </Select>
                ) : (
                  <StatusPill tone={MCP_RISK_TONE[t.risk]} dot={false}>{t.risk}</StatusPill>
                )}
                <span className="w-24 text-right">
                  {t.usable ? <StatusPill tone="success">Approved</StatusPill> : t.status === "blocked" ? <StatusPill tone="danger">Blocked</StatusPill> : <StatusPill tone="warning">To review</StatusPill>}
                </span>
              </div>
              {open === t.id ? <ToolDetail t={t} /> : null}
            </li>
          ))}
        </ul>
      </Card>
      <p className="mt-2 text-xs text-fg-subtle">Risk: {RISKS.map((r) => `${r} = ${RISK_HELP[r].toLowerCase()}`).join(" · ")}. Approval covers the description too: tool descriptions are read by the model, so a changed one needs a fresh look.</p>
    </>
  );
}

function ToolDetail({ t }: { t: Tool }) {
  const pre = "overflow-x-auto whitespace-pre-wrap rounded-md border border-border bg-bg-subtle p-3 font-mono text-xs leading-relaxed";
  if (t.approved) {
    return (
      <div className="grid gap-3 px-4 pb-4 md:grid-cols-2">
        <div>
          <p className="mb-1 text-xs font-medium text-fg-muted">Approved</p>
          <pre className={pre}>{`${t.approved.description}\n\n${JSON.stringify(t.approved.input_schema, null, 2)}`}</pre>
        </div>
        <div>
          <p className="mb-1 text-xs font-medium text-danger">Now</p>
          <pre className={cn(pre, "border-danger/40")}>{`${t.description}\n\n${JSON.stringify(t.input_schema, null, 2)}`}</pre>
        </div>
      </div>
    );
  }
  return (
    <div className="px-4 pb-4">
      <pre className={pre}>{`${t.description}\n\n${JSON.stringify(t.input_schema, null, 2)}${Object.keys(t.annotations).length ? `\n\nAnnotations: ${JSON.stringify(t.annotations)}` : ""}`}</pre>
    </div>
  );
}

// ---- Permissions ----

function describeRule(p: Permission) {
  const tools = p.tools.includes("*") ? "every approved tool" : p.tools.join(", ");
  const risks = p.risks ? ` (${p.risks.join(" or ")} only)` : "";
  const cond = p.conditions.length ? ` when ${p.conditions.map((c) => `${c.argument} ${c.op === "in" ? "is one of" : c.op === "not_in" ? "is not one of" : c.op === "prefix" ? "starts with" : "is"} ${c.values.join(", ")}`).join(" and ")}` : "";
  return `${tools}${risks}${cond}`;
}

function PermissionsTab({ serverId, tools, permissions, manage, onChanged }: { serverId: string; tools: Tool[]; permissions: Permission[]; manage: boolean; onChanged: () => void }) {
  const [adding, setAdding] = useState(false);
  const remove = useMutation({
    mutationFn: (permissionId: string) => unwrap(api.DELETE("/v1/mcp/servers/{id}/permissions/{permissionId}", { params: { path: { id: serverId, permissionId } } })),
    onSuccess: () => (onChanged(), toast.success("Rule removed")),
  });
  return (
    <>
      <div className="mb-3 flex items-center gap-2">
        <p className="flex-1 text-[13px] text-fg-muted">Deny by default. An agent can call a tool when an allow rule matches and no deny rule does.</p>
        {manage ? (
          <Button size="sm" variant="primary" onClick={() => setAdding(true)}>
            <Plus /> Add rule
          </Button>
        ) : null}
      </div>
      <Card className="overflow-hidden">
        {permissions.length ? (
          <ul className="divide-y divide-border">
            {permissions.map((p) => (
              <li key={p.id} className="flex flex-wrap items-center gap-3 px-4 py-3 text-[13px]">
                <StatusPill tone={p.effect === "allow" ? "success" : "danger"}>{p.effect === "allow" ? "Allow" : "Deny"}</StatusPill>
                <div className="min-w-0 flex-1">
                  <p>
                    <span className="font-medium">{p.subject.name}</span> <span className="text-fg-muted">{p.effect === "allow" ? "can use" : "can't use"}</span> {describeRule(p)}
                  </p>
                  {p.description ? <p className="text-xs text-fg-muted">{p.description}</p> : null}
                </div>
                {manage ? (
                  <Button size="sm" variant="ghost" aria-label="Remove rule" onClick={() => remove.mutate(p.id)}>
                    <X />
                  </Button>
                ) : null}
              </li>
            ))}
          </ul>
        ) : (
          <EmptyState title="No rules yet" description="No agent can call these tools until you allow it." />
        )}
      </Card>
      {adding ? <RuleDialog serverId={serverId} tools={tools} onClose={() => setAdding(false)} onSaved={onChanged} /> : null}
    </>
  );
}

type Cond = { argument: string; op: "equals" | "in" | "not_in" | "prefix"; values: string };

function RuleDialog({ serverId, tools, onClose, onSaved }: { serverId: string; tools: Tool[]; onClose: () => void; onSaved: () => void }) {
  const agents = useQuery({ queryKey: ["agents", {}], queryFn: () => unwrap(api.GET("/v1/agents")) });
  const [effect, setEffect] = useState<"allow" | "deny">("allow");
  const [subject, setSubject] = useState<"all_agents" | "agent" | "agent_tag">("agent");
  const [agentId, setAgentId] = useState("");
  const [tag, setTag] = useState("");
  const [allTools, setAllTools] = useState(true);
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [risks, setRisks] = useState<Set<Risk>>(new Set(["read"]));
  const [anyRisk, setAnyRisk] = useState(false);
  const [conds, setConds] = useState<Cond[]>([]);
  const [description, setDescription] = useState("");
  const usable = tools.filter((t) => t.status !== "removed");
  const save = useMutation({
    mutationFn: () =>
      unwrap(
        api.POST("/v1/mcp/servers/{id}/permissions", {
          params: { path: { id: serverId } },
          body: {
            effect,
            subject: subject === "agent" ? { type: "agent", id: agentId } : subject === "agent_tag" ? { type: "agent_tag", tag } : { type: "all_agents" },
            tools: allTools ? ["*"] : [...picked],
            risks: anyRisk ? null : [...risks],
            conditions: conds.filter((c) => c.argument.trim()).map((c) => ({ argument: c.argument.trim(), op: c.op, values: c.values.split(",").map((v) => v.trim()).filter(Boolean) })),
            description,
          },
        }),
      ),
    onSuccess: () => (onSaved(), toast.success("Rule added"), onClose()),
  });
  const ready = (subject !== "agent" || !!agentId) && (subject !== "agent_tag" || !!tag.trim()) && (allTools || picked.size > 0) && (anyRisk || risks.size > 0) && conds.every((c) => !c.argument.trim() || c.values.trim());
  const tags = [...new Set((agents.data?.data ?? []).flatMap((a) => a.tags))];
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent title="Add a tool permission" className="max-w-2xl">
        <div className="space-y-4 text-[13px]">
          <div className="flex flex-wrap items-center gap-2">
            <Select aria-label="Effect" value={effect} onChange={(e) => setEffect(e.target.value as typeof effect)}>
              <option value="allow">Allow</option>
              <option value="deny">Deny</option>
            </Select>
            <Select aria-label="Who" value={subject} onChange={(e) => setSubject(e.target.value as typeof subject)}>
              <option value="agent">the agent</option>
              <option value="agent_tag">agents tagged</option>
              <option value="all_agents">every agent</option>
            </Select>
            {subject === "agent" ? (
              <Select aria-label="Agent" value={agentId} onChange={(e) => setAgentId(e.target.value)}>
                <option value="">Choose…</option>
                {(agents.data?.data ?? []).map((a) => (
                  <option key={a.id} value={a.id}>
                    {a.name}
                  </option>
                ))}
              </Select>
            ) : subject === "agent_tag" ? (
              <>
                <Input aria-label="Tag" className="w-40" list="agent-tags" value={tag} onChange={(e) => setTag(e.target.value.toLowerCase())} placeholder="support" />
                <datalist id="agent-tags">
                  {tags.map((t) => (
                    <option key={t} value={t} />
                  ))}
                </datalist>
              </>
            ) : null}
          </div>
          <fieldset>
            <legend className="mb-1.5 font-medium">Tools</legend>
            <label className="mr-4 inline-flex items-center gap-2">
              <input type="radio" checked={allTools} onChange={() => setAllTools(true)} /> Every approved tool
            </label>
            <label className="inline-flex items-center gap-2">
              <input type="radio" checked={!allTools} onChange={() => setAllTools(false)} /> These tools
            </label>
            {!allTools ? (
              <div className="mt-2 grid max-h-40 grid-cols-2 gap-1 overflow-y-auto rounded-md border border-border p-2">
                {usable.map((t) => (
                  <label key={t.id} className="flex items-center gap-2 font-mono text-xs">
                    <input type="checkbox" checked={picked.has(t.name)} onChange={() => setPicked((s) => toggled(s, t.name))} />
                    {t.name}
                    <StatusPill tone={MCP_RISK_TONE[t.risk]} dot={false}>{t.risk}</StatusPill>
                  </label>
                ))}
              </div>
            ) : null}
          </fieldset>
          <fieldset>
            <legend className="mb-1.5 font-medium">Risk classes</legend>
            <div className="flex flex-wrap gap-3">
              <label className="inline-flex items-center gap-2">
                <input type="checkbox" checked={anyRisk} onChange={(e) => setAnyRisk(e.target.checked)} /> Any
              </label>
              {RISKS.map((r) => (
                <label key={r} className={cn("inline-flex items-center gap-2", anyRisk && "opacity-50")} title={RISK_HELP[r]}>
                  <input type="checkbox" disabled={anyRisk} checked={risks.has(r)} onChange={() => setRisks((s) => toggled(s, r))} /> {r}
                </label>
              ))}
            </div>
          </fieldset>
          <fieldset>
            <legend className="mb-1.5 font-medium">Only when the arguments match (optional)</legend>
            <div className="space-y-2">
              {conds.map((c, i) => (
                <div key={i} className="flex flex-wrap items-center gap-2">
                  <Input aria-label="Argument" className="w-36 font-mono" value={c.argument} onChange={(e) => setConds(conds.map((x, j) => (j === i ? { ...x, argument: e.target.value } : x)))} placeholder="repo" />
                  <Select aria-label="Operator" value={c.op} onChange={(e) => setConds(conds.map((x, j) => (j === i ? { ...x, op: e.target.value as Cond["op"] } : x)))}>
                    <option value="in">is one of</option>
                    <option value="not_in">is not one of</option>
                    <option value="prefix">starts with</option>
                    <option value="equals">is</option>
                  </Select>
                  <Input aria-label="Values" className="min-w-40 flex-1" value={c.values} onChange={(e) => setConds(conds.map((x, j) => (j === i ? { ...x, values: e.target.value } : x)))} placeholder="acme/web, acme/api" />
                  <Button size="sm" variant="ghost" aria-label="Remove condition" onClick={() => setConds(conds.filter((_, j) => j !== i))}>
                    <X />
                  </Button>
                </div>
              ))}
              <Button size="sm" onClick={() => setConds([...conds, { argument: "", op: "in", values: "" }])}>
                <Plus /> Add condition
              </Button>
            </div>
          </fieldset>
          <Field label="Why (optional)" htmlFor="r-why">
            <Input id="r-why" value={description} maxLength={500} onChange={(e) => setDescription(e.target.value)} placeholder="Triage bot reads and labels issues in the web repo" />
          </Field>
          <ErrorBanner error={save.error} />
          <div className="flex justify-end gap-2 border-t border-border pt-4">
            <Button variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button variant="primary" disabled={!ready} loading={save.isPending} onClick={() => save.mutate()}>
              Add rule
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

// ---- What-if ----

function TryTab({ serverId, tools }: { serverId: string; tools: Tool[] }) {
  const agents = useQuery({ queryKey: ["agents", {}], queryFn: () => unwrap(api.GET("/v1/agents")) });
  const [agentId, setAgentId] = useState("");
  const [tool, setTool] = useState("");
  const [args, setArgs] = useState("{}");
  let parsed: Record<string, unknown> | null = null;
  try {
    const v = JSON.parse(args);
    parsed = v && typeof v === "object" && !Array.isArray(v) ? v : null;
  } catch {
    parsed = null;
  }
  const sim = useMutation({ mutationFn: () => unwrap(api.POST("/v1/mcp/servers/{id}/simulate", { params: { path: { id: serverId } }, body: { agent_id: agentId, tool, arguments: parsed ?? {} } })) });
  return (
    <Card className="p-4">
      <p className="mb-3 text-[13px] text-fg-muted">Check what the gateway would decide. Nothing is called.</p>
      <div className="grid gap-3 md:grid-cols-2">
        <Field label="Agent" htmlFor="t-agent">
          <Select id="t-agent" className="w-full" value={agentId} onChange={(e) => setAgentId(e.target.value)}>
            <option value="">Choose…</option>
            {(agents.data?.data ?? []).map((a) => (
              <option key={a.id} value={a.id}>
                {a.name}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Tool" htmlFor="t-tool">
          <Select id="t-tool" className="w-full" value={tool} onChange={(e) => setTool(e.target.value)}>
            <option value="">Choose…</option>
            {tools
              .filter((t) => t.status !== "removed")
              .map((t) => (
                <option key={t.id} value={t.name}>
                  {t.name}
                </option>
              ))}
          </Select>
        </Field>
      </div>
      <Field label="Arguments (JSON)" htmlFor="t-args" error={parsed ? undefined : "Enter a JSON object"}>
        <textarea id="t-args" className="h-20 w-full rounded-md border border-border bg-bg px-2.5 py-2 font-mono text-xs" value={args} onChange={(e) => setArgs(e.target.value)} />
      </Field>
      <div className="mt-3 flex items-center gap-3">
        <Button variant="primary" disabled={!agentId || !tool || !parsed} loading={sim.isPending} onClick={() => sim.mutate()}>
          Check
        </Button>
        {sim.data ? (
          <p className="text-[13px]" aria-live="polite">
            {sim.data.allow ? <StatusPill tone="success">Allowed</StatusPill> : <StatusPill tone="danger">Denied</StatusPill>} <span className="ml-1 text-fg-muted">{sim.data.reason}</span>
          </p>
        ) : null}
      </div>
      <ErrorBanner error={sim.error} />
    </Card>
  );
}
