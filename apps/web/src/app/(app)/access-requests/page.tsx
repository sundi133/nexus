"use client";

import type { Schemas } from "@nexus/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AppWindow, Clock, KeyRound, Plus, ShieldCheck, Trash2, UsersRound } from "lucide-react";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useState } from "react";
import { toast } from "sonner";
import { useStepUp } from "@/components/step-up";
import { Button } from "@/components/ui/button";
import { Field, Input, Select } from "@/components/ui/input";
import { Card, EmptyState, ErrorBanner, PageHeader, Skeleton, StatusPill, type Tone } from "@/components/ui/misc";
import { Dialog, DialogContent, Tabs, TabsContent, TabsList } from "@/components/ui/overlay";
import { api, unwrap } from "@/lib/api";
import { useCan } from "@/lib/queries";
import { cn, timeAgo } from "@/lib/utils";

type Item = Schemas["AccessCatalogItem"];
type Req = Schemas["AccessRequest"];
type Stage = Schemas["ApprovalStage"];

const ICON = { app: AppWindow, group: UsersRound, role: ShieldCheck } as const;
const STATUS: Record<Req["status"], { label: string; tone: Tone }> = {
  pending: { label: "Waiting for approval", tone: "warning" },
  active: { label: "Active", tone: "success" },
  denied: { label: "Denied", tone: "danger" },
  canceled: { label: "Withdrawn", tone: "neutral" },
  ended: { label: "Ended", tone: "neutral" },
  revoked: { label: "Revoked", tone: "neutral" },
};
const DURATIONS = [1, 2, 4, 8, 24, 72, 168, 720];
const hours = (h: number) => (h < 24 ? `${h} hour${h === 1 ? "" : "s"}` : h < 168 ? `${h / 24} day${h === 24 ? "" : "s"}` : h === 168 ? "1 week" : `${Math.round(h / 24)} days`);
const until = (iso: string) => {
  const ms = new Date(iso).getTime() - Date.now();
  return ms <= 0 ? "ending now" : ms < 3600_000 ? `${Math.ceil(ms / 60_000)} min left` : ms < 86_400_000 ? `${Math.round(ms / 3600_000)} h left` : `${Math.round(ms / 86_400_000)} days left`;
};

export default function AccessRequestsPage() {
  return (
    <Suspense>
      <Page />
    </Suspense>
  );
}

function Page() {
  const can = useCan();
  const params = useSearchParams();
  const router = useRouter();
  const approvals = useQuery({ queryKey: ["access-requests", "approvals"], queryFn: () => unwrap(api.GET("/v1/access/requests", { params: { query: { view: "approvals" } } })), refetchInterval: 30_000 });
  const n = approvals.data?.data.length ?? 0;
  const tabs = [
    { value: "request", label: "Request access" },
    { value: "mine", label: "My requests" },
    { value: "approvals", label: n ? `To approve (${n})` : "To approve" },
    ...(can("access:manage") ? [{ value: "all", label: "All requests" }, { value: "catalog", label: "Catalog" }] : []),
  ];
  const view = params.get("view") ?? "request";
  return (
    <>
      <PageHeader title="Access requests" description="Ask for an app, a group or an admin role for as long as you need it. Approvers decide in stages, and access ends by itself." />
      <Tabs value={tabs.some((t) => t.value === view) ? view : "request"} onValueChange={(v) => router.replace(`/access-requests?view=${v}`)}>
        <TabsList tabs={tabs} />
        <TabsContent value="request">
          <RequestTab />
        </TabsContent>
        <TabsContent value="mine">
          <RequestList view="mine" />
        </TabsContent>
        <TabsContent value="approvals">
          <RequestList view="approvals" />
        </TabsContent>
        <TabsContent value="all">
          <RequestList view="all" />
        </TabsContent>
        <TabsContent value="catalog">
          <CatalogTab />
        </TabsContent>
      </Tabs>
    </>
  );
}

function RequestTab() {
  const catalog = useQuery({ queryKey: ["access-catalog"], queryFn: () => unwrap(api.GET("/v1/access/catalog")) });
  const [asking, setAsking] = useState<Item | null>(null);
  if (catalog.isPending) return <Skeleton className="h-40" />;
  if (!catalog.data?.data.length) return <Card><EmptyState icon={<KeyRound />} title="Nothing is requestable yet" description="Admins choose which apps, groups and roles can be requested, in the Catalog tab." /></Card>;
  return (
    <div className="grid gap-3 md:grid-cols-2">
      {catalog.data.data.map((c) => {
        const Icon = ICON[c.resource_type];
        return (
          <Card key={c.id} className="flex items-start gap-3 p-4">
            <div className="rounded-md bg-bg-muted p-2 text-fg-muted">
              <Icon className="size-4" />
            </div>
            <div className="min-w-0 flex-1">
              <p className="text-[13px] font-semibold capitalize">{c.name}</p>
              <p className="text-xs text-fg-muted">{c.description || (c.resource_type === "role" ? "Temporary admin rights" : c.resource_type === "app" ? "App access" : "Group membership")}</p>
              <p className="mt-1 text-xs text-fg-subtle">
                Up to {hours(c.max_hours)}
                {c.allow_permanent ? " or permanently" : ""} · {c.you.eligible ? "pre-approved for you" : c.stages.length ? `${c.stages.length} approval${c.stages.length > 1 ? "s" : ""}` : "no approval needed"}
              </p>
            </div>
            {c.you.has_access ? (
              <StatusPill tone="success">You have it</StatusPill>
            ) : c.you.open_request ? (
              <StatusPill tone="warning">Requested</StatusPill>
            ) : (
              <Button size="sm" variant={c.you.eligible ? "primary" : "secondary"} onClick={() => setAsking(c)}>
                {c.you.eligible ? "Activate" : "Request"}
              </Button>
            )}
          </Card>
        );
      })}
      {asking ? <AskDialog item={asking} onClose={() => setAsking(null)} /> : null}
    </div>
  );
}

function AskDialog({ item, onClose }: { item: Item; onClose: () => void }) {
  const qc = useQueryClient();
  const withStepUp = useStepUp();
  const options = DURATIONS.filter((h) => h <= item.max_hours);
  const [duration, setDuration] = useState<number | null>(options.at(Math.min(2, options.length - 1)) ?? item.max_hours);
  const [why, setWhy] = useState("");
  const ask = useMutation({
    mutationFn: () => {
      const call = () => unwrap(api.POST("/v1/access/requests", { body: { catalog_id: item.id, justification: why.trim(), duration_hours: duration } }));
      return item.you.eligible ? withStepUp(call) : call();
    },
    onSuccess: (r) => {
      qc.invalidateQueries({ queryKey: ["access-catalog"] });
      qc.invalidateQueries({ queryKey: ["access-requests"] });
      toast.success(r.status === "active" ? `You have ${r.resource.name}` : "Request sent", { description: r.status === "active" ? (r.expires_at ? `Until ${new Date(r.expires_at).toLocaleString()}` : undefined) : `Waiting for ${r.approvers.join(", ")}` });
      onClose();
    },
  });
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent title={`${item.you.eligible ? "Activate" : "Request"} ${item.name}`} description={item.you.eligible ? "You're pre-approved: confirm it's you, and it's yours for the time you choose." : "Your request goes to the approvers; you'll be notified when it's decided."}>
        <div className="space-y-4">
          <Field label="Why do you need it?" htmlFor="why" hint="Approvers see this, and it's kept in the audit log.">
            <Input id="why" value={why} onChange={(e) => setWhy(e.target.value)} placeholder="e.g. Rotate the Salesforce API key (ticket IT-1234)" maxLength={1000} />
          </Field>
          <Field label="For how long?" htmlFor="duration">
            <Select id="duration" className="w-full" value={duration === null ? "permanent" : String(duration)} onChange={(e) => setDuration(e.target.value === "permanent" ? null : Number(e.target.value))}>
              {options.map((h) => (
                <option key={h} value={h}>
                  {hours(h)}
                </option>
              ))}
              {!options.includes(item.max_hours) ? <option value={item.max_hours}>{hours(item.max_hours)}</option> : null}
              {item.allow_permanent ? <option value="permanent">Permanently</option> : null}
            </Select>
          </Field>
          <ErrorBanner error={ask.error} />
          <div className="flex justify-end gap-2 border-t border-border pt-4">
            <Button variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button variant="primary" loading={ask.isPending} disabled={why.trim().length < 5} onClick={() => ask.mutate()}>
              {item.you.eligible ? "Activate" : "Send request"}
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

function RequestList({ view }: { view: "mine" | "approvals" | "all" }) {
  const list = useQuery({ queryKey: ["access-requests", view], queryFn: () => unwrap(api.GET("/v1/access/requests", { params: { query: { view } } })), refetchInterval: 30_000 });
  if (list.isPending) return <Skeleton className="h-40" />;
  if (!list.data?.data.length) {
    return (
      <Card>
        <EmptyState title={view === "approvals" ? "Nothing waiting for you" : "No requests yet"} description={view === "approvals" ? "Requests you can approve show up here, and in your notifications." : undefined} />
      </Card>
    );
  }
  return (
    <div className="space-y-3">
      {list.data.data.map((r) => (
        <RequestCard key={r.id} r={r} view={view} />
      ))}
    </div>
  );
}

function RequestCard({ r, view }: { r: Req; view: "mine" | "approvals" | "all" }) {
  const qc = useQueryClient();
  const withStepUp = useStepUp();
  const can = useCan();
  const [comment, setComment] = useState("");
  const done = () => (qc.invalidateQueries({ queryKey: ["access-requests"] }), qc.invalidateQueries({ queryKey: ["access-catalog"] }));
  const decide = useMutation({
    mutationFn: (decision: "approve" | "deny") => {
      const call = () => unwrap(api.POST("/v1/access/requests/{id}/decision", { params: { path: { id: r.id } }, body: { decision, comment } }));
      return decision === "approve" && r.resource.type === "role" ? withStepUp(call) : call();
    },
    onSuccess: (x, d) => (done(), toast.success(d === "deny" ? "Denied" : x.status === "active" ? `Approved: ${x.requester.email} has ${x.resource.name}` : "Approved: on to the next approver")),
  });
  const cancel = useMutation({ mutationFn: () => unwrap(api.POST("/v1/access/requests/{id}/cancel", { params: { path: { id: r.id } } })), onSuccess: done });
  const revoke = useMutation({
    mutationFn: () => withStepUp(() => unwrap(api.POST("/v1/access/requests/{id}/revoke", { params: { path: { id: r.id } }, body: {} }))),
    onSuccess: () => (done(), toast.success(view === "mine" ? `Gave back ${r.resource.name}` : `Revoked ${r.resource.name}`)),
  });
  const Icon = ICON[r.resource.type];
  const mine = view === "mine";
  return (
    <Card className="p-4">
      <div className="flex flex-wrap items-start gap-3">
        <div className="rounded-md bg-bg-muted p-2 text-fg-muted">
          <Icon className="size-4" />
        </div>
        <div className="min-w-0 flex-1 text-[13px]">
          <p className="flex flex-wrap items-center gap-2 font-semibold">
            <span className="capitalize">{r.resource.name}</span>
            {!mine ? <span className="font-normal text-fg-muted">for {r.requester.email}</span> : null}
            <StatusPill tone={STATUS[r.status].tone}>{STATUS[r.status].label}</StatusPill>
            {r.auto_approved ? <span className="text-xs font-normal text-fg-subtle">pre-approved</span> : null}
          </p>
          <p className="mt-0.5 text-fg-muted">“{r.justification}”</p>
          <p className="mt-1 flex flex-wrap items-center gap-x-2 text-xs text-fg-subtle">
            <Clock className="size-3" /> {r.duration_hours ? hours(r.duration_hours) : "Permanent"} · asked {timeAgo(r.created_at)}
            {r.status === "pending" && r.stages > 1 ? ` · approval ${r.stage + 1} of ${r.stages}` : ""}
            {r.status === "pending" && r.approvers.length ? ` · waiting for ${r.approvers.join(", ")}` : ""}
            {r.status === "active" && r.expires_at ? ` · ${until(r.expires_at)}` : ""}
            {r.end_reason && r.status !== "active" && r.status !== "pending" ? ` · ${r.end_reason}` : ""}
          </p>
          {r.decisions.length ? (
            <ul className="mt-2 space-y-0.5 text-xs text-fg-muted">
              {r.decisions.map((d, i) => (
                <li key={i}>
                  {d.decision === "approve" ? "✓" : "✗"} {d.approver} {d.decision === "approve" ? "approved" : "denied"}
                  {d.comment ? `: “${d.comment}”` : ""} · {timeAgo(d.at)}
                </li>
              ))}
            </ul>
          ) : null}
        </div>
        <div className="flex items-center gap-1.5">
          {mine && r.status === "pending" ? (
            <Button size="sm" variant="ghost" loading={cancel.isPending} onClick={() => cancel.mutate()}>
              Withdraw
            </Button>
          ) : null}
          {r.status === "active" && (mine || can("access:manage")) ? (
            <Button size="sm" variant="secondary" loading={revoke.isPending} onClick={() => revoke.mutate()}>
              {mine ? "Give back" : "Revoke"}
            </Button>
          ) : null}
        </div>
      </div>
      {r.you_can_decide && r.status === "pending" ? (
        <div className="mt-3 flex flex-wrap items-center gap-2 border-t border-border pt-3">
          <Input className="min-w-60 flex-1" placeholder="Comment (optional)" value={comment} onChange={(e) => setComment(e.target.value)} aria-label="Comment" />
          <Button size="sm" variant="ghost" loading={decide.isPending && decide.variables === "deny"} onClick={() => decide.mutate("deny")}>
            Deny
          </Button>
          <Button size="sm" variant="primary" loading={decide.isPending && decide.variables === "approve"} onClick={() => decide.mutate("approve")}>
            Approve
          </Button>
        </div>
      ) : null}
      <div className="mt-2">
        <ErrorBanner error={decide.error ?? cancel.error ?? revoke.error} />
      </div>
    </Card>
  );
}

// ---- Catalog (access admins) -----------------------------------------------------------

function stageLabel(s: Stage, names: { users: Map<string, string>; groups: Map<string, string> }) {
  if (s.kind === "manager") return "Their manager";
  if (s.kind === "role") return `Any ${s.role.replace("_", " ")}`;
  if (s.kind === "group") return `Members of ${names.groups.get(s.id) ?? "a group"}`;
  return s.ids.map((i) => names.users.get(i) ?? "someone").join(", ");
}

function useNames() {
  const users = useQuery({ queryKey: ["users", "all-for-picker"], queryFn: () => unwrap(api.GET("/v1/users", { params: { query: { limit: 200 } } })) });
  const groups = useQuery({ queryKey: ["groups", "all-for-picker"], queryFn: () => unwrap(api.GET("/v1/groups", { params: { query: { limit: 200 } } })) });
  const apps = useQuery({ queryKey: ["apps", "all-for-picker"], queryFn: () => unwrap(api.GET("/v1/apps")) });
  return {
    users: users.data?.data ?? [],
    groups: groups.data?.data ?? [],
    apps: apps.data?.data ?? [],
    names: { users: new Map((users.data?.data ?? []).map((u) => [u.id, u.email])), groups: new Map((groups.data?.data ?? []).map((g) => [g.id, g.name])) },
  };
}

function CatalogTab() {
  const qc = useQueryClient();
  const withStepUp = useStepUp();
  const catalog = useQuery({ queryKey: ["access-catalog", "all"], queryFn: () => unwrap(api.GET("/v1/access/catalog", { params: { query: { all: "true" } } })) });
  const { names } = useNames();
  const [adding, setAdding] = useState(false);
  const remove = useMutation({
    mutationFn: (id: string) => withStepUp(() => unwrap(api.DELETE("/v1/access/catalog/{id}", { params: { path: { id } } }))),
    onSuccess: (r) => (qc.setQueryData(["access-catalog", "all"], r), qc.invalidateQueries({ queryKey: ["access-catalog"] })),
  });
  return (
    <div className="space-y-3">
      <div className="flex justify-end">
        <Button variant="primary" onClick={() => setAdding(true)}>
          <Plus /> Make something requestable
        </Button>
      </div>
      {catalog.data?.data.map((c) => {
        const Icon = ICON[c.resource_type];
        return (
          <Card key={c.id} className="flex flex-wrap items-start gap-3 p-4 text-[13px]">
            <div className="rounded-md bg-bg-muted p-2 text-fg-muted">
              <Icon className="size-4" />
            </div>
            <div className="min-w-0 flex-1">
              <p className="flex items-center gap-2 font-semibold capitalize">
                {c.name} {!c.enabled ? <StatusPill>Off</StatusPill> : null}
              </p>
              <p className="text-xs text-fg-muted">
                Up to {hours(c.max_hours)}
                {c.allow_permanent ? " or permanently" : ""} · approvals: {c.stages.length ? c.stages.map((s) => stageLabel(s, names)).join(" → ") : "none"}
              </p>
              {c.eligible.users.length || c.eligible.groups.length ? (
                <p className="text-xs text-fg-subtle">
                  Pre-approved: {[...c.eligible.users.map((u) => names.users.get(u) ?? "someone"), ...c.eligible.groups.map((g) => `members of ${names.groups.get(g) ?? "a group"}`)].join(", ")}
                </p>
              ) : null}
            </div>
            <Button size="sm" variant="ghost" aria-label={`Remove ${c.name}`} loading={remove.isPending && remove.variables === c.id} onClick={() => remove.mutate(c.id)}>
              <Trash2 />
            </Button>
          </Card>
        );
      })}
      <ErrorBanner error={remove.error} />
      {adding ? <CatalogDialog onClose={() => setAdding(false)} /> : null}
    </div>
  );
}

function CatalogDialog({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient();
  const withStepUp = useStepUp();
  const { users, groups, apps } = useNames();
  const [type, setType] = useState<Item["resource_type"]>("app");
  const [resource, setResource] = useState("");
  const [role, setRole] = useState<"admin" | "helpdesk" | "security_analyst" | "readonly">("admin");
  const [description, setDescription] = useState("");
  const [max, setMax] = useState(168);
  const [permanent, setPermanent] = useState(false);
  const [stages, setStages] = useState<Stage[]>([{ kind: "manager" }]);
  const [eligibleGroup, setEligibleGroup] = useState("");
  const save = useMutation({
    mutationFn: () =>
      withStepUp(() =>
        unwrap(
          api.POST("/v1/access/catalog", {
            body: {
              resource_type: type,
              ...(type === "role" ? { role } : { resource_id: resource }),
              description,
              max_hours: max,
              allow_permanent: type !== "role" && permanent,
              stages,
              eligible: { users: [], groups: eligibleGroup ? [eligibleGroup] : [] },
            },
          }),
        ),
      ),
    onSuccess: (r) => (qc.setQueryData(["access-catalog", "all"], r), qc.invalidateQueries({ queryKey: ["access-catalog"] }), toast.success("Now requestable"), onClose()),
  });
  const setStage = (i: number, s: Stage) => setStages(stages.map((x, j) => (j === i ? s : x)));
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent title="Make something requestable" className="max-w-xl">
        <div className="max-h-[72vh] space-y-4 overflow-y-auto pr-1">
          <div className="grid grid-cols-3 gap-2">
            {(["app", "group", "role"] as const).map((t) => {
              const Icon = ICON[t];
              return (
                <button key={t} type="button" onClick={() => (setType(t), setResource(""), t === "role" && (setMax(4), setStages([{ kind: "role", role: "owner" }])))} className={cn("flex items-center gap-2 rounded-md border p-2.5 text-[13px] font-medium", type === t ? "border-primary bg-primary-soft" : "border-border hover:bg-bg-subtle")}>
                  <Icon className="size-4" /> {t === "app" ? "An app" : t === "group" ? "A group" : "An admin role"}
                </button>
              );
            })}
          </div>
          {type === "role" ? (
            <Field label="Role" htmlFor="c-role" hint="Owner can't be requested.">
              <Select id="c-role" className="w-full" value={role} onChange={(e) => setRole(e.target.value as typeof role)}>
                <option value="admin">Admin</option>
                <option value="helpdesk">Help desk</option>
                <option value="security_analyst">Security analyst</option>
                <option value="readonly">Read-only</option>
              </Select>
            </Field>
          ) : (
            <Field label={type === "app" ? "App" : "Group"} htmlFor="c-res">
              <Select id="c-res" className="w-full" value={resource} onChange={(e) => setResource(e.target.value)}>
                <option value="">Choose…</option>
                {(type === "app" ? apps : groups).map((x) => (
                  <option key={x.id} value={x.id}>
                    {x.name}
                  </option>
                ))}
              </Select>
            </Field>
          )}
          <Field label="Description (optional)" htmlFor="c-desc">
            <Input id="c-desc" value={description} onChange={(e) => setDescription(e.target.value)} maxLength={500} />
          </Field>
          <div className="flex flex-wrap items-center gap-3 text-[13px]">
            <label className="flex items-center gap-2">
              Up to
              <Select value={String(max)} onChange={(e) => setMax(Number(e.target.value))} aria-label="Longest grant">
                {DURATIONS.map((h) => (
                  <option key={h} value={h}>
                    {hours(h)}
                  </option>
                ))}
              </Select>
            </label>
            {type !== "role" ? (
              <label className="flex items-center gap-2">
                <input type="checkbox" checked={permanent} onChange={(e) => setPermanent(e.target.checked)} /> or permanently
              </label>
            ) : null}
          </div>
          <div className="space-y-2">
            <p className="text-[13px] font-medium">Approvals, in order</p>
            {stages.map((s, i) => (
              <div key={i} className="flex items-center gap-2">
                <span className="w-5 text-xs text-fg-muted">{i + 1}.</span>
                <Select
                  value={s.kind}
                  onChange={(e) => {
                    const k = e.target.value as Stage["kind"];
                    setStage(i, k === "manager" ? { kind: k } : k === "role" ? { kind: k, role: "owner" } : k === "group" ? { kind: k, id: groups[0]?.id ?? "" } : { kind: k, ids: users[0] ? [users[0].id] : [] });
                  }}
                  aria-label={`Stage ${i + 1} approver type`}
                >
                  <option value="manager">Their manager</option>
                  <option value="group">Members of a group</option>
                  <option value="users">A specific person</option>
                  <option value="role">Anyone with a role</option>
                </Select>
                {s.kind === "group" ? (
                  <Select value={s.id} onChange={(e) => setStage(i, { kind: "group", id: e.target.value })} aria-label="Group">
                    {groups.map((g) => (
                      <option key={g.id} value={g.id}>
                        {g.name}
                      </option>
                    ))}
                  </Select>
                ) : s.kind === "users" ? (
                  <Select value={s.ids[0]} onChange={(e) => setStage(i, { kind: "users", ids: [e.target.value] })} aria-label="Person">
                    {users.map((u) => (
                      <option key={u.id} value={u.id}>
                        {u.email}
                      </option>
                    ))}
                  </Select>
                ) : s.kind === "role" ? (
                  <Select value={s.role} onChange={(e) => setStage(i, { kind: "role", role: e.target.value as "owner" })} aria-label="Role">
                    {["owner", "admin", "helpdesk", "security_analyst"].map((r) => (
                      <option key={r} value={r}>
                        {r.replace("_", " ")}
                      </option>
                    ))}
                  </Select>
                ) : null}
                <Button size="sm" variant="ghost" aria-label="Remove stage" onClick={() => setStages(stages.filter((_, j) => j !== i))}>
                  <Trash2 />
                </Button>
              </div>
            ))}
            {stages.length < 5 ? (
              <Button size="sm" variant="ghost" onClick={() => setStages([...stages, { kind: "manager" }])}>
                <Plus /> Add an approval
              </Button>
            ) : null}
            <p className="text-xs text-fg-muted">With no approvals, anyone can have it at once. If a stage has nobody (say, no manager), owners and admins decide.</p>
          </div>
          <Field label="Pre-approved group (optional)" htmlFor="c-elig" hint="Its members activate it themselves, with MFA and a reason. Good for on-call admins.">
            <Select id="c-elig" className="w-full" value={eligibleGroup} onChange={(e) => setEligibleGroup(e.target.value)}>
              <option value="">Nobody</option>
              {groups.map((g) => (
                <option key={g.id} value={g.id}>
                  {g.name}
                </option>
              ))}
            </Select>
          </Field>
          <ErrorBanner error={save.error} />
          <div className="flex justify-end gap-2 border-t border-border pt-4">
            <Button variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button variant="primary" loading={save.isPending} disabled={type !== "role" && !resource} onClick={() => save.mutate()}>
              Save
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
