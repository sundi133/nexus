"use client";

import type { Schemas } from "@nexus/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Ban, CheckCircle2, CircleSlash, FlaskConical, Info, Laptop, MoreHorizontal, Plus, ShieldCheck, ShieldQuestion, X } from "lucide-react";
import { useMemo, useState } from "react";
import { toast } from "sonner";
import { useStepUp } from "@/components/step-up";
import { Button } from "@/components/ui/button";
import { Field, Input, Select } from "@/components/ui/input";
import { Card, CardHeader, EmptyState, ErrorBanner, PageHeader, Skeleton, StatusPill } from "@/components/ui/misc";
import { Dialog, DialogContent, Menu, MenuContent, MenuItem, MenuSeparator, MenuTrigger } from "@/components/ui/overlay";
import { api, unwrap } from "@/lib/api";
import { useCan } from "@/lib/queries";
import { cn, pluralize } from "@/lib/utils";

type Policy = Schemas["AccessPolicy"];
type Requirement = Policy["requirement"];
type Conditions = Policy["conditions"];
type Principals = { groups: string[]; users: string[] };

const REQUIREMENTS: { value: Requirement; label: string; description: string; icon: typeof ShieldCheck }[] = [
  { value: "require_compliant_device", label: "Require a compliant device", description: "Managed by Nexus and passing every device policy", icon: CheckCircle2 },
  { value: "require_managed_device", label: "Require a managed device", description: "Any device enrolled in Nexus, compliant or not", icon: Laptop },
  { value: "require_mfa", label: "Require MFA", description: "The session must have completed multi-factor authentication", icon: ShieldCheck },
  { value: "block", label: "Block access", description: "Nobody matching this policy can sign in", icon: Ban },
];
const requirementLabel = (r: Requirement) => REQUIREMENTS.find((x) => x.value === r)!.label;

/** Names for the IDs a policy refers to. */
function useDirectory() {
  const apps = useQuery({ queryKey: ["apps"], queryFn: () => unwrap(api.GET("/v1/apps")) });
  const groups = useQuery({ queryKey: ["groups", "all"], queryFn: () => unwrap(api.GET("/v1/groups", { params: { query: { limit: 200 } } })) });
  const users = useQuery({ queryKey: ["users", { limit: "200" }], queryFn: () => unwrap(api.GET("/v1/users", { params: { query: { limit: 200 } } })) });
  return useMemo(() => {
    const app = new Map((apps.data?.data ?? []).map((a) => [a.id, a.name]));
    const group = new Map((groups.data?.data ?? []).map((g) => [g.id, g.name]));
    const user = new Map((users.data?.data ?? []).map((u) => [u.id, u.display_name || u.email]));
    return { apps: apps.data?.data ?? [], groups: groups.data?.data ?? [], users: users.data?.data ?? [], app, group, user };
  }, [apps.data, groups.data, users.data]);
}
type Directory = ReturnType<typeof useDirectory>;

function describeScope(c: Conditions, dir: Directory) {
  const apps = c.apps === "all" ? "All apps" : c.apps.map((id) => dir.app.get(id) ?? "Removed app").join(", ");
  const names = (p: Principals) => [...p.groups.map((id) => dir.group.get(id) ?? "Removed group"), ...p.users.map((id) => dir.user.get(id) ?? "a user")];
  const who = c.users.include === "all" ? "Everyone" : names(c.users.include).join(", ");
  const excluded = names(c.users.exclude);
  return { apps, who: excluded.length ? `${who} except ${excluded.join(", ")}` : who };
}

export default function ConditionalAccessPage() {
  const policies = useQuery({ queryKey: ["access-policies"], queryFn: () => unwrap(api.GET("/v1/access-policies")) });
  const dir = useDirectory();
  const can = useCan();
  const editable = can("policies:write");
  const [editing, setEditing] = useState<Policy | "new" | null>(null);

  return (
    <>
      <PageHeader
        title="Conditional access"
        description="Decide who can sign in to which apps, from which devices, and with what proof."
        actions={
          editable ? (
            <Button variant="primary" onClick={() => setEditing("new")}>
              <Plus /> New policy
            </Button>
          ) : null
        }
      />
      <div className="mb-4 flex items-start gap-2 rounded-lg border border-primary/20 bg-primary-soft px-4 py-3 text-[13px]">
        <Info className="mt-0.5 size-4 shrink-0 text-primary" />
        <p>
          Policies apply to every single sign-in to apps (OIDC and SAML). Start new policies in <span className="font-medium">report-only</span>: nobody is blocked, and you see who would
          have been before you enforce.
        </p>
      </div>

      {policies.isPending ? (
        <Skeleton className="h-40" />
      ) : policies.data?.data.length ? (
        <div className="space-y-3">
          {policies.data.data.map((p) => (
            <PolicyRow key={p.id} policy={p} dir={dir} editable={editable} onEdit={() => setEditing(p)} />
          ))}
        </div>
      ) : (
        <Card>
          <EmptyState
            icon={<ShieldQuestion />}
            title="No policies yet"
            description="Without policies, any assigned user can sign in to their apps from any device. A good first policy: require a compliant device for your most sensitive app, in report-only."
            action={
              editable ? (
                <Button variant="primary" onClick={() => setEditing("new")}>
                  <Plus /> New policy
                </Button>
              ) : undefined
            }
          />
        </Card>
      )}

      <WhatIf dir={dir} />

      {editing ? <PolicyDialog policy={editing === "new" ? null : editing} dir={dir} onClose={() => setEditing(null)} /> : null}
    </>
  );
}

function usePolicyMutations() {
  const qc = useQueryClient();
  const withStepUp = useStepUp();
  const done = (r: { data: Policy[] }) => qc.setQueryData(["access-policies"], r);
  const body = (p: Policy) => ({ name: p.name, enabled: p.enabled, mode: p.mode, requirement: p.requirement, conditions: p.conditions });
  const update = useMutation({
    mutationFn: (p: Policy) => withStepUp(() => unwrap(api.PUT("/v1/access-policies/{id}", { params: { path: { id: p.id } }, body: body(p) }))),
    onSuccess: done,
  });
  const remove = useMutation({
    mutationFn: (p: Policy) => withStepUp(() => unwrap(api.DELETE("/v1/access-policies/{id}", { params: { path: { id: p.id } } }))),
    onSuccess: (r, p) => {
      done(r);
      toast.success(`Deleted “${p.name}”`);
    },
  });
  return { update, remove };
}

function PolicyRow({ policy: p, dir, editable, onEdit }: { policy: Policy; dir: Directory; editable: boolean; onEdit: () => void }) {
  const { update, remove } = usePolicyMutations();
  const scope = describeScope(p.conditions, dir);
  const Icon = REQUIREMENTS.find((r) => r.value === p.requirement)!.icon;
  const setMode = (mode: Policy["mode"]) =>
    update.mutate(
      { ...p, mode },
      {
        onSuccess: () =>
          toast.success(mode === "enforce" ? `“${p.name}” is now enforced` : `“${p.name}” is back in report-only`, {
            description: mode === "enforce" ? "Sign-ins that don't meet it are blocked from now on." : "Nobody is blocked; would-be blocks are recorded.",
          }),
      },
    );

  return (
    <Card className={cn("p-4", !p.enabled && "opacity-70")}>
      <div className="flex items-start gap-3">
        <div className="mt-0.5 rounded-md bg-bg-muted p-2 text-fg-muted">
          <Icon className="size-4" />
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <p className="text-[13px] font-semibold">{p.name}</p>
            {!p.enabled ? (
              <StatusPill>Off</StatusPill>
            ) : p.mode === "enforce" ? (
              <StatusPill tone="success">Enforced</StatusPill>
            ) : (
              <StatusPill tone="warning">Report-only</StatusPill>
            )}
          </div>
          <p className="text-[13px] text-fg-muted">
            {requirementLabel(p.requirement)} · <span className="text-fg">{scope.apps}</span> · {scope.who}
          </p>
          <p className="mt-1.5 text-xs text-fg-subtle">
            Last 7 days:{" "}
            {p.mode === "report_only" ? (
              <span className={p.impact_7d.would_block ? "font-medium text-warning" : ""}>{pluralize(p.impact_7d.would_block, "sign-in")} would have been blocked</span>
            ) : (
              <span className={p.impact_7d.blocked ? "font-medium text-danger" : ""}>{pluralize(p.impact_7d.blocked, "sign-in")} blocked</span>
            )}
          </p>
        </div>
        {editable ? (
          <div className="flex items-center gap-1">
            {p.enabled && p.mode === "report_only" ? (
              <Button size="sm" variant="secondary" loading={update.isPending} onClick={() => setMode("enforce")}>
                Enforce
              </Button>
            ) : null}
            <Menu>
              <MenuTrigger asChild>
                <Button size="sm" variant="ghost" aria-label={`Actions for ${p.name}`}>
                  <MoreHorizontal />
                </Button>
              </MenuTrigger>
              <MenuContent>
                <MenuItem onSelect={onEdit}>Edit</MenuItem>
                {p.mode === "enforce" ? <MenuItem onSelect={() => setMode("report_only")}>Switch to report-only</MenuItem> : null}
                <MenuItem onSelect={() => update.mutate({ ...p, enabled: !p.enabled })}>{p.enabled ? "Turn off" : "Turn on"}</MenuItem>
                <MenuSeparator />
                <MenuItem danger onSelect={() => remove.mutate(p)}>
                  Delete
                </MenuItem>
              </MenuContent>
            </Menu>
          </div>
        ) : null}
      </div>
      <ErrorBanner error={update.error ?? remove.error} />
    </Card>
  );
}

// ---- Builder ----------------------------------------------------------------------

const EMPTY: Principals = { groups: [], users: [] };

function PolicyDialog({ policy, dir, onClose }: { policy: Policy | null; dir: Directory; onClose: () => void }) {
  const qc = useQueryClient();
  const withStepUp = useStepUp();
  const [name, setName] = useState(policy?.name ?? "");
  const [requirement, setRequirement] = useState<Requirement>(policy?.requirement ?? "require_compliant_device");
  const [allApps, setAllApps] = useState(policy ? policy.conditions.apps === "all" : false);
  const [apps, setApps] = useState<string[]>(policy && policy.conditions.apps !== "all" ? policy.conditions.apps : []);
  const [everyone, setEveryone] = useState(policy ? policy.conditions.users.include === "all" : true);
  const [include, setInclude] = useState<Principals>(policy && policy.conditions.users.include !== "all" ? policy.conditions.users.include : EMPTY);
  const [exclude, setExclude] = useState<Principals>(policy?.conditions.users.exclude ?? EMPTY);
  const [mode, setMode] = useState<Policy["mode"]>(policy?.mode ?? "report_only");

  const body = {
    name: name.trim(),
    enabled: policy?.enabled ?? true,
    mode,
    requirement,
    conditions: { apps: allApps ? ("all" as const) : apps, users: { include: everyone ? ("all" as const) : include, exclude } },
  };
  const problem =
    !body.name ? "Give the policy a name" : !allApps && apps.length === 0 ? "Pick at least one app" : !everyone && include.groups.length + include.users.length === 0 ? "Pick who it applies to" : null;

  const save = useMutation({
    mutationFn: () =>
      withStepUp(() =>
        policy ? unwrap(api.PUT("/v1/access-policies/{id}", { params: { path: { id: policy.id } }, body })) : unwrap(api.POST("/v1/access-policies", { body })),
      ),
    onSuccess: (r) => {
      qc.setQueryData(["access-policies"], r);
      toast.success(policy ? "Policy saved" : "Policy created", {
        description: mode === "report_only" ? "Report-only: watch the would-block count, then enforce." : "Enforced from the next sign-in.",
      });
      onClose();
    },
  });

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent title={policy ? "Edit policy" : "New conditional access policy"} className="max-w-xl">
        <form
          className="max-h-[70vh] space-y-5 overflow-y-auto pr-1"
          onSubmit={(e) => {
            e.preventDefault();
            if (!problem) save.mutate();
          }}
        >
          <Field label="Name" htmlFor="ca-name">
            <Input id="ca-name" autoFocus value={name} onChange={(e) => setName(e.target.value)} placeholder="Finance apps need a healthy laptop" maxLength={100} />
          </Field>

          <fieldset className="space-y-2">
            <legend className="mb-1 text-[13px] font-medium">Requirement</legend>
            <div className="grid gap-2 sm:grid-cols-2">
              {REQUIREMENTS.map((r) => (
                <label
                  key={r.value}
                  className={cn(
                    "flex cursor-pointer gap-2 rounded-md border p-3 text-[13px] transition-colors",
                    requirement === r.value ? "border-primary bg-primary-soft" : "border-border hover:bg-bg-subtle",
                  )}
                >
                  <input type="radio" name="requirement" className="sr-only" checked={requirement === r.value} onChange={() => setRequirement(r.value)} />
                  <r.icon className={cn("mt-0.5 size-4 shrink-0", requirement === r.value ? "text-primary" : "text-fg-muted")} />
                  <span>
                    <span className="block font-medium">{r.label}</span>
                    <span className="block text-xs text-fg-muted">{r.description}</span>
                  </span>
                </label>
              ))}
            </div>
          </fieldset>

          <fieldset className="space-y-2">
            <legend className="mb-1 text-[13px] font-medium">Apps</legend>
            <Segmented value={allApps ? "all" : "some"} onChange={(v) => setAllApps(v === "all")} options={[{ value: "some", label: "Selected apps" }, { value: "all", label: "All apps" }]} />
            {!allApps ? (
              <Checklist items={dir.apps.map((a) => ({ id: a.id, label: a.name, hint: a.protocol.toUpperCase() }))} selected={apps} onChange={setApps} empty="No apps yet" />
            ) : null}
          </fieldset>

          <fieldset className="space-y-2">
            <legend className="mb-1 text-[13px] font-medium">Applies to</legend>
            <Segmented value={everyone ? "all" : "some"} onChange={(v) => setEveryone(v === "all")} options={[{ value: "all", label: "Everyone" }, { value: "some", label: "Selected groups and people" }]} />
            {!everyone ? <PrincipalPicker dir={dir} value={include} onChange={setInclude} /> : null}
            <p className="pt-1 text-xs font-medium text-fg-muted">Except</p>
            <PrincipalPicker dir={dir} value={exclude} onChange={setExclude} placeholder="Add exclusions, e.g. a break-glass admin" />
          </fieldset>

          <fieldset className="space-y-2">
            <legend className="mb-1 text-[13px] font-medium">Mode</legend>
            <Segmented value={mode} onChange={(v) => setMode(v as Policy["mode"])} options={[{ value: "report_only", label: "Report-only" }, { value: "enforce", label: "Enforce" }]} />
            <p className="text-xs text-fg-muted">
              {mode === "report_only" ? "Nobody is blocked. Sign-ins that would have been are recorded in the audit log and counted here." : "Sign-ins that don't meet the requirement are blocked, with the reason shown to the user."}
            </p>
          </fieldset>

          <ErrorBanner error={save.error} />
          <div className="flex items-center justify-end gap-2 border-t border-border pt-4">
            {problem ? <span className="mr-auto text-xs text-fg-muted">{problem}</span> : null}
            <Button type="button" variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" variant="primary" loading={save.isPending} disabled={!!problem}>
              {policy ? "Save policy" : "Create policy"}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function Segmented({ value, onChange, options }: { value: string; onChange: (v: string) => void; options: { value: string; label: string }[] }) {
  return (
    <div className="inline-flex rounded-md border border-border bg-bg-subtle p-0.5" role="radiogroup">
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          role="radio"
          aria-checked={value === o.value}
          onClick={() => onChange(o.value)}
          className={cn("rounded px-3 py-1 text-[13px] font-medium", value === o.value ? "bg-bg text-fg shadow-card" : "text-fg-muted hover:text-fg")}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

function Checklist({ items, selected, onChange, empty }: { items: { id: string; label: string; hint?: string }[]; selected: string[]; onChange: (ids: string[]) => void; empty: string }) {
  if (!items.length) return <p className="text-xs text-fg-muted">{empty}</p>;
  return (
    <div className="max-h-40 overflow-y-auto rounded-md border border-border">
      {items.map((i) => (
        <label key={i.id} className="flex cursor-pointer items-center gap-2 border-b border-border px-3 py-2 text-[13px] last:border-0 hover:bg-bg-subtle">
          <input type="checkbox" checked={selected.includes(i.id)} onChange={(e) => onChange(e.target.checked ? [...selected, i.id] : selected.filter((x) => x !== i.id))} />
          <span className="flex-1">{i.label}</span>
          {i.hint ? <span className="text-[11px] text-fg-subtle">{i.hint}</span> : null}
        </label>
      ))}
    </div>
  );
}

/** Chips for chosen groups/people, and a search box to add more. */
function PrincipalPicker({ dir, value, onChange, placeholder = "Search groups and people" }: { dir: Directory; value: Principals; onChange: (v: Principals) => void; placeholder?: string }) {
  const [q, setQ] = useState("");
  const term = q.trim().toLowerCase();
  const matches = term
    ? [
        ...dir.groups.filter((g) => g.name.toLowerCase().includes(term) && !value.groups.includes(g.id)).map((g) => ({ kind: "groups" as const, id: g.id, label: g.name, hint: `${pluralize(g.member_count, "member")}` })),
        ...dir.users
          .filter((u) => (u.display_name + " " + u.email).toLowerCase().includes(term) && !value.users.includes(u.id))
          .map((u) => ({ kind: "users" as const, id: u.id, label: u.display_name || u.email, hint: u.email })),
      ].slice(0, 8)
    : [];
  const chips = [...value.groups.map((id) => ({ kind: "groups" as const, id, label: dir.group.get(id) ?? "Group" })), ...value.users.map((id) => ({ kind: "users" as const, id, label: dir.user.get(id) ?? "User" }))];

  return (
    <div className="space-y-2">
      {chips.length ? (
        <div className="flex flex-wrap gap-1.5">
          {chips.map((c) => (
            <span key={c.id} className="inline-flex items-center gap-1 rounded-full bg-bg-muted py-0.5 pl-2.5 pr-1 text-xs">
              {c.kind === "groups" ? <span className="text-fg-subtle">Group</span> : null}
              {c.label}
              <button type="button" aria-label={`Remove ${c.label}`} className="rounded-full p-0.5 hover:bg-border" onClick={() => onChange({ ...value, [c.kind]: value[c.kind].filter((x) => x !== c.id) })}>
                <X className="size-3" />
              </button>
            </span>
          ))}
        </div>
      ) : null}
      <div className="relative">
        <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder={placeholder} aria-label={placeholder} />
        {matches.length ? (
          <div className="absolute inset-x-0 top-full z-10 mt-1 overflow-hidden rounded-md border border-border bg-bg shadow-card">
            {matches.map((m) => (
              <button
                key={m.id}
                type="button"
                className="flex w-full items-center gap-2 px-3 py-2 text-left text-[13px] hover:bg-bg-subtle"
                onClick={() => {
                  onChange({ ...value, [m.kind]: [...value[m.kind], m.id] });
                  setQ("");
                }}
              >
                {m.kind === "groups" ? <span className="text-[11px] text-fg-subtle">Group</span> : null}
                <span className="flex-1">{m.label}</span>
                <span className="text-[11px] text-fg-subtle">{m.hint}</span>
              </button>
            ))}
          </div>
        ) : null}
      </div>
    </div>
  );
}

// ---- What-if ----------------------------------------------------------------------

const OUTCOME: Record<Schemas["AccessSimulation"]["outcome"], { label: string; tone: "success" | "danger" | "warning"; icon: typeof ShieldCheck }> = {
  allow: { label: "Allowed", tone: "success", icon: CheckCircle2 },
  block: { label: "Blocked", tone: "danger", icon: CircleSlash },
  needs_device: { label: "Device check needed", tone: "warning", icon: Laptop },
  needs_mfa: { label: "MFA needed", tone: "warning", icon: ShieldCheck },
};

function WhatIf({ dir }: { dir: Directory }) {
  const [userId, setUserId] = useState("");
  const [appId, setAppId] = useState("");
  const [mfa, setMfa] = useState(true);
  const [deviceId, setDeviceId] = useState("");
  const devices = useQuery({
    queryKey: ["devices", { user_id: userId }],
    queryFn: () => unwrap(api.GET("/v1/devices", { params: { query: { user_id: userId, limit: 50 } } })),
    enabled: !!userId,
  });
  const sim = useMutation({
    mutationFn: () => unwrap(api.POST("/v1/access-policies/simulate", { body: { user_id: userId, app_id: appId, mfa, device_id: deviceId || null } })),
  });
  const o = sim.data ? OUTCOME[sim.data.outcome] : null;

  return (
    <Card className="mt-6">
      <CardHeader
        title={
          <span className="inline-flex items-center gap-2">
            <FlaskConical className="size-4 text-fg-muted" /> What if…
          </span>
        }
        description="Test a sign-in against every policy, as if report-only policies were enforced. Nothing is recorded."
      />
      <form
        className="grid gap-3 p-4 sm:grid-cols-3"
        onSubmit={(e) => {
          e.preventDefault();
          sim.mutate();
        }}
      >
        <Field label="User" htmlFor="wi-user">
          <Select id="wi-user" className="w-full" value={userId} onChange={(e) => (setUserId(e.target.value), setDeviceId(""), sim.reset())}>
            <option value="">Choose a user</option>
            {dir.users.map((u) => (
              <option key={u.id} value={u.id}>
                {u.display_name || u.email}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="App" htmlFor="wi-app">
          <Select id="wi-app" className="w-full" value={appId} onChange={(e) => (setAppId(e.target.value), sim.reset())}>
            <option value="">Choose an app</option>
            {dir.apps.map((a) => (
              <option key={a.id} value={a.id}>
                {a.name}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Device" htmlFor="wi-device">
          <Select id="wi-device" className="w-full" value={deviceId} disabled={!userId} onChange={(e) => (setDeviceId(e.target.value), sim.reset())}>
            <option value="">Unknown / unmanaged</option>
            {devices.data?.data.map((d) => (
              <option key={d.id} value={d.id}>
                {d.hostname} ({d.compliance.replace("_", "-")})
              </option>
            ))}
          </Select>
        </Field>
        <div className="flex items-center gap-3 sm:col-span-3">
          <label className="flex items-center gap-2 text-[13px]">
            <input type="checkbox" checked={mfa} onChange={(e) => (setMfa(e.target.checked), sim.reset())} /> Signed in with MFA
          </label>
          <Button type="submit" variant="secondary" className="ml-auto" disabled={!userId || !appId} loading={sim.isPending}>
            Test
          </Button>
        </div>
      </form>
      <ErrorBanner error={sim.error} />
      {sim.data && o ? (
        <div className="border-t border-border p-4">
          <div className="flex items-start gap-2">
            <o.icon className={cn("mt-0.5 size-4", o.tone === "success" ? "text-success" : o.tone === "danger" ? "text-danger" : "text-warning")} />
            <div>
              <p className="text-[13px] font-semibold">{o.label}</p>
              <p className="text-[13px] text-fg-muted">{sim.data.reason}</p>
            </div>
          </div>
          {sim.data.results.length ? (
            <ul className="mt-3 divide-y divide-border rounded-md border border-border">
              {sim.data.results.map((r) => (
                <li key={r.policy_id} className="flex items-center gap-3 px-3 py-2 text-[13px]">
                  <span className="w-5 shrink-0">
                    {!r.matched ? <span className="text-fg-subtle">–</span> : r.satisfied ? <CheckCircle2 className="size-4 text-success" /> : <CircleSlash className="size-4 text-danger" />}
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="font-medium">{r.name}</span>
                    {r.mode === "report_only" ? <span className="ml-2 text-[11px] text-warning">report-only</span> : null}
                    <span className="block text-xs text-fg-muted">{r.matched ? r.reason : `Doesn't apply: ${r.reason.toLowerCase()}`}</span>
                  </span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="mt-2 text-xs text-fg-muted">No policies yet.</p>
          )}
        </div>
      ) : null}
    </Card>
  );
}
