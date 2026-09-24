"use client";

import type { Role, UserDetail } from "@nexus/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ChevronLeft, KeyRound, LogOut, Mail, MoreHorizontal, Pencil, ShieldOff, Siren, UserCheck, UserX } from "lucide-react";
import Link from "next/link";
import { use, useState } from "react";
import { toast } from "sonner";
import { ActivityList } from "@/components/features/activity";
import { ConfirmAction } from "@/components/features/confirm-action";
import { MfaBadge, RoleBadges, UserStatusPill } from "@/components/features/user-bits";
import { Button } from "@/components/ui/button";
import { Field, Input } from "@/components/ui/input";
import { Avatar, Card, CardHeader, EmptyState, ErrorBanner, KeyValue, Skeleton } from "@/components/ui/misc";
import { Dialog, DialogContent, Menu, MenuContent, MenuItem, MenuSeparator, MenuTrigger, Tabs, TabsContent, TabsList } from "@/components/ui/overlay";
import { SessionsTable } from "@/components/features/sessions-table";
import { api, unwrap } from "@/lib/api";
import { qk, useCan, useMe } from "@/lib/queries";
import { formatDateTime, pluralize, ROLE_LABELS, timeAgo } from "@/lib/utils";

type Action = "suspend" | "activate" | "contain" | "revoke-sessions" | "reset-mfa";

export default function UserPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const qc = useQueryClient();
  const can = useCan();
  const { data: me } = useMe();
  const [pending, setPending] = useState<Action | null>(null);
  const [editing, setEditing] = useState(false);
  const [rolesOpen, setRolesOpen] = useState(false);

  const user = useQuery({ queryKey: qk.user(id), queryFn: () => unwrap(api.GET("/v1/users/{id}", { params: { path: { id } } })) });
  const activity = useQuery({
    queryKey: ["audit", { subject_id: id }],
    queryFn: () => unwrap(api.GET("/v1/audit/events", { params: { query: { subject_id: id, limit: 50 } } })),
  });

  const refresh = () => {
    qc.invalidateQueries({ queryKey: qk.user(id) });
    qc.invalidateQueries({ queryKey: ["users"] });
    qc.invalidateQueries({ queryKey: ["audit"] });
    qc.invalidateQueries({ queryKey: qk.overview });
  };

  const run = async (action: Action, reason: string) => {
    const r = await unwrap(api.POST(`/v1/users/{id}/${action}` as const, { params: { path: { id } }, body: { reason } }));
    refresh();
    const n = (r.effects as { sessions_revoked?: number }).sessions_revoked;
    toast.success(
      {
        suspend: "User suspended",
        activate: "User reactivated",
        contain: "User contained",
        "revoke-sessions": "Signed out everywhere",
        "reset-mfa": "MFA reset",
      }[action],
      { description: n !== undefined ? `${pluralize(n, "session")} revoked` : undefined },
    );
  };

  const resendInvite = async () => {
    const r = await unwrap(api.POST("/v1/users/{id}/invite", { params: { path: { id } } })).catch((err: Error) => {
      toast.error(err.message);
      return null;
    });
    if (r) {
      refresh();
      toast.success(`Invitation sent to ${r.sent_to}`, { description: "Earlier invitation links no longer work." });
    }
  };

  if (user.isPending) return <Skeleton className="h-40" />;
  if (user.error || !user.data) return <ErrorBanner error={user.error} />;
  const u = user.data;
  const isSelf = me?.user.id === u.id;
  const sessions = u.sessions.length;

  return (
    <>
      <Link href="/users" className="mb-3 inline-flex items-center gap-1 text-[13px] text-fg-muted hover:text-fg">
        <ChevronLeft className="size-4" /> Users
      </Link>

      <div className="mb-5 flex flex-wrap items-start gap-4">
        <Avatar name={u.display_name} size={48} />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <h1 className="text-xl font-semibold tracking-tight">{u.display_name}</h1>
            <UserStatusPill status={u.status} />
            {isSelf ? <span className="text-xs text-fg-subtle">(you)</span> : null}
          </div>
          <p className="mt-0.5 text-[13px] text-fg-muted">
            {u.email}
            {u.title ? ` · ${u.title}` : ""}
            {u.department ? ` · ${u.department}` : ""}
          </p>
          {u.managed_by ? (
            <p className="mt-1 text-xs text-fg-subtle">Synced from {u.managed_by}: name, email, title, department and status follow the directory.</p>
          ) : null}
        </div>
        <div className="flex gap-2">
          {can("users:write") ? (
            <Button onClick={() => setEditing(true)}>
              <Pencil /> Edit
            </Button>
          ) : null}
          {can("users:lifecycle") && !isSelf ? (
            <Menu>
              <MenuTrigger asChild>
                <Button aria-label="More actions">
                  Actions <MoreHorizontal />
                </Button>
              </MenuTrigger>
              <MenuContent>
                {u.status === "staged" ? (
                  <MenuItem onSelect={resendInvite}>
                    <Mail /> Resend invitation
                  </MenuItem>
                ) : u.status === "active" ? (
                  <MenuItem onSelect={() => setPending("suspend")}>
                    <UserX /> Suspend
                  </MenuItem>
                ) : (
                  <MenuItem onSelect={() => setPending("activate")}>
                    <UserCheck /> Reactivate
                  </MenuItem>
                )}
                <MenuItem onSelect={() => setPending("revoke-sessions")} disabled={!sessions}>
                  <LogOut /> Sign out everywhere
                </MenuItem>
                <MenuItem onSelect={() => setPending("reset-mfa")} disabled={!u.mfa_enrolled}>
                  <ShieldOff /> Reset MFA
                </MenuItem>
                {can("admins:manage") ? (
                  <MenuItem onSelect={() => setRolesOpen(true)}>
                    <KeyRound /> Admin roles…
                  </MenuItem>
                ) : null}
                <MenuSeparator />
                <MenuItem danger onSelect={() => setPending("contain")} disabled={u.status !== "active" && !sessions}>
                  <Siren /> Contain…
                </MenuItem>
              </MenuContent>
            </Menu>
          ) : null}
        </div>
      </div>

      {/* Signal strip (docs/UI.md §4.2) */}
      <Card className="mb-5 grid grid-cols-2 divide-border md:grid-cols-4 md:divide-x">
        <Signal label="MFA">
          <MfaBadge enrolled={u.mfa_enrolled} />
        </Signal>
        <Signal label="Admin roles">
          <RoleBadges roles={u.roles} />
        </Signal>
        <Signal label="Active sessions">{sessions}</Signal>
        <Signal label="Last sign-in">{timeAgo(u.last_login_at)}</Signal>
      </Card>

      <Tabs defaultValue="overview">
        <TabsList
          tabs={[
            { value: "overview", label: "Overview" },
            { value: "sessions", label: `Sessions (${sessions})` },
            { value: "activity", label: "Activity" },
          ]}
        />
        <TabsContent value="overview" className="grid gap-5 lg:grid-cols-2">
          <Card>
            <CardHeader title="Profile" />
            <div className="p-4">
              <KeyValue
                items={[
                  ["Email", u.email],
                  ["Title", u.title || "—"],
                  ["Department", u.department || "—"],
                  ["Created", formatDateTime(u.created_at)],
                  ["User ID", <code key="id" className="font-mono text-xs">{u.id}</code>],
                ]}
              />
            </div>
          </Card>
          <Card>
            <CardHeader title="Groups" />
            {u.groups.length ? (
              <ul className="divide-y divide-border">
                {u.groups.map((g) => (
                  <li key={g.id}>
                    <Link href={`/groups/${g.id}`} className="block px-4 py-2.5 text-[13px] hover:bg-bg-subtle">
                      {g.name}
                    </Link>
                  </li>
                ))}
              </ul>
            ) : (
              <EmptyState title="Not in any groups" />
            )}
          </Card>
        </TabsContent>
        <TabsContent value="sessions">
          <Card className="overflow-hidden">
            {sessions ? <SessionsTable sessions={u.sessions} /> : <EmptyState title="No active sessions" />}
          </Card>
        </TabsContent>
        <TabsContent value="activity">
          <Card className="overflow-hidden">
            {activity.data?.data.length ? <ActivityList events={activity.data.data} /> : <EmptyState title="No activity yet" />}
          </Card>
        </TabsContent>
      </Tabs>

      <ConfirmAction
        open={pending === "suspend"}
        onOpenChange={(v) => !v && setPending(null)}
        title={`Suspend ${u.display_name}?`}
        effects={["Block all sign-ins", `Revoke ${pluralize(sessions, "active session")} (web, mobile, CLI)`, "Keep their data, groups and roles so you can reactivate later"]}
        confirmLabel="Suspend user"
        danger
        onConfirm={(r) => run("suspend", r)}
      />
      <ConfirmAction
        open={pending === "activate"}
        onOpenChange={(v) => !v && setPending(null)}
        title={`Reactivate ${u.display_name}?`}
        effects={["Allow them to sign in again"]}
        confirmLabel="Reactivate"
        onConfirm={(r) => run("activate", r)}
      />
      <ConfirmAction
        open={pending === "revoke-sessions"}
        onOpenChange={(v) => !v && setPending(null)}
        title={`Sign ${u.display_name} out everywhere?`}
        effects={[`Revoke ${pluralize(sessions, "active session")}`, "They can sign in again immediately"]}
        confirmLabel="Sign out everywhere"
        onConfirm={(r) => run("revoke-sessions", r)}
      />
      <ConfirmAction
        open={pending === "reset-mfa"}
        onOpenChange={(v) => !v && setPending(null)}
        title={`Reset MFA for ${u.display_name}?`}
        effects={["Remove all their MFA methods", "Sign them out everywhere", "They'll set up MFA again at next sign-in. Verify their identity first."]}
        confirmLabel="Reset MFA"
        danger
        onConfirm={(r) => run("reset-mfa", r)}
      />
      <ConfirmAction
        open={pending === "contain"}
        onOpenChange={(v) => !v && setPending(null)}
        title={`Contain ${u.display_name}?`}
        effects={[
          "Suspend the account immediately",
          `Revoke ${pluralize(sessions, "session")} across web, mobile and CLI`,
          "Alert all owners, admins and security analysts",
          "Reversible: reactivate once the investigation is done",
        ]}
        confirmLabel="Contain now"
        danger
        typeToConfirm={u.email}
        onConfirm={(r) => run("contain", r)}
      />
      <EditUserDialog user={u} open={editing} onOpenChange={setEditing} onSaved={refresh} />
      <RolesDialog user={u} open={rolesOpen} onOpenChange={setRolesOpen} onSaved={refresh} />
    </>
  );
}

function Signal({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="px-4 py-3">
      <p className="text-xs text-fg-muted">{label}</p>
      <div className="mt-1 text-[13px] font-medium tabular">{children}</div>
    </div>
  );
}

function EditUserDialog({ user, open, onOpenChange, onSaved }: { user: UserDetail; open: boolean; onOpenChange: (v: boolean) => void; onSaved: () => void }) {
  const [form, setForm] = useState({ given_name: user.given_name, family_name: user.family_name, title: user.title, department: user.department });
  const save = useMutation({
    mutationFn: () => unwrap(api.PATCH("/v1/users/{id}", { params: { path: { id: user.id } }, body: form })),
    onSuccess: () => {
      onSaved();
      toast.success("Profile updated");
      onOpenChange(false);
    },
    onError: () => {},
  });
  const set = (k: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement>) => setForm({ ...form, [k]: e.target.value });
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent title="Edit profile">
        <form
          className="space-y-3"
          onSubmit={(e) => {
            e.preventDefault();
            save.mutate();
          }}
        >
          <ErrorBanner error={save.error} />
          <div className="grid grid-cols-2 gap-3">
            <Field label="First name" htmlFor="e-gn">
              <Input id="e-gn" value={form.given_name} onChange={set("given_name")} required />
            </Field>
            <Field label="Last name" htmlFor="e-fn">
              <Input id="e-fn" value={form.family_name} onChange={set("family_name")} />
            </Field>
          </div>
          <Field label="Title" htmlFor="e-t">
            <Input id="e-t" value={form.title} onChange={set("title")} />
          </Field>
          <Field label="Department" htmlFor="e-d">
            <Input id="e-d" value={form.department} onChange={set("department")} />
          </Field>
          <div className="flex justify-end gap-2 pt-2">
            <Button type="button" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" variant="primary" loading={save.isPending}>
              Save
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function RolesDialog({ user, open, onOpenChange, onSaved }: { user: UserDetail; open: boolean; onOpenChange: (v: boolean) => void; onSaved: () => void }) {
  const [roles, setRoles] = useState<Role[]>(user.roles);
  const save = useMutation({
    mutationFn: () => unwrap(api.PUT("/v1/users/{id}/roles", { params: { path: { id: user.id } }, body: { roles } })),
    onSuccess: () => {
      onSaved();
      toast.success("Admin roles updated");
      onOpenChange(false);
    },
    onError: () => {},
  });
  const toggle = (r: Role) => setRoles(roles.includes(r) ? roles.filter((x) => x !== r) : [...roles, r]);
  const DESCRIPTIONS: Record<Role, string> = {
    owner: "Everything, including managing other admins",
    admin: "Everything except managing admins",
    helpdesk: "Edit users, reset MFA, suspend and sign out",
    security_analyst: "Read everything, contain users",
    readonly: "Read-only access to the console",
  };
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent title={`Admin roles for ${user.display_name}`} description="Grant the least access needed. Owners are notified of every grant.">
        <div className="space-y-2">
          <ErrorBanner error={save.error} />
          {(Object.keys(DESCRIPTIONS) as Role[]).map((r) => (
            <label key={r} className="flex cursor-pointer items-start gap-3 rounded-md border border-border p-3 hover:bg-bg-subtle">
              <input type="checkbox" className="mt-0.5" checked={roles.includes(r)} onChange={() => toggle(r)} />
              <span>
                <span className="block text-[13px] font-medium">{ROLE_LABELS[r]}</span>
                <span className="block text-xs text-fg-muted">{DESCRIPTIONS[r]}</span>
              </span>
            </label>
          ))}
          <div className="flex justify-end gap-2 pt-2">
            <Button onClick={() => onOpenChange(false)}>Cancel</Button>
            <Button variant="primary" onClick={() => save.mutate()} loading={save.isPending}>
              Save roles
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
