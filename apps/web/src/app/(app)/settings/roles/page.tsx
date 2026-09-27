"use client";

import type { Schemas } from "@nexus/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, ShieldCheck } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { ConfirmAction } from "@/components/features/confirm-action";
import { useStepUp } from "@/components/step-up";
import { Button } from "@/components/ui/button";
import { Field, Input } from "@/components/ui/input";
import { Card, CardHeader, EmptyState, ErrorBanner, PageHeader, Skeleton, StatusPill } from "@/components/ui/misc";
import { Dialog, DialogContent } from "@/components/ui/overlay";
import { api, unwrap } from "@/lib/api";
import { useCan } from "@/lib/queries";
import { pluralize, ROLE_LABELS, toggled } from "@/lib/utils";

type Catalog = Schemas["RoleCatalog"];
type CustomRole = Schemas["CustomRole"];
type Perm = Catalog["permissions"][number]["key"];

/** Permissions grouped by what they're about ("users:read" → Users). */
function byArea(perms: Catalog["permissions"]) {
  const m = new Map<string, Catalog["permissions"]>();
  for (const p of perms) {
    const area = p.key.split(":")[0]!;
    m.set(area, [...(m.get(area) ?? []), p]);
  }
  return [...m.entries()];
}

export default function RolesPage() {
  const qc = useQueryClient();
  const can = useCan();
  const withStepUp = useStepUp();
  const [editing, setEditing] = useState<CustomRole | "new" | null>(null);
  const [deleting, setDeleting] = useState<CustomRole | null>(null);
  const cat = useQuery({ queryKey: ["roles"], queryFn: () => unwrap(api.GET("/v1/roles")) });
  const manage = can("admins:manage");
  if (!cat.data) return cat.error ? <ErrorBanner error={cat.error} /> : <Skeleton className="h-60" />;
  return (
    <>
      <PageHeader
        title="Roles"
        description="What admins can do. Use a custom role for a job that doesn't fit a built-in one, and limit roles to groups on each person's page (e.g. Help Desk for EMEA only)."
        actions={
          manage ? (
            <Button variant="primary" onClick={() => setEditing("new")}>
              <Plus /> New role
            </Button>
          ) : null
        }
      />
      <Card className="mb-5 overflow-hidden">
        <CardHeader title="Custom roles" />
        {cat.data.custom.length ? (
          <ul className="divide-y divide-border border-t border-border">
            {cat.data.custom.map((r) => (
              <li key={r.id} className="flex flex-wrap items-center gap-3 px-4 py-3 text-[13px]">
                <div className="min-w-0 flex-1">
                  <p className="font-medium">
                    {r.name} <span className="font-normal text-fg-muted">· {pluralize(r.holders, "person")}</span>
                  </p>
                  {r.description ? <p className="text-xs text-fg-muted">{r.description}</p> : null}
                  <p className="mt-1 flex flex-wrap gap-1">
                    {r.permissions.map((p) => (
                      <code key={p} className="rounded bg-bg-muted px-1.5 py-0.5 font-mono text-[11px]">
                        {p}
                      </code>
                    ))}
                  </p>
                </div>
                {manage ? (
                  <>
                    <Button size="sm" variant="ghost" onClick={() => setEditing(r)}>
                      Edit
                    </Button>
                    <Button size="sm" variant="ghost" onClick={() => setDeleting(r)}>
                      Delete
                    </Button>
                  </>
                ) : null}
              </li>
            ))}
          </ul>
        ) : (
          <EmptyState icon={<ShieldCheck />} title="No custom roles" description="Built-in roles cover most teams. Create one when a job needs a different set of permissions." />
        )}
      </Card>
      <Card className="overflow-hidden">
        <CardHeader title="Built-in roles" />
        <ul className="divide-y divide-border border-t border-border">
          {cat.data.builtin.map((b) => (
            <li key={b.key} className="px-4 py-3 text-[13px]">
              <p className="font-medium">
                {ROLE_LABELS[b.key]} {b.scopable ? <StatusPill dot={false}>can be limited to groups</StatusPill> : null}
              </p>
              <p className="mt-1 text-xs text-fg-muted">{b.permissions.join(" · ")}</p>
            </li>
          ))}
        </ul>
      </Card>
      {editing ? <RoleDialog role={editing === "new" ? null : editing} catalog={cat.data} onClose={() => setEditing(null)} /> : null}
      <ConfirmAction
        open={!!deleting}
        onOpenChange={(o) => !o && setDeleting(null)}
        title={`Delete "${deleting?.name}"?`}
        effects={[`${pluralize(deleting?.holders ?? 0, "person")} lose${deleting?.holders === 1 ? "s" : ""} it at once`]}
        confirmLabel="Delete role"
        danger
        askReason={false}
        onConfirm={async () => {
          const r = await withStepUp(() => unwrap(api.DELETE("/v1/roles/{id}", { params: { path: { id: deleting!.id } } })));
          qc.setQueryData(["roles"], r);
          toast.success("Role deleted");
        }}
      />
    </>
  );
}

function RoleDialog({ role, catalog, onClose }: { role: CustomRole | null; catalog: Catalog; onClose: () => void }) {
  const qc = useQueryClient();
  const withStepUp = useStepUp();
  const [name, setName] = useState(role?.name ?? "");
  const [description, setDescription] = useState(role?.description ?? "");
  const [perms, setPerms] = useState<Set<Perm>>(new Set(role?.permissions ?? []));
  const save = useMutation({
    mutationFn: () => {
      const body = { name: name.trim(), description, permissions: [...perms] };
      return withStepUp(() => (role ? unwrap(api.PATCH("/v1/roles/{id}", { params: { path: { id: role.id } }, body })) : unwrap(api.POST("/v1/roles", { body }))));
    },
    onSuccess: (r) => (qc.setQueryData(["roles"], r), toast.success(role ? "Role saved: it applies to everyone with it now" : "Role created"), onClose()),
  });
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent title={role ? `Edit ${role.name}` : "New role"} className="max-w-2xl">
        <div className="space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <Field label="Name" htmlFor="role-name">
              <Input id="role-name" value={name} maxLength={60} onChange={(e) => setName(e.target.value)} placeholder="Device operator" />
            </Field>
            <Field label="Description" htmlFor="role-desc">
              <Input id="role-desc" value={description} maxLength={300} onChange={(e) => setDescription(e.target.value)} placeholder="IT staff who handle laptops" />
            </Field>
          </div>
          <div className="grid max-h-80 grid-cols-2 gap-3 overflow-y-auto rounded-md border border-border p-3 md:grid-cols-3">
            {byArea(catalog.permissions).map(([area, ps]) => (
              <fieldset key={area}>
                <legend className="mb-1 text-xs font-semibold capitalize">{area.replace("_", " ")}</legend>
                {ps.map((p) => (
                  <label key={p.key} className={`flex items-center gap-1.5 text-xs ${p.in_custom_roles ? "" : "opacity-50"}`} title={p.in_custom_roles ? (p.scopable ? "Can be limited to groups" : "") : "Owners only"}>
                    <input type="checkbox" disabled={!p.in_custom_roles} checked={perms.has(p.key)} onChange={() => setPerms((s) => toggled(s, p.key))} />
                    <code className="font-mono">{p.key}</code>
                  </label>
                ))}
              </fieldset>
            ))}
          </div>
          <ErrorBanner error={save.error} />
          <div className="flex justify-end gap-2 border-t border-border pt-4">
            <Button variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button variant="primary" disabled={!name.trim() || !perms.size} loading={save.isPending} onClick={() => save.mutate()}>
              {role ? "Save role" : "Create role"}
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
