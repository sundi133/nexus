"use client";

import type { Schemas } from "@nexus/api-client";
import { useQuery } from "@tanstack/react-query";
import { Plus, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Select } from "@/components/ui/input";
import { StatusPill } from "@/components/ui/misc";
import { api, unwrap } from "@/lib/api";
import { ROLE_LABELS } from "@/lib/utils";

export type GrantDraft = { role: string; scope_group_ids: string[] };
type Grant = Schemas["RoleGrant"];

export const useRoleGrants = (userId: string, enabled: boolean) =>
  useQuery({ queryKey: ["role-grants", userId], queryFn: () => unwrap(api.GET("/v1/users/{id}/role-grants", { params: { path: { id: userId } } })), enabled });

/** Custom roles, and built-in roles limited to groups (RBAC v2). */
export function GrantsBadges({ grants }: { grants: Grant[] }) {
  if (!grants.length) return null;
  return (
    <span className="flex flex-wrap gap-1">
      {grants.map((g) => (
        <StatusPill key={g.id} tone="primary" dot={false}>
          {g.role.startsWith("custom:") ? g.name : (ROLE_LABELS[g.role as keyof typeof ROLE_LABELS] ?? g.name)}
          {g.scope.length ? ` · ${g.scope.map((s) => s.name).join(", ")}` : ""}
        </StatusPill>
      ))}
    </span>
  );
}

export function GrantsEditor({ value, onChange }: { value: GrantDraft[]; onChange: (v: GrantDraft[]) => void }) {
  const roles = useQuery({ queryKey: ["roles"], queryFn: () => unwrap(api.GET("/v1/roles")) });
  const groups = useQuery({ queryKey: ["groups", "all-for-picker"], queryFn: () => unwrap(api.GET("/v1/groups", { params: { query: { limit: 200 } } })) });
  const options = [
    ...(["helpdesk", "security_analyst", "readonly"] as const).map((r) => ({ key: r, label: `${ROLE_LABELS[r]} (for groups)` })),
    ...(roles.data?.custom ?? []).map((r) => ({ key: `custom:${r.id}`, label: r.name })),
  ];
  const used = new Set(value.map((g) => g.role));
  const set = (i: number, g: Partial<GrantDraft>) => onChange(value.map((x, j) => (j === i ? { ...x, ...g } : x)));
  return (
    <div className="space-y-2">
      {value.map((g, i) => {
        const builtin = !g.role.startsWith("custom:");
        return (
          <div key={i} className="rounded-md border border-border p-2.5 text-[13px]">
            <div className="flex items-center gap-2">
              <Select aria-label="Role" className="flex-1" value={g.role} onChange={(e) => set(i, { role: e.target.value })}>
                {options
                  .filter((o) => o.key === g.role || !used.has(o.key))
                  .map((o) => (
                    <option key={o.key} value={o.key}>
                      {o.label}
                    </option>
                  ))}
              </Select>
              <Button size="sm" variant="ghost" aria-label="Remove" onClick={() => onChange(value.filter((_, j) => j !== i))}>
                <X />
              </Button>
            </div>
            <p className="mb-1 mt-2 text-xs text-fg-muted">{builtin ? "Only for people in:" : "Limit to people in (leave empty for everyone):"}</p>
            <div className="flex max-h-28 flex-wrap gap-x-3 gap-y-1 overflow-y-auto">
              {(groups.data?.data ?? []).map((gr) => (
                <label key={gr.id} className="flex items-center gap-1.5 text-xs">
                  <input
                    type="checkbox"
                    checked={g.scope_group_ids.includes(gr.id)}
                    onChange={(e) => set(i, { scope_group_ids: e.target.checked ? [...g.scope_group_ids, gr.id] : g.scope_group_ids.filter((x) => x !== gr.id) })}
                  />
                  {gr.name}
                </label>
              ))}
            </div>
          </div>
        );
      })}
      {options.some((o) => !used.has(o.key)) ? (
        <Button size="sm" onClick={() => onChange([...value, { role: options.find((o) => !used.has(o.key))!.key, scope_group_ids: [] }])}>
          <Plus /> Add a custom or group-limited role
        </Button>
      ) : null}
      <p className="text-xs text-fg-subtle">Within groups, a role acts only on those people and their devices; everything else in it that would reach beyond them doesn&apos;t apply.</p>
    </div>
  );
}

export const grantsReady = (v: GrantDraft[]) => v.every((g) => g.role.startsWith("custom:") || g.scope_group_ids.length > 0);
