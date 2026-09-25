"use client";

import type { Schemas } from "@nexus/api-client";
import { useQuery } from "@tanstack/react-query";
import { Plus, X } from "lucide-react";
import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { Input, Select } from "@/components/ui/input";
import { api, unwrap } from "@/lib/api";
import { pluralize } from "@/lib/utils";

export type GroupRule = Schemas["GroupRule"];
type Condition = GroupRule["conditions"][number];

export const ATTRIBUTE_LABELS: Record<Condition["attribute"], string> = {
  email: "Email",
  email_domain: "Email domain",
  department: "Department",
  title: "Title",
  given_name: "First name",
  family_name: "Last name",
  manager_id: "Manager",
  source: "Comes from",
};
const OP_LABELS: Record<Condition["op"], string> = {
  equals: "is",
  not_equals: "is not",
  contains: "contains",
  starts_with: "starts with",
  ends_with: "ends with",
  in: "is one of",
  is_empty: "is empty",
  is_not_empty: "is not empty",
};
const SOURCES = [
  ["none", "Nexus (no directory)"],
  ["google", "Google Workspace"],
  ["entra", "Microsoft Entra ID"],
  ["scim", "SCIM"],
] as const;

export const emptyRule = (): GroupRule => ({ match: "all", conditions: [{ attribute: "department", op: "equals", value: "" }] });

const complete = (c: Condition) => (c.op === "in" ? !!c.values?.length : c.op === "is_empty" || c.op === "is_not_empty" ? true : !!c.value?.trim());
export const ruleComplete = (r: GroupRule) => r.conditions.length > 0 && r.conditions.every(complete);

/** Plain-language summary, e.g. "Department is Engineering and Email domain is acme.com". */
export function describeRule(r: GroupRule, people?: Map<string, string>) {
  return r.conditions
    .map((c) => {
      const v = c.op === "in" ? (c.values ?? []).join(", ") : c.attribute === "manager_id" ? (people?.get(c.value ?? "") ?? "someone") : c.attribute === "source" ? (SOURCES.find(([k]) => k === c.value)?.[1] ?? c.value) : c.value;
      return `${ATTRIBUTE_LABELS[c.attribute]} ${OP_LABELS[c.op]}${c.op === "is_empty" || c.op === "is_not_empty" ? "" : ` ${v}`}`;
    })
    .join(r.match === "all" ? " and " : " or ");
}

function useDebounced<T>(value: T, ms = 350) {
  const [v, setV] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setV(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return v;
}

/** Edits a dynamic group rule and previews, live, who it matches. */
export function RuleBuilder({ rule, onChange, groupId }: { rule: GroupRule; onChange: (r: GroupRule) => void; groupId?: string }) {
  const users = useQuery({ queryKey: ["users", "all-for-picker"], queryFn: () => unwrap(api.GET("/v1/users", { params: { query: { limit: 200 } } })) });
  const set = (i: number, c: Partial<Condition>) => onChange({ ...rule, conditions: rule.conditions.map((x, j) => (j === i ? { ...x, ...c } : x)) });
  const debounced = useDebounced(rule);
  const ready = ruleComplete(debounced);
  const preview = useQuery({
    queryKey: ["group-rule-preview", groupId, debounced],
    queryFn: () => unwrap(api.POST("/v1/groups/rule-preview", { body: { rule: debounced, group_id: groupId } })),
    enabled: ready,
    placeholderData: (prev) => prev,
  });

  return (
    <div className="space-y-3">
      <p className="flex flex-wrap items-center gap-2 text-[13px]">
        Everyone who matches
        <Select aria-label="Match" value={rule.match} onChange={(e) => onChange({ ...rule, match: e.target.value as GroupRule["match"] })}>
          <option value="all">all</option>
          <option value="any">any</option>
        </Select>
        of these:
      </p>
      <ul className="space-y-2">
        {rule.conditions.map((c, i) => (
          <li key={i} className="flex flex-wrap items-center gap-2">
            <Select
              aria-label="Attribute"
              value={c.attribute}
              onChange={(e) => set(i, { attribute: e.target.value as Condition["attribute"], op: "equals", value: e.target.value === "source" ? "none" : "", values: undefined })}
            >
              {Object.entries(ATTRIBUTE_LABELS).map(([k, l]) => (
                <option key={k} value={k}>
                  {l}
                </option>
              ))}
            </Select>
            <Select aria-label="Operator" value={c.op} onChange={(e) => set(i, { op: e.target.value as Condition["op"], values: e.target.value === "in" ? (c.value ? [c.value] : []) : undefined })}>
              {Object.entries(OP_LABELS)
                .filter(([k]) => !(c.attribute === "manager_id" || c.attribute === "source") || ["equals", "not_equals", "is_empty", "is_not_empty"].includes(k))
                .map(([k, l]) => (
                  <option key={k} value={k}>
                    {l}
                  </option>
                ))}
            </Select>
            {c.op === "is_empty" || c.op === "is_not_empty" ? null : c.attribute === "manager_id" ? (
              <Select aria-label="Manager" className="min-w-48 flex-1" value={c.value ?? ""} onChange={(e) => set(i, { value: e.target.value })}>
                <option value="">Choose…</option>
                {(users.data?.data ?? []).map((u) => (
                  <option key={u.id} value={u.id}>
                    {u.display_name} ({u.email})
                  </option>
                ))}
              </Select>
            ) : c.attribute === "source" ? (
              <Select aria-label="Source" className="min-w-48 flex-1" value={c.value ?? "none"} onChange={(e) => set(i, { value: e.target.value })}>
                {SOURCES.map(([k, l]) => (
                  <option key={k} value={k}>
                    {l}
                  </option>
                ))}
              </Select>
            ) : c.op === "in" ? (
              <Input
                aria-label="Values"
                className="min-w-48 flex-1"
                placeholder="Sales, Marketing"
                value={(c.values ?? []).join(", ")}
                onChange={(e) => set(i, { values: e.target.value.split(",").map((x) => x.trim()).filter(Boolean) })}
              />
            ) : (
              <Input aria-label="Value" className="min-w-48 flex-1" placeholder={c.attribute === "email_domain" ? "acme.com" : c.attribute === "department" ? "Engineering" : ""} value={c.value ?? ""} maxLength={200} onChange={(e) => set(i, { value: e.target.value })} />
            )}
            <Button size="sm" variant="ghost" aria-label="Remove condition" disabled={rule.conditions.length === 1} onClick={() => onChange({ ...rule, conditions: rule.conditions.filter((_, j) => j !== i) })}>
              <X />
            </Button>
          </li>
        ))}
      </ul>
      {rule.conditions.length < 20 ? (
        <Button size="sm" onClick={() => onChange({ ...rule, conditions: [...rule.conditions, { attribute: "department", op: "equals", value: "" }] })}>
          <Plus /> Add condition
        </Button>
      ) : null}
      <div className="rounded-md border border-border bg-bg-subtle px-3 py-2.5 text-[13px]" aria-live="polite">
        {!ready ? (
          <span className="text-fg-muted">Fill in every condition to see who matches.</span>
        ) : preview.data ? (
          <>
            <p className="font-medium">
              Matches {pluralize(preview.data.count, "person")}
              {groupId && (preview.data.adds || preview.data.removes) ? (
                <span className="font-normal text-fg-muted">
                  {" "}
                  · adds {preview.data.adds}, removes {preview.data.removes}
                </span>
              ) : groupId ? (
                <span className="font-normal text-fg-muted"> · no change to members</span>
              ) : null}
            </p>
            {preview.data.sample.length ? (
              <p className="mt-0.5 text-xs text-fg-muted">
                {preview.data.sample.map((u) => u.name).join(", ")}
                {preview.data.count > preview.data.sample.length ? `, and ${preview.data.count - preview.data.sample.length} more` : ""}
              </p>
            ) : null}
          </>
        ) : (
          <span className="text-fg-muted">Checking…</span>
        )}
      </div>
      <p className="text-xs text-fg-subtle">Matching ignores case. Offboarded people and break-glass accounts are never members. Membership updates within a minute of people changing.</p>
    </div>
  );
}
