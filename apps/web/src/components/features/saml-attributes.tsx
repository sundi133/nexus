"use client";

import type { Schemas } from "@nexus/api-client";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus, X } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input, Select } from "@/components/ui/input";
import { Card, CardHeader, ErrorBanner } from "@/components/ui/misc";
import { api, unwrap } from "@/lib/api";

type Attr = Schemas["SamlAttribute"];
const SOURCES: { value: Attr["source"]; label: string }[] = [
  { value: "email", label: "Email" },
  { value: "given_name", label: "First name" },
  { value: "family_name", label: "Last name" },
  { value: "display_name", label: "Display name" },
  { value: "user_id", label: "User ID" },
  { value: "department", label: "Department" },
  { value: "title", label: "Title" },
  { value: "groups", label: "Groups (multi-valued)" },
  { value: "static", label: "Fixed value…" },
];

/** Which attributes the app receives in each SAML assertion, and where the values come from. */
export function SamlAttributesEditor({ appId, attributes, editable }: { appId: string; attributes: Attr[]; editable: boolean }) {
  const qc = useQueryClient();
  const [rows, setRows] = useState<Attr[]>(attributes);
  const dirty = JSON.stringify(rows) !== JSON.stringify(attributes);
  const save = useMutation({
    mutationFn: () => unwrap(api.PATCH("/v1/apps/{id}", { params: { path: { id: appId } }, body: { saml: { attributes: rows } } })),
    onSuccess: (a) => {
      qc.setQueryData(["app", appId], a);
      qc.invalidateQueries({ queryKey: ["audit"] });
      toast.success("Attribute mapping saved");
    },
    onError: () => {},
  });
  const update = (i: number, patch: Partial<Attr>) => setRows(rows.map((r, j) => (j === i ? { ...r, ...patch } : r)));

  return (
    <Card className="lg:col-span-2">
      <CardHeader
        title="Attributes sent to the app"
        description="Each sign-in includes these SAML attributes. Empty values are left out."
        actions={
          editable && dirty ? (
            <div className="flex gap-2">
              <Button size="sm" onClick={() => setRows(attributes)}>
                Discard
              </Button>
              <Button size="sm" variant="primary" loading={save.isPending} onClick={() => save.mutate()}>
                Save mapping
              </Button>
            </div>
          ) : null
        }
      />
      <div className="space-y-2 p-4">
        <ErrorBanner error={save.error} />
        {rows.length === 0 ? <p className="text-[13px] text-fg-muted">No attributes: the app only receives the NameID.</p> : null}
        {rows.map((r, i) => (
          <div key={i} className="grid grid-cols-[1fr_1fr_auto] items-center gap-2 sm:grid-cols-[1.2fr_1fr_1.2fr_auto]">
            <Input aria-label="Attribute name" value={r.name} disabled={!editable} onChange={(e) => update(i, { name: e.target.value })} className="font-mono text-xs" />
            <Select aria-label="Value source" value={r.source} disabled={!editable} onChange={(e) => update(i, { source: e.target.value as Attr["source"] })}>
              {SOURCES.map((s) => (
                <option key={s.value} value={s.value}>
                  {s.label}
                </option>
              ))}
            </Select>
            {r.source === "static" ? (
              <Input aria-label="Fixed value" value={r.value ?? ""} disabled={!editable} onChange={(e) => update(i, { value: e.target.value })} className="col-span-2 font-mono text-xs sm:col-span-1" placeholder="value" />
            ) : (
              <span className="hidden sm:block" />
            )}
            {editable ? (
              <Button size="icon" variant="ghost" aria-label={`Remove ${r.name}`} onClick={() => setRows(rows.filter((_, j) => j !== i))}>
                <X />
              </Button>
            ) : null}
          </div>
        ))}
        {editable ? (
          <Button size="sm" variant="ghost" onClick={() => setRows([...rows, { name: "", source: "email" }])}>
            <Plus /> Add attribute
          </Button>
        ) : null}
      </div>
    </Card>
  );
}
