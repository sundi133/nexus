"use client";

import type { Schemas } from "@nexus/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { toast } from "sonner";
import { useStepUp } from "@/components/step-up";
import { Button } from "@/components/ui/button";
import { Select } from "@/components/ui/input";
import { Card, CardHeader, Skeleton } from "@/components/ui/misc";
import { api, unwrap } from "@/lib/api";
import { useCan } from "@/lib/queries";

const LABELS: [string, string][] = [
  ["secret", "API keys, tokens and passwords"],
  ["private_key", "Private keys"],
  ["credit_card", "Payment card numbers"],
  ["us_ssn", "US Social Security numbers"],
  ["iban", "Bank account numbers (IBAN)"],
  ["email_list", "Lists of email addresses"],
];
type Draft = Pick<Schemas["McpDataProtection"], "arguments" | "results" | "custom">;

/** What tool calls may carry out, and what AI may read back: for agents and people alike. */
export function McpDataProtectionCard() {
  const can = useCan();
  const editable = can("mcp:manage");
  const qc = useQueryClient();
  const withStepUp = useStepUp();
  const q = useQuery({ queryKey: ["mcp-dlp"], queryFn: () => unwrap(api.GET("/v1/mcp/data-protection")) });
  const [draft, setDraft] = useState<Draft | null>(null);
  useEffect(() => {
    if (q.data) setDraft({ arguments: q.data.arguments, results: q.data.results, custom: q.data.custom });
  }, [q.data]);
  const save = useMutation({
    mutationFn: () => withStepUp(() => unwrap(api.PUT("/v1/mcp/data-protection", { body: draft! }))),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["mcp-dlp"] });
      toast.success("Data protection saved: it applies to the next tool call");
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : "Couldn't save"),
  });
  const dirty = !!draft && !!q.data && JSON.stringify(draft) !== JSON.stringify({ arguments: q.data.arguments, results: q.data.results, custom: q.data.custom });
  return (
    <Card className="mt-4 overflow-hidden">
      <CardHeader
        title="Data protection for tool calls"
        description="Checked on every call through the gateway, for agents and people's AI clients. Arguments: what leaves for the tool (block stops the call). Results: what the AI is about to read (redact removes it first). Findings are in each call's audit record, never the data."
        actions={
          editable && dirty ? (
            <Button size="sm" variant="primary" onClick={() => save.mutate()} loading={save.isPending}>
              Save
            </Button>
          ) : null
        }
      />
      {!draft ? (
        <Skeleton className="m-4 h-32" />
      ) : (
        <table className="w-full text-[13px]">
          <thead>
            <tr className="text-left text-xs text-fg-muted">
              <th className="px-4 py-2 font-medium">Data</th>
              <th className="px-4 py-2 font-medium">In arguments</th>
              <th className="px-4 py-2 font-medium">In results</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {LABELS.map(([id, label]) => (
              <tr key={id}>
                <td className="px-4 py-2">{label}</td>
                <td className="px-4 py-2">
                  <Select aria-label={`${label} in arguments`} disabled={!editable} value={draft.arguments[id] ?? "off"} onChange={(e) => setDraft({ ...draft, arguments: { ...draft.arguments, [id]: e.target.value as "off" } })}>
                    <option value="off">Off</option>
                    <option value="monitor">Monitor</option>
                    <option value="block">Block the call</option>
                  </Select>
                </td>
                <td className="px-4 py-2">
                  <Select aria-label={`${label} in results`} disabled={!editable} value={draft.results[id] ?? "off"} onChange={(e) => setDraft({ ...draft, results: { ...draft.results, [id]: e.target.value as "off" } })}>
                    <option value="off">Off</option>
                    <option value="monitor">Monitor</option>
                    <option value="redact">Redact</option>
                  </Select>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Card>
  );
}
