"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card, CardHeader } from "@/components/ui/misc";
import { api, unwrap } from "@/lib/api";
import { timeAgo } from "@/lib/utils";

/** The AI clients (Cursor, Claude, VS Code…) I've connected to MCP servers through Nexus. */
export function MyAIClientsCard() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["mcp-connections"], queryFn: () => unwrap(api.GET("/v1/me/mcp-connections")) });
  const disconnect = useMutation({
    mutationFn: (id: string) => unwrap(api.DELETE("/v1/me/mcp-connections/{id}", { params: { path: { id } } })),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["mcp-connections"] });
      toast.success("Disconnected: it'll ask you to sign in again");
    },
  });
  if (!q.data?.data.length) return null;
  return (
    <Card className="overflow-hidden">
      <CardHeader title="AI clients" description="Connected to MCP servers through Nexus, as you. Signing out everywhere disconnects them too." />
      <ul className="divide-y divide-border">
        {q.data.data.map((c) => (
          <li key={c.id} className="flex items-center justify-between gap-3 px-4 py-2.5 text-[13px]">
            <span className="min-w-0">
              <span className="font-medium">{c.client}</span>
              <span className="block truncate font-mono text-[11px] text-fg-muted">{c.resource}</span>
              <span className="block text-xs text-fg-subtle">Connected {timeAgo(c.created_at)} · last used {timeAgo(c.last_used_at)}</span>
            </span>
            <Button size="sm" onClick={() => disconnect.mutate(c.id)} loading={disconnect.isPending && disconnect.variables === c.id}>
              Disconnect
            </Button>
          </li>
        ))}
      </ul>
    </Card>
  );
}
