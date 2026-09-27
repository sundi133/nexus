"use client";

import type { Session } from "@nexus/api-client";
import { Button } from "@/components/ui/button";
import { Table, TD, TH, THead, TR } from "@/components/ui/table";
import { formatDateTime, timeAgo } from "@/lib/utils";

export function SessionsTable({ sessions, onRevoke }: { sessions: Session[]; onRevoke?: (id: string) => void }) {
  return (
    <Table>
      <THead>
        <tr>
          <TH>Client</TH>
          <TH>IP address</TH>
          <TH className="hidden md:table-cell">Signed in</TH>
          <TH>Last seen</TH>
          {onRevoke ? <TH /> : null}
        </tr>
      </THead>
      <tbody>
        {sessions.map((s) => (
          <TR key={s.id}>
            <TD>
              <span className="font-medium capitalize">{s.client}</span>
              {s.current ? <span className="ml-2 text-xs text-success">This session</span> : null}
              <p className="max-w-xs truncate text-xs text-fg-subtle" title={s.user_agent}>
                {s.user_agent || "Unknown device"}
              </p>
            </TD>
            <TD className="font-mono text-xs">{s.ip || "—"}</TD>
            <TD className="hidden text-fg-muted md:table-cell">{formatDateTime(s.created_at)}</TD>
            <TD className="text-fg-muted">{timeAgo(s.last_seen_at)}</TD>
            {onRevoke ? (
              <TD className="text-right">
                {!s.current ? (
                  <Button size="sm" variant="ghost" onClick={() => onRevoke(s.id)}>
                    Sign out
                  </Button>
                ) : null}
              </TD>
            ) : null}
          </TR>
        ))}
      </tbody>
    </Table>
  );
}

