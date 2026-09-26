import type { Schemas } from "@nexus/api-client";
import Link from "next/link";
import { EmptyState, StatusPill } from "@/components/ui/misc";
import { Table, TD, TH, THead, TR } from "@/components/ui/table";
import { timeAgo } from "@/lib/utils";

export const ACTION: Record<Schemas["EnforcementEvent"]["action"], { label: string; tone: "danger" | "warning" | "neutral" }> = {
  terminated: { label: "Stopped", tone: "danger" },
  would_terminate: { label: "Would stop", tone: "warning" },
  domain_blocked: { label: "Blocked", tone: "danger" },
  failed: { label: "Failed", tone: "neutral" },
};

export function EventsTable({ events, showDevice }: { events: Schemas["EnforcementEvent"][]; showDevice?: boolean }) {
  if (!events.length) return <EmptyState title="Nothing stopped yet" />;
  return (
    <Table>
      <THead>
        <tr>
          <TH>When</TH>
          {showDevice ? <TH>Device</TH> : null}
          <TH>Rule</TH>
          <TH>What</TH>
          <TH>Result</TH>
        </tr>
      </THead>
      <tbody>
        {events.map((e) => (
          <TR key={e.id}>
            <TD className="whitespace-nowrap text-fg-muted">{timeAgo(e.occurred_at)}</TD>
            {showDevice ? (
              <TD>
                <Link href={`/devices/${e.device_id}`} className="font-medium hover:underline">
                  {e.hostname}
                </Link>
              </TD>
            ) : null}
            <TD>{e.rule_name || <span className="text-fg-subtle">{e.action === "failed" ? "Device" : "removed rule"}</span>}</TD>
            <TD className="max-w-[26rem]">
              <code className="block truncate font-mono text-xs" title={e.subject}>
                {e.subject || "—"}
              </code>
              {e.user ? <span className="text-xs text-fg-subtle">as {e.user}</span> : null}
              {e.detail ? <span className="block text-xs text-fg-muted">{e.detail}</span> : null}
            </TD>
            <TD className="whitespace-nowrap">
              <StatusPill tone={ACTION[e.action].tone}>{ACTION[e.action].label}</StatusPill>
              {e.count > 1 ? <span className="ml-1 text-xs text-fg-muted">×{e.count}</span> : null}
            </TD>
          </TR>
        ))}
      </tbody>
    </Table>
  );
}

