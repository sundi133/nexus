import type { Schemas } from "@nexus/api-client";
import Link from "next/link";
import { EmptyState, StatusPill, type Tone } from "@/components/ui/misc";
import { Table, TD, TH, THead, TR } from "@/components/ui/table";
import { formatDateTime } from "@/lib/utils";

type Ev = Schemas["ProcessEvent"];
export const DETECTION: Record<NonNullable<Ev["detection"]>, { label: string; tone: Tone }> = {
  ai_network_tool: { label: "AI ran a network tool", tone: "danger" },
  ai_shell: { label: "AI started a shell", tone: "neutral" },
  exec_from_temp: { label: "Ran from temp/Downloads", tone: "warning" },
};
const base = (p: string) => p.split(/[\\/]/).pop() ?? p;

/** Program starts, newest first, each with its launch chain. */
export function ProcessEventsTable({ events, showDevice }: { events: Ev[]; showDevice?: boolean }) {
  if (!events.length) return <EmptyState title="No events" />;
  return (
    <Table>
      <THead>
        <tr>
          <TH>When</TH>
          {showDevice ? <TH>Device</TH> : null}
          <TH>Program</TH>
          <TH>Started by</TH>
          <TH>Finding</TH>
        </tr>
      </THead>
      <tbody>
        {events.map((e) => {
          const chain = [e.parent_path, ...e.ancestors].filter(Boolean).map(base);
          return (
            <TR key={e.id}>
              <TD className="whitespace-nowrap text-xs text-fg-muted">{formatDateTime(e.time)}</TD>
              {showDevice ? (
                <TD>
                  <Link href={`/devices/${e.device_id}`} className="font-medium hover:underline">
                    {e.hostname}
                  </Link>
                </TD>
              ) : null}
              <TD className="max-w-[20rem]">
                <span className="font-medium">{base(e.path)}</span>
                {e.user ? <span className="text-xs text-fg-subtle"> · {e.user}</span> : null}
                <code className="block truncate font-mono text-xs text-fg-muted" title={e.cmdline || e.path}>
                  {e.cmdline || e.path}
                </code>
              </TD>
              <TD className="max-w-[12rem] text-xs text-fg-muted">
                <span className="block truncate" title={[e.parent_path, ...e.ancestors].filter(Boolean).join(" ← ")}>
                  {chain.length ? chain.join(" ← ") : "—"}
                </span>
                {e.responsible_path ? <span className="block truncate text-fg-subtle">for {base(e.responsible_path)}</span> : null}
              </TD>
              <TD className="whitespace-nowrap">{e.detection ? <StatusPill tone={DETECTION[e.detection].tone}>{DETECTION[e.detection].label}</StatusPill> : null}</TD>
            </TR>
          );
        })}
      </tbody>
    </Table>
  );
}
