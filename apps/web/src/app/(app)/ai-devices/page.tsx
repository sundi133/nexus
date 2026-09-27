"use client";

import type { Schemas } from "@nexus/api-client";
import { useQuery } from "@tanstack/react-query";
import { BrainCircuit, ChevronDown, ChevronRight } from "lucide-react";
import Link from "next/link";
import { Fragment, useState } from "react";
import { GOVERNANCE, GovernancePill, SecretFlag, TOOL_KIND } from "@/components/features/ai-bits";
import { Card, CardHeader, EmptyState, ErrorBanner, PageHeader, Skeleton } from "@/components/ui/misc";
import { Table, TD, TH, THead, TR } from "@/components/ui/table";
import { api, unwrap } from "@/lib/api";
import { cn, pluralize } from "@/lib/utils";

type Server = Schemas["FleetMcpServer"];

export default function AIDevicesPage() {
  const inv = useQuery({ queryKey: ["ai-inventory"], queryFn: () => unwrap(api.GET("/v1/devices/ai-inventory")), refetchInterval: 60_000 });
  const [filter, setFilter] = useState<"all" | "attention">("attention");

  if (inv.isPending) return <Skeleton className="h-64" />;
  if (!inv.data) return <ErrorBanner error={inv.error} />;
  const { summary: s, servers, tools } = inv.data;
  const attention = servers.filter((x) => x.governance === "bypass" || x.governance === "remote" || x.inline_secrets > 0);
  const shown = filter === "attention" ? attention : servers;

  return (
    <>
      <PageHeader
        title="AI on devices"
        description="The AI tools people run and the MCP servers they connect them to, found by the Nexus agent in Claude, Cursor, VS Code, Codex and other AI clients. Nexus reads only which servers are configured: never prompts, files or secret values."
      />
      <div className="mb-5 grid grid-cols-2 gap-3 sm:grid-cols-5">
        <Stat n={s.reporting} label={`of ${pluralize(s.devices, "device")} reporting`} />
        <Stat n={s.with_ai_tools} label="with AI tools" />
        <Stat n={s.with_mcp} label="with MCP servers" />
        <Stat n={s.ungoverned} label="use ungoverned MCP" tone={s.ungoverned ? "warning" : undefined} />
        <Stat n={s.inline_secrets} label="have tokens in config files" tone={s.inline_secrets ? "danger" : undefined} />
      </div>

      {s.reporting === 0 ? (
        <Card>
          <EmptyState
            icon={<BrainCircuit className="size-5" />}
            title="No AI reports yet"
            description="Devices report their AI tools once they run a recent Nexus agent. Update agents under Agent updates."
          />
        </Card>
      ) : (
        <div className="space-y-5">
          <Card className="overflow-hidden">
            <CardHeader
              title="MCP servers"
              description="Each server once, however many devices use it. Route servers through the Nexus gateway (MCP servers page) so tool calls follow policy and land in the audit log."
              actions={
                <div className="inline-flex shrink-0 rounded-md border border-border p-0.5" role="radiogroup" aria-label="Which servers">
                  {(
                    [
                      ["attention", `Needs attention (${attention.length})`],
                      ["all", `All (${servers.length})`],
                    ] as const
                  ).map(([v, label]) => (
                    <button key={v} type="button" role="radio" aria-checked={filter === v} onClick={() => setFilter(v)} className={cn("whitespace-nowrap rounded px-2.5 py-1 text-xs font-medium", filter === v ? "bg-primary text-white" : "text-fg-muted hover:bg-bg-subtle")}>
                      {label}
                    </button>
                  ))}
                </div>
              }
            />
            {shown.length ? <ServerTable servers={shown} /> : <EmptyState title="Nothing needs attention" description="Every MCP server in use goes through the Nexus gateway, runs locally, or is on an allowed host." />}
          </Card>

          <Card className="overflow-hidden">
            <CardHeader title="AI tools" description="Apps, command-line tools and editor extensions, by how many devices have them." />
            {tools.length ? (
              <Table>
                <THead>
                  <tr>
                    <TH>Tool</TH>
                    <TH>Kind</TH>
                    <TH className="text-right">Devices</TH>
                    <TH>Versions seen</TH>
                  </tr>
                </THead>
                <tbody>
                  {tools.map((t) => (
                    <TR key={`${t.name}-${t.kind}`}>
                      <TD className="font-medium">{t.name}</TD>
                      <TD className="text-fg-muted">{TOOL_KIND[t.kind]}</TD>
                      <TD className="text-right tabular-nums">{t.devices}</TD>
                      <TD className="font-mono text-xs text-fg-muted">{t.versions.join(", ") || "—"}</TD>
                    </TR>
                  ))}
                </tbody>
              </Table>
            ) : (
              <EmptyState title="No AI tools found" />
            )}
          </Card>
        </div>
      )}
    </>
  );
}

function ServerTable({ servers }: { servers: Server[] }) {
  const [open, setOpen] = useState<string | null>(null);
  return (
    <Table>
      <THead>
        <tr>
          <TH className="w-8" />
          <TH>Connects to</TH>
          <TH>Named</TH>
          <TH>Clients</TH>
          <TH className="text-right">Devices</TH>
          <TH>Status</TH>
        </tr>
      </THead>
      <tbody>
        {servers.map((x) => (
          <Fragment key={x.key}>
            <TR className="cursor-pointer" onClick={() => setOpen(open === x.key ? null : x.key)}>
              <TD>
                <button type="button" aria-expanded={open === x.key} aria-label={`Devices using ${x.target}`} className="text-fg-muted">
                  {open === x.key ? <ChevronDown className="size-4" /> : <ChevronRight className="size-4" />}
                </button>
              </TD>
              <TD>
                <code className="font-mono text-xs">{x.target}</code>
                {x.transport === "stdio" ? <span className="ml-1.5 text-xs text-fg-subtle">runs locally</span> : null}
              </TD>
              <TD className="text-fg-muted">{x.names.join(", ")}</TD>
              <TD className="text-fg-muted">{x.clients.join(", ")}</TD>
              <TD className="text-right tabular-nums">
                {x.devices}
                <span className="block text-xs text-fg-subtle">{pluralize(x.people, "person")}</span>
              </TD>
              <TD>
                <div className="flex flex-col items-start gap-1">
                  <GovernancePill governance={x.governance} via={x.via} />
                  {x.inline_secrets ? <span className="text-xs text-danger">{pluralize(x.inline_secrets, "device")} with a token in config</span> : null}
                </div>
              </TD>
            </TR>
            {open === x.key ? (
              <tr className="border-b border-border bg-bg-subtle/60">
                <td />
                <td colSpan={5} className="px-3 py-2">
                  {x.governance === "bypass" ? <p className="mb-2 text-xs text-fg-muted">{GOVERNANCE.bypass.help}: point these clients at the gateway URL for {x.via} instead.</p> : null}
                  <ul className="space-y-1 text-[13px]">
                    {x.on.map((o) => (
                      <li key={o.device_id} className="flex flex-wrap items-center gap-2">
                        <Link href={`/devices/${o.device_id}`} className="font-medium hover:underline">
                          {o.hostname}
                        </Link>
                        <span className="text-fg-muted">{o.user_email ?? "no user assigned"}</span>
                        <span className="text-fg-subtle">· {o.clients.join(", ")}</span>
                        {o.inline_secrets ? <SecretFlag /> : null}
                      </li>
                    ))}
                  </ul>
                </td>
              </tr>
            ) : null}
          </Fragment>
        ))}
      </tbody>
    </Table>
  );
}

function Stat({ n, label, tone }: { n: number; label: string; tone?: "warning" | "danger" }) {
  return (
    <div className="rounded-md bg-bg-subtle px-3 py-2">
      <p className={cn("text-lg font-semibold tabular-nums", tone === "warning" && "text-warning", tone === "danger" && "text-danger")}>{n.toLocaleString()}</p>
      <p className="text-xs text-fg-muted">{label}</p>
    </div>
  );
}
