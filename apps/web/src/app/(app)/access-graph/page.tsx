"use client";

import type { Schemas } from "@nexus/api-client";
import { useQuery } from "@tanstack/react-query";
import { Network } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { Card, CardHeader, EmptyState, ErrorBanner, PageHeader, Skeleton, StatusPill, type Tone } from "@/components/ui/misc";
import { api, unwrap } from "@/lib/api";
import { cn, pluralize } from "@/lib/utils";

type Person = Schemas["PersonRisk"];
const LEVEL: Record<Person["level"], { label: string; tone: Tone }> = {
  critical: { label: "Critical", tone: "danger" },
  high: { label: "High", tone: "danger" },
  medium: { label: "Medium", tone: "warning" },
  low: { label: "Low", tone: "success" },
};

export default function AccessGraphPage() {
  const people = useQuery({ queryKey: ["risk-people"], queryFn: () => unwrap(api.GET("/v1/risk/people")) });
  const [selected, setSelected] = useState<string | null>(null);
  const current = selected ?? people.data?.data[0]?.user_id ?? null;

  return (
    <>
      <PageHeader
        title="Access graph"
        description="Who can do what with AI: each person, their devices, the AI clients and MCP servers on them, the AI agents they own, and the tools those reach through the Nexus gateway. Scores add up named reasons, so each one says what to fix."
      />
      {people.isPending ? (
        <Skeleton className="h-64" />
      ) : !people.data ? (
        <ErrorBanner error={people.error} />
      ) : (
        <div className="grid gap-5 lg:grid-cols-[20rem_1fr]">
          <Card className="max-h-[32rem] self-start overflow-y-auto">
            <ul className="divide-y divide-border" aria-label="People by risk">
              {people.data.data.map((p) => (
                <li key={p.user_id}>
                  <button
                    type="button"
                    aria-current={current === p.user_id}
                    onClick={() => setSelected(p.user_id)}
                    className={cn("flex w-full items-start gap-3 px-4 py-2.5 text-left hover:bg-bg-subtle", current === p.user_id && "bg-primary-soft/50")}
                  >
                    <span className={cn("mt-0.5 w-8 shrink-0 text-right text-sm font-semibold tabular-nums", p.level === "critical" || p.level === "high" ? "text-danger" : p.level === "medium" ? "text-warning" : "text-fg-muted")}>{p.score}</span>
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-[13px] font-medium">{p.name}</span>
                      <span className="block truncate text-xs text-fg-subtle">{p.factors[0]?.title ?? "Nothing to fix"}</span>
                    </span>
                    <StatusPill tone={LEVEL[p.level].tone}>{LEVEL[p.level].label}</StatusPill>
                  </button>
                </li>
              ))}
            </ul>
          </Card>
          {current ? <PersonGraph userId={current} /> : <EmptyState title="No people yet" />}
        </div>
      )}
      {current ? <GraphCard userId={current} /> : null}
    </>
  );
}

function PersonGraph({ userId }: { userId: string }) {
  const g = useQuery({ queryKey: ["risk-graph", userId], queryFn: () => unwrap(api.GET("/v1/risk/people/{id}/graph", { params: { path: { id: userId } } })) });
  if (g.isPending) return <Skeleton className="h-96" />;
  if (!g.data) return <ErrorBanner error={g.error} />;
  const { person } = g.data;
  return (
    <div className="min-w-0">
      <Card>
        <CardHeader
          title={
            <span className="flex items-center gap-2">
              <Link href={`/users/${person.user_id}`} className="hover:underline">
                {person.name}
              </Link>
              <StatusPill tone={LEVEL[person.level].tone}>
                {LEVEL[person.level].label} · {person.score}
              </StatusPill>
            </span>
          }
          description={[person.email, pluralize(person.devices, "device"), pluralize(person.ai_clients, "AI client"), pluralize(person.mcp_servers, "MCP server"), `${pluralize(person.agents, "agent")} owned`].join(" · ")}
        />
        {person.factors.length ? (
          <ul className="divide-y divide-border">
            {person.factors.map((f) => (
              <li key={f.key} className="flex gap-3 px-4 py-2 text-[13px]">
                <span className="w-10 shrink-0 text-right font-semibold tabular-nums text-fg-muted">+{f.points}</span>
                <span className="min-w-0">
                  <span className="font-medium">{f.title}</span>
                  <span className="block text-xs text-fg-muted">{f.detail}</span>
                </span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="px-4 py-3 text-[13px] text-fg-muted">Nothing raises this person&apos;s risk.</p>
        )}
      </Card>
    </div>
  );
}

function GraphCard({ userId }: { userId: string }) {
  const g = useQuery({ queryKey: ["risk-graph", userId], queryFn: () => unwrap(api.GET("/v1/risk/people/{id}/graph", { params: { path: { id: userId } } })) });
  if (!g.data) return null;
  const { nodes, edges } = g.data;
  return (
    <Card className="mt-5 overflow-hidden">
      <CardHeader title="Graph" description="Green goes through the Nexus gateway (policy and audit apply); orange is ungoverned; red bypasses the gateway, holds a token in a config file, or reaches destructive tools. Click a box to open it." />
      {nodes.length > 1 ? <Graph nodes={nodes} edges={edges} /> : <EmptyState icon={<Network className="size-5" />} title="Nothing connected yet" description="No devices, AI clients or agents for this person." />}
    </Card>
  );
}

type GNode = { id: string; type: string; column: number; label: string; sublabel: string; tone: "neutral" | "success" | "warning" | "danger"; href?: string };
type GEdge = { from: string; to: string; label: string; tone: "neutral" | "success" | "warning" | "danger"; dashed?: boolean };

const COLUMNS = ["Person", "Devices", "AI clients · agents", "MCP servers", "Nexus gateway", "Tools"];
const W = 176;
const H = 48;
const GAP_X = 70;
const GAP_Y = 18;
const TOP = 34;
const STROKE: Record<GEdge["tone"], string> = { neutral: "var(--color-border-strong)", success: "var(--color-success)", warning: "var(--color-warning)", danger: "var(--color-danger)" };
const FILL: Record<GEdge["tone"], string> = { neutral: "var(--color-bg)", success: "var(--color-success-soft)", warning: "var(--color-warning-soft)", danger: "var(--color-danger-soft)" };

function Graph({ nodes, edges }: { nodes: GNode[]; edges: GEdge[] }) {
  const router = useRouter();
  const cols = [...new Set(nodes.map((n) => n.column))].sort((a, b) => a - b);
  const byCol = new Map(cols.map((c) => [c, nodes.filter((n) => n.column === c)]));
  const tallest = Math.max(...[...byCol.values()].map((ns) => ns.length));
  const height = TOP + tallest * (H + GAP_Y) + 10;
  const pos = new Map<string, { x: number; y: number }>();
  cols.forEach((c, i) => {
    const ns = byCol.get(c)!;
    const offset = ((tallest - ns.length) * (H + GAP_Y)) / 2;
    ns.forEach((n, j) => pos.set(n.id, { x: 10 + i * (W + GAP_X), y: TOP + offset + j * (H + GAP_Y) }));
  });
  const width = 20 + cols.length * (W + GAP_X) - GAP_X;
  return (
    <div className="overflow-x-auto p-4">
      <svg viewBox={`0 0 ${width} ${height}`} width="100%" style={{ maxWidth: width, minWidth: Math.min(width, 720) }} role="img" aria-label="Access graph" className="text-[11px]">
        {cols.map((c, i) => (
          <text key={c} x={10 + i * (W + GAP_X)} y={14} fill="var(--color-fg-muted)" className="font-medium">
            {COLUMNS[c]}
          </text>
        ))}
        {edges.map((e, i) => {
          const a = pos.get(e.from);
          const b = pos.get(e.to);
          if (!a || !b) return null;
          const x1 = a.x + W;
          const y1 = a.y + H / 2;
          const x2 = b.x;
          const y2 = b.y + H / 2;
          const mx = (x1 + x2) / 2;
          return (
            <g key={i}>
              <path d={`M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`} fill="none" stroke={STROKE[e.tone]} strokeWidth={e.tone === "neutral" ? 1.2 : 2} strokeDasharray={e.dashed ? "5 4" : undefined} />
              {e.label ? (
                <text x={mx} y={(y1 + y2) / 2 - 4} textAnchor="middle" fill="var(--color-fg-muted)" stroke="var(--color-bg)" strokeWidth={3} paintOrder="stroke">
                  {e.label.length > 22 ? `${e.label.slice(0, 21)}…` : e.label}
                </text>
              ) : null}
            </g>
          );
        })}
        {nodes.map((n) => {
          const p = pos.get(n.id)!;
          return (
            <g
              key={n.id}
              transform={`translate(${p.x},${p.y})`}
              onClick={() => n.href && router.push(n.href)}
              className={n.href ? "cursor-pointer" : undefined}
              role={n.href ? "link" : undefined}
              aria-label={`${n.label}: ${n.sublabel}`}
            >
              <title>{`${n.label}\n${n.sublabel}`}</title>
              <rect width={W} height={H} rx={8} fill={FILL[n.tone]} stroke={STROKE[n.tone]} strokeWidth={1.2} />
              <text x={10} y={20} fill="var(--color-fg)" className="text-[12px] font-medium">
                {n.label.length > 24 ? `${n.label.slice(0, 23)}…` : n.label}
              </text>
              <text x={10} y={36} fill="var(--color-fg-muted)">
                {n.sublabel.length > 30 ? `${n.sublabel.slice(0, 29)}…` : n.sublabel}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}
