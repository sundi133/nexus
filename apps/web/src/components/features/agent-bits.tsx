"use client";

import type { Schemas } from "@nexus/api-client";
import { StatusPill } from "@/components/ui/misc";

type Agent = Schemas["Agent"];

export const RISK_TONE = { low: "neutral", medium: "primary", high: "warning", critical: "danger" } as const;

export function AgentStatus({ a }: { a: Agent }) {
  if (a.status === "suspended") return <StatusPill tone="danger">Suspended</StatusPill>;
  if (a.owner && !a.owner.active) return <StatusPill tone="warning">Owner inactive</StatusPill>;
  if (a.stale) return <StatusPill tone="warning">Stale</StatusPill>;
  return <StatusPill tone="success">Active</StatusPill>;
}

export const MCP_RISK_TONE = { read: "neutral", write: "primary", external: "warning", destructive: "danger" } as const;
