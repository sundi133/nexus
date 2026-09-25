"use client";

import type { Schemas } from "@nexus/api-client";
import { StatusPill } from "@/components/ui/misc";

type Alert = Schemas["Alert"];

export const SEVERITY_TONE = { low: "neutral", medium: "primary", high: "warning", critical: "danger" } as const;

export function AlertStatus({ a }: { a: Alert }) {
  if (a.status === "resolved") return <StatusPill>{a.resolution ? a.resolution.replace("_", " ") : "Resolved"}</StatusPill>;
  if (a.snoozed_until) return <StatusPill>Snoozed</StatusPill>;
  return a.status === "acknowledged" ? <StatusPill tone="primary">Acknowledged</StatusPill> : <StatusPill tone="warning">Open</StatusPill>;
}
