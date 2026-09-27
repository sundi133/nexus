import { type Custom, redact, scan } from "@nexus/dlp";
import { z } from "@hono/zod-openapi";
import type { Tx } from "../platform/db.js";

/**
 * Data protection for MCP tool calls. Arguments are what leaves for the upstream tool (a secret
 * pasted into an issue, a customer list sent to a webhook): off, monitor, or block the call.
 * Results are what the AI is about to read (a query returning card numbers, a file with a
 * key): off, monitor, or redact before it gets them. The same detectors as the browser extension.
 */

export const DETECTOR_IDS = ["secret", "private_key", "credit_card", "us_ssn", "iban", "email_list"] as const;
export const ArgAction = z.enum(["off", "monitor", "block"]);
export const ResultAction = z.enum(["off", "monitor", "redact"]);
export type McpDlp = {
  arguments: Record<string, z.infer<typeof ArgAction>>;
  results: Record<string, z.infer<typeof ResultAction>>;
  custom: (Custom & { arguments: z.infer<typeof ArgAction>; results: z.infer<typeof ResultAction> })[];
};

export const DEFAULT_MCP_DLP: McpDlp = {
  arguments: { secret: "block", private_key: "block", credit_card: "off", us_ssn: "off", iban: "off", email_list: "off" },
  results: { secret: "redact", private_key: "redact", credit_card: "monitor", us_ssn: "monitor", iban: "off", email_list: "off" },
  custom: [],
};

export async function loadMcpDlp(tx: Tx): Promise<McpDlp> {
  const r = await tx.selectFrom("mcp_dlp_policies").selectAll().executeTakeFirst();
  return {
    arguments: { ...DEFAULT_MCP_DLP.arguments, ...((r?.arguments ?? {}) as McpDlp["arguments"]) },
    results: { ...DEFAULT_MCP_DLP.results, ...((r?.results ?? {}) as McpDlp["results"]) },
    custom: (r?.custom ?? []) as McpDlp["custom"],
  };
}

export type DlpNote = { detector: string; name: string; count: number; action: string };

/** Every string in a JSON value, with a way to replace it. */
function mapStrings(v: unknown, fn: (s: string) => string): unknown {
  if (typeof v === "string") return fn(v);
  if (Array.isArray(v)) return v.map((x) => mapStrings(x, fn));
  if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, mapStrings(x, fn)]));
  return v;
}

/** Checks a call's arguments. `block` names what was found when the call must not go out. */
export function checkArguments(p: McpDlp, args: Record<string, unknown>): { block: string | null; notes: DlpNote[] } {
  const on = Object.entries(p.arguments).filter(([, a]) => a !== "off").map(([k]) => k);
  const custom = p.custom.filter((c) => c.arguments !== "off");
  const texts: string[] = [];
  mapStrings(args, (s) => (texts.push(s), s));
  const actionOf = (d: string) => (d.startsWith("custom:") ? custom.find((c) => `custom:${c.id}` === d)?.arguments : p.arguments[d]) ?? "off";
  const findings = scan(texts.join("\n"), on, custom);
  const notes = findings.map((f) => ({ detector: f.detector, name: f.name, count: f.count, action: actionOf(f.detector) }));
  const blocked = notes.filter((n) => n.action === "block");
  return { block: blocked.length ? [...new Set(blocked.map((n) => n.name))].join(", ") : null, notes };
}

/** Redacts (and notes) sensitive data in a tool's result before the AI reads it. */
export function protectResult(p: McpDlp, result: unknown): { result: unknown; notes: DlpNote[] } {
  const redactOn = Object.entries(p.results).filter(([, a]) => a === "redact").map(([k]) => k);
  const monitorOn = Object.entries(p.results).filter(([, a]) => a === "monitor").map(([k]) => k);
  const customRedact = p.custom.filter((c) => c.results === "redact");
  const customMonitor = p.custom.filter((c) => c.results === "monitor");
  if (!redactOn.length && !monitorOn.length && !customRedact.length && !customMonitor.length) return { result, notes: [] };
  const counts = new Map<string, DlpNote>();
  const note = (f: { detector: string; name: string; count: number }, action: string) => {
    const k = `${f.detector}|${action}`;
    const cur = counts.get(k);
    if (cur) cur.count += f.count;
    else counts.set(k, { detector: f.detector, name: f.name, count: f.count, action });
  };
  const out = mapStrings(result, (s) => {
    const r = redact(s, redactOn, customRedact);
    for (const f of r.findings) note(f, "redact");
    for (const f of scan(r.text, monitorOn, customMonitor)) note(f, "monitor");
    return r.text;
  });
  return { result: out, notes: [...counts.values()] };
}
