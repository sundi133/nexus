import { createHash } from "node:crypto";

/**
 * MCP tool policy (SPEC MCP-04, MCP-10): risk classes and per-tool
 * authorization. Pure functions over rows, so the gateway, the what-if
 * simulator and tests share one implementation.
 */

export const RISKS = ["read", "write", "external", "destructive"] as const;
export type Risk = (typeof RISKS)[number];

export type ToolAnnotations = { readOnlyHint?: boolean; destructiveHint?: boolean; openWorldHint?: boolean; idempotentHint?: boolean; title?: string };

const DESTRUCTIVE = /(^|[_\-.\s])(delete|remove|drop|destroy|purge|wipe|erase|truncate|revoke|terminate|kill|reset|force[_-]?push|archive)([_\-.\s]|$)/i;
const EXTERNAL = /(^|[_\-.\s])(send|email|mail|post|publish|tweet|slack|message|notify|fetch|http|request|webhook|browse|download|upload|share|invite)([_\-.\s]|$)/i;
const WRITE = /(^|[_\-.\s])(create|update|write|set|put|patch|add|insert|edit|modify|merge|push|commit|move|rename|assign|approve|close|open|comment|run|exec|execute|deploy|trigger|start|stop|restart|install|transfer|pay|charge|refund)([_\-.\s]|$)/i;

/**
 * The risk class of a tool. The server's own annotations win when they're
 * explicit; otherwise the name (and then the description) decides. Unknown
 * tools default to "write": we'd rather over-classify than under-classify.
 */
export function classify(name: string, description: string, a: ToolAnnotations): { risk: Risk; source: "annotations" | "heuristic" } {
  if (a.destructiveHint === true && a.readOnlyHint !== true) return { risk: "destructive", source: "annotations" };
  if (a.readOnlyHint === true) return { risk: a.openWorldHint === true ? "external" : "read", source: "annotations" };
  const words = name.replace(/([a-z])([A-Z])/g, "$1_$2");
  if (DESTRUCTIVE.test(words)) return { risk: "destructive", source: "heuristic" };
  if (EXTERNAL.test(words) || a.openWorldHint === true) return { risk: "external", source: "heuristic" };
  if (WRITE.test(words)) return { risk: "write", source: "heuristic" };
  if (/^(get|list|search|find|read|query|describe|show|lookup|count|view|fetch_?info|whoami)/i.test(words) || /(^|_)(get|list|search|read)(_|$)/i.test(words)) return { risk: "read", source: "heuristic" };
  if (DESTRUCTIVE.test(description)) return { risk: "destructive", source: "heuristic" };
  return { risk: "write", source: "heuristic" };
}

/** Canonical JSON (sorted keys), so the hash only changes when the content does. */
export function canonical(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  if (v && typeof v === "object") {
    return `{${Object.keys(v as object)
      .sort()
      .filter((k) => (v as Record<string, unknown>)[k] !== undefined)
      .map((k) => `${JSON.stringify(k)}:${canonical((v as Record<string, unknown>)[k])}`)
      .join(",")}}`;
  }
  return JSON.stringify(v ?? null);
}

/** What an approval covers: a changed description is a changed tool (tool poisoning hides in descriptions). */
export const toolHash = (t: { description: string; inputSchema: unknown; annotations: unknown; title?: string }) =>
  createHash("sha256").update(canonical({ d: t.description, s: t.inputSchema ?? {}, a: t.annotations ?? {}, t: t.title ?? "" })).digest("hex");

export const argsHash = (args: unknown) => createHash("sha256").update(canonical(args ?? {})).digest("hex");

// ---- Authorization ------------------------------------------------------------------

export type Condition = { argument: string; op: "equals" | "in" | "not_in" | "prefix"; values: string[] };
export type Rule = {
  id: string;
  effect: "allow" | "deny";
  subject_type: "all_agents" | "agent" | "agent_tag";
  subject_id: string | null;
  subject_tag: string | null;
  tools: string[];
  risks: string[] | null;
  conditions: Condition[];
};
export type Caller = { agentId: string; tags: string[] };
export type Tool = { name: string; status: string; risk: Risk; hash: string; approved_hash: string | null };
export type Decision = { allow: boolean; reason: string; rule_id: string | null };

/** The value at a dotted path in the arguments, as a string (or undefined). */
function argAt(args: Record<string, unknown>, path: string): string[] | undefined {
  let v: unknown = args;
  for (const k of path.split(".")) {
    if (!v || typeof v !== "object" || Array.isArray(v)) return undefined;
    v = (v as Record<string, unknown>)[k];
  }
  if (v === undefined || v === null) return undefined;
  // Arrays: every element must satisfy the condition.
  const list = Array.isArray(v) ? v : [v];
  if (list.some((x) => typeof x === "object")) return undefined;
  return list.map((x) => String(x));
}

export function conditionHolds(c: Condition, args: Record<string, unknown>): boolean {
  const vals = argAt(args, c.argument);
  if (!vals || !vals.length) return c.op === "not_in"; // missing: only "not one of" holds
  switch (c.op) {
    case "equals":
      return vals.every((v) => v === c.values[0]);
    case "in":
      return vals.every((v) => c.values.includes(v));
    case "not_in":
      return vals.every((v) => !c.values.includes(v));
    case "prefix":
      return vals.every((v) => c.values.some((p) => v.startsWith(p)));
  }
}

const subjectMatches = (r: Rule, who: Caller) => r.subject_type === "all_agents" || (r.subject_type === "agent" && r.subject_id === who.agentId) || (r.subject_type === "agent_tag" && who.tags.includes(r.subject_tag!));
const toolMatches = (r: Rule, t: Tool) => (r.tools.includes("*") || r.tools.includes(t.name)) && (!r.risks || r.risks.includes(t.risk));

export const isUsable = (t: Tool) => t.status === "approved" && t.approved_hash === t.hash;

/**
 * Deny by default. The tool must be approved as it is now; a matching deny rule
 * wins over any allow; an allow rule applies when all its argument conditions
 * hold. Deny rules with conditions deny when their conditions hold.
 */
export function authorize(tool: Tool | undefined, rules: Rule[], who: Caller, args: Record<string, unknown> | null): Decision {
  if (!tool || tool.status === "removed") return { allow: false, reason: "No such tool", rule_id: null };
  if (tool.status === "blocked") return { allow: false, reason: "This tool is blocked by an admin", rule_id: null };
  if (!isUsable(tool)) return { allow: false, reason: tool.approved_hash ? "This tool changed since it was approved and needs re-approval" : "This tool hasn't been approved yet", rule_id: null };
  const applicable = rules.filter((r) => subjectMatches(r, who) && toolMatches(r, tool));
  for (const r of applicable.filter((x) => x.effect === "deny")) {
    if (args === null ? !r.conditions.length : r.conditions.every((c) => conditionHolds(c, args))) return { allow: false, reason: "Denied by a rule", rule_id: r.id };
  }
  const allows = applicable.filter((x) => x.effect === "allow");
  if (!allows.length) return { allow: false, reason: "No rule allows this agent to use this tool", rule_id: null };
  // For listing (args unknown), a tool is visible if some allow rule could apply.
  if (args === null) return { allow: true, reason: "Allowed", rule_id: allows[0]!.id };
  const ok = allows.find((r) => r.conditions.every((c) => conditionHolds(c, args)));
  if (ok) return { allow: true, reason: "Allowed", rule_id: ok.id };
  const failed = allows.flatMap((r) => r.conditions.filter((c) => !conditionHolds(c, args)));
  return { allow: false, reason: `The arguments aren't allowed (${[...new Set(failed.map((c) => c.argument))].join(", ")})`, rule_id: null };
}
