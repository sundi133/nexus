import { createRoute, z } from "@hono/zod-openapi";
import { sql } from "kysely";
import type { App, Deps, RequestMeta } from "../context.js";
import { audit } from "../audit/record.js";
import { assertDeviceInScope, requirePermission } from "../auth/guard.js";
import type { Tx } from "../platform/db.js";
import { newId } from "../platform/ids.js";
import type { JobRunner } from "../platform/jobs.js";
import { bearer, Id, iso, json, problemResponses } from "../schemas.js";

/**
 * Real-time process events (DEV events): every program a device starts, from
 * osquery's event tables (macOS Endpoint Security, Windows ETW, Linux eBPF),
 * with its parent chain, so Nexus can tell when an AI tool (Cursor, Claude,
 * Codex…) runs a shell or a network tool. Off until an admin turns on the
 * `process_events` organization setting; kept 7 days.
 */

export const RETENTION_DAYS = 7;
const s = (n: number) => z.string().max(n).default("");

export const ProcessEventsBody = z.object({
  status: z.string().max(500).default(""),
  dropped: z.number().int().min(0).default(0),
  events: z
    .array(
      z.object({
        time: z.number().int().min(0),
        pid: z.number().int().min(0).default(0),
        path: s(1000),
        cmdline: s(4000),
        user: s(200),
        parent_path: s(1000),
        ancestors: z.array(z.string().max(1000)).max(5).default([]),
        responsible_path: s(1000),
        signer: s(200),
      }),
    )
    .max(2000),
});
type Incoming = z.infer<typeof ProcessEventsBody>["events"][number];

// ---- Redaction -----------------------------------------------------------------------------

const TOKEN = /\b(ghp_|gho_|ghu_|ghs_|github_pat_|glpat-|xox[abprs]-|sk-|sk_live_|rk_live_|AKIA|ASIA|AIza|ya29\.|ntn_|lin_api_|npm_|dop_v1_|shpat_)[A-Za-z0-9_\-.]{8,}/g;
const JWT = /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}/g;
const SECRETISH = "(?:password|passwd|pwd|token|secret|api[_-]?key|apikey|access[_-]?key|private[_-]?key|credential|authorization|auth[_-]?token)";
// KEY=value or key: value (not "Authorization: Bearer …", which BEARER handles).
const ASSIGN = new RegExp(`\\b([A-Za-z0-9_-]*${SECRETISH}[A-Za-z0-9_-]*)(\\s*[=:]\\s*)(?!Bearer\\b|Basic\\b|<redacted>)("[^"]*"|'[^']*'|[^\\s'"]+)`, "gi");
// --password value, -token value: only flags take a space-separated value.
const FLAG = new RegExp(`(^|\\s)(--?[A-Za-z0-9_-]*${SECRETISH}[A-Za-z0-9_-]*)(\\s+)(?!-|<redacted>)("[^"]*"|'[^']*'|\\S+)`, "gi");
const BEARER = /\b(Bearer|Basic)\s+[A-Za-z0-9_\-.=+/]{8,}/gi;
const URL_CREDS = /(\b[a-z][a-z0-9+.-]*:\/\/)[^\s/@:]+:[^\s/@]+@/gi;

/** Removes secrets from a command line: tokens, "password=…"-style values, bearer headers, URL credentials. */
export function redact(cmd: string) {
  return cmd
    .replace(URL_CREDS, "$1<redacted>@")
    .replace(BEARER, "$1 <redacted>")
    .replace(JWT, "<redacted>")
    .replace(TOKEN, "<redacted>")
    .replace(ASSIGN, "$1$2<redacted>")
    .replace(FLAG, "$1$2$3<redacted>")
    .slice(0, 2000);
}

// ---- Detection -------------------------------------------------------------------------------

const AI_CLIENTS: [RegExp, string][] = [
  [/\/Cursor\.app\/|\\cursor\\|\/cursor(-agent)?$|\\cursor\.exe$/i, "Cursor"],
  [/\/Claude\.app\/|\\AnthropicClaude\\|\/claude$|\\claude\.exe$|\/\.claude\/local\//i, "Claude"],
  [/\/Windsurf\.app\/|\\Windsurf\\/i, "Windsurf"],
  [/\/ChatGPT\.app\/|\\ChatGPT\\/i, "ChatGPT"],
  [/\/Visual Studio Code\.app\/|\\Microsoft VS Code\\|\/code\/code$/i, "VS Code"],
  [/\/(codex|gemini|aider|goose|opencode|amp)$|\\(codex|gemini|aider|goose|opencode)\.exe$/i, "an AI CLI"],
  [/\/Kiro\.app\/|\/Trae\.app\/|\\Kiro\\/i, "an AI IDE"],
];
const SHELLS = new Set(["sh", "bash", "zsh", "fish", "dash", "ksh", "tcsh", "csh", "pwsh", "pwsh.exe", "powershell.exe", "cmd.exe", "bash.exe", "wsl.exe"]);
const NETWORK = new Set(["curl", "wget", "nc", "ncat", "netcat", "socat", "scp", "sftp", "ssh", "rsync", "ftp", "tftp", "telnet", "curl.exe", "wget.exe", "scp.exe", "ssh.exe", "ftp.exe", "bitsadmin.exe", "certutil.exe", "nc.exe"]);
const TEMP = /^(\/tmp\/|\/private\/tmp\/|\/var\/tmp\/|\/private\/var\/folders\/[^/]+\/[^/]+\/T\/|\/Users\/[^/]+\/Downloads\/|\/home\/[^/]+\/Downloads\/)|\\AppData\\Local\\Temp\\|\\Downloads\\|^C:\\Windows\\Temp\\/i;

const base = (p: string) => (p.split(/[\\/]/).pop() ?? "").toLowerCase();

export type Detection = { key: "ai_network_tool" | "ai_shell" | "exec_from_temp"; severity: "high" | "info" | "low"; title: string; client?: string };

/** What an event means, judged on the program and the chain of programs that started it. */
export function detect(e: Pick<Incoming, "path" | "parent_path" | "ancestors" | "responsible_path">): Detection | null {
  const chain = [e.parent_path, ...e.ancestors, e.responsible_path].filter(Boolean);
  const client = chain.map((p) => AI_CLIENTS.find(([re]) => re.test(p))?.[1]).find(Boolean);
  const name = base(e.path);
  if (client && !AI_CLIENTS.some(([re]) => re.test(e.path))) {
    if (NETWORK.has(name)) return { key: "ai_network_tool", severity: "high", title: `${client} ran ${name}`, client };
    if (SHELLS.has(name)) return { key: "ai_shell", severity: "info", title: `${client} started a shell`, client };
  }
  if (TEMP.test(e.path)) return { key: "exec_from_temp", severity: "low", title: "Program ran from a temporary or downloads folder" };
  return null;
}

// ---- Ingest -----------------------------------------------------------------------------------

export async function ingestProcessEvents(tx: Tx, device: { id: string; org_id: string; hostname: string }, body: z.infer<typeof ProcessEventsBody>, meta: RequestMeta) {
  const status = body.status + (body.dropped ? ` (${body.dropped} events dropped while offline)` : "");
  await tx.updateTable("devices").set({ events_status: status.slice(0, 500) }).where("id", "=", device.id).execute();
  if (!body.events.length) return { stored: 0, detections: 0 };
  const rows = body.events.map((e) => {
    const d = detect(e);
    return {
      id: newId(),
      org_id: device.org_id,
      device_id: device.id,
      time: new Date(e.time * 1000),
      pid: e.pid,
      path: e.path,
      cmdline: redact(e.cmdline),
      user_name: e.user,
      parent_path: e.parent_path,
      ancestors: e.ancestors,
      responsible_path: e.responsible_path,
      signer: e.signer,
      detection: d?.key ?? null,
      severity: d?.severity ?? null,
      _d: d,
    };
  });
  // Audit what matters (high), once per device, detection and program an hour: alerts follow the audit log.
  // Decided before this batch is stored, against what's already there.
  const since = new Date(Date.now() - 3600_000);
  const toAudit: typeof rows = [];
  const seen = new Set<string>();
  for (const r of rows.filter((x) => x._d?.severity === "high")) {
    const k = `${r.detection}|${r.path}`;
    if (seen.has(k)) continue;
    seen.add(k);
    const earlier = await tx
      .selectFrom("device_process_events")
      .select("id")
      .where("device_id", "=", device.id)
      .where("detection", "=", r.detection)
      .where("path", "=", r.path)
      .where("received_at", ">", since)
      .executeTakeFirst();
    if (!earlier) toAudit.push(r);
  }
  for (let i = 0; i < rows.length; i += 500) {
    await tx
      .insertInto("device_process_events")
      .values(rows.slice(i, i + 500).map(({ _d, ...r }) => r))
      .execute();
  }
  for (const r of toAudit) {
    await audit(tx, device.org_id, { meta }, {
      type: "device.detection",
      actor: { type: "system", id: null, display: "Nexus agent" },
      target: { type: "device", id: device.id, display: device.hostname },
      details: { detection: r.detection, severity: r._d!.severity, title: r._d!.title, path: r.path, cmdline: r.cmdline.slice(0, 500), parent: r.parent_path, responsible: r.responsible_path, user: r.user_name },
    });
  }
  const audited = toAudit.length;
  return { stored: rows.length, detections: rows.filter((r) => r.detection).length, audited };
}

// ---- API -------------------------------------------------------------------------------------------

const EventOut = z
  .object({
    id: Id,
    device_id: Id,
    hostname: z.string(),
    time: z.string(),
    pid: z.number().int(),
    path: z.string(),
    cmdline: z.string(),
    user: z.string(),
    parent_path: z.string(),
    ancestors: z.array(z.string()),
    responsible_path: z.string(),
    signer: z.string(),
    detection: z.enum(["ai_network_tool", "ai_shell", "exec_from_temp"]).nullable(),
    severity: z.enum(["info", "low", "medium", "high"]).nullable(),
  })
  .openapi("ProcessEvent");

async function list(tx: Tx, q: { device_id?: string; detections?: boolean; severity?: string; q?: string; limit: number }) {
  let query = tx.selectFrom("device_process_events").innerJoin("devices", "devices.id", "device_process_events.device_id").selectAll("device_process_events").select("devices.hostname").orderBy("device_process_events.time", "desc").limit(q.limit);
  if (q.device_id) query = query.where("device_process_events.device_id", "=", q.device_id);
  if (q.detections) query = query.where("device_process_events.detection", "is not", null);
  if (q.severity) query = query.where("device_process_events.severity", "=", q.severity as "high");
  if (q.q) {
    const like = `%${q.q.replace(/[%_\\]/g, "\\$&")}%`;
    query = query.where((eb) => eb.or([eb("device_process_events.path", "ilike", like), eb("device_process_events.cmdline", "ilike", like), eb("device_process_events.parent_path", "ilike", like)]));
  }
  return (await query.execute()).map((r) => ({
    id: r.id,
    device_id: r.device_id,
    hostname: r.hostname,
    time: iso(r.time),
    pid: Number(r.pid),
    path: r.path,
    cmdline: r.cmdline,
    user: r.user_name,
    parent_path: r.parent_path,
    ancestors: r.ancestors,
    responsible_path: r.responsible_path,
    signer: r.signer,
    detection: r.detection as z.infer<typeof EventOut>["detection"],
    severity: r.severity,
  }));
}

export function registerProcessEventRoutes(app: App) {
  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/devices/{id}/process-events",
      tags: ["Devices"],
      summary: "Programs a device started (real-time events), newest first",
      security: bearer,
      request: { params: z.object({ id: Id }), query: z.object({ detections: z.coerce.boolean().optional(), q: z.string().trim().max(200).optional(), limit: z.coerce.number().int().min(1).max(1000).default(200) }) },
      responses: { 200: json(z.object({ data: z.array(EventOut), status: z.string() })), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "devices:read", { scoped: true });
      const { id } = c.req.valid("param");
      const q = c.req.valid("query");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        await assertDeviceInScope(tx, p, "devices:read", id);
        const d = await tx.selectFrom("devices").select("events_status").where("id", "=", id).executeTakeFirst();
        return { data: await list(tx, { ...q, device_id: id }), status: d?.events_status ?? "" };
      });
      return c.json(out, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/detections",
      tags: ["Devices"],
      summary: "Recent detections across devices (AI tools running network tools or shells, programs run from temp folders)",
      security: bearer,
      request: { query: z.object({ severity: z.enum(["info", "low", "medium", "high"]).optional(), q: z.string().trim().max(200).optional(), limit: z.coerce.number().int().min(1).max(1000).default(200) }) },
      responses: { 200: json(z.object({ data: z.array(EventOut) })), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "devices:read");
      const q = c.req.valid("query");
      return c.json({ data: await c.get("deps").db.tenant(p.orgId, (tx) => list(tx, { ...q, detections: true })) }, 200);
    },
  );
}

/** Hourly: events older than the retention window go, across every organization. */
export function scheduleProcessEventRetention(jobs: JobRunner, deps: Deps) {
  let last = 0;
  jobs.onTick(async () => {
    if (Date.now() - last < 60 * 60_000) return;
    last = Date.now();
    await deps.db.unscoped((tx) => sql`SELECT nexus_prune_process_events(${`${RETENTION_DAYS} days`}::interval)`.execute(tx));
  });
}
