import { sql } from "kysely";
import type { Deps, RequestMeta } from "../context.js";
import { audit } from "../audit/record.js";
import { newId } from "../platform/ids.js";
import { enqueue, type JobRunner, registerJobHandler } from "../platform/jobs.js";
import { notifyRoles } from "../notify/send.js";
import { classify, type ToolAnnotations, toolHash } from "./policy.js";
import { discover, type UpstreamConfig } from "./upstream.js";

/**
 * Tool discovery and drift (MCP-01/02/10). The gateway reads each server's
 * tools on registration, on demand and every 6 hours. A new tool, or a tool
 * whose description, schema or annotations changed, needs an admin's approval
 * before any agent can call it — descriptions are prompts, and a changed one
 * can carry an injection ("tool poisoning").
 */

export const VERSION = "1.0";
export const serverAad = (id: string) => `mcp-server:${id}`;

type ServerRow = { id: string; url: string; auth_kind: string; auth_header: string; secret: Buffer | null };

export function upstreamConfig(deps: Deps, s: ServerRow): UpstreamConfig {
  const headers: Record<string, string> = {};
  if (s.secret) {
    const value = deps.sealer.open(s.secret, serverAad(s.id)).toString();
    if (s.auth_kind === "bearer") headers.authorization = `Bearer ${value}`;
    else if (s.auth_kind === "header") headers[s.auth_header.toLowerCase()] = value;
  }
  return { id: s.id, url: s.url, headers, allowPrivate: deps.cfg.allowPrivateOutbound, version: VERSION };
}

export type SyncResult = { ok: boolean; error: string; added: string[]; changed: string[]; removed: string[]; approved_automatically: string[] };

const SYSTEM: RequestMeta = { ip: "", userAgent: "nexus-mcp-gateway", requestId: "" };

/** Reads the server's tools and records what's new, changed or gone. */
export async function syncServer(deps: Deps, orgId: string, serverId: string, meta: RequestMeta = SYSTEM): Promise<SyncResult> {
  const server = await deps.db.tenant(orgId, (tx) => tx.selectFrom("mcp_servers").selectAll().where("id", "=", serverId).executeTakeFirst());
  if (!server) return { ok: false, error: "No such server", added: [], changed: [], removed: [], approved_automatically: [] };
  let found: Awaited<ReturnType<typeof discover>>;
  try {
    found = await discover(upstreamConfig(deps, server));
  } catch (e) {
    const error = (e as Error).message.slice(0, 500);
    await deps.db.tenant(orgId, (tx) => tx.updateTable("mcp_servers").set({ last_sync_error: error, last_synced_at: new Date() }).where("id", "=", serverId).execute());
    return { ok: false, error, added: [], changed: [], removed: [], approved_automatically: [] };
  }

  return deps.db.tenant(orgId, async (tx) => {
    const now = new Date();
    const existing = new Map((await tx.selectFrom("mcp_tools").selectAll().where("server_id", "=", serverId).execute()).map((t) => [t.name, t]));
    const out: SyncResult = { ok: true, error: "", added: [], changed: [], removed: [], approved_automatically: [] };
    const seen = new Set<string>();
    for (const t of found.tools) {
      if (seen.has(t.name)) continue;
      seen.add(t.name);
      const annotations = (t.annotations ?? {}) as ToolAnnotations;
      const description = String(t.description ?? "").slice(0, 10_000);
      const title = String(t.title ?? annotations.title ?? "").slice(0, 200);
      const hash = toolHash({ description, inputSchema: t.inputSchema ?? {}, annotations, title });
      const prev = existing.get(t.name);
      const cls = classify(t.name, description, annotations);
      const fields = { title, description, input_schema: JSON.stringify(t.inputSchema ?? {}), annotations: JSON.stringify(annotations), hash };
      if (!prev) {
        const auto = server.auto_approve_read && cls.risk === "read";
        await tx
          .insertInto("mcp_tools")
          .values({
            id: newId(),
            org_id: orgId,
            server_id: serverId,
            name: t.name,
            ...fields,
            risk: cls.risk,
            risk_source: cls.source,
            status: auto ? "approved" : "pending",
            change: auto ? "" : "new",
            ...(auto ? { approved_hash: hash, approved_snapshot: JSON.stringify({ title, description, input_schema: t.inputSchema ?? {}, annotations }), approved_at: now } : {}),
          })
          .execute();
        (auto ? out.approved_automatically : out.added).push(t.name);
        continue;
      }
      if (prev.hash === hash && prev.status !== "removed") continue;
      // Changed (or back after being removed): usable again only if it's exactly what was approved.
      const back = prev.approved_hash === hash;
      await tx
        .updateTable("mcp_tools")
        .set({
          ...fields,
          ...(prev.risk_source === "admin" ? {} : { risk: cls.risk, risk_source: cls.source }),
          status: prev.status === "blocked" ? "blocked" : back ? "approved" : "pending",
          change: back ? "" : prev.approved_hash ? "changed" : "new",
          changed_at: now,
        })
        .where("id", "=", prev.id)
        .execute();
      if (!back && prev.hash !== hash) out.changed.push(t.name);
    }
    for (const [name, prev] of existing) {
      if (seen.has(name) || prev.status === "removed") continue;
      await tx.updateTable("mcp_tools").set({ status: "removed", changed_at: now }).where("id", "=", prev.id).execute();
      out.removed.push(name);
    }
    await tx.updateTable("mcp_servers").set({ last_synced_at: now, last_sync_error: "", server_info: JSON.stringify(found.info) }).where("id", "=", serverId).execute();
    if (out.added.length || out.changed.length || out.removed.length) {
      await audit(tx, orgId, { meta }, {
        type: "mcp.tools_discovered",
        actor: { type: "system", id: null, display: "MCP gateway" },
        target: { type: "mcp_server", id: serverId, display: server.name },
        details: { added: out.added, changed: out.changed, removed: out.removed, approved_automatically: out.approved_automatically },
      });
    }
    // Drift on tools that were in use is a security event: someone must look before agents can use them again.
    const drifted = out.changed.filter((n) => existing.get(n)?.approved_hash);
    if (drifted.length) {
      await notifyRoles(tx, orgId, ["owner", "admin", "security_analyst"], {
        category: "security.alert",
        severity: "warning",
        title: `${server.name}: ${drifted.length === 1 ? `tool ${drifted[0]} changed` : `${drifted.length} tools changed`}`,
        body: "Agents can't call a changed tool until someone reviews and re-approves it.",
        entity: { type: "mcp_server", id: serverId },
        link: `/mcp/${serverId}`,
      });
    } else if (out.added.length && existing.size) {
      await notifyRoles(tx, orgId, ["owner", "admin"], {
        category: "mcp.tools",
        severity: "info",
        title: `${server.name}: ${out.added.length} new tool${out.added.length === 1 ? "" : "s"} to review`,
        link: `/mcp/${serverId}`,
      });
    }
    return out;
  });
}

registerJobHandler("mcp.sync", async (deps, job) => {
  const { server_id } = job.payload as { server_id: string };
  await syncServer(deps, job.org_id, server_id, { ...SYSTEM, requestId: job.id });
});

/** Re-discovers every server's tools every 6 hours (drift detection). */
export function scheduleMcpSyncs(jobs: JobRunner, deps: Deps) {
  let last = 0;
  jobs.onTick(async () => {
    if (Date.now() - last < 5 * 60_000) return;
    last = Date.now();
    const due = await deps.db.unscoped(async (tx) => (await sql<{ org_id: string; server_id: string }>`SELECT * FROM nexus_due_mcp_syncs()`.execute(tx)).rows);
    for (const d of due) await deps.db.tenant(d.org_id, (tx) => enqueue(tx, d.org_id, "mcp.sync", { server_id: d.server_id }, { dedupeKey: `mcp.sync:${d.server_id}` }));
  });
}
