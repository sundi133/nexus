import { ApiProblem, createClient, unwrap } from "@nexus/api-client";
import { parse as parseYaml, stringify as toYaml } from "yaml";

/**
 * `nexus`, the Votal Nexus CLI. Config as code first (export, plan, apply a
 * YAML file, for GitOps and staging-to-production promotion), plus the
 * incident-time basics: stop an agent, look at alerts, verify the audit log.
 *
 * Authenticates with an API key: NEXUS_URL and NEXUS_TOKEN, or `nexus login`
 * (stored in ~/.config/nexus/credentials.json, readable only by you).
 */

export type IO = {
  env: Record<string, string | undefined>;
  fetch?: typeof fetch;
  out: (s: string) => void;
  err: (s: string) => void;
  readFile: (path: string) => Promise<string>;
  writeFile: (path: string, data: string, mode?: number) => Promise<void>;
  /** Answers a yes/no question; undefined when there's no terminal (then --yes is required). */
  confirm?: (question: string) => Promise<boolean>;
  home: string;
};

const HELP = `nexus: the Votal Nexus command line

Usage:
  nexus login --url <api-url> --token <api-key>
  nexus whoami
  nexus config export [-o nexus.yaml]
  nexus config plan -f nexus.yaml [--prune]
  nexus config apply -f nexus.yaml [--prune] [--yes]
  nexus agents list
  nexus agents suspend <name> [--reason <text>]
  nexus alerts list [--status active|resolved|all]
  nexus audit verify

Environment: NEXUS_URL and NEXUS_TOKEN (an API key) override saved credentials.
MCP server secrets in the config come from the environment variables named by
auth.token_env; they are never written to exported files.
`;

type Flags = Record<string, string | boolean>;
function parseArgs(argv: string[]): { args: string[]; flags: Flags } {
  const args: string[] = [];
  const flags: Flags = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    const short: Record<string, string> = { "-f": "file", "-o": "output", "-y": "yes", "-h": "help" };
    const key = a.startsWith("--") ? a.slice(2) : short[a];
    if (!key) {
      args.push(a);
      continue;
    }
    const [k, inline] = key.split("=", 2) as [string, string | undefined];
    if (inline !== undefined) flags[k] = inline;
    else if (["prune", "yes", "help", "json"].includes(k)) flags[k] = true;
    else flags[k] = argv[++i] ?? "";
  }
  return { args, flags };
}

class UsageError extends Error {}

const credentialsPath = (io: IO) => `${io.home}/.config/nexus/credentials.json`;

async function credentials(io: IO) {
  if (io.env.NEXUS_URL && io.env.NEXUS_TOKEN) return { url: io.env.NEXUS_URL, token: io.env.NEXUS_TOKEN };
  try {
    const c = JSON.parse(await io.readFile(credentialsPath(io))) as { url: string; token: string };
    return { url: io.env.NEXUS_URL ?? c.url, token: io.env.NEXUS_TOKEN ?? c.token };
  } catch {
    throw new UsageError("Not signed in. Run `nexus login --url <api-url> --token <api-key>`, or set NEXUS_URL and NEXUS_TOKEN.");
  }
}

async function client(io: IO) {
  const c = await credentials(io);
  return createClient({ baseUrl: c.url.replace(/\/+$/, ""), getToken: () => c.token, clientId: "cli/0.1.0", fetch: io.fetch });
}

type Change = { section: string; action: "create" | "update" | "delete"; key: string; changes?: Record<string, { from: unknown; to: unknown }> };

const short = (v: unknown) => {
  const s = typeof v === "string" ? v : JSON.stringify(v);
  return s.length > 60 ? `${s.slice(0, 57)}...` : s;
};

export function renderPlan(changes: Change[]) {
  if (!changes.length) return "No changes. The organization matches the config.\n";
  const sign = { create: "+", update: "~", delete: "-" } as const;
  const lines = changes.map((c) => {
    const head = `  ${sign[c.action]} ${c.section}: ${c.key}`;
    const fields = Object.entries(c.changes ?? {}).map(([k, v]) => `      ${k}: ${short(v.from)} -> ${short(v.to)}`);
    return [head, ...fields].join("\n");
  });
  const n = (a: Change["action"]) => changes.filter((c) => c.action === a).length;
  return `${lines.join("\n")}\n\nPlan: ${n("create")} to create, ${n("update")} to change, ${n("delete")} to delete.\n`;
}

/** Reads a config file and fills MCP server secrets from the environment. */
async function loadConfig(io: IO, file: string) {
  const doc = parseYaml(await io.readFile(file)) as { mcp_servers?: { slug: string; auth?: { kind: string; token?: string; token_env?: string } }[] } & Record<string, unknown>;
  if (!doc || typeof doc !== "object") throw new UsageError(`${file} isn't a config document`);
  for (const s of doc.mcp_servers ?? []) {
    const env = s.auth?.token_env;
    if (env && io.env[env]) s.auth = { ...s.auth!, token: io.env[env] };
    if (s.auth) delete s.auth.token_env;
  }
  return doc;
}

async function main(argv: string[], io: IO): Promise<number> {
  const { args, flags } = parseArgs(argv);
  const [cmd, sub, ...rest] = args;
  if (!cmd || flags.help) {
    io.out(HELP);
    return cmd ? 0 : 1;
  }

  if (cmd === "login") {
    const url = String(flags.url ?? "");
    const token = String(flags.token ?? "");
    if (!url || !token) throw new UsageError("Usage: nexus login --url <api-url> --token <api-key>");
    await io.writeFile(credentialsPath(io), JSON.stringify({ url, token }, null, 2), 0o600);
    io.out(`Saved credentials for ${url}. Check them with \`nexus whoami\`.\n`);
    return 0;
  }

  const api = await client(io);

  if (cmd === "whoami") {
    const s = await unwrap(api.GET("/v1/org/settings"));
    io.out(`Connected. MFA policy: ${s.mfa_policy}; audit retention: ${s.audit_retention_days} days.\n`);
    return 0;
  }

  if (cmd === "config") {
    if (sub === "export") {
      const doc = await unwrap(api.GET("/v1/config"));
      const text = `# Votal Nexus config (export). Secrets are never included: MCP server tokens\n# are read from the environment variables named by auth.token_env on apply.\n${toYaml(doc, { lineWidth: 0 })}`;
      if (flags.output) {
        await io.writeFile(String(flags.output), text);
        io.err(`Wrote ${flags.output}\n`);
      } else io.out(text);
      return 0;
    }
    if (sub === "plan" || sub === "apply") {
      const file = String(flags.file ?? rest[0] ?? "");
      if (!file) throw new UsageError(`Usage: nexus config ${sub} -f nexus.yaml [--prune]`);
      const config = await loadConfig(io, file);
      const prune = !!flags.prune;
      const plan = await unwrap(api.POST("/v1/config/plan", { body: { config: config as never, prune } }));
      io.out(renderPlan(plan.changes as Change[]));
      if (sub === "plan" || !plan.changes.length) return 0;
      if (!flags.yes) {
        if (!io.confirm) throw new UsageError("Run with --yes to apply without a prompt.");
        if (!(await io.confirm("Apply these changes?"))) {
          io.out("Cancelled.\n");
          return 1;
        }
      }
      const done = await unwrap(api.POST("/v1/config/apply", { body: { config: config as never, prune, plan_id: plan.plan_id } }));
      io.out(`Applied ${done.changes.length} change${done.changes.length === 1 ? "" : "s"} (plan ${done.plan_id}).\n`);
      return 0;
    }
    throw new UsageError("Usage: nexus config export|plan|apply");
  }

  if (cmd === "agents") {
    const list = await unwrap(api.GET("/v1/agents"));
    if (sub === "list" || !sub) {
      for (const a of list.data) io.out(`${a.status === "active" ? (a.stale ? "stale    " : "active   ") : "SUSPENDED"}  ${a.name}  (${a.risk_tier}, owner ${a.owner?.name ?? "none"}, last seen ${a.last_seen_at ?? "never"})\n`);
      return 0;
    }
    if (sub === "suspend") {
      const name = rest.join(" ");
      const a = list.data.find((x) => x.name.toLowerCase() === name.toLowerCase());
      if (!a) throw new UsageError(`No agent named "${name}"`);
      await unwrap(api.POST("/v1/agents/{id}/suspend", { params: { path: { id: a.id } }, body: { reason: String(flags.reason ?? "Suspended from the CLI") } }));
      io.out(`Suspended ${a.name}: its tokens stopped working.\n`);
      return 0;
    }
    throw new UsageError("Usage: nexus agents list | nexus agents suspend <name>");
  }

  if (cmd === "alerts") {
    const status = String(flags.status ?? "active") as "active";
    const list = await unwrap(api.GET("/v1/alerts", { params: { query: { status } } }));
    if (!list.data.length) io.out("No alerts.\n");
    for (const a of list.data) io.out(`${a.severity.toUpperCase().padEnd(8)} ${a.status.padEnd(12)} ${a.title} (${a.count}x, last ${a.last_seen_at})\n`);
    return 0;
  }

  if (cmd === "audit" && sub === "verify") {
    const v = await unwrap(api.GET("/v1/audit/integrity"));
    if (v.ok) io.out(`OK: ${v.events_checked} events in ${v.blocks_checked} blocks verified${v.head ? `; head ${v.head.digest} (block ${v.head.block})` : ""}.\n`);
    else io.err(`FAILED: ${v.problem?.detail ?? "integrity check failed"}\n`);
    return v.ok ? 0 : 2;
  }

  throw new UsageError(`Unknown command: ${args.join(" ")}\n\n${HELP}`);
}

/** Runs the CLI; returns the exit code. */
export async function run(argv: string[], io: IO): Promise<number> {
  try {
    return await main(argv, io);
  } catch (e) {
    if (e instanceof UsageError) io.err(`${e.message}\n`);
    else if (e instanceof ApiProblem) {
      io.err(`Error: ${e.problem.title}${e.problem.code ? ` (${e.problem.code})` : ""}\n`);
      const problems = (e.problem as { problems?: string[] }).problems;
      for (const p of problems ?? []) io.err(`  - ${p}\n`);
    } else io.err(`Error: ${(e as Error).message}\n`);
    return 1;
  }
}
