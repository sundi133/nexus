import { type LdapConfig, readDirectory } from "@nexus/ldap-directory";
import type { IO } from "./cli.js";

/**
 * The on-prem directory connector: `nexus directory push`. Runs inside the
 * network (cron, systemd timer or a container), reads Active Directory / LDAP,
 * and reconciles Votal Nexus through the organization's SCIM endpoint, the
 * same way Okta or Entra ID provision. Nothing inbound is opened; the
 * directory's service account password never leaves the network.
 */

export type ConnectorConfig = {
  scim: { url: string; token_env: string };
  ldap: Omit<LdapConfig, "ca_cert"> & { bind_password_env: string; ca_cert_file?: string };
  groups?: boolean;
};

type ScimUser = { id: string; externalId?: string; userName: string; active: boolean; name?: { givenName?: string; familyName?: string }; title?: string; "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"?: { department?: string } };
type ScimGroup = { id: string; externalId?: string; displayName: string; members?: { value: string }[] };

const ENTERPRISE = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";

export class PushError extends Error {}

function scimClient(io: IO, base: string, token: string) {
  const f = io.fetch ?? fetch;
  return async <T>(method: string, path: string, body?: unknown): Promise<T> => {
    const url = `${base.replace(/\/+$/, "")}${path}`;
    let res: Response;
    try {
      res = await f(url, {
        method,
        headers: { authorization: `Bearer ${token}`, "content-type": "application/scim+json", accept: "application/scim+json" },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
    } catch (e) {
      const cause = (e as { cause?: { code?: string; message?: string } }).cause;
      throw new PushError(`Couldn't reach Nexus at ${new URL(url).origin}: ${cause?.code ?? cause?.message ?? (e as Error).message}`);
    }
    if (res.status === 401) throw new PushError("Nexus refused the SCIM token: copy it again from Directory sync (or rotate it)");
    const text = await res.text();
    if (res.status === 429) throw new PushError("Nexus paused this sync: it would deactivate many people at once. An admin can approve it under Directory sync; run the connector again afterwards.");
    if (!res.ok) throw new PushError(`${method} ${path}: HTTP ${res.status} ${text.slice(0, 300)}`);
    return (text ? JSON.parse(text) : null) as T;
  };
}

async function listAll<T>(call: ReturnType<typeof scimClient>, path: string): Promise<T[]> {
  const out: T[] = [];
  for (let start = 1; ; ) {
    const page = await call<{ Resources?: T[]; totalResults: number; itemsPerPage?: number }>("GET", `${path}${path.includes("?") ? "&" : "?"}startIndex=${start}&count=500`);
    const items = page.Resources ?? [];
    out.push(...items);
    if (!items.length || out.length >= page.totalResults) return out;
    start += items.length;
  }
}

export type PushResult = { created: string[]; updated: string[]; deactivated: string[]; reactivated: string[]; groups_created: string[]; groups_updated: string[] };

export async function pushDirectory(io: IO, cfg: ConnectorConfig, opts: { dryRun: boolean }): Promise<PushResult> {
  const token = io.env[cfg.scim.token_env];
  if (!token) throw new PushError(`Set ${cfg.scim.token_env} to the SCIM token from Nexus (Directory sync, SCIM connection)`);
  const bindPassword = io.env[cfg.ldap.bind_password_env];
  if (!bindPassword) throw new PushError(`Set ${cfg.ldap.bind_password_env} to the directory service account's password`);
  const { bind_password_env: _b, ca_cert_file, ...ldap } = cfg.ldap;
  const ca = ca_cert_file ? await io.readFile(ca_cert_file) : undefined;
  const dir = await readDirectory({ ...ldap, ...(ca ? { ca_cert: ca } : {}) }, bindPassword, { groups: cfg.groups !== false });

  const call = scimClient(io, cfg.scim.url, token);
  const existing = (await listAll<ScimUser>(call, "/Users")).filter((u) => u.externalId);
  const byExt = new Map(existing.map((u) => [u.externalId!, u]));
  const r: PushResult = { created: [], updated: [], deactivated: [], reactivated: [], groups_created: [], groups_updated: [] };
  const scimId = new Map<string, string>(); // directory id -> Nexus id

  for (const u of dir.users) {
    const body = {
      schemas: ["urn:ietf:params:scim:schemas:core:2.0:User", ENTERPRISE],
      externalId: u.external_id,
      userName: u.email,
      name: { givenName: u.given_name, familyName: u.family_name },
      emails: [{ value: u.email, primary: true, type: "work" }],
      title: u.title,
      active: u.active,
      [ENTERPRISE]: { department: u.department },
    };
    const cur = byExt.get(u.external_id);
    if (!cur) {
      if (!u.active) continue; // disabled before we ever saw them: nothing to create
      r.created.push(u.email);
      if (!opts.dryRun) scimId.set(u.external_id, (await call<ScimUser>("POST", "/Users", body)).id);
      continue;
    }
    scimId.set(u.external_id, cur.id);
    const changed =
      cur.userName.toLowerCase() !== u.email ||
      (cur.name?.givenName ?? "") !== u.given_name ||
      (cur.name?.familyName ?? "") !== u.family_name ||
      (cur.title ?? "") !== u.title ||
      (cur[ENTERPRISE]?.department ?? "") !== u.department ||
      cur.active !== u.active;
    if (!changed) continue;
    (cur.active && !u.active ? r.deactivated : !cur.active && u.active ? r.reactivated : r.updated).push(u.email);
    if (!opts.dryRun) await call("PUT", `/Users/${cur.id}`, body);
  }
  // People the connector created who are no longer in the directory (deleted or moved out of scope).
  const seen = new Set(dir.users.map((u) => u.external_id));
  for (const cur of existing.filter((x) => !seen.has(x.externalId!) && x.active)) {
    r.deactivated.push(cur.userName);
    if (!opts.dryRun) await call("PATCH", `/Users/${cur.id}`, { schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], Operations: [{ op: "replace", value: { active: false } }] });
  }

  if (cfg.groups !== false) {
    const groups = (await listAll<ScimGroup>(call, "/Groups")).filter((g) => g.externalId);
    const gByExt = new Map(groups.map((g) => [g.externalId!, g]));
    for (const g of dir.groups) {
      const members = g.member_ids.map((id) => scimId.get(id)).filter((x): x is string => !!x).sort();
      const body = { schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"], externalId: g.external_id, displayName: g.name, members: members.map((value) => ({ value })) };
      const cur = gByExt.get(g.external_id);
      if (!cur) {
        r.groups_created.push(g.name);
        if (!opts.dryRun) await call("POST", "/Groups", body);
        continue;
      }
      const have = (cur.members ?? []).map((m) => m.value).sort();
      if (cur.displayName === g.name && have.join() === members.join()) continue;
      r.groups_updated.push(g.name);
      if (!opts.dryRun) await call("PUT", `/Groups/${cur.id}`, body);
    }
  }
  return r;
}

export function renderPush(r: PushResult, dryRun: boolean) {
  const line = (label: string, xs: string[]) => (xs.length ? `  ${label}: ${xs.length} (${xs.slice(0, 5).join(", ")}${xs.length > 5 ? ", ..." : ""})\n` : "");
  const body = line("create", r.created) + line("update", r.updated) + line("deactivate", r.deactivated) + line("reactivate", r.reactivated) + line("new groups", r.groups_created) + line("group changes", r.groups_updated);
  return body ? `${dryRun ? "Would change" : "Changed"}:\n${body}` : "Nexus already matches the directory.\n";
}
