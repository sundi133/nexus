import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import { z } from "@hono/zod-openapi";
import { DirectoryError, type LdapConfig, readDirectory, verifyPassword } from "@nexus/ldap-directory";
import type { Deps } from "../../context.js";
import { _isPrivate } from "../../platform/outbound.js";
import { ProviderError } from "./providers.js";
import type { Remote } from "./plan.js";

/**
 * Active Directory and LDAP (SPEC DIR-01 on-prem): a direct LDAPS/StartTLS
 * connection from Nexus, for self-hosted deployments or directories reachable
 * from the internet. Where Nexus can't reach the directory, the `nexus` CLI
 * runs on-prem and pushes the same data over SCIM. Optionally, people sign in
 * with their directory password (delegated authentication).
 */

export const LdapConfigSchema = z
  .object({
    preset: z.enum(["active_directory", "openldap", "custom"]).default("active_directory"),
    url: z.string().max(300).regex(/^ldaps?:\/\/[^/\s]+\/?$/i, "ldaps://host:636 or ldap://host:389").openapi({ example: "ldaps://dc1.corp.example.com:636" }),
    start_tls: z.boolean().default(false),
    ca_cert: z.string().max(20_000).optional().openapi({ description: "PEM of your internal CA, if the directory's certificate isn't publicly trusted" }),
    bind_dn: z.string().min(1).max(500).openapi({ example: "CN=svc-nexus,OU=Service Accounts,DC=corp,DC=example,DC=com" }),
    base_dn: z.string().min(1).max(500).openapi({ example: "DC=corp,DC=example,DC=com" }),
    user_base_dn: z.string().max(500).optional(),
    group_base_dn: z.string().max(500).optional(),
    user_search_filter: z.string().max(1000).optional(),
    group_search_filter: z.string().max(1000).optional(),
    disabled_filter: z.string().max(1000).optional().openapi({ description: "Matches disabled people (Active Directory's disabled flag is always honoured)" }),
    attributes: z.record(z.string(), z.string().max(100)).optional(),
    password_auth: z.boolean().default(false).openapi({ description: "People sign in to Nexus with their directory password" }),
  })
  .openapi("LdapConfig");
export type LdapSettings = z.infer<typeof LdapConfigSchema>;

/** Directory hosts must be public unless this deployment allows private ones (self-hosted, dev). */
export function hostCheck(allowPrivate: boolean) {
  return async (host: string) => {
    if (allowPrivate) return;
    const h = host.replace(/^\[|\]$/g, "");
    const addrs = isIP(h) ? [h] : (await lookup(h, { all: true }).catch(() => [])).map((a) => a.address);
    if (!addrs.length) throw new DirectoryError(`Couldn't resolve ${h}`, true);
    if (addrs.some(_isPrivate)) throw new DirectoryError(`${h} is a private address, which this Nexus can't reach. Run the on-prem connector (nexus directory push) instead.`, true);
  };
}

// Same as service.secretAad (kept here to avoid an import cycle).
const secretAad = (connectionId: string) => `directory_connection:${connectionId}`;

const toProviderError = (e: unknown) => (e instanceof DirectoryError ? new ProviderError(e.message, e.permanent) : e);

export async function fetchLdap(deps: Pick<Deps, "cfg">, rawCfg: unknown, secret: string, opts: { groups: boolean }): Promise<Remote> {
  const cfg = LdapConfigSchema.parse(rawCfg) as LdapConfig;
  try {
    const d = await readDirectory(cfg, secret, opts, { checkHost: hostCheck(deps.cfg.allowPrivateDirectory) });
    return {
      users: d.users.map(({ dn: _dn, ...u }) => u),
      groups: d.groups.map(({ dn: _dn, ...g }) => g),
    };
  } catch (e) {
    throw toProviderError(e);
  }
}

/**
 * Delegated authentication: when this person comes from an LDAP connection
 * with password sign-in on, returns a checker that binds as them. Null when
 * their password is Nexus's own.
 */
export async function directoryPasswordCheck(deps: Deps, orgId: string, userId: string) {
  const conn = await deps.db.tenant(orgId, (tx) =>
    tx
      .selectFrom("directory_links")
      .innerJoin("directory_connections", "directory_connections.id", "directory_links.connection_id")
      .select(["directory_connections.id", "directory_connections.name", "directory_connections.config", "directory_connections.secret", "directory_links.external_id"])
      .where("directory_links.kind", "=", "user")
      .where("directory_links.local_id", "=", userId)
      .where("directory_connections.provider", "=", "ldap")
      .executeTakeFirst(),
  );
  if (!conn?.secret) return null;
  const cfg = LdapConfigSchema.safeParse(conn.config);
  if (!cfg.success || !cfg.data.password_auth) return null;
  const servicePassword = deps.sealer.open(conn.secret, secretAad(conn.id)).toString();
  return {
    connection: conn.name,
    verify: (password: string) => verifyPassword(cfg.data as LdapConfig, servicePassword, conn.external_id, password, { checkHost: hostCheck(deps.cfg.allowPrivateDirectory) }),
  };
}
