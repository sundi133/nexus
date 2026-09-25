import { z } from "@hono/zod-openapi";
import { importPKCS8, SignJWT } from "jose";
import type { Config } from "../../config.js";
import type { Remote, RemoteGroup, RemoteUser } from "./plan.js";

/**
 * Read-only clients for Google Workspace (Admin SDK Directory API, service
 * account with domain-wide delegation) and Microsoft Entra ID (Microsoft
 * Graph, app-only client credentials). They only ever read.
 */

export class ProviderError extends Error {
  constructor(
    message: string,
    readonly permanent: boolean, // credentials/permissions: retrying won't help
  ) {
    super(message);
  }
}

type Endpoints = Pick<Config, "googleTokenUrl" | "googleAdminBase" | "entraLoginBase" | "graphBase">;

const MAX_PAGES = 1000;
const TIMEOUT_MS = 30_000;

export async function getJson(url: string, init: RequestInit, what: string): Promise<any> {
  let res: Response;
  try {
    res = await fetch(url, { ...init, signal: AbortSignal.timeout(TIMEOUT_MS), redirect: "error" });
  } catch (err) {
    throw new ProviderError(`${what}: ${(err as Error).message}`, false);
  }
  const text = await res.text();
  let body: any = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    /* not JSON */
  }
  if (!res.ok) {
    const detail = body?.error_description ?? body?.error?.message ?? (typeof body?.error === "string" ? body.error : "") ?? "";
    const permanent = res.status === 400 || res.status === 401 || res.status === 403 || res.status === 404;
    throw new ProviderError(`${what} failed (HTTP ${res.status})${detail ? `: ${detail}` : ""}`, permanent);
  }
  return body;
}

// ---- Google Workspace ------------------------------------------------------------------

export const GoogleConfig = z.object({
  admin_email: z.email().openapi({ description: "A Google Workspace admin the service account acts as (domain-wide delegation)" }),
  customer_id: z.string().regex(/^[A-Za-z0-9_]+$/).default("my_customer"),
});
export const GoogleKey = z.object({
  type: z.literal("service_account"),
  client_email: z.email(),
  private_key: z.string().includes("PRIVATE KEY"),
  token_uri: z.string().optional(),
});

const GOOGLE_SCOPES = [
  "https://www.googleapis.com/auth/admin.directory.user.readonly",
  "https://www.googleapis.com/auth/admin.directory.group.readonly",
  "https://www.googleapis.com/auth/admin.directory.group.member.readonly",
].join(" ");

async function googleToken(ep: Endpoints, cfg: z.infer<typeof GoogleConfig>, key: z.infer<typeof GoogleKey>) {
  // The key file names its token endpoint; never follow it anywhere but Google's.
  if (key.token_uri && key.token_uri !== ep.googleTokenUrl) throw new ProviderError(`Unexpected token_uri in the key file: ${key.token_uri}`, true);
  let pk: CryptoKey;
  try {
    pk = await importPKCS8(key.private_key, "RS256");
  } catch {
    throw new ProviderError("The service account key's private_key couldn't be read", true);
  }
  const now = Math.floor(Date.now() / 1000);
  const assertion = await new SignJWT({ scope: GOOGLE_SCOPES })
    .setProtectedHeader({ alg: "RS256", typ: "JWT" })
    .setIssuer(key.client_email)
    .setSubject(cfg.admin_email)
    .setAudience(ep.googleTokenUrl)
    .setIssuedAt(now)
    .setExpirationTime(now + 3600)
    .sign(pk);
  const body = await getJson(
    ep.googleTokenUrl,
    { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion }) },
    "Google sign-in",
  );
  if (!body?.access_token) throw new ProviderError("Google returned no access token", true);
  return String(body.access_token);
}

async function googlePages(url: URL, token: string, field: string, what: string) {
  const items: any[] = [];
  for (let i = 0; i < MAX_PAGES; i++) {
    const body = await getJson(url.toString(), { headers: { authorization: `Bearer ${token}` } }, what);
    items.push(...(body?.[field] ?? []));
    if (!body?.nextPageToken) return items;
    url.searchParams.set("pageToken", body.nextPageToken);
  }
  throw new ProviderError(`${what}: too many pages`, false);
}

export async function fetchGoogle(ep: Endpoints, rawCfg: unknown, secret: string, opts: { groups: boolean }): Promise<Remote> {
  const cfg = GoogleConfig.parse(rawCfg);
  const key = GoogleKey.parse(JSON.parse(secret));
  const token = await googleToken(ep, cfg, key);
  const base = `${ep.googleAdminBase}/admin/directory/v1`;

  const u = new URL(`${base}/users`);
  u.searchParams.set("customer", cfg.customer_id);
  u.searchParams.set("maxResults", "500");
  u.searchParams.set("projection", "full");
  const users: RemoteUser[] = (await googlePages(u, token, "users", "Listing Google users")).map((x) => {
    const org = (x.organizations ?? []).find((o: any) => o.primary) ?? x.organizations?.[0] ?? {};
    return {
      external_id: String(x.id),
      email: String(x.primaryEmail ?? ""),
      given_name: String(x.name?.givenName ?? ""),
      family_name: String(x.name?.familyName ?? ""),
      title: String(org.title ?? ""),
      department: String(org.department ?? ""),
      active: !x.suspended && !x.archived,
    };
  });

  const groups: RemoteGroup[] = [];
  if (opts.groups) {
    const g = new URL(`${base}/groups`);
    g.searchParams.set("customer", cfg.customer_id);
    g.searchParams.set("maxResults", "200");
    for (const x of await googlePages(g, token, "groups", "Listing Google groups")) {
      const m = new URL(`${base}/groups/${encodeURIComponent(String(x.id))}/members`);
      m.searchParams.set("maxResults", "200");
      m.searchParams.set("includeDerivedMembership", "true"); // nested groups flattened: Nexus groups aren't nested
      const members = await googlePages(m, token, "members", `Listing members of ${x.name}`);
      groups.push({
        external_id: String(x.id),
        name: String(x.name ?? x.email ?? x.id).slice(0, 100),
        description: String(x.description ?? "").slice(0, 500),
        member_ids: members.filter((y) => y.type === "USER").map((y) => String(y.id)),
      });
    }
  }
  return { users, groups };
}

// ---- Microsoft Entra ID ---------------------------------------------------------------

export const EntraConfig = z.object({
  tenant_id: z.string().regex(/^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[A-Za-z0-9.-]+\.[A-Za-z]{2,})$/i, "A tenant ID (GUID) or primary domain"),
  client_id: z.guid(),
});

export async function entraToken(ep: Endpoints, cfg: z.infer<typeof EntraConfig>, secret: string) {
  const body = await getJson(
    `${ep.entraLoginBase}/${encodeURIComponent(cfg.tenant_id)}/oauth2/v2.0/token`,
    {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "client_credentials", client_id: cfg.client_id, client_secret: secret, scope: `${ep.graphBase}/.default` }),
    },
    "Microsoft sign-in",
  );
  if (!body?.access_token) throw new ProviderError("Microsoft returned no access token", true);
  return String(body.access_token);
}

export async function graphPages(ep: Endpoints, first: string, token: string, what: string) {
  const items: any[] = [];
  let url: string | undefined = first;
  for (let i = 0; i < MAX_PAGES && url; i++) {
    // Follow nextLink only on the Graph host.
    if (!url.startsWith(`${ep.graphBase}/`)) throw new ProviderError(`${what}: unexpected next page URL`, true);
    const body = await getJson(url, { headers: { authorization: `Bearer ${token}`, ConsistencyLevel: "eventual" } }, what);
    items.push(...(body?.value ?? []));
    url = body?.["@odata.nextLink"];
  }
  if (url) throw new ProviderError(`${what}: too many pages`, false);
  return items;
}

export async function fetchEntra(ep: Endpoints, rawCfg: unknown, secret: string, opts: { groups: boolean }): Promise<Remote> {
  const cfg = EntraConfig.parse(rawCfg);
  const token = await entraToken(ep, cfg, secret);
  const g = `${ep.graphBase}/v1.0`;
  const users: RemoteUser[] = (
    await graphPages(ep, `${g}/users?$select=id,givenName,surname,mail,userPrincipalName,accountEnabled,jobTitle,department,userType&$top=999`, token, "Listing Entra users")
  )
    .filter((x) => x.userType !== "Guest") // guests belong to other organizations
    .map((x) => ({
      external_id: String(x.id),
      email: String(x.mail || x.userPrincipalName || ""),
      given_name: String(x.givenName ?? ""),
      family_name: String(x.surname ?? ""),
      title: String(x.jobTitle ?? ""),
      department: String(x.department ?? ""),
      active: x.accountEnabled !== false,
    }));
  const groups: RemoteGroup[] = [];
  if (opts.groups) {
    for (const x of await graphPages(ep, `${g}/groups?$select=id,displayName,description&$top=999`, token, "Listing Entra groups")) {
      const members = await graphPages(ep, `${g}/groups/${encodeURIComponent(String(x.id))}/transitiveMembers/microsoft.graph.user?$select=id&$top=999`, token, `Listing members of ${x.displayName}`);
      groups.push({
        external_id: String(x.id),
        name: String(x.displayName ?? x.id).slice(0, 100),
        description: String(x.description ?? "").slice(0, 500),
        member_ids: members.map((y) => String(y.id)),
      });
    }
  }
  return { users, groups };
}

export function fetchDirectory(ep: Endpoints, provider: "google" | "entra", cfg: unknown, secret: string, opts: { groups: boolean }) {
  return provider === "google" ? fetchGoogle(ep, cfg, secret, opts) : fetchEntra(ep, cfg, secret, opts);
}
