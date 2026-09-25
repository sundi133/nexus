/**
 * SCIM 2.0 (RFC 7643/7644) resource mapping, filters and PATCH, as pure
 * functions. Written for what Okta and Microsoft Entra ID actually send:
 * capitalised ops ("Replace"), path-less value objects, "False" as a string,
 * enterprise-extension paths, and member filters in remove paths.
 */

export const SCHEMA = {
  user: "urn:ietf:params:scim:schemas:core:2.0:User",
  group: "urn:ietf:params:scim:schemas:core:2.0:Group",
  enterprise: "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
  list: "urn:ietf:params:scim:api:messages:2.0:ListResponse",
  patch: "urn:ietf:params:scim:api:messages:2.0:PatchOp",
  error: "urn:ietf:params:scim:api:messages:2.0:Error",
} as const;

export class ScimError extends Error {
  constructor(
    readonly status: number,
    message: string,
    readonly scimType?: "invalidFilter" | "invalidValue" | "invalidPath" | "noTarget" | "uniqueness" | "mutability" | "invalidSyntax" | "tooMany",
  ) {
    super(message);
  }
  body() {
    return { schemas: [SCHEMA.error], status: String(this.status), ...(this.scimType ? { scimType: this.scimType } : {}), detail: this.message };
  }
}

type Json = Record<string, any>;

// ---- Representations ------------------------------------------------------------------

export type LocalUser = { id: string; email: string; given_name: string; family_name: string; title: string; department: string; status: string; created_at: Date; updated_at: Date; manager_id?: string | null };

export function toScimUser(u: LocalUser, a: { externalId: string | null; groups: { id: string; name: string }[]; base: string }): Json {
  const display = `${u.given_name} ${u.family_name}`.trim() || u.email;
  return {
    schemas: [SCHEMA.user, SCHEMA.enterprise],
    id: u.id,
    ...(a.externalId ? { externalId: a.externalId } : {}),
    userName: u.email,
    name: { givenName: u.given_name, familyName: u.family_name, formatted: display },
    displayName: display,
    emails: [{ value: u.email, type: "work", primary: true }],
    active: u.status === "active" || u.status === "staged",
    ...(u.title ? { title: u.title } : {}),
    [SCHEMA.enterprise]: { ...(u.department ? { department: u.department } : {}), ...(u.manager_id ? { manager: { value: u.manager_id, $ref: `${a.base}/Users/${u.manager_id}` } } : {}) },
    groups: a.groups.map((g) => ({ value: g.id, display: g.name, $ref: `${a.base}/Groups/${g.id}` })),
    meta: { resourceType: "User", created: u.created_at.toISOString(), lastModified: u.updated_at.toISOString(), location: `${a.base}/Users/${u.id}`, version: `W/"${u.updated_at.getTime()}"` },
  };
}

export function toScimGroup(g: { id: string; name: string; created_at: Date; updated_at: Date }, a: { externalId: string | null; members: { id: string; email: string }[] | null; base: string }): Json {
  return {
    schemas: [SCHEMA.group],
    id: g.id,
    ...(a.externalId ? { externalId: a.externalId } : {}),
    displayName: g.name,
    ...(a.members ? { members: a.members.map((m) => ({ value: m.id, display: m.email, $ref: `${a.base}/Users/${m.id}` })) } : {}),
    meta: { resourceType: "Group", created: g.created_at.toISOString(), lastModified: g.updated_at.toISOString(), location: `${a.base}/Groups/${g.id}` },
  };
}

/** Case-insensitive property access (SCIM attribute names are case-insensitive). */
const get = (o: Json | undefined, key: string): any => {
  if (!o || typeof o !== "object") return undefined;
  const k = Object.keys(o).find((x) => x.toLowerCase() === key.toLowerCase());
  return k === undefined ? undefined : o[k];
};

export const toBool = (v: unknown): boolean | undefined => {
  if (typeof v === "boolean") return v;
  if (typeof v === "string" && /^(true|false)$/i.test(v)) return v.toLowerCase() === "true"; // Entra ID sends "False"
  return undefined;
};

export type UserFields = { email: string; given_name: string; family_name: string; title: string; department: string; active: boolean; external_id: string | null; manager_id?: string | null };

const EMAIL = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

/** The Nexus fields a SCIM user carries. The email is the work (or primary) email, else userName. */
export function userFields(r: Json): UserFields {
  const emails = (get(r, "emails") as Json[] | undefined) ?? [];
  const pick = emails.find((e) => get(e, "primary") === true || toBool(get(e, "primary"))) ?? emails.find((e) => get(e, "type") === "work") ?? emails[0];
  const userName = String(get(r, "userName") ?? "").trim();
  const email = String(get(pick, "value") ?? (EMAIL.test(userName) ? userName : "")).trim().toLowerCase();
  if (!EMAIL.test(email)) throw new ScimError(400, "A user needs an email address (emails or an email-shaped userName)", "invalidValue");
  const name = (get(r, "name") as Json | undefined) ?? {};
  const display = String(get(r, "displayName") ?? "").trim();
  const ext = (get(r, SCHEMA.enterprise) as Json | undefined) ?? {};
  const active = get(r, "active") === undefined ? true : toBool(get(r, "active"));
  if (active === undefined) throw new ScimError(400, "active must be true or false", "invalidValue");
  return {
    email,
    given_name: String(get(name, "givenName") ?? display.split(" ")[0] ?? "").slice(0, 100),
    family_name: String(get(name, "familyName") ?? display.split(" ").slice(1).join(" ")).slice(0, 100),
    title: String(get(r, "title") ?? "").slice(0, 200),
    department: String(get(ext, "department") ?? "").slice(0, 200),
    active,
    external_id: get(r, "externalId") ? String(get(r, "externalId")).slice(0, 500) : null,
    // The manager is a SCIM user ID, i.e. a Nexus user ID; absent means "not managed through SCIM".
    ...(get(ext, "manager") !== undefined ? { manager_id: get(get(ext, "manager") as Json, "value") ? String(get(get(ext, "manager") as Json, "value")) : null } : {}),
  };
}

// ---- Filters ----------------------------------------------------------------------------

type Cmp = { attr: string; sub?: { attr: string; op: string; value: unknown }; then?: string; op: string; value: unknown };
export type Filter = { or: Cmp[][] }; // OR of ANDs

const OPS = new Set(["eq", "ne", "co", "sw", "ew", "pr", "gt", "ge", "lt", "le"]);

function tokenize(s: string): string[] {
  const out: string[] = [];
  const re = /\s*("(?:[^"\\]|\\.)*"|\[|\]|\(|\)|[^\s[\]()"]+)/g;
  let m: RegExpExecArray | null;
  let at = 0;
  while ((m = re.exec(s))) {
    if (m.index !== at && s.slice(at, m.index).trim()) throw new ScimError(400, `Can't parse filter near "${s.slice(at, at + 20)}"`, "invalidFilter");
    out.push(m[1]!);
    at = re.lastIndex;
  }
  if (s.slice(at).trim()) throw new ScimError(400, "Can't parse filter", "invalidFilter");
  return out;
}

function literal(t: string | undefined): unknown {
  if (t === undefined) throw new ScimError(400, "Filter is missing a value", "invalidFilter");
  if (t.startsWith('"')) return JSON.parse(t);
  if (t === "true" || t === "false") return t === "true";
  if (t === "null") return null;
  if (/^-?\d+(\.\d+)?$/.test(t)) return Number(t);
  throw new ScimError(400, `Unexpected filter value ${t}`, "invalidFilter");
}

/** Parses `attr op value` comparisons joined by and/or (and binds tighter), with `attr[sub op value].x` paths. */
export function parseFilter(input: string): Filter {
  if (input.length > 1000) throw new ScimError(400, "Filter too long", "invalidFilter");
  const t = tokenize(input);
  let i = 0;
  const cmp = (): Cmp => {
    const attr = t[i++];
    if (!attr || attr === "(" || OPS.has(attr.toLowerCase())) throw new ScimError(400, "Grouping with parentheses isn't supported", "invalidFilter");
    let sub: Cmp["sub"];
    let then: string | undefined;
    if (t[i] === "[") {
      i++;
      const sa = t[i++]!;
      const so = t[i++]!.toLowerCase();
      const sv = literal(t[i++]);
      if (t[i++] !== "]") throw new ScimError(400, "Unclosed [ in filter", "invalidFilter");
      sub = { attr: sa, op: so, value: sv };
      if (t[i]?.startsWith(".")) then = t[i++]!.slice(1);
    }
    const op = t[i]?.toLowerCase();
    if (!op || !OPS.has(op)) {
      if (sub) return { attr, sub, then, op: "pr", value: undefined }; // `members[value eq "x"]` on its own
      throw new ScimError(400, `Unsupported filter operator ${t[i]}`, "invalidFilter");
    }
    i++;
    return { attr, sub, then, op, value: op === "pr" ? undefined : literal(t[i++]) };
  };
  const or: Cmp[][] = [[cmp()]];
  while (i < t.length) {
    const j = t[i++]!.toLowerCase();
    if (j === "and") or.at(-1)!.push(cmp());
    else if (j === "or") or.push([cmp()]);
    else throw new ScimError(400, `Unexpected "${t[i - 1]}" in filter`, "invalidFilter");
  }
  return { or };
}

/** Values at an attribute path (`name.givenName`, `emails.value`, `urn:…:User:department`). */
function valuesAt(r: Json, path: string): unknown[] {
  const ext = path.toLowerCase().startsWith(SCHEMA.enterprise.toLowerCase() + ":");
  const [head, ...rest] = ext ? [SCHEMA.enterprise, path.slice(SCHEMA.enterprise.length + 1)] : path.split(".");
  let vals: unknown[] = [get(r, head!)];
  for (const seg of ext ? rest : rest) {
    vals = vals.flatMap((v) => (Array.isArray(v) ? v : [v])).map((v) => get(v as Json, seg));
  }
  return vals.flatMap((v) => (Array.isArray(v) ? v : [v])).filter((v) => v !== undefined);
}

function compare(v: unknown, op: string, want: unknown): boolean {
  if (op === "pr") return v !== undefined && v !== null && v !== "";
  const a = typeof v === "string" ? v.toLowerCase() : v;
  const b = typeof want === "string" ? want.toLowerCase() : want;
  switch (op) {
    case "eq":
      return a === b;
    case "ne":
      return a !== b;
    case "co":
      return typeof a === "string" && typeof b === "string" && a.includes(b);
    case "sw":
      return typeof a === "string" && typeof b === "string" && a.startsWith(b);
    case "ew":
      return typeof a === "string" && typeof b === "string" && a.endsWith(b);
    case "gt":
      return (a as number) > (b as number);
    case "ge":
      return (a as number) >= (b as number);
    case "lt":
      return (a as number) < (b as number);
    case "le":
      return (a as number) <= (b as number);
  }
  return false;
}

export function matches(f: Filter, r: Json): boolean {
  return f.or.some((all) =>
    all.every((c) => {
      if (c.sub) {
        const items = ((get(r, c.attr) as Json[] | undefined) ?? []).filter((it) => compare(get(it, c.sub!.attr), c.sub!.op, c.sub!.value));
        if (!c.then) return items.length > 0;
        return items.some((it) => compare(get(it, c.then!), c.op, c.value));
      }
      const vals = valuesAt(r, c.attr);
      return c.op === "pr" ? vals.some((v) => compare(v, "pr", undefined)) : vals.some((v) => compare(v, c.op, c.value));
    }),
  );
}

/** `attr eq "value"` for one of the given attributes: lets the caller answer with an index lookup. */
export function simpleEq(f: Filter, attrs: string[]): { attr: string; value: string } | null {
  if (f.or.length !== 1 || f.or[0]!.length !== 1) return null;
  const c = f.or[0]![0]!;
  if (c.op !== "eq" || c.sub || typeof c.value !== "string") return null;
  const attr = attrs.find((a) => a.toLowerCase() === c.attr.toLowerCase());
  return attr ? { attr, value: c.value } : null;
}

// ---- PATCH ------------------------------------------------------------------------------

export type PatchOp = { op: string; path?: string; value?: unknown };

export function patchOps(body: Json): PatchOp[] {
  const ops = get(body, "Operations");
  if (!Array.isArray(ops) || !ops.length) throw new ScimError(400, "PATCH needs Operations", "invalidSyntax");
  return ops.map((o: Json) => {
    const op = String(get(o, "op") ?? "").toLowerCase();
    if (!["add", "replace", "remove"].includes(op)) throw new ScimError(400, `Unsupported op ${get(o, "op")}`, "invalidSyntax");
    return { op, path: get(o, "path") as string | undefined, value: get(o, "value") };
  });
}

/** Sets a value at a simple path on a copy-in-place resource (for add/replace on users). */
function setAt(r: Json, path: string, value: unknown) {
  const lower = path.toLowerCase();
  if (lower.startsWith(SCHEMA.enterprise.toLowerCase() + ":")) {
    const attr = path.slice(SCHEMA.enterprise.length + 1);
    r[SCHEMA.enterprise] = { ...(get(r, SCHEMA.enterprise) ?? {}), [attr]: value };
    return;
  }
  const filtered = /^(\w+)\[(\w+)\s+eq\s+"([^"]*)"\]\.(\w+)$/i.exec(path); // emails[type eq "work"].value
  if (filtered) {
    const [, attr, subAttr, subVal, leaf] = filtered as unknown as [string, string, string, string, string];
    const list: Json[] = [...((get(r, attr) as Json[]) ?? [])];
    const item = list.find((x) => String(get(x, subAttr)).toLowerCase() === subVal.toLowerCase());
    if (item) item[leaf] = value;
    else list.push({ [subAttr]: subVal, [leaf]: value, ...(attr.toLowerCase() === "emails" ? { primary: list.length === 0 } : {}) });
    r[attr] = list;
    return;
  }
  const parts = path.split(".");
  if (parts.length === 2) {
    r[parts[0]!] = { ...(get(r, parts[0]!) ?? {}), [parts[1]!]: value };
    return;
  }
  r[path] = value;
}

/** Applies add/replace/remove to a user resource. Unknown attributes are ignored, as RFC 7644 allows. */
export function patchUser(resource: Json, ops: PatchOp[]): Json {
  const r: Json = JSON.parse(JSON.stringify(resource));
  for (const o of ops) {
    if (o.op === "remove") {
      if (!o.path) throw new ScimError(400, "remove needs a path", "noTarget");
      const p = o.path.toLowerCase();
      if (p === "title") r.title = "";
      else if (p === `${SCHEMA.enterprise.toLowerCase()}:department`) r[SCHEMA.enterprise] = { ...(get(r, SCHEMA.enterprise) ?? {}), department: "" };
      else if (p === "name.givenname") r.name = { ...(r.name ?? {}), givenName: "" };
      else if (p === "name.familyname") r.name = { ...(r.name ?? {}), familyName: "" };
      continue; // removing anything else (e.g. phone numbers we don't store) is a no-op
    }
    if (o.path) {
      setAt(r, o.path, o.value);
    } else if (o.value && typeof o.value === "object") {
      for (const [k, v] of Object.entries(o.value as Json)) {
        if (k.toLowerCase() === SCHEMA.enterprise.toLowerCase() && v && typeof v === "object") r[SCHEMA.enterprise] = { ...(get(r, SCHEMA.enterprise) ?? {}), ...v };
        else if (k.includes(".") || k.includes(":")) setAt(r, k, v); // Entra: { "name.givenName": "Ada" }
        else if (k.toLowerCase() === "name" && v && typeof v === "object") r.name = { ...(r.name ?? {}), ...v };
        else r[k] = v;
      }
    } else {
      throw new ScimError(400, "An operation without a path needs an object value", "invalidValue");
    }
  }
  return r;
}

/** Group PATCH, reduced to what changes: name, external ID, members added/removed/replaced. */
export function groupChanges(ops: PatchOp[]): { displayName?: string; externalId?: string; add: string[]; remove: string[]; replace?: string[] } {
  const out: ReturnType<typeof groupChanges> = { add: [], remove: [] };
  const ids = (v: unknown) => (Array.isArray(v) ? v : v ? [v] : []).map((m) => String(get(m as Json, "value") ?? "")).filter(Boolean);
  for (const o of ops) {
    const path = o.path?.trim();
    const memberFilter = path && /^members\[\s*value\s+eq\s+"([^"]+)"\s*\]$/i.exec(path);
    if (memberFilter) {
      if (o.op !== "remove") throw new ScimError(400, "Only remove is supported on a filtered members path", "invalidPath");
      out.remove.push(memberFilter[1]!);
    } else if (path?.toLowerCase() === "members") {
      if (o.op === "add") out.add.push(...ids(o.value));
      else if (o.op === "remove") out.remove.push(...ids(o.value)); // Entra: value lists who to remove
      else out.replace = ids(o.value);
    } else if (path?.toLowerCase() === "displayname") {
      if (o.op === "remove") throw new ScimError(400, "displayName can't be removed", "mutability");
      out.displayName = String(o.value ?? "");
    } else if (path?.toLowerCase() === "externalid") {
      out.externalId = o.op === "remove" ? "" : String(o.value ?? "");
    } else if (!path && o.value && typeof o.value === "object") {
      const v = o.value as Json;
      if (get(v, "displayName") !== undefined) out.displayName = String(get(v, "displayName"));
      if (get(v, "externalId") !== undefined) out.externalId = String(get(v, "externalId"));
      if (get(v, "members") !== undefined) {
        if (o.op === "add") out.add.push(...ids(get(v, "members")));
        else out.replace = ids(get(v, "members"));
      }
    }
  }
  return out;
}
