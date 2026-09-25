import { networkError } from "../platform/outbound.js";

/**
 * Minimal SCIM 2.0 client (RFC 7643/7644) for pushing people and groups to
 * apps. Only the operations provisioning needs; PATCH uses value-only
 * "replace", which Slack, GitHub, Atlassian, Zoom and others accept.
 */

export class ScimError extends Error {
  constructor(
    message: string,
    readonly status: number, // 0 = network
    readonly retryable: boolean,
  ) {
    super(message);
  }
}

const CORE_USER = "urn:ietf:params:scim:schemas:core:2.0:User";
const ENTERPRISE = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
const GROUP = "urn:ietf:params:scim:schemas:core:2.0:Group";
const PATCH = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

export type ScimUser = {
  userName: string;
  externalId: string;
  name: { givenName: string; familyName: string; formatted: string };
  displayName: string;
  emails: { value: string; type: "work"; primary: true }[];
  title: string;
  department: string;
};

export function scimUser(u: { id: string; email: string; given_name: string; family_name: string; title: string; department: string }): ScimUser {
  const formatted = `${u.given_name} ${u.family_name}`.trim() || u.email;
  return {
    userName: u.email,
    externalId: u.id,
    name: { givenName: u.given_name, familyName: u.family_name, formatted },
    displayName: formatted,
    emails: [{ value: u.email, type: "work", primary: true }],
    title: u.title,
    department: u.department,
  };
}

const userBody = ({ department, ...u }: ScimUser, active: boolean) => ({
  schemas: [CORE_USER, ENTERPRISE],
  ...u,
  active,
  [ENTERPRISE]: { department },
});

export class ScimClient {
  private base: string;
  constructor(
    base: string,
    private token: string,
  ) {
    this.base = base.replace(/\/+$/, "");
  }

  private async req(method: string, path: string, body?: unknown): Promise<any> {
    let res: Response;
    try {
      res = await fetch(this.base + path, {
        method,
        headers: { authorization: `Bearer ${this.token}`, accept: "application/scim+json, application/json", ...(body ? { "content-type": "application/scim+json" } : {}) },
        body: body ? JSON.stringify(body) : undefined,
        signal: AbortSignal.timeout(20_000),
        redirect: "error",
      });
    } catch (err) {
      throw new ScimError(`Couldn't reach the app: ${networkError(err)}`, 0, true);
    }
    const text = await res.text();
    let json: any = null;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {
      /* not JSON */
    }
    if (!res.ok) {
      const detail = json?.detail ?? json?.message ?? "";
      const what = res.status === 401 || res.status === 403 ? "The app rejected the provisioning token" : `The app answered HTTP ${res.status}`;
      throw new ScimError(`${what}${detail ? `: ${String(detail).slice(0, 300)}` : ""}`, res.status, res.status === 429 || res.status >= 500);
    }
    return json;
  }

  /** Confirms the endpoint speaks SCIM and the token works. */
  async probe() {
    await this.req("GET", "/Users?count=1&startIndex=1");
  }

  async createUser(u: ScimUser): Promise<string> {
    const r = await this.req("POST", "/Users", userBody(u, true));
    if (!r?.id) throw new ScimError("The app didn't return an id for the new account", 200, false);
    return String(r.id);
  }

  async findUser(userName: string): Promise<string | null> {
    const q = encodeURIComponent(`userName eq "${userName.replace(/(["\\])/g, "\\$1")}"`);
    const r = await this.req("GET", `/Users?filter=${q}&count=2`);
    const found = r?.Resources?.[0];
    return found?.id ? String(found.id) : null;
  }

  async updateUser(id: string, u: ScimUser, active: boolean) {
    const { schemas: _s, ...value } = userBody(u, active);
    await this.req("PATCH", `/Users/${encodeURIComponent(id)}`, { schemas: [PATCH], Operations: [{ op: "replace", value }] });
  }

  async setActive(id: string, active: boolean) {
    await this.req("PATCH", `/Users/${encodeURIComponent(id)}`, { schemas: [PATCH], Operations: [{ op: "replace", value: { active } }] });
  }

  async deleteUser(id: string) {
    await this.req("DELETE", `/Users/${encodeURIComponent(id)}`);
  }

  async createGroup(displayName: string, memberIds: string[]): Promise<string> {
    const r = await this.req("POST", "/Groups", { schemas: [GROUP], displayName, members: memberIds.map((value) => ({ value })) });
    if (!r?.id) throw new ScimError("The app didn't return an id for the new group", 200, false);
    return String(r.id);
  }

  async updateGroup(id: string, displayName: string, memberIds: string[]) {
    await this.req("PATCH", `/Groups/${encodeURIComponent(id)}`, {
      schemas: [PATCH],
      Operations: [
        { op: "replace", value: { displayName } },
        { op: "replace", path: "members", value: memberIds.map((value) => ({ value })) },
      ],
    });
  }

  async deleteGroup(id: string) {
    await this.req("DELETE", `/Groups/${encodeURIComponent(id)}`);
  }
}
