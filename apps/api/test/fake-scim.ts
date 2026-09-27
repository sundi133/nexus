import http from "node:http";
import type { AddressInfo } from "node:net";

/** A strict fake SCIM 2.0 service: bearer auth, 409 on duplicate userName, filter search, PATCH replace, failures on demand. */

export type ScimUser = { id: string; userName: string; active: boolean; name?: { givenName: string; familyName: string }; title?: string; externalId?: string; [k: string]: unknown };
export const TOKEN = "scim-token-123";

export class FakeScim {
  state = {
    users: new Map<string, ScimUser>(),
    groups: new Map<string, { id: string; displayName: string; members: string[] }>(),
    requests: [] as string[],
    fail: [] as number[], // status codes to answer next, in order
    seq: 0,
  };
  private server: http.Server | null = null;

  async start(port = 0) {
    this.server = http.createServer((req, res) => void this.handle(req, res).catch((e) => res.writeHead(500).end(String(e))));
    await new Promise<void>((r) => this.server!.listen(port, "127.0.0.1", r));
    return `http://127.0.0.1:${(this.server.address() as AddressInfo).port}`;
  }

  stop() {
    this.server?.close();
  }

  byEmail(email: string) {
    return [...this.state.users.values()].find((u) => u.userName === email);
  }

  private async handle(req: http.IncomingMessage, res: http.ServerResponse) {
    const scim = this.state;
    const url = new URL(req.url!, "http://x");
    const body = await new Promise<any>((r) => {
      let d = "";
      req.on("data", (c) => (d += c)).on("end", () => r(d ? JSON.parse(d) : null));
    });
    const send = (status: number, json?: unknown) => res.writeHead(status, { "content-type": "application/scim+json" }).end(json ? JSON.stringify(json) : undefined);
    scim.requests.push(`${req.method} ${url.pathname}`);
    if (req.headers.authorization !== `Bearer ${TOKEN}`) return send(401, { detail: "Bad token" });
    const injected = scim.fail.shift();
    if (injected) return send(injected, { detail: "injected failure" });

    const path = url.pathname.replace(/^\/scim\/v2/, "");
    let m: RegExpExecArray | null;
    if (path === "/Users" && req.method === "GET") {
      const f = /^userName eq "(.+)"$/.exec(url.searchParams.get("filter") ?? "");
      const found = f ? [...scim.users.values()].filter((u) => u.userName === f[1]) : [...scim.users.values()].slice(0, 1);
      return send(200, { totalResults: found.length, Resources: found });
    }
    if (path === "/Users" && req.method === "POST") {
      if ([...scim.users.values()].some((u) => u.userName === body.userName)) return send(409, { detail: "userName already exists" });
      const u = { ...body, id: `u${++scim.seq}` };
      scim.users.set(u.id, u);
      return send(201, u);
    }
    if ((m = /^\/Users\/([^/]+)$/.exec(path))) {
      const u = scim.users.get(m[1]!);
      if (!u) return send(404, { detail: "no such user" });
      if (req.method === "PATCH") {
        for (const op of body.Operations) Object.assign(u, op.value);
        return send(200, u);
      }
      if (req.method === "DELETE") {
        scim.users.delete(u.id);
        return send(204);
      }
    }
    if (path === "/Groups" && req.method === "POST") {
      const g = { id: `g${++scim.seq}`, displayName: body.displayName, members: body.members.map((x: { value: string }) => x.value) };
      scim.groups.set(g.id, g);
      return send(201, g);
    }
    if ((m = /^\/Groups\/([^/]+)$/.exec(path))) {
      const g = scim.groups.get(m[1]!);
      if (!g) return send(404, { detail: "no such group" });
      if (req.method === "PATCH") {
        for (const op of body.Operations) {
          if (op.path === "members") g.members = op.value.map((x: { value: string }) => x.value);
          else Object.assign(g, op.value);
        }
        return send(200, g);
      }
      if (req.method === "DELETE") {
        scim.groups.delete(g.id);
        return send(204);
      }
    }
    send(404, { detail: "unknown route" });
  }
}
