import net from "node:net";
import { sql } from "kysely";
import pg from "pg";
import { afterAll, describe, expect, it } from "vitest";
import { Db } from "../src/platform/db.js";

/**
 * A database that disappears without closing connections (a failover, a deleted pod: packets
 * go nowhere) must not wedge the API: queries time out, dead connections are dropped, and it
 * works again as soon as the database is reachable.
 */

/** A TCP proxy to the test database that can stop forwarding without closing anything. */
function blackholeProxy(target: URL) {
  let frozen = false;
  const sockets = new Set<net.Socket>();
  const server = net.createServer((client) => {
    const upstream = net.connect(Number(target.port || 5432), target.hostname);
    sockets.add(client).add(upstream);
    client.on("data", (d) => !frozen && upstream.write(d));
    upstream.on("data", (d) => !frozen && client.write(d));
    const close = () => (client.destroy(), upstream.destroy());
    client.on("error", close).on("close", close);
    upstream.on("error", close).on("close", close);
  });
  return {
    listen: () => new Promise<number>((r) => server.listen(0, "127.0.0.1", () => r((server.address() as net.AddressInfo).port))),
    freeze: () => (frozen = true),
    // Recovery: new connections work again; the old ones stay dead, as after a real failover.
    thaw: () => {
      frozen = false;
      for (const s of sockets) s.pause();
    },
    close: () => {
      for (const s of sockets) s.destroy();
      server.close();
    },
  };
}

const target = new URL(process.env.NEXUS_DATABASE_URL!);
const proxy = blackholeProxy(target);
let db: Db | null = null;
afterAll(async () => {
  proxy.close();
  await db?.close().catch(() => {});
});

describe("a database that stops answering", () => {
  it("times queries out, drops the dead connections, and recovers without a restart", async () => {
    const port = await proxy.listen();
    const url = new URL(target.toString());
    url.hostname = "127.0.0.1";
    url.port = String(port);
    db = new Db(url.toString(), { queryTimeoutMs: 1500, poolSize: 4 });
    const ping = () => db!.unscoped((tx) => sql<{ ok: number }>`SELECT 1 AS ok`.execute(tx)).then((r) => r.rows[0]!.ok);
    expect(await ping()).toBe(1);

    proxy.freeze();
    const t0 = Date.now();
    const stuck = await Promise.allSettled([ping(), ping(), ping(), ping(), ping(), ping()]);
    expect(stuck.every((s) => s.status === "rejected")).toBe(true); // failed, not hung
    expect(Date.now() - t0).toBeLessThan(10_000);

    proxy.thaw();
    let ok = 0;
    for (let i = 0; i < 40 && ok < 3; i++) {
      ok += (await ping().catch(() => 0)) === 1 ? 1 : 0;
      await new Promise((r) => setTimeout(r, 250));
    }
    expect(ok).toBe(3); // working again on fresh connections
  }, 30_000);
});

describe("the database ending a connection that's in use", () => {
  it("fails that request without taking the process down", async () => {
    const url = new URL(process.env.NEXUS_DATABASE_URL!);
    url.searchParams.set("application_name", "nexus-in-use-test");
    const local = new Db(url.toString(), { poolSize: 2 });
    const owner = new pg.Client({ connectionString: process.env.NEXUS_DATABASE_OWNER_URL });
    await owner.connect();
    const crashes: unknown[] = [];
    const onCrash = (e: unknown) => crashes.push(e);
    process.on("uncaughtException", onCrash);
    try {
      // A request holds a connection between two queries (a transaction), and the server ends it
      // meanwhile, as a restart or failover does to every connection.
      const inFlight = local.unscoped(async (tx) => {
        await sql`SELECT 1`.execute(tx);
        await owner.query("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name = 'nexus-in-use-test'");
        await new Promise((r) => setTimeout(r, 300));
        return sql`SELECT 2`.execute(tx);
      });
      await expect(inFlight).rejects.toThrow();
      await new Promise((r) => setTimeout(r, 200));
      expect(crashes).toEqual([]);
      // And the next request gets a fresh connection.
      expect((await local.unscoped((tx) => sql<{ n: number }>`SELECT 3 AS n`.execute(tx))).rows[0]!.n).toBe(3);
    } finally {
      process.off("uncaughtException", onCrash);
      await owner.end();
      await local.close();
    }
  }, 20_000);
});
