import { createServer, type Server } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { Realtime } from "./realtime.js";

/** A "database" that accepts connections and drops them at once, like one that's restarting. */
function droppingServer(): Promise<{ server: Server; port: number; attempts: () => number }> {
  let n = 0;
  const server = createServer((s) => {
    n++;
    s.destroy();
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve({ server, port: (server.address() as { port: number }).port, attempts: () => n })));
}

let rt: Realtime | null = null;
let srv: Server | null = null;
afterEach(async () => {
  await rt?.stop();
  srv?.close();
});

describe("Realtime reconnection", () => {
  it("retries one attempt at a time with backoff while the database is down (no reconnect storm)", async () => {
    const db = await droppingServer();
    srv = db.server;
    rt = new Realtime(`postgres://u:p@127.0.0.1:${db.port}/x`);
    await expect(rt.start()).rejects.toThrow();
    (rt as unknown as { reconnect: () => void }).reconnect(); // what a lost connection triggers
    await new Promise((r) => setTimeout(r, 4200));
    // Backoff 1 s, 2 s (then 4 s): the first connect plus about 2 retries in 4 seconds, not dozens.
    expect(db.attempts()).toBeLessThanOrEqual(4);
    expect(db.attempts()).toBeGreaterThanOrEqual(2);
  }, 10_000);
});
