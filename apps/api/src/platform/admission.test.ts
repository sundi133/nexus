import { describe, expect, it } from "vitest";
import { Gate, retryAfter } from "./admission.js";

describe("Gate", () => {
  it("runs up to its concurrency, queues the next, and hands slots over in order", async () => {
    const g = new Gate(2, 10, 1000);
    const a = await g.acquire();
    const b = await g.acquire();
    expect(g.stats).toEqual({ running: 2, waiting: 0 });
    const order: string[] = [];
    const c = g.acquire().then((r) => (order.push("c"), r));
    const d = g.acquire().then((r) => (order.push("d"), r));
    expect(g.stats).toEqual({ running: 2, waiting: 2 });
    a!();
    a!(); // releasing twice frees one slot only
    const rc = await c;
    expect(order).toEqual(["c"]);
    expect(g.stats).toEqual({ running: 2, waiting: 1 });
    b!();
    const rd = await d;
    rc!();
    rd!();
    expect(g.stats).toEqual({ running: 0, waiting: 0 });
  });

  it("sheds at once when the queue is full, and after the wait limit", async () => {
    const g = new Gate(1, 1, 30);
    const a = await g.acquire();
    const queued = g.acquire();
    expect(await g.acquire()).toBeNull(); // queue full: immediate
    expect(await queued).toBeNull(); // waited 30 ms, gave up
    expect(g.stats).toEqual({ running: 1, waiting: 0 });
    a!();
    expect(g.stats).toEqual({ running: 0, waiting: 0 });
  });

  it("spreads Retry-After over [base, 2×base)", () => {
    for (let i = 0; i < 200; i++) {
      const s = retryAfter(15);
      expect(s).toBeGreaterThanOrEqual(15);
      expect(s).toBeLessThan(30);
    }
  });
});
