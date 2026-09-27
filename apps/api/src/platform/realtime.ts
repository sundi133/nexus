import { EventEmitter } from "node:events";
import pg from "pg";

export type InboxSignal = { org_id: string; user_id: string; id: string; op: "insert" | "update" };
export type ChallengeSignal = { org_id: string; user_id: string; session_id: string; id: string; status: string };

/**
 * Fans Postgres NOTIFY signals out to in-process subscribers (SSE streams).
 * Works across API replicas because every replica LISTENs. Payloads carry IDs
 * only; subscribers re-read rows through RLS before sending anything.
 */
export class Realtime {
  private readonly emitter = new EventEmitter();
  private client: pg.Client | null = null;
  private stopped = false;

  constructor(private readonly url: string) {
    this.emitter.setMaxListeners(0);
  }

  async start() {
    this.stopped = false;
    // query_timeout: the heartbeat below must fail, not hang, on a connection that died silently.
    const client = new pg.Client({ connectionString: this.url, query_timeout: 10_000 });
    client.on("notification", (msg) => {
      if (!msg.payload) return;
      const data = JSON.parse(msg.payload) as InboxSignal | ChallengeSignal;
      if (msg.channel === "nexus_inbox") this.emitter.emit(`user:${data.user_id}`, { kind: "inbox", data });
      if (msg.channel === "nexus_challenge") {
        const ch = data as ChallengeSignal;
        this.emitter.emit(`user:${ch.user_id}`, { kind: "challenge", data: ch });
        this.emitter.emit(`session:${ch.session_id}`, { kind: "challenge", data: ch });
      }
    });
    // A lost connection (a restart, a failover) reconnects; events from a client we've given up
    // on are ignored, so one outage never starts more than one reconnect loop.
    client.on("error", () => this.client === client && this.reconnect());
    client.on("end", () => this.client === client && this.reconnect());
    try {
      await client.connect();
      await client.query("LISTEN nexus_inbox");
      await client.query("LISTEN nexus_challenge");
    } catch (err) {
      client.removeAllListeners();
      client.on("error", () => {}); // a late error from the dead socket must not crash the process
      await client.end().catch(() => {});
      throw err;
    }
    this.client = client;
    // A LISTEN connection carries no traffic of its own: one to a server that vanished (a
    // failover) would wait forever, missing every notification. A heartbeat finds out.
    if (this.heartbeat) clearInterval(this.heartbeat);
    this.heartbeat = setInterval(() => {
      if (this.client !== client) return;
      client.query("SELECT 1").catch(() => this.client === client && this.reconnect());
    }, 30_000);
    this.heartbeat.unref();
  }

  /** Starts listening, or keeps trying in the background if the database isn't there yet (boot during an outage). */
  startOrRetry() {
    this.stopped = false;
    this.start().catch(() => this.reconnect());
  }

  private heartbeat: NodeJS.Timeout | null = null;
  private reconnecting = false;

  /** One retry loop at a time, backing off from 1 s to 30 s until the database answers. */
  private reconnect() {
    if (this.stopped || this.reconnecting) return;
    this.reconnecting = true;
    const old = this.client;
    this.client = null;
    if (old) {
      old.removeAllListeners();
      old.on("error", () => {});
      void old.end().catch(() => {});
    }
    const attempt = (delay: number) => {
      this.retry = setTimeout(() => {
        if (this.stopped) return void (this.reconnecting = false);
        this.start().then(
          () => (this.reconnecting = false),
          () => attempt(Math.min(delay * 2, 30_000)),
        );
      }, delay);
    };
    attempt(1000);
  }

  private retry: NodeJS.Timeout | null = null;

  subscribe(key: `user:${string}` | `session:${string}`, fn: (e: RealtimeEvent) => void): () => void {
    this.emitter.on(key, fn);
    return () => this.emitter.off(key, fn);
  }

  async stop() {
    this.stopped = true;
    if (this.retry) clearTimeout(this.retry);
    if (this.heartbeat) clearInterval(this.heartbeat);
    await this.client?.end().catch(() => {});
  }
}

export type RealtimeEvent =
  | { kind: "inbox"; data: InboxSignal }
  | { kind: "challenge"; data: ChallengeSignal };
