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
    const client = new pg.Client({ connectionString: this.url });
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
    client.on("error", () => this.reconnect());
    client.on("end", () => this.reconnect());
    await client.connect();
    await client.query("LISTEN nexus_inbox");
    await client.query("LISTEN nexus_challenge");
    this.client = client;
  }

  private reconnect() {
    if (this.stopped) return;
    this.client = null;
    setTimeout(() => this.start().catch(() => this.reconnect()), 1000);
  }

  subscribe(key: `user:${string}` | `session:${string}`, fn: (e: RealtimeEvent) => void): () => void {
    this.emitter.on(key, fn);
    return () => this.emitter.off(key, fn);
  }

  async stop() {
    this.stopped = true;
    await this.client?.end().catch(() => {});
  }
}

export type RealtimeEvent =
  | { kind: "inbox"; data: InboxSignal }
  | { kind: "challenge"; data: ChallengeSignal };
