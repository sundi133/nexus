/**
 * Mobile push delivery (ARCHITECTURE §11). Payloads are content-free: an ID and
 * a generic title. The app fetches details over the authenticated API, so no
 * security data sits in Apple/Google infrastructure or on a lock screen.
 */
export type PushTarget = { platform: "ios" | "android" | "web"; token: string };
export type PushPayload = { title: string; category: string; id: string; priority: "high" | "normal" };

export interface PushSender {
  send(target: PushTarget, payload: PushPayload): Promise<{ ok: boolean; invalidToken?: boolean }>;
}

/** Dev/test sender: records pushes instead of calling APNs/FCM (the app also receives challenges live over SSE). */
export class RecordingPushSender implements PushSender {
  readonly sent: { target: PushTarget; payload: PushPayload }[] = [];
  constructor(private readonly log = false) {}
  async send(target: PushTarget, payload: PushPayload) {
    this.sent.push({ target, payload });
    if (this.log) console.log(`[push] ${target.platform} ${target.token.slice(0, 12)}… ${payload.category} ${payload.id}`);
    return { ok: true };
  }
}
