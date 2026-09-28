/**
 * Mobile push delivery (ARCHITECTURE §11). Payloads are content-free: an ID and
 * a generic title. The app fetches details over the authenticated API, so no
 * security data sits in Apple/Google infrastructure or on a lock screen.
 */
export type PushTarget = { platform: "ios" | "android" | "web"; token: string };
export type PushPayload = { title: string; category: string; id: string; priority: "high" | "normal" };

/**
 * How urgently a notification should interrupt: sign-in approvals must reach someone within
 * seconds; requests waiting for them soon; the rest whenever. The phone app creates matching
 * Android notification channels with these IDs.
 */
export type PushChannel = "sign-ins" | "approvals" | "updates";
export function pushChannel(category: string): PushChannel {
  if (category === "auth.mfa_challenge") return "sign-ins";
  if (category === "access.approval") return "approvals";
  return "updates";
}

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

/** Sends each push through the service for its platform; platforms without a configured service are skipped. */
export class RoutingPushSender implements PushSender {
  constructor(private readonly routes: Partial<Record<PushTarget["platform"], PushSender>>, private readonly fallback?: PushSender) {}
  async send(target: PushTarget, payload: PushPayload) {
    const s = this.routes[target.platform] ?? this.fallback;
    return s ? s.send(target, payload) : { ok: false };
  }
}
