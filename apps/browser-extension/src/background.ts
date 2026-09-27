import { type Event, navigationRules, type Policy } from "./policy.js";

/**
 * Service worker: syncs with Nexus every minute (sends queued events, gets the policy when it
 * changed), keeps navigation rules for blocked and warned apps, and runs the content script only
 * on AI apps' pages.
 *
 * Configuration comes from managed policy (Google Admin, Intune, Group Policy):
 *   { "server": "https://api.nexus.example.com", "token": "nxb_…" }
 */

const VERSION: string = chrome.runtime.getManifest().version;
const MAX_QUEUE = 5000;
const ALLOW_MINUTES = 60; // "Continue" on a warning lets that app through for an hour

type Config = { server: string; token: string };
type Local = { policy?: Policy; queue?: Event[]; allowed?: Record<string, number>; lastSync?: string; lastError?: string; retryAt?: number; user?: string };

const local = (): Promise<Local> => chrome.storage.local.get(null);
const save = (v: Partial<Local>) => chrome.storage.local.set(v);

async function config(): Promise<Config | null> {
  const m = (await chrome.storage.managed.get(["server", "token"]).catch(() => ({}))) as Partial<Config>;
  if (m.server && m.token) return { server: m.server.replace(/\/+$/, ""), token: m.token };
  // Unpacked pilots and tests: the same settings, stored by hand (see the README).
  const d = ((await chrome.storage.local.get("devConfig")) as { devConfig?: Partial<Config> }).devConfig;
  return d?.server && d.token ? { server: d.server.replace(/\/+$/, ""), token: d.token } : null;
}

async function profileEmail(): Promise<string> {
  try {
    const u = await chrome.identity.getProfileUserInfo({ accountStatus: "ANY" });
    if (u?.email) return u.email;
  } catch {}
  return ((await chrome.storage.local.get("devUser")) as { devUser?: string }).devUser ?? "";
}

/**
 * Every change to the queue goes through here, one at a time: a read-modify-write of storage
 * from two messages at once would lose events.
 */
let queueLock: Promise<unknown> = Promise.resolve();
function withQueue<T>(fn: (queue: Event[]) => Promise<{ queue: Event[]; result: T }> | { queue: Event[]; result: T }): Promise<T> {
  const run = queueLock.then(async () => {
    const { queue = [] } = await local();
    const out = await fn(queue);
    await save({ queue: out.queue });
    return out.result;
  });
  queueLock = run.catch(() => {});
  return run;
}

/** Queues events for the next sync (bounded: oldest dropped first). */
export function report(events: Event[]) {
  if (!events.length) return Promise.resolve();
  return withQueue((queue) => {
    const next = [...queue, ...events];
    return { queue: next.slice(Math.max(0, next.length - MAX_QUEUE)), result: undefined };
  });
}

let syncing: Promise<void> | null = null;
async function sync() {
  syncing ??= doSync().finally(() => (syncing = null));
  return syncing;
}

async function doSync() {
  const cfg = await config();
  const st = await local();
  if (!cfg) return save({ lastError: "Not configured: install through your organization's browser policy" });
  if (st.retryAt && Date.now() < st.retryAt) return;
  const events = await withQueue((queue) => ({ queue, result: queue.slice(0, 500) })); // a consistent snapshot
  const user = await profileEmail();
  try {
    const res = await fetch(`${cfg.server}/v1/browser/extension/sync`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `NexusBrowser ${cfg.token}` },
      body: JSON.stringify({ user, extension_version: VERSION, policy_version: st.policy?.version ?? "", events }),
    });
    if (res.status === 503 || res.status === 429) {
      const wait = Number(res.headers.get("retry-after")) || 60;
      return save({ retryAt: Date.now() + wait * 1000, lastError: "Nexus is busy; retrying soon" });
    }
    if (res.status === 400 || res.status === 413) {
      // Nexus can't take this batch: drop it rather than send it forever.
      await withQueue((queue) => ({ queue: queue.slice(events.length), result: undefined }));
      return save({ lastError: `Nexus refused ${events.length} events (${res.status})` });
    }
    if (!res.ok) return save({ lastError: `Nexus answered ${res.status}` });
    const body = (await res.json()) as { policy: Policy | null };
    // Only drop what was sent: events queued meanwhile stay.
    await withQueue((queue) => ({ queue: queue.slice(events.length), result: undefined }));
    await save({ lastSync: new Date().toISOString(), lastError: "", retryAt: 0, user });
    if (body.policy) {
      await save({ policy: body.policy });
      await applyPolicy(body.policy);
    }
  } catch (e) {
    await save({ lastError: `Can't reach Nexus: ${(e as Error).message}` });
  }
}

/** Navigation rules and content scripts follow the policy (and any "continue" allowances). */
async function applyPolicy(policy: Policy) {
  const { allowed = {} } = await local();
  const now = Date.now();
  const allowHosts = Object.entries(allowed).filter(([, until]) => until > now).map(([h]) => h);
  const rules = navigationRules(policy, `chrome-extension://${chrome.runtime.id}`, allowHosts);
  const old = await chrome.declarativeNetRequest.getDynamicRules();
  await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: old.map((r: { id: number }) => r.id), addRules: rules });

  const matches = [...new Set(policy.apps.flatMap((a) => a.hosts.flatMap((h) => [`*://${h}/*`, `*://*.${h}/*`])))];
  await chrome.scripting.unregisterContentScripts().catch(() => {});
  if (matches.length) {
    await chrome.scripting.registerContentScripts([{ id: "nexus-ai", js: ["content.js"], matches, runAt: "document_start", allFrames: false, persistAcrossSessions: true }]);
  }
}

chrome.runtime.onInstalled.addListener(() => {
  chrome.alarms.create("sync", { periodInMinutes: 1 });
  void sync();
});
chrome.runtime.onStartup.addListener(() => void sync());
chrome.alarms.onAlarm.addListener((a: { name: string }) => {
  if (a.name === "sync") void sync();
  if (a.name === "allowances") void local().then((s) => s.policy && applyPolicy(s.policy));
});
chrome.storage.onChanged.addListener((changes: Record<string, unknown>, area: string) => {
  if (area === "managed" || (area === "local" && "devConfig" in changes)) void sync();
});

/** Content scripts and the interstitial page talk to us through messages. */
chrome.runtime.onMessage.addListener((msg: any, _sender: unknown, reply: (v: unknown) => void) => {
  void (async () => {
    const st = await local();
    switch (msg?.type) {
      case "policy":
        return reply({ policy: st.policy ?? null });
      case "report":
        await report(msg.events as Event[]);
        return reply({ ok: true });
      case "allow": {
        // "Continue" on a warning: this app's hosts pass for an hour.
        const app = st.policy?.apps.find((a) => a.key === msg.app);
        if (!app) return reply({ ok: false });
        const until = Date.now() + ALLOW_MINUTES * 60_000;
        const allowed = { ...(st.allowed ?? {}), ...Object.fromEntries(app.hosts.map((h) => [h, until])) };
        await save({ allowed });
        await applyPolicy(st.policy!);
        chrome.alarms.create("allowances", { when: until + 1000 });
        return reply({ ok: true });
      }
      case "status":
        return reply({ configured: !!(await config()), user: st.user ?? "", policy: st.policy ?? null, lastSync: st.lastSync ?? null, lastError: st.lastError ?? "", queued: st.queue?.length ?? 0 });
      case "sync":
        await sync();
        return reply({ ok: true });
    }
    reply(null);
  })();
  return true; // async reply
});
