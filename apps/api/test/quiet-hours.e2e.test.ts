import { randomUUID } from "node:crypto";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { notifyUsers } from "../src/notify/send.js";
import type { RecordingPushSender } from "../src/platform/push.js";
import type { MemoryMailer } from "../src/platform/mailer.js";
import { bootApp, PASSWORD, uniqueEmail } from "./harness.js";

/** Quiet hours and the daily email digest (NTF-07): critical never waits; the rest arrives as one summary. */

let h: Awaited<ReturnType<typeof bootApp>>;
let owner: pg.Client;
let token = "";
let orgId = "";
let userId = "";
const pushes = () => (h.deps.push as RecordingPushSender).sent.filter((p) => p.target.token.endsWith(RUN));
const mails = () => (h.deps.mailer as MemoryMailer).sent.filter((m) => m.to === email);
const RUN = randomUUID().slice(0, 8);
const email = uniqueEmail("quinn");

/** "HH:MM" in UTC, `minutes` from now. */
const utc = (minutes: number) => new Date(Date.now() + minutes * 60_000).toISOString().slice(11, 16);
const notify = (severity: "info" | "warning" | "critical", title: string) =>
  h.deps.db.tenant(orgId, (tx) => notifyUsers(tx, orgId, [userId], { category: "security.alert", severity, title, link: "/audit" }));
const inbox = async () => (await h.call("GET", "/v1/me/notifications?limit=20&filter=all", { token })).body.data as { id: string; title: string }[];
const deliveries = async (title: string) => {
  const n = (await inbox()).find((x) => x.title === title)!;
  return (await h.call("GET", `/v1/me/notifications/${n.id}/deliveries`, { token })).body.data as { channel: string; status: string; detail: string }[];
};
const summaryJobs = async () => (await owner.query("SELECT dedupe_key, run_at FROM jobs WHERE org_id = $1 AND kind = 'notify.summary' AND status = 'queued' ORDER BY dedupe_key", [orgId])).rows;
/** Run what's due now (the job runner's view), without touching run_at. */
const runDue = () => h.jobs.runOnce({ orgId });
const runAll = async () => {
  await owner.query("UPDATE jobs SET run_at = now() WHERE org_id = $1 AND status = 'queued'", [orgId]);
  await h.jobs.runOnce({ orgId });
};
const prefs = (body: Record<string, unknown>) => h.call("PUT", "/v1/me/notification-preferences", { token, body });

beforeAll(async () => {
  h = await bootApp();
  owner = new pg.Client({ connectionString: process.env.NEXUS_DATABASE_OWNER_URL });
  await owner.connect();
  token = (await h.call("POST", "/v1/signup", { body: { organization_name: "Quiet Co", email, password: PASSWORD, given_name: "Quinn" } })).body.token;
  const me = (await h.call("GET", "/v1/me", { token })).body;
  orgId = me.organization.id;
  userId = me.user.id;
  await owner.query("INSERT INTO push_registrations (id, org_id, user_id, platform, token, last_seen_at) VALUES ($1, $2, $3, 'ios', $4, now())", [randomUUID(), orgId, userId, `phone-${RUN}`]);
  await runAll(); // sign-up's own notifications, if any
});
afterAll(async () => {
  await owner.end();
  await h.close();
});

describe("preferences", () => {
  it("defaults to no quiet hours and no digest, and validates what you set", async () => {
    const r = await h.call("GET", "/v1/me/notification-preferences", { token });
    expect(r.body).toEqual({ email: "important", push: "important", timezone: "UTC", quiet_hours: { enabled: false, start: "22:00", end: "07:00" }, digest: { enabled: false, time: "08:00" } });
    expect((await prefs({ timezone: "Mars/Olympus" })).status).toBe(400);
    expect((await prefs({ quiet_hours: { enabled: true, start: "25:00", end: "07:00" } })).status).toBe(400);
    // Partial updates keep the rest.
    expect((await prefs({ push: "all" })).body).toMatchObject({ push: "all", email: "important", timezone: "UTC" });
    await prefs({ email: "all" });
  });
});

describe("quiet hours", () => {
  it("holds non-critical push and email, but never critical ones", async () => {
    await prefs({ timezone: "UTC", quiet_hours: { enabled: true, start: utc(-60), end: utc(60) } });
    const before = { push: pushes().length, mail: mails().length };
    await notify("warning", "Sync needs attention");
    await notify("info", "Weekly report ready");
    await notify("critical", "Account contained");
    await runDue();

    expect(pushes().length - before.push).toBe(1); // only the critical one
    expect(mails().length - before.mail).toBe(1);
    expect(mails().at(-1)!.subject).toBe("[Critical] Account contained");
    expect(await deliveries("Sync needs attention")).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ channel: "push", status: "held", detail: `Quiet hours until ${utc(60)}` }),
        expect.objectContaining({ channel: "email", status: "held" }),
      ]),
    );
    // One summary per channel, due when quiet hours end.
    const jobs = await summaryJobs();
    expect(jobs.map((j) => j.dedupe_key)).toEqual([`notify.summary:${userId}:email`, `notify.summary:${userId}:push`]);
    const due = new Date(jobs[0].run_at).getTime() - Date.now();
    expect(due).toBeGreaterThan(58 * 60_000);
    expect(due).toBeLessThan(61 * 60_000);
  });

  it("sends one summary when they end: unread only by push, everything by email", async () => {
    const n = (await inbox()).find((x) => x.title === "Weekly report ready")!;
    await h.call("POST", `/v1/me/notifications/${n.id}/read`, { token }); // seen in the console meanwhile
    const before = { push: pushes().length, mail: mails().length };
    // Quiet hours end.
    await prefs({ quiet_hours: { enabled: true, start: utc(-120), end: utc(-60) } });
    await runDue(); // the settings change re-timed the summaries to now

    const newPushes = pushes().slice(before.push);
    expect(newPushes).toHaveLength(1);
    expect(newPushes[0]!.payload).toMatchObject({ title: "New notification", category: "notify.summary" }); // content-free
    const newMails = mails().slice(before.mail);
    expect(newMails).toHaveLength(1);
    expect(newMails[0]!.subject).toBe("2 notifications during quiet hours");
    expect(newMails[0]!.text).toContain("- Sync needs attention (Needs attention · ");
    expect(newMails[0]!.text).toContain("- Weekly report ready");
    expect(newMails[0]!.html).toContain("Sync needs attention");

    expect(await deliveries("Weekly report ready")).toEqual(
      expect.arrayContaining([expect.objectContaining({ channel: "push", status: "skipped", detail: "Already read in Nexus" }), expect.objectContaining({ channel: "email", status: "sent" })]),
    );
    expect((await deliveries("Sync needs attention")).find((d) => d.channel === "push")).toMatchObject({ status: "sent", detail: expect.stringMatching(/^In the \d\d:\d\d summary \(1\)$/) });
    expect(await summaryJobs()).toEqual([]);
  });

  it("waits again if the summary comes due while still in quiet hours", async () => {
    await prefs({ quiet_hours: { enabled: true, start: utc(-60), end: utc(60) } });
    await notify("warning", "Rollout halted");
    await runDue();
    const before = pushes().length;
    await runAll(); // forced early
    expect(pushes().length).toBe(before);
    expect((await summaryJobs()).length).toBe(2); // rescheduled for the end
    await prefs({ quiet_hours: { enabled: false, start: "22:00", end: "07:00" } });
    await runDue(); // turning quiet hours off releases it now
    expect(pushes().length).toBe(before + 1);
  });
});

describe("daily digest", () => {
  it("collects non-critical email into one message at the chosen time", async () => {
    const digestAt = utc(30);
    await prefs({ digest: { enabled: true, time: digestAt } });
    const before = { push: pushes().length, mail: mails().length };
    await notify("warning", "Device out of compliance");
    await notify("info", "App assigned");
    await notify("critical", "Break-glass account used");
    await runDue();
    expect(mails().length - before.mail).toBe(1); // only critical, right away
    expect(pushes().length - before.push).toBe(3); // push isn't affected by the digest
    expect((await deliveries("App assigned")).find((d) => d.channel === "email")).toMatchObject({ status: "held", detail: `In the daily digest at ${digestAt}` });

    await runAll(); // forced early: still waits for the digest time
    expect(mails().length - before.mail).toBe(1);
    // Digest time comes: held two minutes ago, digest at one minute ago.
    await owner.query("UPDATE notification_deliveries SET at = at - interval '2 minutes' WHERE org_id = $1 AND status = 'held'", [orgId]);
    await owner.query("UPDATE notification_preferences SET digest_time = $2 WHERE user_id = $1", [userId, utc(-1)]);
    await runAll();
    const digest = mails().at(-1)!;
    expect(digest.subject).toBe("Your Nexus digest: 2 notifications");
    expect(digest.html).toContain("Your Nexus digest");
    expect(digest.text).toContain("Device out of compliance");
    expect(digest.text).toContain("App assigned");
    expect(digest.text).not.toContain("Break-glass");
  });
});
