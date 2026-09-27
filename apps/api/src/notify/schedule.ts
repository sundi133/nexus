/**
 * Local-time arithmetic for quiet hours and digests (NTF-07), in the user's
 * IANA time zone, DST included. Times are "HH:MM" strings.
 */

export const isTimeZone = (tz: string) => {
  try {
    new Intl.DateTimeFormat("en-US", { timeZone: tz });
    return true;
  } catch {
    return false;
  }
};

const toMinutes = (hhmm: string) => Number(hhmm.slice(0, 2)) * 60 + Number(hhmm.slice(3, 5));

/** Minutes since local midnight at `at` in `tz`. */
export function localMinutes(at: Date, tz: string): number {
  const parts = new Intl.DateTimeFormat("en-US", { timeZone: tz, hour: "2-digit", minute: "2-digit", hourCycle: "h23" }).formatToParts(at);
  const get = (t: string) => Number(parts.find((p) => p.type === t)!.value);
  return get("hour") * 60 + get("minute");
}

/** Whether `at` falls in the window [start, end), which may wrap past midnight. start === end means no window. */
export function inWindow(at: Date, start: string, end: string, tz: string): boolean {
  const m = localMinutes(at, tz);
  const s = toMinutes(start);
  const e = toMinutes(end);
  if (s === e) return false;
  return s < e ? m >= s && m < e : m >= s || m < e;
}

/**
 * The next instant after `from` when the local clock in `tz` reads `hhmm`
 * (whole minutes). If the time doesn't exist that day (a DST gap), the first
 * minute after the gap.
 */
export function nextLocalTime(from: Date, hhmm: string, tz: string): Date {
  const target = toMinutes(hhmm);
  const start = new Date(Math.floor(from.getTime() / 60_000) * 60_000 + 60_000); // strictly after, on a minute boundary
  let delta = (target - localMinutes(start, tz) + 1440) % 1440;
  let t = new Date(start.getTime() + delta * 60_000);
  // DST shifts the wall clock by up to an hour (or 30 minutes) between now and then: correct once or twice.
  for (let i = 0; i < 3; i++) {
    const off = target - localMinutes(t, tz);
    if (off === 0) return t;
    const fix = ((off + 1440 + 720) % 1440) - 720; // shortest way round
    const next = new Date(t.getTime() + fix * 60_000);
    if (next.getTime() <= from.getTime()) break;
    t = next;
  }
  // In a gap the target never appears: take the first local minute after it.
  delta = 0;
  while (localMinutes(t, tz) < target && delta++ < 120) t = new Date(t.getTime() + 60_000);
  return t;
}

/** Local "HH:MM" for display. */
export const hhmm = (at: Date, tz: string) => {
  const m = localMinutes(at, tz);
  return `${String(Math.floor(m / 60)).padStart(2, "0")}:${String(m % 60).padStart(2, "0")}`;
};
