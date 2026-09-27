// Steady traffic against the API Service from inside the cluster, for the HA drill. Runs in the API
// image (Node). Prints one JSON line per 5 s and a summary: every failure, with its time.
const base = process.env.BASE, seconds = Number(process.env.SECONDS_TO_RUN ?? 120), concurrency = 4;
const email = `drill-${Date.now()}@drill.example`;
let token;
for (let i = 0; !token; i++) {
  try {
    const r = await fetch(`${base}/v1/signup`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ organization_name: "Drill", email, password: "violet-harbor-quartz-drill", given_name: "D" }) });
    token = (await r.json()).token;
  } catch {}
  if (!token) { if (i > 30) throw new Error("signup failed"); await new Promise((r) => setTimeout(r, 2000)); }
}
const start = Date.now(), until = start + seconds * 1000;
let ok = 0; const failures = []; let window = { ok: 0, failed: 0 };
const one = async () => {
  const t = Date.now();
  try {
    const r = await fetch(`${base}/v1/me`, { headers: { authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(10_000) });
    await r.arrayBuffer();
    if (r.status === 200) { ok++; window.ok++; return; }
    failures.push({ at: Math.round((t - start) / 1000), status: r.status }); window.failed++;
  } catch (e) {
    failures.push({ at: Math.round((t - start) / 1000), error: String(e.cause?.code ?? e.name) }); window.failed++;
  }
};
const tick = setInterval(() => { console.log(JSON.stringify({ t: Math.round((Date.now() - start) / 1000), ...window })); window = { ok: 0, failed: 0 }; }, 5000);
await Promise.all(Array.from({ length: concurrency }, async () => { while (Date.now() < until) { await one(); await new Promise((r) => setTimeout(r, 20)); } }));
clearInterval(tick);
console.log("SUMMARY " + JSON.stringify({ ok, failed: failures.length, failures: failures.slice(0, 50) }));
