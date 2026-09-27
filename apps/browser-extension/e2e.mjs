// End-to-end: the built extension in a real Chromium, against a fake Nexus and fake AI apps on
// *.localhost (Chromium resolves those to this machine). Drives the browser over the DevTools
// protocol with Node's own WebSocket; no test framework or browser driver needed.
//   CHROME_PATH=/path/to/chromium node e2e.mjs      (after `node build.mjs`)
// Branded Chrome ignores --load-extension since 137: use Chromium or Chrome for Testing (e.g. Playwright's).
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, existsSync, readdirSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir, homedir } from "node:os";
import { join, resolve } from "node:path";

const fail = (msg) => {
  console.error(`  FAIL ${msg}`);
  process.exitCode = 1;
  throw new Error(msg);
};
const pass = (msg) => console.log(`  ok   ${msg}`);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(what, fn, ms = 15000) {
  const end = Date.now() + ms;
  for (;;) {
    const v = await fn().catch(() => undefined);
    if (v) return v;
    if (Date.now() > end) fail(`timed out waiting for ${what}`);
    await sleep(200);
  }
}

function findChromium() {
  if (process.env.CHROME_PATH) return process.env.CHROME_PATH;
  const cache = join(homedir(), process.platform === "darwin" ? "Library/Caches/ms-playwright" : ".cache/ms-playwright");
  const dirs = existsSync(cache) ? readdirSync(cache).filter((d) => /^chromium-\d+$/.test(d)).sort().reverse() : [];
  for (const d of dirs) {
    for (const p of [
      "chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing",
      "chrome-mac-x64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing",
      "chrome-mac/Chromium.app/Contents/MacOS/Chromium",
      "chrome-mac-arm64/Chromium.app/Contents/MacOS/Chromium",
      "chrome-linux64/chrome",
      "chrome-linux/chrome",
    ]) {
      if (existsSync(join(cache, d, p))) return join(cache, d, p);
    }
  }
  fail("no Chromium: set CHROME_PATH");
}

// ---- A fake Nexus and fake AI apps ------------------------------------------------------------------

const TOKEN = "nxb_e2e_token";
const synced = [];
const policy = {
  version: "e2e-1",
  apps: [
    { key: "testai", name: "Test AI", hosts: ["chat.localhost"], action: "allow" },
    { key: "blockedai", name: "Blocked AI", hosts: ["blocked.localhost"], action: "block" },
    { key: "shadow-app", name: "Shadow App", hosts: ["shadow.localhost"], action: "block", kind: "saas" },
  ],
  // As many hosts as the real catalog (about 2,400), so registering the sign-in script is tested at scale.
  saas: { discovery: true, apps: [{ key: "work-app", hosts: ["work.localhost"] }, ...Array.from({ length: 2400 }, (_, i) => ({ key: `app-${i}`, hosts: [`app${i}.example.com`] }))] },
  dlp: { detectors: { secret: "block", private_key: "block", credit_card: "warn", us_ssn: "monitor", iban: "off", email_list: "off" }, custom: [] },
  uploads: "block",
  message: "See go/ai-policy",
};
const page = `<!doctype html><title>Test AI</title><textarea id="box"></textarea><input type="file" id="file"><button aria-label="Send message" id="send">Send</button>`;
const server = createServer((req, res) => {
  if (req.url === "/v1/browser/extension/sync" && req.method === "POST") {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      if (req.headers.authorization !== `NexusBrowser ${TOKEN}`) return res.writeHead(401).end("{}");
      const b = JSON.parse(body);
      synced.push(b);
      res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ version: policy.version, policy: b.policy_version === policy.version ? null : policy, accepted: b.events.length }));
    });
    return;
  }
  // A work app's sign-in page: no form, a button (like many single-page apps).
  if (String(req.headers.host).startsWith("work.localhost")) return res.writeHead(200, { "content-type": "text/html" }).end(`<!doctype html><title>Work</title><input id="email"><input type="password" id="pw"><button id="login">Sign in</button>`);
  res.writeHead(200, { "content-type": "text/html" }).end(page);
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const port = server.address().port;

// ---- Chromium with the extension ---------------------------------------------------------------------

const ext = resolve("dist");
if (!existsSync(join(ext, "manifest.json"))) fail("build first: node build.mjs");
const profile = mkdtempSync(join(tmpdir(), "nexus-ext-"));
const chrome = spawn(findChromium(), [
  "--headless=new", `--user-data-dir=${profile}`, "--remote-debugging-port=0", "--no-first-run", "--no-default-browser-check",
  // CI runners (Ubuntu 24.04's AppArmor) don't allow Chromium's sandbox; a throwaway VM is the sandbox there.
  ...(process.env.CI ? ["--no-sandbox"] : []),
  `--disable-extensions-except=${ext}`, `--load-extension=${ext}`, "--host-resolver-rules=MAP *.localhost 127.0.0.1", "about:blank",
], { stdio: ["ignore", "ignore", "pipe"] });
const wsUrl = await new Promise((resolveUrl, reject) => {
  let err = "";
  chrome.stderr.on("data", (d) => {
    err += d;
    const m = /DevTools listening on (ws:\/\/\S+)/.exec(err);
    if (m) resolveUrl(m[1]);
  });
  chrome.on("exit", (code) => reject(new Error(`Chromium exited (${code}): ${err.slice(-500)}`)));
});

// A tiny DevTools protocol client (flat sessions).
const ws = new WebSocket(wsUrl);
await new Promise((r) => ws.addEventListener("open", r, { once: true }));
let nextId = 1;
const waiting = new Map();
const listeners = [];
ws.addEventListener("message", (m) => {
  const msg = JSON.parse(m.data);
  if (msg.id && waiting.has(msg.id)) {
    const { resolve: ok, reject } = waiting.get(msg.id);
    waiting.delete(msg.id);
    msg.error ? reject(new Error(msg.error.message)) : ok(msg.result);
  } else for (const l of listeners) l(msg);
});
const cdp = (method, params = {}, sessionId) =>
  new Promise((ok, reject) => {
    const id = nextId++;
    waiting.set(id, { resolve: ok, reject });
    ws.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
  });
const evaluate = async (sessionId, expression) => {
  const r = await cdp("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true }, sessionId);
  if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description ?? r.exceptionDetails.text);
  return r.result.value;
};

try {
  console.log("==> the extension's service worker syncs with Nexus");
  const sw = await until("the service worker", async () => (await cdp("Target.getTargets")).targetInfos.find((t) => t.type === "service_worker" && t.url.endsWith("/background.js")));
  const extOrigin = sw.url.replace(/\/background\.js$/, ""); // URL.origin is "null" for chrome-extension:
  const swSession = (await cdp("Target.attachToTarget", { targetId: sw.targetId, flatten: true })).sessionId;
  await evaluate(swSession, `chrome.storage.local.set({ devConfig: { server: "http://127.0.0.1:${port}", token: "${TOKEN}" }, devUser: "pat@example.test" })`);
  await until("the first sync", async () => synced.length > 0);
  if (synced[0].user !== "pat@example.test") fail(`user: ${synced[0].user}`);
  pass("synced with the organization token, as the profile's user");
  await until("rules and content scripts", async () => {
    const [rules, scripts] = await evaluate(swSession, `Promise.all([chrome.declarativeNetRequest.getDynamicRules(), chrome.scripting.getRegisteredContentScripts()]).then(([r, s]) => [r.length, s.length])`);
    return rules === 2 && scripts === 2;
  });
  pass("navigation rules for the blocked AI and SaaS apps; content scripts on AI apps and, for sign-ins, on known SaaS apps");

  console.log("==> in an AI app");
  const { targetId } = await cdp("Target.createTarget", { url: `http://chat.localhost:${port}/` });
  const tab = (await cdp("Target.attachToTarget", { targetId, flatten: true })).sessionId;
  await until("the page and the content script", async () => (await evaluate(tab, `document.readyState === "complete" && !!document.getElementById("box")`)) && (await sleep(800), true));
  const paste = (text) =>
    evaluate(tab, `(() => { const dt = new DataTransfer(); dt.setData("text/plain", ${JSON.stringify(text)}); const box = document.getElementById("box"); box.focus();
      return box.dispatchEvent(new ClipboardEvent("paste", { clipboardData: dt, bubbles: true, cancelable: true })); })()`);
  if ((await paste("my key AKIAIOSFODNN7EXAMPLE, why does s3 fail?")) !== false) fail("a pasted AWS key went through");
  pass("pasting an AWS key is stopped");
  if ((await paste("How do I write a binary search in Go?")) !== true) fail("an ordinary paste was stopped");
  pass("an ordinary paste goes through");
  if ((await paste("SSN 123-45-6789 for the form")) !== true) fail("a monitored paste was stopped");
  pass("a monitored detector reports without stopping");
  const enter = await evaluate(tab, `(() => { const box = document.getElementById("box"); box.value = "-----BEGIN RSA PRIVATE KEY-----\\nMIIE"; box.focus();
    return box.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true, cancelable: true })); })()`);
  if (enter !== false) fail("Enter with a private key in the box went through");
  pass("sending a private key with Enter is stopped");
  const upload = await evaluate(tab, `(() => { const input = document.getElementById("file"); const dt = new DataTransfer(); dt.items.add(new File(["x"], "customers.csv")); input.files = dt.files;
    const went = input.dispatchEvent(new Event("change", { bubbles: true, cancelable: true })); return [went, input.value]; })()`);
  if (upload[0] !== false || upload[1] !== "") fail(`upload not blocked: ${JSON.stringify(upload)}`);
  pass("uploading a file is blocked, and the file is cleared");

  console.log("==> a blocked AI app");
  await cdp("Page.enable", {}, tab);
  await cdp("Page.navigate", { url: `http://blocked.localhost:${port}/chat?q=1` }, tab);
  const landed = await until("the interstitial", async () => {
    const href = await evaluate(tab, "location.href");
    return href.startsWith(`${extOrigin}/interstitial.html`) && href;
  });
  if (!landed.includes("mode=block&app=blockedai") || !landed.endsWith(`#http://blocked.localhost:${port}/chat?q=1`)) fail(`interstitial: ${landed}`);
  const title = await until("its text", async () => {
    const t = await evaluate(tab, `document.getElementById("title").textContent`);
    return t.includes("blocked") && t;
  });
  pass(`it's replaced by the interstitial: "${title}"`);

  console.log("==> SaaS discovery and access control");
  await cdp("Page.navigate", { url: `http://work.localhost:${port}/login` }, tab);
  await until("the work app and its script", async () => (await evaluate(tab, `location.hostname === "work.localhost" && document.readyState === "complete" && !!document.getElementById("pw")`)) && (await sleep(800), true));
  await evaluate(tab, `(() => { document.getElementById("email").value = "pat@example.test"; document.getElementById("pw").value = "hunter2-Secret!"; document.getElementById("login").click(); })()`);
  await cdp("Page.navigate", { url: `http://shadow.localhost:${port}/` }, tab);
  const shadowTitle = await until("the SaaS interstitial", async () => {
    const t = (await evaluate(tab, "location.href")).startsWith(`${extOrigin}/interstitial.html`) && (await evaluate(tab, `document.getElementById("body").textContent`));
    return t && t.includes("apps your organization approves") && t;
  });
  pass(`an unapproved SaaS app is blocked: "${shadowTitle.slice(0, 60)}…"`);

  console.log("==> what Nexus hears");
  const before = synced.length;
  await evaluate(swSession, `chrome.storage.local.get("devConfig").then(({ devConfig }) => chrome.storage.local.set({ devConfig: { ...devConfig, nudge: Date.now() } }))`);
  await until("the next sync", async () => synced.length > before);
  const events = synced.flatMap((s) => s.events);
  const has = (p) => events.some((e) => Object.entries(p).every(([k, v]) => e[k] === v));
  if (!has({ kind: "dlp", action: "blocked", detector: "secret", app: "testai" })) fail(`no blocked secret: ${JSON.stringify(events)}`);
  if (!has({ kind: "dlp", action: "monitored", detector: "us_ssn" })) fail("no monitored SSN");
  if (!has({ kind: "dlp", action: "blocked", detector: "private_key" })) fail("no blocked private key");
  if (!has({ kind: "upload", action: "blocked", detail: "1 file (csv)" })) fail("no blocked upload");
  if (!has({ kind: "visit", action: "blocked", app: "blockedai" })) fail("no blocked visit");
  if (!has({ kind: "visit", action: "allowed", app: "testai" })) fail("no visit");
  if (!has({ kind: "saas", app: "work-app", host: "" })) fail(`no SaaS visit: ${JSON.stringify(events.filter((e) => e.kind.startsWith("saas")))}`);
  if (!has({ kind: "saas_login", app: "work-app" })) fail("no password sign-in");
  if (!has({ kind: "visit", action: "blocked", app: "shadow-app" })) fail("no blocked SaaS visit");
  if (events.some((e) => e.kind === "saas" && e.app !== "work-app")) fail("a page outside the catalog was counted");
  const raw = JSON.stringify(synced);
  if (raw.includes("AKIAIOSFODNN7EXAMPLE") || raw.includes("123-45-6789") || raw.includes("binary search")) fail("pasted text reached the server");
  if (raw.includes("hunter2") || raw.includes("/login")) fail("a password or a page address reached the server");
  pass(`${events.length} events, with detectors and masked hints; no pasted text reached the server`);
  console.log("==> browser extension e2e passed");
} finally {
  ws.close();
  chrome.kill();
  server.close();
  await sleep(300);
  rmSync(profile, { recursive: true, force: true });
}
