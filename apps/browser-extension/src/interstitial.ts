import type { Policy } from "./policy.js";

/** Shown instead of an AI app the organization blocks, or asks people to think twice about. */
const q = new URLSearchParams(location.search);
const mode = q.get("mode") === "warn" ? "warn" : "block";
const appKey = q.get("app") ?? "";
const target = location.hash.slice(1); // the address that was requested
const $ = (id: string) => document.getElementById(id)!;

void chrome.runtime.sendMessage({ type: "policy" }).then((r: { policy: Policy | null }) => {
  const app = r?.policy?.apps.find((a) => a.key === appKey);
  const name = app?.name ?? "This AI app";
  document.title = `${name}: ${mode === "block" ? "blocked" : "check first"}`;
  $("title").textContent = mode === "block" ? `${name} is blocked by your organization` : `Your organization asks you to check before using ${name}`;
  $("body").textContent =
    mode === "block"
      ? "Company data shouldn't go to this AI app. Use one your organization approves instead."
      : "It isn't one your organization approves. Don't share company, customer or personal data in it.";
  if (r?.policy?.message) $("message").textContent = r.policy.message;
  let host = "";
  try {
    host = new URL(target).hostname;
  } catch {}
  void chrome.runtime.sendMessage({ type: "report", events: [{ at: new Date().toISOString(), kind: "visit", action: mode === "block" ? "blocked" : "warned", app: appKey, host }] });
  if (mode === "warn" && /^https?:\/\//.test(target)) {
    const go = $("continue") as HTMLButtonElement;
    go.hidden = false;
    go.onclick = async () => {
      await chrome.runtime.sendMessage({ type: "allow", app: appKey });
      await chrome.runtime.sendMessage({ type: "report", events: [{ at: new Date().toISOString(), kind: "visit", action: "continued", app: appKey, host }] });
      location.replace(target);
    };
  }
});
$("back").onclick = () => (history.length > 1 ? history.back() : window.close());
