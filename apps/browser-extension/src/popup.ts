import type { Policy } from "./policy.js";

type Status = { configured: boolean; user: string; policy: Policy | null; lastSync: string | null; lastError: string; queued: number; discovery: boolean };
const $ = (id: string) => document.getElementById(id)!;

async function render() {
  const s = (await chrome.runtime.sendMessage({ type: "status" })) as Status;
  $("state").textContent = !s.configured ? "Not set up" : s.lastError ? "Needs attention" : "Protecting you";
  $("state").className = !s.configured || s.lastError ? "warn" : "ok";
  $("detail").textContent = s.lastError || (s.lastSync ? `Policy up to date (${new Date(s.lastSync).toLocaleTimeString()})` : "Connecting…");
  $("user").textContent = s.user || "—";
  const blocked = s.policy?.apps.filter((a) => a.action === "block").map((a) => a.name) ?? [];
  $("blocked").textContent = blocked.length ? blocked.join(", ") : "none";
  // Say plainly what's reported about browsing.
  $("discovery").textContent = s.discovery ? "Which work apps you use, and whether you sign in with a password (never pages or what you type)" : "Nothing about your browsing";
  $("version").textContent = chrome.runtime.getManifest().version;
}
$("sync").onclick = async () => {
  await chrome.runtime.sendMessage({ type: "sync" });
  await render();
};
void render();
