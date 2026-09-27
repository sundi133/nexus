import { appFor, check, describe, dlpEvents, type Event as ReportEvent, type Policy, type Verdict } from "./policy.js";

/**
 * Runs on AI apps' pages. Before the page sees them, it checks what people paste, what they
 * send (Enter or a Send button) and what files they upload, against the organization's policy.
 * Text is scanned here and never leaves the browser: reports carry the detector and a masked hint.
 */

let policy: Policy | null = null;
let app: ReturnType<typeof appFor> = null;
const host = location.hostname.toLowerCase();

const send = (msg: unknown): Promise<any> => chrome.runtime.sendMessage(msg).catch(() => null);
const report = (events: ReportEvent[]) => void send({ type: "report", events });
const now = () => new Date().toISOString();

// ---- Reading and writing what people type -------------------------------------------------------

const isEditable = (el: Element | null): el is HTMLElement =>
  !!el && ((el as HTMLElement).isContentEditable || el instanceof HTMLTextAreaElement || (el instanceof HTMLInputElement && /^(text|search|url|email|)$/.test(el.type)));

let lastEditable: HTMLElement | null = null;
const textOf = (el: HTMLElement | null) => (!el ? "" : el instanceof HTMLTextAreaElement || el instanceof HTMLInputElement ? el.value : el.innerText);

function insert(el: HTMLElement, text: string) {
  el.focus();
  // execCommand keeps the page's editor (React, ProseMirror…) in step, unlike setting the value.
  if (!document.execCommand("insertText", false, text) && (el instanceof HTMLTextAreaElement || el instanceof HTMLInputElement)) {
    el.setRangeText(text, el.selectionStart ?? el.value.length, el.selectionEnd ?? el.value.length, "end");
    el.dispatchEvent(new Event("input", { bubbles: true }));
  }
}

// ---- What people see (in a shadow root, so the page's styles can't touch it) --------------------------

let shadow: ShadowRoot | null = null;
function root() {
  if (shadow) return shadow;
  const hostEl = document.createElement("nexus-guard");
  hostEl.style.cssText = "all:initial;position:fixed;inset:0;z-index:2147483647;pointer-events:none";
  (document.body ?? document.documentElement).appendChild(hostEl);
  shadow = hostEl.attachShadow({ mode: "closed" });
  const style = document.createElement("style");
  style.textContent = `
    .toast,.dialog{font:14px/1.45 -apple-system,Segoe UI,Inter,sans-serif;color:#0f1115;pointer-events:auto}
    .toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%);max-width:520px;background:#0f1115;color:#fff;border-radius:10px;padding:12px 16px;box-shadow:0 8px 30px rgba(0,0,0,.25)}
    .scrim{position:fixed;inset:0;background:rgba(15,17,21,.45);pointer-events:auto;display:flex;align-items:center;justify-content:center}
    .dialog{background:#fff;border-radius:12px;max-width:460px;width:calc(100% - 32px);padding:22px;box-shadow:0 20px 60px rgba(0,0,0,.3)}
    .brand{font-weight:600;font-size:12px;color:#5b606b;margin-bottom:10px}
    h2{font-size:17px;margin:0 0 8px}
    p{margin:0 0 10px;color:#3b3f47}
    .msg{font-size:13px;color:#5b606b}
    .row{display:flex;gap:8px;justify-content:flex-end;margin-top:16px}
    button{font:inherit;border-radius:7px;padding:8px 14px;border:1px solid #d6d8dd;background:#fff;cursor:pointer}
    button.primary{background:#4f46e5;border-color:#4f46e5;color:#fff}
    @media (prefers-color-scheme: dark){.dialog{background:#1a1c22;color:#eceef2}p{color:#c7cad1}.msg{color:#9aa0ab}button{background:#23262e;color:#eceef2;border-color:#3a3e48}}`;
  shadow.appendChild(style);
  return shadow;
}

function toast(text: string) {
  const el = document.createElement("div");
  el.className = "toast";
  el.setAttribute("role", "status");
  el.textContent = text;
  root().appendChild(el);
  setTimeout(() => el.remove(), 6000);
}

/** A confirmation: resolves true if the person chose to go ahead. */
function confirmDialog(title: string, body: string, proceed: string): Promise<boolean> {
  return new Promise((resolve) => {
    const scrim = document.createElement("div");
    scrim.className = "scrim";
    const d = document.createElement("div");
    d.className = "dialog";
    d.setAttribute("role", "alertdialog");
    d.setAttribute("aria-label", title);
    const el = (tag: string, cls: string, text: string) => Object.assign(document.createElement(tag), { className: cls, textContent: text });
    d.append(el("div", "brand", "Votal Nexus · your organization"), el("h2", "", title), el("p", "", body));
    if (policy?.message) d.append(el("p", "msg", policy.message));
    const row = el("div", "row", "");
    const cancel = el("button", "primary", "Cancel") as HTMLButtonElement;
    const go = el("button", "", proceed) as HTMLButtonElement;
    row.append(go, cancel);
    d.append(row);
    scrim.append(d);
    root().appendChild(scrim);
    const done = (v: boolean) => {
      scrim.remove();
      resolve(v);
    };
    cancel.onclick = () => done(false);
    go.onclick = () => done(true);
    cancel.focus();
  });
}

const stop = (e: Event) => {
  e.preventDefault();
  e.stopImmediatePropagation();
};

// ---- Text: paste, Enter, Send ------------------------------------------------------------------------

/** Handles a verdict for text on its way in. Returns true when it may go ahead now. */
async function decide(v: Verdict, what: "paste" | "send"): Promise<boolean> {
  if (!app) return true;
  const found = describe(v);
  if (v.action === "block") {
    report(dlpEvents(v, app.key, host, "blocked"));
    toast(`Blocked: this looks like ${found}. Your organization doesn't allow it in ${app.name}.`);
    return false;
  }
  if (v.action === "warn") {
    const ok = await confirmDialog(`${what === "paste" ? "Paste" : "Send"} ${found} to ${app.name}?`, `This looks like ${found}. Once it's sent, ${app.name} has it.`, what === "paste" ? "Paste anyway" : "Send anyway");
    report(dlpEvents(v, app.key, host, ok ? "continued" : "warned"));
    return ok;
  }
  if (v.action === "monitor") report(dlpEvents(v, app.key, host, "monitored"));
  return true;
}

function onPaste(e: ClipboardEvent) {
  if (!policy || !app || !e.clipboardData) return;
  if (e.clipboardData.files.length) return void onFiles(e, e.clipboardData.files, e.target as HTMLElement);
  const text = e.clipboardData.getData("text/plain");
  if (!text) return;
  const v = check(policy, text);
  if (v.action === "off") return;
  if (v.action === "monitor") return void decide(v, "paste");
  stop(e);
  const target = (isEditable(e.target as Element) ? e.target : lastEditable) as HTMLElement | null;
  void decide(v, "paste").then((ok) => ok && target && insert(target, text));
}

let approved = ""; // text the person chose to send anyway: the next Enter goes through
function onSend(e: Event, el: HTMLElement | null) {
  if (!policy || !app) return;
  const text = textOf(el).trim();
  if (!text || text === approved) return;
  const v = check(policy, text);
  if (v.action === "off") return;
  if (v.action === "monitor") return void decide(v, "send");
  stop(e);
  void decide(v, "send").then((ok) => {
    if (!ok) return;
    approved = text;
    el?.focus();
    toast("Press Enter (or Send) again to send it.");
  });
}

function onKeydown(e: KeyboardEvent) {
  if (e.key !== "Enter" || e.shiftKey || e.isComposing || !isEditable(e.target as Element)) return;
  onSend(e, e.target as HTMLElement);
}

function onClick(e: MouseEvent) {
  const b = (e.target as Element | null)?.closest?.("button,[role=button]");
  if (!b) return;
  const label = `${b.getAttribute("aria-label") ?? ""} ${b.getAttribute("data-testid") ?? ""} ${b.textContent ?? ""}`.toLowerCase();
  if (/\bsend\b|submit|send-button|composer-submit/.test(label)) onSend(e, lastEditable);
}

// ---- Files: the attach button, drag and drop, pasted images -------------------------------------------

let uploadApproved = false;
function describeFiles(files: FileList) {
  const exts = [...new Set([...files].map((f) => (f.name.includes(".") ? f.name.split(".").pop()!.toLowerCase() : "file")))];
  return `${files.length} file${files.length === 1 ? "" : "s"} (${exts.slice(0, 5).join(", ")})`;
}

function onFiles(e: Event, files: FileList, target: HTMLElement | null, again?: () => void) {
  if (!policy || !app || !files.length || policy.uploads === "allow") return;
  if (uploadApproved) {
    uploadApproved = false;
    return;
  }
  // FileList is live: clearing the input empties it, so describe the files first.
  const count = files.length;
  const detail = describeFiles(files);
  const upload = (action: ReportEvent["action"]): ReportEvent => ({ at: now(), kind: "upload", action, app: app!.key, host, count, detail });
  stop(e);
  if (policy.uploads === "block") {
    if (target instanceof HTMLInputElement) target.value = "";
    report([upload("blocked")]);
    return toast(`Blocked: your organization doesn't allow uploading files to ${app.name}.`);
  }
  void confirmDialog(`Upload ${detail} to ${app.name}?`, `Files you upload are sent to ${app.name}.`, "Upload anyway").then((ok) => {
    report([upload(ok ? "continued" : "warned")]);
    if (!ok) {
      if (target instanceof HTMLInputElement) target.value = "";
      return;
    }
    uploadApproved = true;
    again?.();
  });
}

function onChange(e: Event) {
  const input = e.target;
  if (!(input instanceof HTMLInputElement) || input.type !== "file" || !input.files?.length) return;
  onFiles(e, input.files, input, () => input.dispatchEvent(new Event("change", { bubbles: true })));
}

function onDrop(e: DragEvent) {
  const dt = e.dataTransfer;
  if (!dt?.files.length) return;
  const target = e.target as HTMLElement;
  onFiles(e, dt.files, target, () => target.dispatchEvent(new DragEvent("drop", { bubbles: true, cancelable: true, dataTransfer: dt })));
}

// ---- Start ---------------------------------------------------------------------------------------

function listen() {
  const opts = { capture: true };
  window.addEventListener("paste", onPaste, opts);
  window.addEventListener("keydown", onKeydown, opts);
  window.addEventListener("click", onClick, opts);
  window.addEventListener("change", onChange, opts);
  window.addEventListener("drop", onDrop, opts);
  window.addEventListener("focusin", (e) => isEditable(e.target as Element) && (lastEditable = e.target as HTMLElement), opts);
}

listen(); // at document_start, before the page's own handlers; they do nothing until the policy is known
void send({ type: "policy" }).then((r: { policy: Policy | null } | null) => {
  policy = r?.policy ?? null;
  app = appFor(policy, host);
  if (app) report([{ at: now(), kind: "visit", action: "allowed", app: app.key, host }]);
});
