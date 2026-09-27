/**
 * Runs on known SaaS apps while the organization's SaaS discovery is on. It notices one thing: a
 * sign-in with a password (a filled password field being submitted), so admins can see which apps
 * people use without single sign-on. The password, and everything else on the page, stays here.
 */

let told = false;
const tell = () => {
  if (told) return;
  told = true;
  void chrome.runtime.sendMessage({ type: "saas-login" }).catch(() => {});
};
const filled = (root: ParentNode) => Array.from(root.querySelectorAll<HTMLInputElement>('input[type="password"]')).some((i) => i.value.length > 0);

document.addEventListener("submit", (e) => void (e.target instanceof HTMLFormElement && filled(e.target) && tell()), true);
document.addEventListener(
  "keydown",
  (e) => void (e.key === "Enter" && e.target instanceof HTMLInputElement && e.target.type === "password" && e.target.value && tell()),
  true,
);
// Sign-in pages without a real form: a button pressed while a password is filled in.
document.addEventListener("click", (e) => void ((e.target as Element | null)?.closest?.('button, input[type="submit"], [role="button"]') && filled(document) && tell()), true);
