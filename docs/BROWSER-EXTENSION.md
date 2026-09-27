# AI in browsers: the Nexus browser extension

Most AI use at work happens in a browser tab: ChatGPT, Claude, Gemini, Copilot, DeepSeek and others. **AI in browsers** does three things for Chrome and Edge:

- **Visibility:** who uses which AI apps.
- **Control:** apps can be allowed, warned about, or blocked.
- **Data protection:** it stops company data that people paste, send or upload.

## What people see

| Situation | What happens |
|---|---|
| A blocked AI app | The page is replaced by *"DeepSeek is blocked by your organization"*, with your message (for example a link to your AI policy) |
| A "warn" app | A page asks them to check first. They can go back, or continue for an hour (reported as *went ahead after a warning*) |
| Pasting or sending sensitive data | **Block:** stopped, with a note saying what it looked like, e.g. *"this looks like an AWS access key"*. **Warn:** they confirm or cancel. **Monitor:** allowed, and recorded |
| Uploading a file (the attach button, drag and drop, a pasted image) | Allowed, warned or blocked, per your setting |

## What Nexus learns, and what it doesn't

- **Text is checked in the browser.** What people type or paste is never sent to Nexus.
- Reports carry only the app, the kind of data (for example *Payment card number*) and a masked hint (*•••• 4242*, *AKIA…LE*). For files, the count and extensions.
- **Visits:** which AI apps each person opened, and how often.
- **The person** is the managed browser profile's email (Chrome/Edge signed into your Google Workspace or Entra ID account), matched to people in Nexus.
- **Trust model:** the extension token identifies your organization, not a person, so events are self-reported by managed browsers. Revoke the token to stop a leaked one.
- **Audit:** blocked sensitive data, blocked uploads and "went ahead after a warning" are in the audit log (`browser.dlp_blocked`, `browser.dlp_continued`, `browser.upload_blocked`, …), so they reach your SIEM and alert rules.
- **Retention:** events are kept 90 days.
- **Work apps:** with SaaS discovery on, the extension also counts visits to known work apps and password sign-ins on them. See [SAAS.md](SAAS.md).

## Detectors

| Detector | Finds | Default |
|---|---|---|
| API keys, tokens and passwords | AWS, GitHub, Slack, OpenAI, Anthropic, Google, Stripe keys; JWTs; connection strings with passwords; `password = "…"` literals (not code like `password = input.value`) | Block |
| Private keys | PEM and OpenSSH private keys | Block |
| Payment card numbers | Real card-network ranges, Luhn-checked | Warn |
| US Social Security numbers | Valid formats only (not 000, 666, 9xx) | Warn |
| Bank accounts (IBAN) | Mod-97 checked | Monitor |
| Lists of email addresses | 10 or more in one paste | Monitor |
| Your own patterns | Regular expressions: project code names, customer IDs, internal hosts | — |

The detectors favor few false alarms: people stop reading warnings that cry wolf.

## Setting it up

1. **AI in browsers → Setup → Create token.**
2. Force-install the extension and give it its configuration:
   - **Google Admin:** Devices → Chrome → Apps & extensions → add the extension, set *Force install*, and under *Policy for extensions* paste:
     ```json
     { "server": { "Value": "https://api.nexus.example.com" }, "token": { "Value": "nxb_…" } }
     ```
   - **Intune / Group Policy (Windows):** add the extension to `ExtensionInstallForcelist`, and set `server` and `token` under `HKLM\Software\Policies\Google\Chrome\3rdparty\extensions\<extension ID>\policy`. For Edge, use `Microsoft\Edge` instead of `Google\Chrome`.
   - **macOS (Jamf, Intune, Kandji):** a configuration profile for `com.google.Chrome.extensions.<extension ID>` with `server` and `token`.
3. Choose app actions and data protection under **Apps** and **Data protection**. Browsers pick up changes within a minute.

**Distribution:** force-installing a Chrome or Edge extension needs it listed in the Chrome Web Store (or self-hosted as a signed CRX). The Web Store listing needs a publisher account (see the roadmap). Until then, pilot it unpacked, as below.

## Pilot it unpacked

```bash
cd apps/browser-extension && pnpm build     # → dist/
```

1. Open `chrome://extensions`, turn on Developer mode, *Load unpacked*, and choose `dist/`.
2. Click *service worker* on the extension and run:
   ```js
   chrome.storage.local.set({ devConfig: { server: "https://api.nexus.example.com", token: "nxb_…" } })
   ```
3. Open chatgpt.com and paste `AKIAIOSFODNN7EXAMPLE`. It's stopped, and **Events** shows *ChatGPT · AWS access key AKIA…LE · blocked* after the next sync, within a minute.
4. Set an app to *Block* and open it: you get the blocked page.

## How it's tested

- **Unit tests:** the detectors, including false-positive cases like code and ISBNs; the policy decisions; the navigation rules (no look-alike hosts).
- **End to end (`node e2e.mjs`, run in CI):** the built extension in real Chromium, against a fake Nexus and fake AI apps on `*.localhost`. It covers:
  - sync with the token;
  - rules registered;
  - an AWS key paste stopped, and an ordinary paste allowed;
  - a monitored detector reported;
  - Enter with a private key stopped;
  - an upload blocked and cleared;
  - a blocked app replaced by the interstitial;
  - the events reaching Nexus without the pasted text.
- **API tests:** policy validation, including rejecting patterns that could freeze a browser; tokens; sync; audit; usage.

## Limits

- Chrome and Edge (Chromium, version 116 or later). Safari and Firefox aren't covered yet.
- It checks what people paste, send with Enter or a Send button, and upload in AI apps' pages. Text typed and sent some other way, or an AI app not in the catalog, isn't checked. The catalog covers the major apps and grows with releases.
- An admin on the device can remove a force-installed extension's policy. Pair it with device management and the Nexus agent, whose block rules also stop AI apps' domains.
