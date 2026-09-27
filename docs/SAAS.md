# SaaS management

See which work apps people use, approve the ones you've vetted, and warn about or block the rest. Everything comes from the Nexus browser extension ([BROWSER-EXTENSION.md](BROWSER-EXTENSION.md)) in managed Chrome and Edge.

Open **Access → SaaS apps** in the console.

## Discovery

Discovery is **off** until someone with `devices:enforce` turns it on (with a recent MFA). While it's on, each browser reports, per app per day:

- how many times the person opened the app;
- how many times they signed in to it **with a password** (a filled password field being submitted);
- visits it blocked.

Nothing else about browsing is reported: no addresses, page titles or contents, and nothing people type. The password itself never leaves the page, only the fact that one was used. Sites that aren't in the catalog aren't counted at all. The extension's popup tells people what's reported. Turning discovery off stops counting straight away, even from browsers that haven't picked up the change yet.

The catalog covers about 1,700 business apps in 21 categories, each matched by the hosts people use it on (and their subdomains). It leaves out personal sites on purpose: social feeds, personal banking, airlines and hotels, job boards and health apps. The same catalog feeds the app directory under **Applications**.

## What you see

- **Apps in use:** people and visits in the last 30 days, and when the app was last used.
- **Sign-in:**
  - **SSO:** the app is set up for single sign-on in Nexus (matched by template or name).
  - **Password:** people sign in with passwords.
  - **SSO, but some people use a password:** a gap to close in the app's own settings, for example "require SSO".
- **Each app:** who uses it, how often, whether they used a password, and any blocked visits.

## Decisions

**Review** an app to decide:

| Decision | In browsers |
|---|---|
| **Approved** | Nothing changes |
| **Unapproved: allow** | Nothing changes; it's flagged here |
| **Unapproved: warn** | A page asks people to check first; they can continue for an hour |
| **Unapproved: block** | A page says it isn't approved, and the app doesn't open |
| **Not reviewed** | Nothing changes (the default) |

Warning and blocking need a recent MFA. Browsers pick up changes within a minute. Every decision is audited as `saas.app_reviewed`.

## Licenses

Under **Licenses**, add what you pay for an app: seats, price per seat (monthly or yearly), currency, renewal date and plan. Then choose who holds the seats:

- **People assigned in Nexus SSO:** everyone assigned to the app under **Applications**, directly or through a group.
- **A list:** emails pasted from the app's own admin console. People outside Nexus, like contractors, are kept as given.

Each seat holder is:

| Status | Meaning |
|---|---|
| **Uses it** | Opened the app in a managed browser, or signed in to it through Nexus, in the last 30 days |
| **Not used** | Neither, while Nexus can see use (discovery is on, or the app is on SSO) |
| **Left** | Suspended or offboarded in Nexus |
| **Can't tell** | Nexus can't see use of this app: turn on discovery, or set up SSO |

**Could reclaim** adds up seats nobody holds, seats held by people who left, and seats not used, priced per year. Licenses renewing in the next 60 days are flagged, so you can right-size before paying again. Changes are audited as `saas.license_created`, `saas.license_updated`, `saas.license_deleted` and `saas.license_holders_updated`.

## API

- `GET /v1/saas/apps` and `GET /v1/saas/apps/{key}`: usage and decisions (`apps:read`).
- `PUT /v1/saas/apps/{key}`: decide (`apps:write`).
- `GET /v1/saas/catalog`: search the catalog.
- `PUT /v1/browser/policy` with `saas_discovery`: turn discovery on or off.
- `GET`/`POST /v1/saas/licenses`, `GET`/`PUT`/`DELETE /v1/saas/licenses/{id}`, `PUT /v1/saas/licenses/{id}/holders`: licenses and seat holders.

## Retention

Daily counts are kept 180 days.

## Limits

- **Managed Chrome and Edge only.** Other browsers, desktop apps and phones aren't seen.
- **Sign-in method is inferred.** A password sign-in is counted when a filled password field is submitted on the app's pages. Single sign-on, passkeys and magic links count as visits only.
- **Licenses are entered by hand.** Nexus doesn't read invoices or vendors' billing APIs; seat lists come from SSO assignments or a pasted list.
- **Self-reported:** like the rest of the extension, counts come from managed browsers using your organization's token.
