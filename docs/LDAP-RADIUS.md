# LDAP & RADIUS

Some things can't use SAML or OIDC: Jenkins, Grafana, NAS boxes and printers speak LDAP, and VPNs and Wi-Fi speak RADIUS. Nexus answers both, from the same people, groups and passwords, so there's no second directory to keep in sync. Suspending someone in Nexus refuses them in LDAP and RADIUS at once.

**Settings → LDAP & RADIUS**: each is off until you turn it on.

## LDAP

A read-only LDAPv3 directory, over LDAPS.

| Entry | DN | Object class |
|---|---|---|
| Organization | `o=<org>,dc=nexus` | organization |
| People (active only) | `uid=<email>,ou=users,o=<org>,dc=nexus` | inetOrgPerson: `uid`, `mail`, `cn`, `givenName`, `sn`, `title`, `departmentNumber`, `memberOf`, `entryUUID` |
| Groups | `cn=<name>,ou=groups,o=<org>,dc=nexus` | groupOfNames: `cn`, `description`, `member` |
| Service accounts | `cn=<name>,ou=services,o=<org>,dc=nexus` | bind only; never listed |

**Configuring an app** (Grafana, Jenkins, GitLab and others):

| Setting | Value |
|---|---|
| Server | the address on the settings page, e.g. `ldaps://ldap.nexus.example.com:636` |
| Bind DN / password | a service account (one per app, so each can be revoked alone) |
| User search base | `ou=users,o=<org>,dc=nexus` |
| User filter | `(uid=%s)` or `(mail=%s)`: people sign in with their email |
| Group search base | `ou=groups,o=<org>,dc=nexus`, with membership in `member` (or `memberOf` on the person) |

**Who can see what:**
- Anonymous binds see only the root entry.
- Service accounts see the whole organization.
- A person bound with their own password sees only their own entry and their groups.

**Rules:**
- Passwords are checked like any Nexus sign-in: 10 attempts per person and 60 per address every 5 minutes.
- Every person's bind is audited (`ldap.bind`), and so are failed service binds.
- Changes (modify, add, delete) are refused: people and groups change in Nexus.

**Limits:**
- LDAP can't do MFA. Use it only for apps that can't do SSO, and prefer SAML or OIDC wherever possible.
- People who sign in only through your identity provider have no Nexus password, so they can't bind.

## RADIUS

RADIUS (RFC 2865) with PAP, over UDP, for VPN concentrators (Palo Alto, Fortinet, Cisco, OpenVPN…) and Wi-Fi controllers.

- **Clients** are registered by the address they send from (an IP, or a range no broader than /16), each with its own shared secret. Requests from anywhere else get no answer. An address belongs to one client of one organization.
- **Blast-RADIUS mitigation:** every request must carry a valid Message-Authenticator, and every answer carries one as its first attribute.
- **MFA:** after the password, an Access-Challenge asks for the code from the person's authenticator app. Set it per organization:
  - *always*: people without an authenticator app can't sign in;
  - *when the person has MFA*;
  - *never*.
- **Accepted sign-ins** carry the person's groups as `Class = group:<name>`. Map those to VLANs or VPN policies on the device.
- **Audit:** every attempt is in the audit log (`radius.auth`, with the reason).
- **Retransmissions** get the same answer, so a slow network doesn't count as a second attempt.

**Limits:**
- PAP only. EAP (WPA2-Enterprise's PEAP and EAP-TTLS) and CHAP are refused with a message; put Wi-Fi behind a controller that does PAP to Nexus.
- Push approval isn't offered over RADIUS yet: people need an authenticator app.

## Deploying

- **Environment:**
  - `NEXUS_LDAP_PORT`, with `NEXUS_LDAP_TLS_CERT` and `NEXUS_LDAP_TLS_KEY` (PEM), required in production;
  - `NEXUS_RADIUS_PORT`;
  - `NEXUS_LDAP_PUBLIC_ADDRESS` and `NEXUS_RADIUS_PUBLIC_ADDRESS`, which are shown to admins.
- **Helm:** `directoryServices.enabled=true` with `directoryServices.ldap.tlsSecret`. The API pods listen on 1636 (LDAPS) and 1812/UDP. A LoadBalancer Service exposes 636 and 1812 with `externalTrafficPolicy: Local`, so RADIUS sees the real client addresses.
- **Replicas:** RADIUS challenges live in the replica that issued them. Keep UDP source-address affinity on the load balancer (the default for most network load balancers).

## Tests

- **`directory-services.e2e.test.ts`:**
  - LDAP with a real client (`ldapts`): root entry, binds, filters an app would use, a person's limited view, suspended people gone, read-only;
  - RADIUS with a VPN-like client: unknown addresses and missing Message-Authenticators dropped, response authenticators checked independently, groups in Class, retransmissions, the TOTP challenge, MFA required.
- **CI interop (`deploy/ops/interop-ldap-radius.sh`):** OpenLDAP's `ldapsearch` and FreeRADIUS's `radclient` against a running Nexus.
