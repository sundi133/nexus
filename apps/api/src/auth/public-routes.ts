/**
 * Deny by default: every /v1 endpoint needs credentials (a session, an API key
 * or — for agent endpoints — a device signature they verify themselves),
 * except these. Checked before request validation, so anonymous callers learn
 * nothing about request shapes. Keep in step with OpenAPI `security`; a test
 * enforces it.
 */
export const PUBLIC_ROUTES: { method: string; path: RegExp; why: string }[] = [
  { method: "POST", path: /^\/v1\/signup$/, why: "create an organization" },
  { method: "POST", path: /^\/v1\/auth\/login$/, why: "sign in" },
  { method: "POST", path: /^\/v1\/auth\/passkey(\/options)?$/, why: "passwordless sign-in" },
  { method: "POST", path: /^\/v1\/auth\/password-reset(\/complete)?$/, why: "forgot password" },
  { method: "POST", path: /^\/v1\/auth\/federation\/(discover|start|complete)$/, why: "sign in through the organization's IdP" },
  { method: "GET", path: /^\/v1\/federation\/saml\/[^/]+\/metadata$/, why: "SAML metadata for the IdP admin" },
  { method: "GET", path: /^\/v1\/invitations\/[^/]+$/, why: "open an invitation link" },
  { method: "POST", path: /^\/v1\/invitations\/accept$/, why: "accept an invitation" },
  { method: "POST", path: /^\/v1\/devices\/pair$/, why: "a phone redeems a pairing code" },
  { method: "POST", path: /^\/v1\/agent\/(enroll|checkin)$/, why: "device-signed agent calls" },
  { method: "GET", path: /^\/v1\/agent\/releases\/[^/]+\/[^/]+$/, why: "signed agent binaries" },
  { method: "GET", path: /^\/v1\/sso\//, why: "SSO decisions answer 'sign in first' themselves" },
  { method: "GET", path: /^\/v1\/openapi\.json$/, why: "API description" },
];

export const isPublicRoute = (method: string, path: string) => method === "OPTIONS" || PUBLIC_ROUTES.some((r) => r.method === method && r.path.test(path));
