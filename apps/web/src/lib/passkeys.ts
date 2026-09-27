"use client";

import { browserSupportsWebAuthn, startAuthentication, startRegistration, WebAuthnError } from "@simplewebauthn/browser";
import { useSyncExternalStore } from "react";
import { api, ApiProblem, unwrap } from "./api";

export const passkeysSupported = () => typeof window !== "undefined" && browserSupportsWebAuthn();

const noop = () => () => {};
/** Hydration-safe: false during server render and the first client render, then the real answer. */
export const usePasskeysSupported = () => useSyncExternalStore(noop, passkeysSupported, () => false);

/** Turns browser WebAuthn errors into something a person can act on. */
export function passkeyErrorMessage(err: unknown) {
  if (err instanceof ApiProblem) return err.message;
  if (err instanceof WebAuthnError || (err instanceof Error && err.name === "NotAllowedError")) {
    return "The passkey request was cancelled or timed out. Try again.";
  }
  return err instanceof Error ? err.message : "Something went wrong with the passkey";
}

type Options = Parameters<typeof startRegistration>[0]["optionsJSON"];
type AuthOptions = Parameters<typeof startAuthentication>[0]["optionsJSON"];

/** Adds a passkey to the signed-in account (also completes mandatory enrollment). */
export async function registerPasskey(name: string) {
  const { challenge_id, options } = await unwrap(api.POST("/v1/me/factors/webauthn/options"));
  const response = await startRegistration({ optionsJSON: options as unknown as Options });
  return unwrap(api.POST("/v1/me/factors/webauthn", { body: { challenge_id, name, response: response as unknown as Record<string, unknown> } }));
}

/** Second factor or step-up with an existing passkey. */
export async function verifyWithPasskey() {
  const { challenge_id, options } = await unwrap(api.POST("/v1/auth/mfa/webauthn/options"));
  const response = await startAuthentication({ optionsJSON: options as unknown as AuthOptions });
  return unwrap(api.POST("/v1/auth/mfa/webauthn", { body: { challenge_id, response: response as unknown as Record<string, unknown> } }));
}

/** Passwordless sign-in; the BFF stores the resulting session in the HttpOnly cookie. */
export async function signInWithPasskey(email: string) {
  const { challenge_id, options } = await unwrap(api.POST("/v1/auth/passkey/options", { body: { email } }));
  if (!(options as { allowCredentials?: unknown[] }).allowCredentials?.length) {
    throw new Error("No passkey is set up for this email yet. Sign in with your password, then add one under My security.");
  }
  const response = await startAuthentication({ optionsJSON: options as unknown as AuthOptions });
  const res = await fetch("/bff/auth/passkey", {
    method: "POST",
    headers: { "content-type": "application/json", "x-nexus-csrf": "1" },
    body: JSON.stringify({ email, challenge_id, response }),
  });
  const data = await res.json();
  if (!res.ok) throw new ApiProblem(res.status, data);
  return data;
}

/** Asks the local Nexus agent to vouch for this computer (it answers only this console's origin). */
async function attestHere(agentUrl: string, nonce: string) {
  try {
    const res = await fetch(`${agentUrl}/v1/attest`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ nonce }), signal: AbortSignal.timeout(4000) });
    if (!res.ok) throw new Error(String(res.status));
    return ((await res.json()) as { attestation: string }).attestation;
  } catch {
    throw new Error("The Nexus agent isn't answering on this computer. Sign in with your email instead.");
  }
}

/** Sign in with this managed computer: its agent vouches for it, Touch ID or Windows Hello for you. */
export async function signInWithDevice() {
  const start = await unwrap(api.POST("/v1/auth/device/start"));
  const attestation = await attestHere(start.agent_url, start.nonce);
  const { ticket, options } = await unwrap(api.POST("/v1/auth/device/options", { body: { ticket: start.ticket, attestation } }));
  const response = await startAuthentication({ optionsJSON: options as unknown as AuthOptions });
  const res = await fetch("/bff/auth/device", { method: "POST", headers: { "content-type": "application/json", "x-nexus-csrf": "1" }, body: JSON.stringify({ ticket, response }) });
  const data = await res.json();
  if (!res.ok) throw new ApiProblem(res.status, data);
  return data;
}

/** Sets up device sign-in on this computer: verify it, make a passkey here, and bind the two. */
export async function setUpDeviceSignIn() {
  const ch = await unwrap(api.POST("/v1/me/device-trust/challenge", {}));
  const attestation = await attestHere(ch.agent_url, ch.nonce);
  const device = await unwrap(api.POST("/v1/me/device-trust", { body: { challenge_id: ch.challenge_id, attestation } }));
  const factor = (await registerPasskey(`${device.hostname} (device sign-in)`)) as { id: string };
  return unwrap(api.POST("/v1/me/device-sign-in", { body: { factor_id: factor.id } }));
}
