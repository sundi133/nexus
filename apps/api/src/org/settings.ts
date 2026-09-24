import { z } from "@hono/zod-openapi";
import type { Tx } from "../platform/db.js";

/** Organization security settings (SPEC ORG-04). Stored in organizations.settings; defaults apply to missing keys. */
export const OrgSettings = z
  .object({
    mfa_policy: z
      .enum(["off", "admins", "everyone"])
      .openapi({ description: "Who must enroll MFA. Users without a factor are asked to set one up at their next sign-in." }),
    session_ttl_hours: z.number().int().min(1).max(168).openapi({ description: "How long a sign-in lasts before re-authentication" }),
  })
  .openapi("OrgSettings");

export type OrgSettings = z.infer<typeof OrgSettings>;

// Secure by default: admins must use MFA from day one.
export const DEFAULT_SETTINGS: OrgSettings = { mfa_policy: "admins", session_ttl_hours: 12 };

export async function getSettings(tx: Tx, orgId: string): Promise<OrgSettings> {
  const row = await tx.selectFrom("organizations").select("settings").where("id", "=", orgId).executeTakeFirstOrThrow();
  return { ...DEFAULT_SETTINGS, ...(OrgSettings.partial().safeParse(row.settings).data ?? {}) };
}

export async function saveSettings(tx: Tx, orgId: string, next: OrgSettings) {
  await tx
    .updateTable("organizations")
    .set({ settings: JSON.stringify(next), updated_at: new Date() })
    .where("id", "=", orgId)
    .execute();
}

/** Whether the org policy requires this user to have MFA. */
export function mfaRequired(settings: OrgSettings, isAdmin: boolean) {
  return settings.mfa_policy === "everyone" || (settings.mfa_policy === "admins" && isAdmin);
}

/** Field-by-field diff for the audit log / change history (SPEC OPS-06). */
export function diff<T extends Record<string, unknown>>(before: T, after: T) {
  const out: Record<string, { from: unknown; to: unknown }> = {};
  for (const k of Object.keys(after)) if (before[k] !== after[k]) out[k] = { from: before[k], to: after[k] };
  return out;
}
