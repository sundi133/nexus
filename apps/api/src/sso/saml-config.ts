import { z } from "@hono/zod-openapi";
import type { Deps } from "../context.js";
import { parseXml } from "../platform/xml.js";

/**
 * SAML app configuration shared by the IdP (saml.ts) and app management
 * (apps.ts), in its own module so neither has to import the other.
 */

const NS = { md: "urn:oasis:names:tc:SAML:2.0:metadata" };
const HTTP_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";

export const NAMEID = {
  email: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
  persistent: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
} as const;

export const ATTRIBUTE_SOURCES = ["email", "given_name", "family_name", "display_name", "user_id", "department", "title", "groups", "static"] as const;

export const AttributeMapping = z
  .object({
    name: z.string().trim().min(1).max(256),
    source: z.enum(ATTRIBUTE_SOURCES),
    value: z.string().max(2048).optional().openapi({ description: "Required when source is `static`" }),
  })
  .refine((a) => a.source !== "static" || !!a.value, { message: "A static attribute needs a value", path: ["value"] })
  .openapi("SamlAttribute");
export type AttributeMapping = z.infer<typeof AttributeMapping>;

/** What apps get when no mapping is configured. */
export const DEFAULT_ATTRIBUTES: AttributeMapping[] = [
  { name: "email", source: "email" },
  { name: "firstName", source: "given_name" },
  { name: "lastName", source: "family_name" },
  { name: "displayName", source: "display_name" },
  { name: "groups", source: "groups" },
];

export type SamlConfig = {
  entity_id: string;
  acs_url: string;
  name_id_format: keyof typeof NAMEID;
  default_relay_state?: string;
  sign: "assertion" | "response_and_assertion";
  attributes?: AttributeMapping[];
};

export const idpUrls = (deps: Deps, slug: string) => {
  const base = `${deps.cfg.publicUrl}/saml/${slug}`;
  return { entityId: base, ssoUrl: `${base}/sso`, metadataUrl: `${base}/metadata` };
};

/** Pulls entity ID and the HTTP-POST ACS URL out of SP metadata (SPEC SSO-04). */
export function parseSpMetadata(xml: string): { entity_id: string; acs_url: string } {
  const root = parseXml(xml).documentElement!;
  if (root.localName !== "EntityDescriptor") throw new Error("Not SAML metadata (expected an EntityDescriptor)");
  const entity_id = root.getAttribute("entityID");
  const acs = Array.from(root.getElementsByTagNameNS(NS.md, "AssertionConsumerService")).filter((e) => e.getAttribute("Binding") === HTTP_POST);
  const pick = acs.find((e) => e.getAttribute("isDefault") === "true") ?? acs.sort((a, b) => Number(a.getAttribute("index") ?? 0) - Number(b.getAttribute("index") ?? 0))[0];
  const acs_url = pick?.getAttribute("Location");
  if (!entity_id || !acs_url) throw new Error("Metadata needs an entityID and an HTTP-POST AssertionConsumerService");
  return { entity_id, acs_url };
}
