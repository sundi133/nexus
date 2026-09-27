import { createRoute, z } from "@hono/zod-openapi";
import type { App } from "../context.js";
import { requirePermission } from "../auth/guard.js";
import { badRequest, notFound } from "../platform/errors.js";
import { bearer, body, json, problemResponses } from "../schemas.js";
import { ApplicationCreated, createApplication, type AppInput } from "./apps.js";
import type { AttributeMapping } from "./saml-config.js";

/**
 * App catalog (SPEC SSO-03): pre-built SSO settings for common apps.
 *
 * Where a vendor uses fixed, documented SP URLs we template them from a few
 * validated fields. Where the vendor generates per-tenant URLs (Google
 * Workspace, IAM Identity Center, Atlassian, Notion) the admin copies them from
 * the vendor's console instead of us guessing. Each template must be checked
 * against the vendor's current documentation before GA.
 */

type Field = { key: string; label: string; placeholder: string; help?: string; pattern: string };

type SamlTemplate = {
  entity_id: string;
  acs_url: string;
  name_id_format: "email" | "persistent";
  sign?: "assertion" | "response_and_assertion";
  attributes?: AttributeMapping[];
  default_relay_state?: string;
};
type OidcTemplate = { redirect_uris: string[]; client_type: "confidential" | "public" };

type Template = {
  key: string;
  name: string;
  category: "Communication" | "Engineering" | "Cloud" | "Productivity" | "Design" | "Observability";
  description: string;
  protocol: "saml" | "oidc";
  fields: Field[];
  saml?: SamlTemplate;
  oidc?: OidcTemplate;
  launch_url?: string;
  /** Shown after install. Placeholders: {{idp_metadata_url}} {{idp_sso_url}} {{idp_entity_id}} {{issuer}} {{client_id}} {{client_secret}} and any field. */
  setup: string[];
};

const SUBDOMAIN = "^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$";
const HTTPS_URL = "^https://[^\\s]+$";

const copiedUrl = (key: string, label: string, help: string): Field => ({ key, label, placeholder: "https://…", help, pattern: HTTPS_URL });

export const CATALOG: Template[] = [
  {
    key: "slack",
    name: "Slack",
    category: "Communication",
    description: "Sign in to your Slack workspace with Nexus.",
    protocol: "saml",
    fields: [{ key: "workspace", label: "Workspace subdomain", placeholder: "acme", help: "The part before .slack.com", pattern: SUBDOMAIN }],
    saml: {
      entity_id: "https://slack.com",
      acs_url: "https://{{workspace}}.slack.com/sso/saml",
      name_id_format: "email",
      attributes: [
        { name: "User.Email", source: "email" },
        { name: "first_name", source: "given_name" },
        { name: "last_name", source: "family_name" },
      ],
    },
    launch_url: "https://{{workspace}}.slack.com",
    setup: [
      "In Slack, open Admin → Security → Configure SAML.",
      "SAML 2.0 Endpoint (HTTP): {{idp_sso_url}}",
      "Identity Provider Issuer: {{idp_entity_id}}",
      "Public certificate: paste the certificate from this app's Setup tab.",
      "Test the configuration before making SSO required.",
    ],
  },
  {
    key: "github",
    name: "GitHub Enterprise Cloud",
    category: "Engineering",
    description: "SAML SSO for a GitHub organization.",
    protocol: "saml",
    fields: [{ key: "org", label: "Organization name", placeholder: "acme-inc", help: "As in github.com/orgs/<name>", pattern: "^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$" }],
    saml: {
      entity_id: "https://github.com/orgs/{{org}}",
      acs_url: "https://github.com/orgs/{{org}}/saml/consume",
      name_id_format: "persistent",
      attributes: [
        { name: "emails", source: "email" },
        { name: "full_name", source: "display_name" },
      ],
    },
    launch_url: "https://github.com/orgs/{{org}}/sso",
    setup: [
      "In GitHub, open your organization → Settings → Authentication security → Enable SAML authentication.",
      "Sign on URL: {{idp_sso_url}}",
      "Issuer: {{idp_entity_id}}",
      "Public certificate: paste the certificate from this app's Setup tab. Signature method RSA-SHA256, digest SHA256.",
      "Click “Test SAML configuration”, then save and download recovery codes.",
    ],
  },
  {
    key: "aws",
    name: "AWS (IAM federation)",
    category: "Cloud",
    description: "Console access to one AWS account through an IAM role.",
    protocol: "saml",
    fields: [
      { key: "account_id", label: "AWS account ID", placeholder: "123456789012", pattern: "^\\d{12}$" },
      { key: "role_name", label: "IAM role name", placeholder: "NexusReadOnly", pattern: "^[\\w+=,.@-]{1,64}$" },
      { key: "provider_name", label: "IAM identity provider name", placeholder: "VotalNexus", pattern: "^[\\w.-]{1,128}$" },
    ],
    saml: {
      entity_id: "urn:amazon:webservices",
      acs_url: "https://signin.aws.amazon.com/saml",
      name_id_format: "persistent",
      default_relay_state: "https://console.aws.amazon.com/",
      attributes: [
        {
          name: "https://aws.amazon.com/SAML/Attributes/Role",
          source: "static",
          value: "arn:aws:iam::{{account_id}}:role/{{role_name}},arn:aws:iam::{{account_id}}:saml-provider/{{provider_name}}",
        },
        { name: "https://aws.amazon.com/SAML/Attributes/RoleSessionName", source: "email" },
      ],
    },
    setup: [
      "In IAM → Identity providers → Add provider: type SAML, name “{{provider_name}}”, upload the metadata from {{idp_metadata_url}}.",
      "Create (or edit) the role “{{role_name}}” with a trust policy for that SAML provider and the audience https://signin.aws.amazon.com/saml.",
      "People assigned here sign in from My apps and land in the AWS console.",
    ],
  },
  {
    key: "aws-identity-center",
    name: "AWS IAM Identity Center",
    category: "Cloud",
    description: "Single sign-on across AWS accounts and applications.",
    protocol: "saml",
    fields: [
      copiedUrl("acs_url", "IAM Identity Center ACS URL", "Settings → Identity source → Change to external IdP → Service provider metadata"),
      copiedUrl("entity_id", "IAM Identity Center issuer URL", "Shown right below the ACS URL"),
    ],
    saml: { entity_id: "{{entity_id}}", acs_url: "{{acs_url}}", name_id_format: "email", attributes: [] },
    setup: [
      "In IAM Identity Center, finish “Change identity source → External identity provider”.",
      "IdP SAML metadata: upload the file from {{idp_metadata_url}} (or enter the sign-in URL {{idp_sso_url}}, issuer {{idp_entity_id}} and the certificate).",
      "Users must exist in Identity Center with the same email address (SCIM provisioning comes later).",
    ],
  },
  {
    key: "google-workspace",
    name: "Google Workspace",
    category: "Productivity",
    description: "Sign in to Gmail, Drive and other Google apps with Nexus.",
    protocol: "saml",
    fields: [
      copiedUrl("entity_id", "Entity ID", "Admin console → Security → SSO with third-party IdP → your SSO profile"),
      copiedUrl("acs_url", "ACS URL", "Same page, “SP details”"),
    ],
    saml: { entity_id: "{{entity_id}}", acs_url: "{{acs_url}}", name_id_format: "email", attributes: [] },
    setup: [
      "In the Google Admin console, open your third-party SSO profile.",
      "Sign-in page URL: {{idp_sso_url}}",
      "Verification certificate: upload the certificate from this app's Setup tab.",
      "Assign the profile to the organizational units or groups that should use Nexus.",
    ],
  },
  {
    key: "atlassian",
    name: "Atlassian Cloud",
    category: "Engineering",
    description: "Jira, Confluence and other Atlassian Cloud products.",
    protocol: "saml",
    fields: [
      copiedUrl("entity_id", "Service provider entity URL", "admin.atlassian.com → Security → Identity providers → your SAML configuration"),
      copiedUrl("acs_url", "Service provider assertion consumer service URL", "Same page"),
    ],
    saml: { entity_id: "{{entity_id}}", acs_url: "{{acs_url}}", name_id_format: "email", attributes: [] },
    setup: [
      "In Atlassian Administration, add a SAML identity provider.",
      "Identity provider Entity ID: {{idp_entity_id}}",
      "Identity provider SSO URL: {{idp_sso_url}}",
      "Public x509 certificate: paste the certificate from this app's Setup tab.",
      "Add your verified domains to the authentication policy that uses this provider.",
    ],
  },
  {
    key: "zoom",
    name: "Zoom",
    category: "Communication",
    description: "Sign in to Zoom with your company account.",
    protocol: "saml",
    fields: [{ key: "vanity", label: "Zoom vanity URL name", placeholder: "acme", help: "The part before .zoom.us", pattern: SUBDOMAIN }],
    saml: {
      entity_id: "{{vanity}}.zoom.us",
      acs_url: "https://{{vanity}}.zoom.us/saml/SSO",
      name_id_format: "email",
      attributes: [
        { name: "email", source: "email" },
        { name: "firstName", source: "given_name" },
        { name: "lastName", source: "family_name" },
      ],
    },
    launch_url: "https://{{vanity}}.zoom.us",
    setup: [
      "In the Zoom web portal, open Advanced → Single Sign-On.",
      "Sign-in page URL: {{idp_sso_url}}",
      "Identity provider certificate: paste the certificate from this app's Setup tab.",
      "Issuer (IdP entity ID): {{idp_entity_id}}",
      "Binding: HTTP-Redirect. Save and test with a non-admin account first.",
    ],
  },
  {
    key: "figma",
    name: "Figma",
    category: "Design",
    description: "SAML SSO for Figma Organization and Enterprise plans.",
    protocol: "saml",
    fields: [{ key: "tenant_id", label: "Figma tenant ID", placeholder: "123456789012345678", help: "Admin → Settings → SAML SSO", pattern: "^\\d{6,30}$" }],
    saml: {
      entity_id: "https://www.figma.com/saml/{{tenant_id}}",
      acs_url: "https://www.figma.com/saml/{{tenant_id}}/consume",
      name_id_format: "email",
      attributes: [],
    },
    setup: [
      "In Figma, open Admin → Settings → SAML SSO → Configure.",
      "Choose “Other”, then provide the IdP metadata URL {{idp_metadata_url}}.",
      "Set the SSO mode for your domain once a test sign-in works.",
    ],
  },
  {
    key: "dropbox",
    name: "Dropbox",
    category: "Productivity",
    description: "SSO for Dropbox Business teams.",
    protocol: "saml",
    fields: [],
    saml: { entity_id: "Dropbox", acs_url: "https://www.dropbox.com/saml_login", name_id_format: "email", attributes: [] },
    launch_url: "https://www.dropbox.com/sso",
    setup: [
      "In the Dropbox admin console, open Settings → Single sign-on.",
      "Identity provider sign-in URL: {{idp_sso_url}}",
      "X.509 certificate: upload the certificate from this app's Setup tab.",
      "Start with “Optional” SSO, then switch to “Required” after testing.",
    ],
  },
  {
    key: "grafana",
    name: "Grafana",
    category: "Observability",
    description: "OpenID Connect sign-in for a self-hosted or Cloud Grafana.",
    protocol: "oidc",
    fields: [{ key: "host", label: "Grafana host", placeholder: "grafana.acme.com", pattern: "^[a-z0-9.-]+(?::\\d{2,5})?$" }],
    oidc: { redirect_uris: ["https://{{host}}/login/generic_oauth"], client_type: "confidential" },
    launch_url: "https://{{host}}/login",
    setup: [
      "In grafana.ini (or environment variables), under [auth.generic_oauth]:",
      "enabled = true, name = Votal Nexus, client_id = {{client_id}}, client_secret = {{client_secret}}",
      "scopes = openid email profile groups",
      "auth_url = {{issuer}}/authorize, token_url = {{issuer}}/token, api_url = {{issuer}}/userinfo",
      "Optional: map roles from the “groups” claim with role_attribute_path.",
    ],
  },
];

const fill = (tpl: string, values: Record<string, string>) => tpl.replace(/\{\{(\w+)\}\}/g, (_, k: string) => values[k] ?? `{{${k}}}`);

const CatalogField = z.object({ key: z.string(), label: z.string(), placeholder: z.string(), help: z.string().optional(), pattern: z.string() }).openapi("CatalogField");
const CatalogEntry = z
  .object({
    key: z.string(),
    name: z.string(),
    category: z.string(),
    description: z.string(),
    protocol: z.enum(["saml", "oidc"]),
    fields: z.array(CatalogField),
  })
  .openapi("CatalogEntry");

export function registerCatalogRoutes(app: App) {
  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/app-catalog",
      tags: ["Applications"],
      summary: "Pre-built SSO templates for common apps",
      security: bearer,
      responses: { 200: json(z.object({ data: z.array(CatalogEntry) })), ...problemResponses },
    }),
    (c) => {
      requirePermission(c, "apps:read");
      return c.json({ data: CATALOG.map(({ key, name, category, description, protocol, fields }) => ({ key, name, category, description, protocol, fields })) }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/app-catalog/{key}/install",
      tags: ["Applications"],
      summary: "Add an app from the catalog",
      description: "Returns the new app plus setup steps with the values to enter in the vendor's admin console.",
      security: bearer,
      request: {
        params: z.object({ key: z.string().max(64) }),
        ...body(z.object({ name: z.string().trim().min(1).max(100).optional(), fields: z.record(z.string(), z.string().trim().max(512)).default({}) })),
      },
      responses: {
        201: json(ApplicationCreated.extend({ setup_steps: z.array(z.string()) }).openapi("CatalogInstalled"), "Created"),
        ...problemResponses,
      },
    }),
    async (c) => {
      const p = requirePermission(c, "apps:write");
      const { key } = c.req.valid("param");
      const input = c.req.valid("json");
      const tpl = CATALOG.find((t) => t.key === key);
      if (!tpl) throw notFound("Catalog app");

      // Every field is required and must match its pattern: values end up inside URLs and signed attributes.
      const fields: Record<string, string> = {};
      const errors = [];
      for (const f of tpl.fields) {
        const v = input.fields[f.key] ?? "";
        if (!new RegExp(f.pattern).test(v)) errors.push({ path: `fields.${f.key}`, message: v ? `${f.label} doesn't look right` : `${f.label} is required` });
        fields[f.key] = v;
      }
      if (errors.length) throw badRequest("invalid_request", "Some fields are invalid", { errors });

      const name = input.name ?? tpl.name;
      const launch_url = tpl.launch_url ? fill(tpl.launch_url, fields) : "";
      const appInput: AppInput =
        tpl.protocol === "saml"
          ? {
              protocol: "saml",
              name,
              entity_id: fill(tpl.saml!.entity_id, fields),
              acs_url: fill(tpl.saml!.acs_url, fields),
              name_id_format: tpl.saml!.name_id_format,
              sign: tpl.saml!.sign ?? "assertion",
              ...(tpl.saml!.default_relay_state ? { default_relay_state: tpl.saml!.default_relay_state } : {}),
              ...(tpl.saml!.attributes ? { attributes: tpl.saml!.attributes.map((a) => (a.value ? { ...a, value: fill(a.value, fields) } : a)) } : {}),
              launch_url,
            }
          : { protocol: "oidc", name, client_type: tpl.oidc!.client_type, redirect_uris: tpl.oidc!.redirect_uris.map((u) => fill(u, fields)), launch_url };

      const created = await createApplication(c.get("deps"), p, c.get("meta"), appInput, tpl.key);
      const values: Record<string, string> = {
        ...fields,
        idp_metadata_url: created.app.saml?.idp_metadata_url ?? "",
        idp_sso_url: created.app.saml?.idp_sso_url ?? "",
        idp_entity_id: created.app.saml?.idp_entity_id ?? "",
        issuer: created.app.oidc?.issuer ?? "",
        client_id: created.app.oidc?.client_id ?? "",
        client_secret: created.client_secret ?? "(shown once above)",
      };
      return c.json({ ...created, setup_steps: tpl.setup.map((s) => fill(s, values)) }, 201);
    },
  );
}
