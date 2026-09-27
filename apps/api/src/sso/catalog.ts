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
  category: "Communication" | "Engineering" | "Cloud" | "Productivity" | "Design" | "Observability" | "Business" | "Security" | "IT";
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

const HOST = "^[a-z0-9.-]+(?::\\d{2,5})?$";
const host = (label: string, placeholder: string): Field => ({ key: "host", label, placeholder, help: "Host name only, no https://", pattern: HOST });
const sub = (label: string, placeholder: string, help: string): Field => ({ key: "subdomain", label, placeholder, help, pattern: SUBDOMAIN });
const EMAIL_NAMES = [
  { name: "email", source: "email" },
  { name: "firstName", source: "given_name" },
  { name: "lastName", source: "family_name" },
] as AttributeMapping[];
const certStep = "Certificate: paste the certificate from this app's Setup tab (or use the IdP metadata URL: {{idp_metadata_url}}).";

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
  // ---- Business ---------------------------------------------------------------------
  {
    key: "salesforce",
    name: "Salesforce",
    category: "Business",
    description: "SAML single sign-on for a Salesforce org (My Domain).",
    protocol: "saml",
    fields: [copiedUrl("entity_id", "Entity ID", "Setup → Single Sign-On Settings → your SAML config → Entity ID (usually https://<mydomain>.my.salesforce.com)"), copiedUrl("acs_url", "Login URL", "Same page: “Login URL” (the ACS)")],
    saml: { entity_id: "{{entity_id}}", acs_url: "{{acs_url}}", name_id_format: "email", attributes: [] },
    setup: ["In Salesforce Setup → Single Sign-On Settings → New from Metadata URL: {{idp_metadata_url}}", "SAML Identity Type: username is the Federation ID; set each user's Federation ID to their email.", "Enable the SSO config for your My Domain login page."],
  },
  {
    key: "hubspot",
    name: "HubSpot",
    category: "Business",
    description: "SAML single sign-on for your HubSpot account.",
    protocol: "saml",
    fields: [copiedUrl("entity_id", "Audience URI (Entity ID)", "Settings → Account defaults → Security → Single sign-on → Set up"), copiedUrl("acs_url", "Sign-on URL (ACS)", "Same dialog")],
    saml: { entity_id: "{{entity_id}}", acs_url: "{{acs_url}}", name_id_format: "email", attributes: [] },
    setup: ["In HubSpot's SSO setup, paste Identity Provider Identifier: {{idp_entity_id}}", "Identity Provider Single Sign-On URL: {{idp_sso_url}}", certStep, "Verify, then require SSO."],
  },
  {
    key: "docusign",
    name: "DocuSign",
    category: "Business",
    description: "SAML single sign-on for a DocuSign organization.",
    protocol: "saml",
    fields: [copiedUrl("entity_id", "Service Provider Issuer", "DocuSign Admin → Identity Providers → your IdP → Actions → View SAML 2.0 Endpoints"), copiedUrl("acs_url", "Service Provider Login URL", "Same page")],
    saml: { entity_id: "{{entity_id}}", acs_url: "{{acs_url}}", name_id_format: "email", attributes: [{ name: "surname", source: "family_name" }, { name: "givenname", source: "given_name" }, { name: "emailaddress", source: "email" }] },
    setup: ["In DocuSign Admin → Identity Providers → Add: Identity Provider Issuer {{idp_entity_id}}, Login URL {{idp_sso_url}}.", certStep, "Map claims emailaddress, givenname, surname; claim a verified domain."],
  },
  {
    key: "workday-sp",
    name: "Workday (sign-in)",
    category: "Business",
    description: "People sign in to Workday itself with Nexus.",
    protocol: "saml",
    fields: [copiedUrl("entity_id", "Service Provider ID", "Edit Tenant Setup – Security → SAML Setup → Service Provider ID"), copiedUrl("acs_url", "SSO URL", "Your tenant's login URL, e.g. https://wd2-impl.workday.com/<tenant>/login-saml.flex")],
    saml: { entity_id: "{{entity_id}}", acs_url: "{{acs_url}}", name_id_format: "email", attributes: [] },
    setup: ["In Workday: Edit Tenant Setup – Security → SAML Identity Providers → Add: Issuer {{idp_entity_id}}, x509 certificate from this app's Setup tab.", "Enable SAML authentication and set users' SAML Subject to their email (or map Workday usernames)."],
  },
  {
    key: "smartsheet",
    name: "Smartsheet",
    category: "Productivity",
    description: "SAML single sign-on for a Smartsheet plan.",
    protocol: "saml",
    fields: [copiedUrl("entity_id", "Entity ID", "Admin Center → Security Controls → SAML → Add IdP"), copiedUrl("acs_url", "ACS URL", "Same page")],
    saml: { entity_id: "{{entity_id}}", acs_url: "{{acs_url}}", name_id_format: "email", attributes: [] },
    setup: ["In Smartsheet Admin Center → SAML: paste the IdP metadata from {{idp_metadata_url}}.", "Activate the IdP and choose which domains use it."],
  },
  {
    key: "airtable",
    name: "Airtable",
    category: "Productivity",
    description: "SAML single sign-on for an Airtable Enterprise account.",
    protocol: "saml",
    fields: [copiedUrl("entity_id", "Entity ID", "Admin panel → Settings → SSO"), copiedUrl("acs_url", "ACS URL", "Same page")],
    saml: { entity_id: "{{entity_id}}", acs_url: "{{acs_url}}", name_id_format: "email", attributes: EMAIL_NAMES },
    setup: ["In Airtable's SSO settings, upload the IdP metadata from {{idp_metadata_url}}.", "Test, then enforce SSO for your verified domains."],
  },
  // ---- Productivity -----------------------------------------------------------------
  {
    key: "asana",
    name: "Asana",
    category: "Productivity",
    description: "SAML single sign-on for an Asana organization.",
    protocol: "saml",
    fields: [],
    saml: { entity_id: "https://app.asana.com", acs_url: "https://app.asana.com/-/saml/consume", name_id_format: "email", attributes: [] },
    launch_url: "https://app.asana.com",
    setup: ["In Asana: Admin console → Security → SAML authentication.", "Sign-in page URL: {{idp_sso_url}}", certStep, "Choose Optional first, test, then Required."],
  },
  {
    key: "notion",
    name: "Notion",
    category: "Productivity",
    description: "SAML single sign-on for a Notion workspace.",
    protocol: "saml",
    fields: [copiedUrl("acs_url", "Assertion Consumer Service (ACS) URL", "Settings → Identity & provisioning → SAML Single sign-on → Edit SAML SSO configuration")],
    saml: { entity_id: "https://www.notion.so/sso/saml", acs_url: "{{acs_url}}", name_id_format: "email", attributes: [{ name: "email", source: "email" }, { name: "firstName", source: "given_name" }, { name: "lastName", source: "family_name" }] },
    launch_url: "https://www.notion.so",
    setup: ["In Notion's SAML SSO configuration, paste the IdP metadata URL: {{idp_metadata_url}}", "Verify your email domain, then turn on SAML SSO."],
  },
  {
    key: "miro",
    name: "Miro",
    category: "Design",
    description: "SAML single sign-on for a Miro company account.",
    protocol: "saml",
    fields: [],
    saml: { entity_id: "https://miro.com/", acs_url: "https://miro.com/sso/saml", name_id_format: "email", attributes: [] },
    launch_url: "https://miro.com/sso/login/",
    setup: ["In Miro: Settings → Security → Enable SSO/SAML.", "SAML Sign-in URL: {{idp_sso_url}}", certStep, "Add your domains and test."],
  },
  {
    key: "box",
    name: "Box",
    category: "Productivity",
    description: "SAML single sign-on for Box Business and Enterprise.",
    protocol: "saml",
    fields: [],
    saml: { entity_id: "box.net", acs_url: "https://sso.services.box.net/sp/ACS.saml2", name_id_format: "email", attributes: [] },
    launch_url: "https://app.box.com",
    setup: ["Box enables SSO through Box support: send them the IdP metadata URL {{idp_metadata_url}}.", "Once active, turn on SSO in Admin Console → Enterprise Settings → User Settings."],
  },
  // ---- Support ----------------------------------------------------------------------
  {
    key: "zendesk",
    name: "Zendesk",
    category: "Business",
    description: "SAML single sign-on for Zendesk agents and admins.",
    protocol: "saml",
    fields: [sub("Zendesk subdomain", "acme", "The part before .zendesk.com")],
    saml: { entity_id: "https://{{subdomain}}.zendesk.com", acs_url: "https://{{subdomain}}.zendesk.com/access/saml", name_id_format: "email", attributes: [{ name: "name", source: "display_name" }] },
    launch_url: "https://{{subdomain}}.zendesk.com/access/sso",
    setup: ["In Zendesk Admin Center → Account → Security → Single sign-on → Create SSO configuration → SAML.", "SAML SSO URL: {{idp_sso_url}}", "Certificate fingerprint: the SHA-256 fingerprint shown on this app's Setup tab.", "Enable it for team members under Security → Team member authentication."],
  },
  {
    key: "freshdesk",
    name: "Freshdesk",
    category: "Business",
    description: "SAML single sign-on for Freshdesk agents.",
    protocol: "saml",
    fields: [sub("Freshdesk subdomain", "acme", "The part before .freshdesk.com")],
    saml: { entity_id: "https://{{subdomain}}.freshdesk.com", acs_url: "https://{{subdomain}}.freshdesk.com/login/saml", name_id_format: "email", attributes: [{ name: "username", source: "email" }] },
    launch_url: "https://{{subdomain}}.freshdesk.com",
    setup: ["In Freshdesk Admin → Security → Single Sign-On → SAML.", "SAML login URL: {{idp_sso_url}}", "Security certificate: paste the certificate from this app's Setup tab."],
  },
  {
    key: "servicenow",
    name: "ServiceNow",
    category: "IT",
    description: "SAML single sign-on for a ServiceNow instance (Multi-Provider SSO).",
    protocol: "saml",
    fields: [sub("Instance name", "acme", "The part before .service-now.com")],
    saml: { entity_id: "https://{{subdomain}}.service-now.com", acs_url: "https://{{subdomain}}.service-now.com/navpage.do", name_id_format: "email", attributes: [] },
    launch_url: "https://{{subdomain}}.service-now.com/login_with_sso.do",
    setup: ["Activate the Multi-Provider SSO plugin, then Multi-Provider SSO → Identity Providers → New → SAML.", "Import IdP metadata from {{idp_metadata_url}}", "User Field: email. Test the connection, then activate."],
  },
  {
    key: "pagerduty",
    name: "PagerDuty",
    category: "Observability",
    description: "SAML single sign-on for a PagerDuty account.",
    protocol: "saml",
    fields: [sub("PagerDuty subdomain", "acme", "The part before .pagerduty.com")],
    saml: { entity_id: "https://{{subdomain}}.pagerduty.com", acs_url: "https://{{subdomain}}.pagerduty.com/sso/saml/consume", name_id_format: "email", attributes: [] },
    launch_url: "https://{{subdomain}}.pagerduty.com",
    setup: ["In PagerDuty: User Icon → Account Settings → Single Sign-on → SAML.", "Login URL: {{idp_sso_url}}", certStep],
  },
  // ---- Engineering and cloud --------------------------------------------------------
  {
    key: "gitlab-com",
    name: "GitLab.com",
    category: "Engineering",
    description: "SAML SSO for a top-level group on GitLab.com.",
    protocol: "saml",
    fields: [{ key: "group", label: "Group path", placeholder: "acme", help: "As in gitlab.com/<group>", pattern: "^[A-Za-z0-9_.-]{1,255}$" }],
    saml: { entity_id: "https://gitlab.com/groups/{{group}}", acs_url: "https://gitlab.com/groups/{{group}}/-/saml/callback", name_id_format: "persistent", attributes: [{ name: "email", source: "email" }, { name: "first_name", source: "given_name" }, { name: "last_name", source: "family_name" }] },
    launch_url: "https://gitlab.com/groups/{{group}}/-/saml/sso",
    setup: ["In GitLab: your group → Settings → SAML SSO.", "Identity provider single sign-on URL: {{idp_sso_url}}", "Certificate fingerprint: the SHA-1 fingerprint shown on this app's Setup tab.", "Save, test, then enforce SSO."],
  },
  {
    key: "sentry",
    name: "Sentry",
    category: "Observability",
    description: "SAML single sign-on for a Sentry organization.",
    protocol: "saml",
    fields: [{ key: "org", label: "Organization slug", placeholder: "acme", pattern: "^[a-z0-9_-]{1,64}$" }],
    saml: { entity_id: "https://sentry.io/saml/metadata/{{org}}/", acs_url: "https://sentry.io/saml/acs/{{org}}/", name_id_format: "email", attributes: [{ name: "email", source: "email" }, { name: "firstName", source: "given_name" }, { name: "lastName", source: "family_name" }] },
    launch_url: "https://sentry.io/auth/login/{{org}}/",
    setup: ["In Sentry: Settings → Auth → Configure SAML2.", "Metadata URL: {{idp_metadata_url}}", "Map attributes: IdP user ID → email, email → email, first name → firstName, last name → lastName."],
  },
  {
    key: "datadog",
    name: "Datadog",
    category: "Observability",
    description: "SAML single sign-on for a Datadog organization.",
    protocol: "saml",
    fields: [{ key: "site", label: "Datadog site", placeholder: "app.datadoghq.com", help: "app.datadoghq.com, us3.datadoghq.com, app.datadoghq.eu…", pattern: "^[a-z0-9.-]+\\.datadoghq\\.(com|eu)$|^app\\.ddog-gov\\.com$" }],
    saml: { entity_id: "https://{{site}}/account/saml/metadata.xml", acs_url: "https://{{site}}/account/saml/assertion", name_id_format: "email", attributes: [{ name: "sn", source: "family_name" }, { name: "givenName", source: "given_name" }] },
    launch_url: "https://{{site}}/account/login",
    setup: ["In Datadog: Organization Settings → Login Methods → SAML → Configure.", "Upload the IdP metadata from {{idp_metadata_url}}", "Enable SAML; optionally turn on IdP-initiated login."],
  },
  {
    key: "snowflake",
    name: "Snowflake",
    category: "Cloud",
    description: "SAML single sign-on for a Snowflake account.",
    protocol: "saml",
    fields: [{ key: "account", label: "Account identifier", placeholder: "acme-xy12345", help: "The part before .snowflakecomputing.com", pattern: "^[a-z0-9._-]{1,100}$" }],
    saml: { entity_id: "https://{{account}}.snowflakecomputing.com", acs_url: "https://{{account}}.snowflakecomputing.com/fed/login", name_id_format: "email", attributes: [] },
    launch_url: "https://{{account}}.snowflakecomputing.com",
    setup: ["In Snowflake, create a SAML2 security integration (CREATE SECURITY INTEGRATION … TYPE = SAML2):", "SAML2_ISSUER = '{{idp_entity_id}}', SAML2_SSO_URL = '{{idp_sso_url}}', SAML2_PROVIDER = 'CUSTOM', SAML2_X509_CERT = the certificate from this app's Setup tab (without header lines).", "Users' login names must match their email."],
  },
  {
    key: "cloudflare-access",
    name: "Cloudflare Zero Trust",
    category: "Security",
    description: "Nexus as a SAML identity provider for Cloudflare Access.",
    protocol: "saml",
    fields: [{ key: "team", label: "Team domain", placeholder: "acme", help: "The part before .cloudflareaccess.com", pattern: SUBDOMAIN }],
    saml: { entity_id: "https://{{team}}.cloudflareaccess.com/cdn-cgi/access/callback", acs_url: "https://{{team}}.cloudflareaccess.com/cdn-cgi/access/callback", name_id_format: "email", attributes: [{ name: "email", source: "email" }] },
    setup: ["In Zero Trust: Settings → Authentication → Login methods → Add new → SAML.", "Single Sign-On URL: {{idp_sso_url}}; IdP entity ID: {{idp_entity_id}}; signing certificate from this app's Setup tab.", "Email attribute name: email. Test, then use it in Access policies."],
  },
  {
    key: "jamf-pro",
    name: "Jamf Pro",
    category: "IT",
    description: "SAML single sign-on for Jamf Pro admins.",
    protocol: "saml",
    fields: [host("Jamf Pro host", "acme.jamfcloud.com")],
    saml: { entity_id: "https://{{host}}/saml/metadata", acs_url: "https://{{host}}/saml/SSO", name_id_format: "email", attributes: [] },
    launch_url: "https://{{host}}",
    setup: ["In Jamf Pro: Settings → System → Single Sign-On → Edit.", "Identity Provider: Other; Identity Provider Metadata Source: Metadata URL {{idp_metadata_url}}", "User mapping: NameID → Email. Keep a failover login URL for emergencies."],
  },
  {
    key: "jenkins",
    name: "Jenkins",
    category: "Engineering",
    description: "SAML sign-in for Jenkins (SAML plugin).",
    protocol: "saml",
    fields: [host("Jenkins host", "ci.acme.com")],
    saml: { entity_id: "https://{{host}}/securityRealm/finishLogin", acs_url: "https://{{host}}/securityRealm/finishLogin", name_id_format: "email", attributes: [{ name: "displayName", source: "display_name" }] },
    launch_url: "https://{{host}}",
    setup: ["Install the SAML plugin. Manage Jenkins → Security → Security Realm: SAML 2.0.", "IdP Metadata URL: {{idp_metadata_url}}", "Display name attribute: displayName; username case: lowercase."],
  },
  {
    key: "mattermost",
    name: "Mattermost",
    category: "Communication",
    description: "SAML sign-in for a self-hosted Mattermost.",
    protocol: "saml",
    fields: [host("Mattermost host", "chat.acme.com")],
    saml: { entity_id: "https://{{host}}", acs_url: "https://{{host}}/login/sso/saml", name_id_format: "email", attributes: [{ name: "email", source: "email" }, { name: "firstName", source: "given_name" }, { name: "lastName", source: "family_name" }] },
    launch_url: "https://{{host}}",
    setup: ["System Console → Authentication → SAML 2.0: SAML SSO URL {{idp_sso_url}}, Identity Provider Issuer URL {{idp_entity_id}}, IdP public certificate from this app's Setup tab.", "Email attribute: email; first name: firstName; last name: lastName."],
  },
  // ---- OIDC apps --------------------------------------------------------------------
  ...(
    [
      ["argocd", "Argo CD", "Engineering", "OpenID Connect sign-in for Argo CD.", "argocd.acme.com", ["https://{{host}}/auth/callback"], "In argocd-cm, set oidc.config: name Votal Nexus, issuer {{issuer}}, clientID {{client_id}}, clientSecret $oidc.nexus.clientSecret (put {{client_secret}} in argocd-secret), requestedScopes [openid, profile, email, groups]."],
      ["gitlab-self-managed", "GitLab (self-managed)", "Engineering", "OpenID Connect sign-in for a self-managed GitLab.", "gitlab.acme.com", ["https://{{host}}/users/auth/openid_connect/callback"], "In gitlab.rb, add an omniauth provider openid_connect with issuer {{issuer}}, discovery true, client_options identifier {{client_id}}, secret {{client_secret}}, redirect_uri https://{{host}}/users/auth/openid_connect/callback."],
      ["kibana", "Kibana / Elastic", "Observability", "OpenID Connect sign-in for Kibana (Elastic Stack).", "kibana.acme.com", ["https://{{host}}/api/security/oidc/callback"], "In elasticsearch.yml, add an oidc realm: rp.client_id {{client_id}}, rp.redirect_uri https://{{host}}/api/security/oidc/callback, op.issuer {{issuer}}, op.jwkset_path from {{issuer}}/.well-known/openid-configuration; put {{client_secret}} in the keystore as rp.client_secret."],
      ["vault", "HashiCorp Vault", "Security", "OIDC auth method for Vault (UI and CLI).", "vault.acme.com:8200", ["https://{{host}}/ui/vault/auth/oidc/oidc/callback", "http://localhost:8250/oidc/callback"], "vault auth enable oidc; vault write auth/oidc/config oidc_discovery_url={{issuer}} oidc_client_id={{client_id}} oidc_client_secret={{client_secret}} default_role=default; create a role with both redirect URIs."],
      ["harbor", "Harbor", "Engineering", "OIDC sign-in for the Harbor registry.", "harbor.acme.com", ["https://{{host}}/c/oidc/callback"], "Administration → Configuration → Authentication: OIDC, endpoint {{issuer}}, client ID {{client_id}}, secret {{client_secret}}, scope openid,profile,email,groups, group claim groups."],
      ["minio", "MinIO", "Cloud", "OpenID sign-in for the MinIO console.", "minio.acme.com", ["https://{{host}}/oauth_callback"], "In MinIO: Identity → OpenID → Create: config URL {{issuer}}/.well-known/openid-configuration, client ID {{client_id}}, secret {{client_secret}}, claim name for policies (e.g. groups), scopes openid,profile,email,groups."],
      ["nextcloud", "Nextcloud", "Productivity", "OpenID Connect sign-in for Nextcloud (user_oidc app).", "cloud.acme.com", ["https://{{host}}/apps/user_oidc/code"], "Install the OpenID Connect user backend app, then Settings → OpenID Connect → Register provider: identifier Nexus, client ID {{client_id}}, secret {{client_secret}}, discovery {{issuer}}/.well-known/openid-configuration."],
      ["outline", "Outline", "Productivity", "OIDC sign-in for a self-hosted Outline wiki.", "wiki.acme.com", ["https://{{host}}/auth/oidc.callback"], "Set OIDC_CLIENT_ID={{client_id}}, OIDC_CLIENT_SECRET={{client_secret}}, OIDC_AUTH_URI={{issuer}}/authorize, OIDC_TOKEN_URI={{issuer}}/token, OIDC_USERINFO_URI={{issuer}}/userinfo, OIDC_DISPLAY_NAME=Nexus."],
      ["rancher", "Rancher", "Cloud", "Generic OIDC sign-in for Rancher.", "rancher.acme.com", ["https://{{host}}/verify-auth"], "Users & Authentication → Auth Provider → Generic OIDC: client ID {{client_id}}, secret {{client_secret}}, issuer {{issuer}}, Rancher URL https://{{host}}."],
      ["portainer", "Portainer", "Cloud", "OAuth sign-in for Portainer.", "portainer.acme.com", ["https://{{host}}/"], "Settings → Authentication → OAuth → Custom: client ID {{client_id}}, secret {{client_secret}}, authorization URL {{issuer}}/authorize, access token URL {{issuer}}/token, resource URL {{issuer}}/userinfo, redirect https://{{host}}/, user identifier email, scopes openid profile email."],
    ] as const
  ).map(([key, name, category, description, placeholder, redirects, setup]) => ({
    key,
    name,
    category,
    description,
    protocol: "oidc" as const,
    fields: [host(`${name} host`, placeholder)],
    oidc: { redirect_uris: [...redirects], client_type: "confidential" as const },
    launch_url: "https://{{host}}",
    setup: [setup, "Test signing in with a Nexus account assigned to this app."],
  })),
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
