import { createRoute, z } from "@hono/zod-openapi";
import type { App } from "../context.js";
import { requirePermission } from "../auth/guard.js";
import { bearer, json, problemResponses } from "../schemas.js";
import { SAAS_APPS } from "../saas/catalog.js";
import { CATALOG } from "./catalog.js";

/**
 * The app directory: well-known apps that support SAML 2.0 or OpenID Connect single sign-on
 * (usually on their business plans). Unlike catalog templates, an entry carries no vendor URLs:
 * choosing one opens the generic SAML/OIDC form with its name, and the admin imports the vendor's
 * SP metadata (or copies its URLs). Nothing is guessed, so nothing is wrong.
 *
 * Apps from the SaaS catalog (saas/catalog.ts) that aren't listed here are in the directory too,
 * marked unverified: many offer SAML or OIDC on some plans, but Nexus doesn't claim it for them.
 */

type Protocol = "saml" | "oidc";
const S: Protocol[] = ["saml"];
const O: Protocol[] = ["oidc"];
const SO: Protocol[] = ["saml", "oidc"];

// [name, category, protocols]
const ENTRIES: [string, string, Protocol[]][] = [
  // Communication and collaboration
  ["Microsoft Teams", "Communication", S], ["Webex", "Communication", S], ["RingCentral", "Communication", S], ["Dialpad", "Communication", S], ["Aircall", "Communication", S],
  ["8x8", "Communication", S], ["Vonage", "Communication", S], ["GoTo Meeting", "Communication", S], ["Loom", "Communication", S], ["Discourse", "Communication", SO],
  ["Rocket.Chat", "Communication", SO], ["Zulip", "Communication", SO], ["Workplace from Meta", "Communication", S], ["Front", "Communication", S], ["Twilio", "Communication", S],
  // Productivity and documents
  ["Microsoft 365", "Productivity", S], ["Dropbox Sign", "Productivity", S], ["Adobe Acrobat Sign", "Productivity", S], ["Adobe Creative Cloud", "Design", S], ["Canva", "Design", S],
  ["Lucid", "Design", S], ["Webflow", "Design", S], ["Sketch", "Design", S], ["InVision", "Design", S], ["Frame.io", "Design", S],
  ["Coda", "Productivity", S], ["ClickUp", "Productivity", S], ["Monday.com", "Productivity", S], ["Wrike", "Productivity", S], ["Trello", "Productivity", S],
  ["Basecamp", "Productivity", S], ["Todoist", "Productivity", S], ["Evernote", "Productivity", S], ["Quip", "Productivity", S], ["Egnyte", "Productivity", S],
  ["ShareFile", "Productivity", S], ["Confluence Data Center", "Productivity", S], ["Guru", "Productivity", S], ["Slab", "Productivity", S], ["Tettra", "Productivity", S],
  ["Calendly", "Productivity", S], ["Zapier", "Productivity", S], ["Make", "Productivity", S], ["Typeform", "Productivity", S], ["SurveyMonkey", "Productivity", S],
  ["Qualtrics", "Productivity", S], ["Grammarly", "Productivity", S], ["Otter.ai", "Productivity", S], ["Gong", "Business", S], ["Chorus", "Business", S],
  // Engineering
  ["Bitbucket", "Engineering", S], ["Jira Data Center", "Engineering", S], ["Linear", "Engineering", S], ["Vercel", "Engineering", S], ["Netlify", "Engineering", S],
  ["Heroku", "Engineering", S], ["CircleCI", "Engineering", S], ["Buildkite", "Engineering", S], ["Travis CI", "Engineering", S], ["TeamCity", "Engineering", SO],
  ["Postman", "Engineering", S], ["Docker Hub", "Engineering", S], ["JFrog Artifactory", "Engineering", SO], ["Sonatype Nexus Repository", "Engineering", S], ["SonarQube", "Engineering", SO],
  ["Snyk", "Security", S], ["Terraform Cloud", "Engineering", S], ["Pulumi Cloud", "Engineering", S], ["LaunchDarkly", "Engineering", S], ["Statsig", "Engineering", S],
  ["Retool", "Engineering", SO], ["Airflow", "Engineering", O], ["Backstage", "Engineering", O], ["Gitea", "Engineering", O], ["Jupyter Hub", "Engineering", O],
  ["Coder", "Engineering", O], ["Gitpod", "Engineering", O], ["Sourcegraph", "Engineering", SO], ["Figma Dev Mode", "Design", S], ["Cursor", "Engineering", S],
  ["GitHub Copilot", "Engineering", S], ["OpenAI ChatGPT Enterprise", "Productivity", S], ["Anthropic Claude for Work", "Productivity", S], ["Perplexity Enterprise", "Productivity", S], ["Glean", "Productivity", S],
  // Cloud and data
  ["Google Cloud", "Cloud", S], ["Microsoft Azure", "Cloud", S], ["Oracle Cloud", "Cloud", S], ["IBM Cloud", "Cloud", S], ["DigitalOcean", "Cloud", S],
  ["Cloudflare dashboard", "Cloud", S], ["Fastly", "Cloud", S], ["Akamai", "Cloud", S], ["MongoDB Atlas", "Cloud", S], ["Databricks", "Cloud", S],
  ["Confluent Cloud", "Cloud", S], ["Elastic Cloud", "Cloud", S], ["Redis Cloud", "Cloud", S], ["Supabase", "Cloud", S], ["Neon", "Cloud", S],
  ["Tableau", "Business", S], ["Looker", "Business", S], ["Power BI", "Business", S], ["Mode", "Business", S], ["Metabase", "Business", SO],
  ["Sigma Computing", "Business", S], ["ThoughtSpot", "Business", S], ["dbt Cloud", "Engineering", SO], ["Fivetran", "Engineering", S], ["Segment", "Engineering", S],
  ["Amplitude", "Business", S], ["Mixpanel", "Business", S], ["Heap", "Business", S], ["Pendo", "Business", S], ["FullStory", "Business", S],
  ["Hotjar", "Business", S], ["LogRocket", "Engineering", S],
  // Observability and incident response
  ["New Relic", "Observability", S], ["Splunk Cloud", "Observability", S], ["Sumo Logic", "Observability", S], ["Dynatrace", "Observability", S], ["Honeycomb", "Observability", S],
  ["Grafana Cloud", "Observability", SO], ["Lightstep", "Observability", S], ["Opsgenie", "Observability", S], ["incident.io", "Observability", S], ["FireHydrant", "Observability", S],
  ["Rootly", "Observability", S], ["Statuspage", "Observability", S], ["BetterStack", "Observability", S], ["Rollbar", "Observability", S], ["Bugsnag", "Observability", S],
  // Security and IT
  ["CrowdStrike Falcon", "Security", S], ["SentinelOne", "Security", S], ["Microsoft Defender", "Security", S], ["Palo Alto Prisma Access", "Security", S], ["Zscaler", "Security", S],
  ["Netskope", "Security", S], ["Tailscale", "Security", O], ["Twingate", "Security", S], ["Wiz", "Security", S], ["Lacework", "Security", S],
  ["Orca Security", "Security", S], ["Vanta", "Security", S], ["Drata", "Security", S], ["Secureframe", "Security", S], ["KnowBe4", "Security", S],
  ["1Password Business", "Security", O], ["Bitwarden", "Security", SO], ["Keeper", "Security", S], ["LastPass", "Security", S], ["Dashlane", "Security", S],
  ["Kandji", "IT", S], ["Mosyle", "IT", S], ["Microsoft Intune", "IT", S], ["Addigy", "IT", S], ["NinjaOne", "IT", S],
  ["Kaseya", "IT", S], ["TeamViewer", "IT", S], ["Splashtop", "IT", S], ["AnyDesk", "IT", S], ["Zendesk Sell", "Business", S],
  ["Freshservice", "IT", S], ["Jira Service Management", "IT", S], ["Ivanti", "IT", S], ["SolarWinds Service Desk", "IT", S], ["Snipe-IT", "IT", S],
  // Business, sales and marketing
  ["Microsoft Dynamics 365", "Business", S], ["SAP SuccessFactors", "HR", S], ["SAP Concur", "Finance", S], ["Oracle NetSuite", "Finance", S], ["QuickBooks Online", "Finance", S],
  ["Xero", "Finance", S], ["Expensify", "Finance", S], ["Ramp", "Finance", S], ["Brex", "Finance", S], ["Bill.com", "Finance", S],
  ["Coupa", "Finance", S], ["Stripe", "Finance", S], ["Pipedrive", "Business", S], ["Outreach", "Business", S], ["Salesloft", "Business", S],
  ["Apollo.io", "Business", S], ["ZoomInfo", "Business", S], ["LinkedIn Sales Navigator", "Business", S], ["Marketo", "Business", S], ["Mailchimp", "Business", S],
  ["Braze", "Business", S], ["Iterable", "Business", S], ["Klaviyo", "Business", S], ["Intercom", "Business", S], ["Drift", "Business", S],
  ["Gainsight", "Business", S], ["ChurnZero", "Business", S], ["Highspot", "Business", S], ["Seismic", "Business", S], ["Contentful", "Business", S],
  ["Sanity", "Business", S], ["WordPress VIP", "Business", S], ["Sprout Social", "Business", S], ["Hootsuite", "Business", S], ["Semrush", "Business", S],
  // HR
  ["BambooHR", "HR", S], ["Rippling", "HR", S], ["Gusto", "HR", S], ["HiBob", "HR", S], ["Personio", "HR", S],
  ["Deel", "HR", S], ["Remote", "HR", S], ["ADP Workforce Now", "HR", S], ["UKG Pro", "HR", S], ["Lattice", "HR", S],
  ["Culture Amp", "HR", S], ["15Five", "HR", S], ["Greenhouse", "HR", S], ["Lever", "HR", S], ["Ashby", "HR", S],
  ["Workable", "HR", S], ["Namely", "HR", S], ["Paylocity", "HR", S], ["Paycom", "HR", S], ["Leapsome", "HR", S],
  ["Docebo", "HR", S], ["Cornerstone", "HR", S], ["TalentLMS", "HR", S], ["Coursera for Business", "HR", S], ["LinkedIn Learning", "HR", S],
  ["Udemy Business", "HR", S], ["Pluralsight", "HR", S], ["Navan", "Finance", S], ["Egencia", "Finance", S], ["Envoy", "IT", S],
];

const DirectoryEntry = z
  .object({
    key: z.string(),
    name: z.string(),
    category: z.string(),
    protocols: z.array(z.enum(["saml", "oidc"])).openapi({ description: "Empty when SSO support isn't verified" }),
    template: z.string().nullable().openapi({ description: "A catalog template to use instead, when there is one" }),
    verified: z.boolean().openapi({ description: "Known to support SAML or OIDC single sign-on. Otherwise check the vendor's documentation (it's often on business plans only)" }),
  })
  .openapi("AppDirectoryEntry");

const slug = (n: string) => n.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");

/** The directory, with catalog templates first-class: an entry that has a template points at it. */
export function directory() {
  const byName = new Map(CATALOG.map((t) => [t.name.toLowerCase(), t.key]));
  const out = new Map<string, z.infer<typeof DirectoryEntry>>();
  for (const t of CATALOG) out.set(t.key, { key: t.key, name: t.name, category: t.category, protocols: [t.protocol], template: t.key, verified: true });
  for (const [name, category, protocols] of ENTRIES) {
    const key = slug(name);
    if (out.has(key) || byName.has(name.toLowerCase())) continue;
    out.set(key, { key, name, category, protocols, template: null, verified: true });
    byName.set(name.toLowerCase(), key);
  }
  for (const a of SAAS_APPS) {
    if (out.has(a.key) || byName.has(a.name.toLowerCase())) continue;
    out.set(a.key, { key: a.key, name: a.name, category: a.category, protocols: [], template: null, verified: false });
  }
  return [...out.values()].sort((a, b) => a.name.localeCompare(b.name));
}

export function registerAppDirectoryRoutes(app: App) {
  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/app-directory",
      tags: ["Applications"],
      summary: "Every app you can connect with a template or a generic SAML/OIDC setup",
      security: bearer,
      responses: { 200: json(z.object({ data: z.array(DirectoryEntry) })), ...problemResponses },
    }),
    async (c) => {
      requirePermission(c, "apps:write");
      return c.json({ data: directory() }, 200);
    },
  );
}
