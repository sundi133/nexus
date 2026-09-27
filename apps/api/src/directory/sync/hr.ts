import { z } from "@hono/zod-openapi";
import type { Config } from "../../config.js";
import { assertSafeUrl } from "../../platform/outbound.js";
import type { Remote, RemoteGroup, RemoteUser } from "./plan.js";
import { getJson, ProviderError } from "./providers.js";

/**
 * HR systems as the source of truth for joiners, movers and leavers (like JumpCloud's HR
 * directory integrations). Read-only: BambooHR through a custom report over its API, Workday
 * through a custom report published as a web service (RaaS, JSON).
 *
 * - Joiners: employees with a work email who are active.
 * - Movers: title, department and manager (the HR supervisor) follow HR.
 * - Leavers: an employee is active until HR marks them terminated, or their termination date
 *   (their last day, UTC) has passed.
 * - Departments can become groups, so access can follow the org chart.
 */

type Endpoints = Pick<Config, "bamboohrBase" | "allowPrivateOutbound">;

const today = () => new Date().toISOString().slice(0, 10);
/** A last day that has passed (dates are YYYY-MM-DD; anything else is ignored). */
const leftBefore = (date: string, now = today()) => /^\d{4}-\d{2}-\d{2}$/.test(date) && date !== "0000-00-00" && date < now;

function departmentGroups(users: RemoteUser[], source: string): RemoteGroup[] {
  const by = new Map<string, string[]>();
  for (const u of users) if (u.department) by.set(u.department, [...(by.get(u.department) ?? []), u.external_id]);
  return [...by].map(([name, ids]) => ({ external_id: `department:${name.toLowerCase()}`, name, description: `People in ${name}, from ${source}`, member_ids: ids }));
}

// ---- BambooHR -------------------------------------------------------------------------------

export const BambooConfig = z.object({
  subdomain: z
    .string()
    .trim()
    .toLowerCase()
    .regex(/^[a-z0-9][a-z0-9-]{0,62}$/, "Your BambooHR company subdomain: the “acme” in acme.bamboohr.com"),
});

const BAMBOO_FIELDS = ["id", "firstName", "lastName", "preferredName", "workEmail", "jobTitle", "department", "supervisorEId", "status", "terminationDate"];

export async function fetchBambooHR(ep: Endpoints, rawCfg: unknown, apiKey: string, opts: { groups: boolean }): Promise<Remote> {
  const cfg = BambooConfig.parse(rawCfg);
  const url = `${ep.bamboohrBase}/${cfg.subdomain}/v1/reports/custom?format=JSON&onlyCurrent=true`;
  const body = await getJson(
    url,
    {
      method: "POST",
      headers: { authorization: `Basic ${Buffer.from(`${apiKey}:x`).toString("base64")}`, accept: "application/json", "content-type": "application/json" },
      body: JSON.stringify({ title: "Nexus directory sync", fields: BAMBOO_FIELDS }),
    },
    "BambooHR employee report",
  );
  if (!body || !Array.isArray(body.employees)) throw new ProviderError("BambooHR returned no employee list (check the subdomain and that the API key's user can run reports)", true);
  const now = today();
  const users: RemoteUser[] = (body.employees as Record<string, unknown>[]).map((e) => {
    const s = (k: string) => (typeof e[k] === "string" ? (e[k] as string).trim() : e[k] == null ? "" : String(e[k]));
    const term = s("terminationDate");
    const left = leftBefore(term, now);
    const active = s("status").toLowerCase() === "active" && !left;
    return {
      external_id: s("id"),
      email: s("workEmail"),
      given_name: s("preferredName") || s("firstName"),
      family_name: s("lastName"),
      title: s("jobTitle"),
      department: s("department"),
      manager_external_id: s("supervisorEId") || undefined,
      active,
      inactive_reason: active ? undefined : left ? `Left the company in BambooHR (last day ${term})` : "Inactive in BambooHR",
    };
  });
  return { users, groups: opts.groups ? departmentGroups(users.filter((u) => u.active), "BambooHR") : [] };
}

// ---- Workday ----------------------------------------------------------------------------------

/** Workday report columns are named by whoever built the report: these are the defaults, each can be renamed. */
export const WORKDAY_DEFAULT_FIELDS = {
  employee_id: "Employee_ID",
  email: "Email_Address",
  given_name: "First_Name",
  family_name: "Last_Name",
  title: "Business_Title",
  department: "Department",
  manager_id: "Manager_Employee_ID",
  active: "Active",
  termination_date: "Termination_Date",
} as const;

const Column = z.string().trim().min(1).max(100).regex(/^[A-Za-z0-9_.-]+$/, "A report column name, like Employee_ID");
export const WorkdayConfig = z.object({
  report_url: z.string().trim().url().max(2000).openapi({ description: "The custom report's JSON web-service URL (…/ccx/service/customreport2/{tenant}/{owner}/{report})" }),
  fields: z
    .object(Object.fromEntries(Object.keys(WORKDAY_DEFAULT_FIELDS).map((k) => [k, Column.optional()])) as Record<keyof typeof WORKDAY_DEFAULT_FIELDS, z.ZodOptional<typeof Column>>)
    .default({}),
});
export const WorkdaySecret = z.object({ username: z.string().min(1).max(200), password: z.string().min(1).max(500) });

const WORKDAY_HOST = /(^|\.)(workday|myworkday)\.com$/i;

/** Only Workday's own hosts over https (anything else in dev/test, for fakes). */
export async function checkWorkdayUrl(ep: Pick<Config, "allowPrivateOutbound">, raw: string) {
  const url = await assertSafeUrl(raw, { allowPrivate: ep.allowPrivateOutbound }).catch((e: Error) => {
    throw new ProviderError(`Workday report URL: ${e.message}`, true);
  });
  if (!ep.allowPrivateOutbound && !WORKDAY_HOST.test(url.hostname)) throw new ProviderError("The report URL must be on your Workday tenant (…workday.com or …myworkday.com)", true);
  if (!/\/ccx\/service\/customreport2\//.test(url.pathname)) throw new ProviderError("That isn't a Workday custom report URL (it contains /ccx/service/customreport2/)", true);
  url.searchParams.set("format", "json");
  return url;
}

/** Workday values can be plain, a list, or an object with a Descriptor / ID. */
function text(v: unknown): string {
  if (v == null) return "";
  if (Array.isArray(v)) return text(v[0]);
  if (typeof v === "object") {
    const o = v as Record<string, unknown>;
    return text(o.Descriptor ?? o.descriptor ?? o.ID ?? o.id ?? "");
  }
  return String(v).trim();
}
const truthy = (v: string) => ["1", "true", "yes", "active", "y"].includes(v.toLowerCase());

export async function fetchWorkday(ep: Endpoints, rawCfg: unknown, rawSecret: string, opts: { groups: boolean }): Promise<Remote> {
  const cfg = WorkdayConfig.parse(rawCfg);
  const secret = WorkdaySecret.parse(JSON.parse(rawSecret));
  const url = await checkWorkdayUrl(ep, cfg.report_url);
  const col = { ...WORKDAY_DEFAULT_FIELDS, ...Object.fromEntries(Object.entries(cfg.fields).filter(([, v]) => v)) } as Record<keyof typeof WORKDAY_DEFAULT_FIELDS, string>;
  const body = await getJson(
    url.toString(),
    { headers: { authorization: `Basic ${Buffer.from(`${secret.username}:${secret.password}`).toString("base64")}`, accept: "application/json" } },
    "Workday report",
  );
  const rows = body?.Report_Entry;
  if (!Array.isArray(rows)) throw new ProviderError("Workday returned no Report_Entry list: is the report published as a web service, with JSON enabled?", true);
  const now = today();
  const users: RemoteUser[] = (rows as Record<string, unknown>[]).map((r) => {
    const g = (k: keyof typeof col) => text(r[col[k]]);
    const term = g("termination_date").slice(0, 10);
    const left = leftBefore(term, now);
    // No "active" column: everyone listed is active unless they've left.
    const activeCol = col.active in r ? truthy(g("active")) : true;
    const active = activeCol && !left;
    return {
      external_id: g("employee_id"),
      email: g("email"),
      given_name: g("given_name"),
      family_name: g("family_name"),
      title: g("title"),
      department: g("department"),
      manager_external_id: g("manager_id") || undefined,
      active,
      inactive_reason: active ? undefined : left ? `Left the company in Workday (last day ${term})` : "Inactive in Workday",
    };
  });
  const missing = users.filter((u) => !u.external_id).length;
  if (users.length && missing === users.length) throw new ProviderError(`None of the report's rows has a “${col.employee_id}” column: check the field names`, true);
  return { users: users.filter((u) => u.external_id), groups: opts.groups ? departmentGroups(users.filter((u) => u.active), "Workday") : [] };
}
