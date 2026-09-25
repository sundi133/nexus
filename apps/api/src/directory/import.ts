import { touchUsers } from "../provisioning/service.js";
import { emailAdmission } from "../org/domains.js";
import { createRoute, z } from "@hono/zod-openapi";
import { sql } from "kysely";
import type { App } from "../context.js";
import { audit } from "../audit/record.js";
import { requirePermission } from "../auth/guard.js";
import { badRequest } from "../platform/errors.js";
import { newId } from "../platform/ids.js";
import { bearer, body, json, problemResponses } from "../schemas.js";
import { issueInvitation, sendInvite, type PendingInvite } from "./invitations.js";

const MAX_ROWS = 5000;
const COLUMNS = ["email", "given_name", "family_name", "title", "department", "groups"] as const;
const ALIASES: Record<string, (typeof COLUMNS)[number]> = {
  email: "email",
  "e-mail": "email",
  "work email": "email",
  first_name: "given_name",
  "first name": "given_name",
  given_name: "given_name",
  firstname: "given_name",
  last_name: "family_name",
  "last name": "family_name",
  family_name: "family_name",
  lastname: "family_name",
  surname: "family_name",
  title: "title",
  "job title": "title",
  department: "department",
  dept: "department",
  groups: "groups",
  group: "groups",
};

/** RFC 4180 CSV parsing (quoted fields, escaped quotes, CRLF), enough for spreadsheet exports. */
export function parseCsv(input: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let quoted = false;
  const text = input.replace(/^﻿/, "");
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;
    if (quoted) {
      if (ch === '"' && text[i + 1] === '"') {
        field += '"';
        i++;
      } else if (ch === '"') quoted = false;
      else field += ch;
    } else if (ch === '"') quoted = true;
    else if (ch === ",") {
      row.push(field);
      field = "";
    } else if (ch === "\n" || ch === "\r") {
      if (ch === "\r" && text[i + 1] === "\n") i++;
      row.push(field);
      if (row.some((f) => f.trim() !== "")) rows.push(row);
      row = [];
      field = "";
    } else field += ch;
  }
  row.push(field);
  if (row.some((f) => f.trim() !== "")) rows.push(row);
  return rows;
}

const ImportRow = z
  .object({
    line: z.number().int(),
    email: z.string(),
    name: z.string(),
    action: z.enum(["create", "skip", "error"]),
    message: z.string(),
    groups: z.array(z.string()),
  })
  .openapi("ImportRow");

const ImportResult = z
  .object({
    dry_run: z.boolean(),
    summary: z.object({ create: z.number().int(), skip: z.number().int(), error: z.number().int(), new_groups: z.array(z.string()) }),
    rows: z.array(ImportRow),
  })
  .openapi("ImportResult");

const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function registerImportRoutes(app: App) {
  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/users/import",
      tags: ["Users"],
      summary: "Bulk import users from CSV (SPEC DIR-03)",
      description:
        "Columns (header row, case-insensitive): `email` (required), `first name`, `last name`, `title`, `department`, `groups` (separated by `;`). Run with `dry_run: true` first to preview; nothing is written. Existing emails are skipped, never overwritten.",
      security: bearer,
      request: body(
        z.object({
          csv: z.string().max(5_000_000),
          dry_run: z.boolean().default(true),
          invite: z.boolean().default(true).openapi({ description: "Email each new user an invitation" }),
        }),
      ),
      responses: { 200: json(ImportResult), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "users:write");
      const { csv, dry_run, invite } = c.req.valid("json");
      const table = parseCsv(csv);
      if (table.length < 2) throw badRequest("empty_csv", "The file needs a header row and at least one user");
      if (table.length - 1 > MAX_ROWS) throw badRequest("too_many_rows", `Import at most ${MAX_ROWS} users at a time`);

      const header = table[0]!.map((h) => ALIASES[h.trim().toLowerCase()]);
      if (!header.includes("email")) throw badRequest("missing_email_column", "The header row must include an `email` column");
      const col = (r: string[], k: (typeof COLUMNS)[number]) => {
        const i = header.indexOf(k);
        return i >= 0 ? (r[i] ?? "").trim() : "";
      };

      const deps = c.get("deps");
      const invites: PendingInvite[] = [];
      const result = await deps.db.tenant(p.orgId, async (tx) => {
        const emails = table.slice(1).map((r) => col(r, "email").toLowerCase());
        const existing = new Set(
          (await tx.selectFrom("users").select("email").where("email", "in", emails.length ? emails : [""]).execute()).map((u) => u.email),
        );
        // Emails are unique across all organizations (login is email-first), so also check outside this tenant.
        const takenElsewhere = new Set(
          (
            await sql<{ e: string }>`SELECT e FROM unnest(${emails}::text[]) AS e WHERE nexus_email_taken(e)`.execute(tx)
          ).rows.map((r) => r.e),
        );
        const groupRows = await tx.selectFrom("groups").select(["id", "name"]).execute();
        const groups = new Map(groupRows.map((g) => [g.name.toLowerCase(), g]));
        const newGroups = new Set<string>();
        const seen = new Set<string>();
        const rows: z.infer<typeof ImportRow>[] = [];

        for (const [i, r] of table.slice(1).entries()) {
          const email = col(r, "email").toLowerCase();
          const given = col(r, "given_name");
          const family = col(r, "family_name");
          const groupNames = col(r, "groups")
            .split(";")
            .map((g) => g.trim())
            .filter(Boolean);
          const base = { line: i + 2, email, name: `${given} ${family}`.trim(), groups: groupNames };
          if (!EMAIL.test(email)) {
            rows.push({ ...base, action: "error", message: "Missing or invalid email" });
            continue;
          }
          if (!given) {
            rows.push({ ...base, action: "error", message: "First name is required" });
            continue;
          }
          if (existing.has(email) || seen.has(email)) {
            rows.push({ ...base, action: "skip", message: seen.has(email) ? "Duplicate row in this file" : "Already in your directory" });
            continue;
          }
          if (takenElsewhere.has(email)) {
            rows.push({ ...base, action: "error", message: "This email is already used by another Nexus account" });
            continue;
          }
          const refused = await emailAdmission(tx, p.orgId, email);
          if (refused) {
            rows.push({ ...base, action: "error", message: refused });
            continue;
          }
          seen.add(email);
          for (const g of groupNames) if (!groups.has(g.toLowerCase())) newGroups.add(g);
          rows.push({ ...base, action: "create", message: invite ? "Will be invited by email" : "Will be created (no password yet)" });
        }

        if (!dry_run) {
          for (const name of newGroups) {
            const id = newId();
            await tx.insertInto("groups").values({ id, org_id: p.orgId, name, description: "Created by CSV import", updated_at: new Date() }).execute();
            groups.set(name.toLowerCase(), { id, name });
          }
          for (const row of rows.filter((x) => x.action === "create")) {
            const r = table[row.line - 1]!;
            const id = newId();
            await tx
              .insertInto("users")
              .values({
                id,
                org_id: p.orgId,
                email: row.email,
                given_name: col(r, "given_name"),
                family_name: col(r, "family_name"),
                title: col(r, "title"),
                department: col(r, "department"),
                status: "staged",
                password_hash: null,
                attributes: JSON.stringify({ source: "csv_import" }),
                updated_at: new Date(),
              })
              .execute();
            for (const g of row.groups) {
              await tx
                .insertInto("group_members")
                .values({ org_id: p.orgId, group_id: groups.get(g.toLowerCase())!.id, user_id: id })
                .onConflict((oc) => oc.doNothing())
                .execute();
            }
            if (invite) invites.push(await issueInvitation(tx, p, id));
            if (row.groups.length) await touchUsers(tx, p.orgId, [id]);
          }
          const summary = { created: rows.filter((x) => x.action === "create").length, skipped: rows.filter((x) => x.action === "skip").length };
          await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, {
            type: "user.imported",
            details: { ...summary, errors: rows.filter((x) => x.action === "error").length, new_groups: [...newGroups], invited: invite },
          });
        }

        const count = (a: string) => rows.filter((x) => x.action === a).length;
        return { dry_run, summary: { create: count("create"), skip: count("skip"), error: count("error"), new_groups: [...newGroups] }, rows };
      });

      // Send after commit, and don't fail the import if one mailbox rejects.
      await Promise.allSettled(invites.map((inv) => sendInvite(deps, inv)));
      return c.json(result, 200);
    },
  );
}
