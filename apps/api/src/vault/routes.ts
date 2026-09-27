import { createRoute, z } from "@hono/zod-openapi";
import type { App } from "../context.js";
import { audit } from "../audit/record.js";
import { requirePermission, requireSession } from "../auth/guard.js";
import type { Tx } from "../platform/db.js";
import { badRequest, conflict, forbidden, notFound } from "../platform/errors.js";
import { newId } from "../platform/ids.js";
import { bearer, body, Id, iso, json, problemResponses } from "../schemas.js";

/**
 * The password manager, zero-knowledge: every secret is encrypted in the browser (see the web
 * app's lib/vault-crypto.ts). The server keeps ciphertext, public keys and wrapped vault keys, and
 * decides only who may read or write which vault: members read, editors and owners write, owners
 * share. It can't decrypt anything, including for admins.
 */

const B64 = z.string().max(20_000).regex(/^[A-Za-z0-9+/=]+$/);
const Sealed = z.object({ iv: z.string().regex(/^[A-Za-z0-9+/=]{16}$/), ct: z.string().max(90_000).regex(/^[A-Za-z0-9+/=]+$/) });
const Kdf = z.object({ alg: z.literal("PBKDF2-SHA256"), iterations: z.number().int().min(100_000).max(10_000_000), salt: z.string().regex(/^[A-Za-z0-9+/=]{20,64}$/) });
const Role = z.enum(["owner", "editor", "viewer"]);

const Account = z.object({ public_key: B64, private_key_enc: Sealed, kdf: Kdf }).openapi("VaultAccount");
const VaultOut = z.object({ id: Id, kind: z.enum(["personal", "shared"]), name_enc: Sealed, role: Role, wrapped_key: B64, members: z.number().int(), items: z.number().int() }).openapi("Vault");
const ItemOut = z.object({ id: Id, data: Sealed, updated_at: z.string(), updated_by: z.string().nullable() }).openapi("VaultItem");

async function membership(tx: Tx, vaultId: string, userId: string) {
  const m = await tx.selectFrom("vault_members").select(["role"]).where("vault_id", "=", vaultId).where("user_id", "=", userId).executeTakeFirst();
  if (!m) throw notFound("Vault"); // not a member: it doesn't exist for you
  return m.role;
}
const canWrite = (r: string) => r === "owner" || r === "editor";

export function registerVaultRoutes(app: App) {
  app.openapi(
    createRoute({ method: "get", path: "/v1/vault/account", tags: ["Passwords"], summary: "Your vault key material (encrypted), if you've set up the password manager", security: bearer, responses: { 200: json(Account.nullable()), ...problemResponses } }),
    async (c) => {
      const p = requireSession(c);
      const a = await c.get("deps").db.tenant(p.orgId, (tx) => tx.selectFrom("vault_accounts").select(["public_key", "private_key_enc", "kdf"]).where("user_id", "=", p.userId).executeTakeFirst());
      return c.json(a ? { public_key: a.public_key, private_key_enc: a.private_key_enc as z.infer<typeof Sealed>, kdf: a.kdf as z.infer<typeof Kdf> } : null, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "put",
      path: "/v1/vault/account",
      tags: ["Passwords"],
      summary: "Set up the password manager, or change your master password",
      description: "The first call stores your public key and encrypted private key. Later calls may only re-encrypt the same private key (a new master password); the public key can't change, or shared vaults would break.",
      security: bearer,
      request: body(Account),
      responses: { 200: json(Account), ...problemResponses },
    }),
    async (c) => {
      const p = requireSession(c);
      const input = c.req.valid("json");
      await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const cur = await tx.selectFrom("vault_accounts").select("public_key").where("user_id", "=", p.userId).executeTakeFirst();
        if (cur && cur.public_key !== input.public_key) throw conflict("key_change", "Your vault's public key can't change: shared vaults are wrapped to it");
        await tx
          .insertInto("vault_accounts")
          .values({ user_id: p.userId, org_id: p.orgId, public_key: input.public_key, private_key_enc: JSON.stringify(input.private_key_enc), kdf: JSON.stringify(input.kdf) })
          .onConflict((oc) => oc.column("user_id").doUpdateSet({ private_key_enc: JSON.stringify(input.private_key_enc), kdf: JSON.stringify(input.kdf), updated_at: new Date() }))
          .execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: cur ? "vault.master_password_changed" : "vault.set_up", target: { type: "user", id: p.userId, display: p.email } });
      });
      return c.json(input, 200);
    },
  );

  app.openapi(
    createRoute({ method: "get", path: "/v1/vault/vaults", tags: ["Passwords"], summary: "Vaults you're a member of", security: bearer, responses: { 200: json(z.object({ data: z.array(VaultOut) })), ...problemResponses } }),
    async (c) => {
      const p = requireSession(c);
      const rows = await c.get("deps").db.tenant(p.orgId, (tx) =>
        tx
          .selectFrom("vault_members as me")
          .innerJoin("vaults", "vaults.id", "me.vault_id")
          .select(["vaults.id", "vaults.kind", "vaults.name_enc", "me.role", "me.wrapped_key"])
          .select((eb) => [
            eb.selectFrom("vault_members").whereRef("vault_members.vault_id", "=", "vaults.id").select((x) => x.fn.countAll<number>().as("n")).as("members"),
            eb.selectFrom("vault_items").whereRef("vault_items.vault_id", "=", "vaults.id").select((x) => x.fn.countAll<number>().as("n")).as("items"),
          ])
          .where("me.user_id", "=", p.userId)
          .orderBy("vaults.created_at")
          .execute(),
      );
      return c.json({ data: rows.map((r) => ({ id: r.id, kind: r.kind, name_enc: r.name_enc as z.infer<typeof Sealed>, role: r.role, wrapped_key: r.wrapped_key, members: Number(r.members ?? 0), items: Number(r.items ?? 0) })) }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/vault/vaults",
      tags: ["Passwords"],
      summary: "Create a vault (its key comes wrapped to your public key)",
      security: bearer,
      request: body(z.object({ kind: z.enum(["personal", "shared"]).default("shared"), name_enc: Sealed, wrapped_key: B64 })),
      responses: { 201: json(z.object({ id: Id })), ...problemResponses },
    }),
    async (c) => {
      const p = requireSession(c);
      const input = c.req.valid("json");
      const id = newId();
      await c.get("deps").db.tenant(p.orgId, async (tx) => {
        if (!(await tx.selectFrom("vault_accounts").select("user_id").where("user_id", "=", p.userId).executeTakeFirst())) throw badRequest("not_set_up", "Set up the password manager first");
        if (input.kind === "personal") {
          const has = await tx.selectFrom("vaults").innerJoin("vault_members", "vault_members.vault_id", "vaults.id").select("vaults.id").where("vaults.kind", "=", "personal").where("vault_members.user_id", "=", p.userId).executeTakeFirst();
          if (has) throw conflict("personal_exists", "You already have a personal vault");
        }
        await tx.insertInto("vaults").values({ id, org_id: p.orgId, kind: input.kind, name_enc: JSON.stringify(input.name_enc), created_by: p.userId }).execute();
        await tx.insertInto("vault_members").values({ vault_id: id, user_id: p.userId, org_id: p.orgId, wrapped_key: input.wrapped_key, role: "owner", added_by: p.userId }).execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "vault.created", target: { type: "vault", id }, details: { kind: input.kind } });
      });
      return c.json({ id }, 201);
    },
  );

  app.openapi(
    createRoute({ method: "get", path: "/v1/vault/vaults/{id}/items", tags: ["Passwords"], summary: "A vault's items (encrypted)", security: bearer, request: { params: z.object({ id: Id }) }, responses: { 200: json(z.object({ data: z.array(ItemOut) })), ...problemResponses } }),
    async (c) => {
      const p = requireSession(c);
      const { id } = c.req.valid("param");
      const rows = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        await membership(tx, id, p.userId);
        return tx.selectFrom("vault_items").leftJoin("users", "users.id", "vault_items.updated_by").select(["vault_items.id", "vault_items.data", "vault_items.updated_at", "users.email"]).where("vault_id", "=", id).orderBy("vault_items.created_at").execute();
      });
      return c.json({ data: rows.map((r) => ({ id: r.id, data: r.data as z.infer<typeof Sealed>, updated_at: iso(r.updated_at), updated_by: r.email ?? null })) }, 200);
    },
  );

  app.openapi(
    createRoute({ method: "post", path: "/v1/vault/vaults/{id}/items", tags: ["Passwords"], summary: "Add an item (encrypted with the vault key)", security: bearer, request: { params: z.object({ id: Id }), ...body(z.object({ data: Sealed })) }, responses: { 201: json(z.object({ id: Id })), ...problemResponses } }),
    async (c) => {
      const p = requireSession(c);
      const { id } = c.req.valid("param");
      const { data } = c.req.valid("json");
      const itemId = newId();
      await c.get("deps").db.tenant(p.orgId, async (tx) => {
        if (!canWrite(await membership(tx, id, p.userId))) throw forbidden("You can view this vault but not change it");
        await tx.insertInto("vault_items").values({ id: itemId, org_id: p.orgId, vault_id: id, data: JSON.stringify(data), created_by: p.userId, updated_by: p.userId }).execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "vault.item_added", target: { type: "vault", id }, details: { item_id: itemId } });
      });
      return c.json({ id: itemId }, 201);
    },
  );

  app.openapi(
    createRoute({ method: "put", path: "/v1/vault/items/{id}", tags: ["Passwords"], summary: "Replace an item", security: bearer, request: { params: z.object({ id: Id }), ...body(z.object({ data: Sealed })) }, responses: { 204: { description: "Saved" }, ...problemResponses } }),
    async (c) => {
      const p = requireSession(c);
      const { id } = c.req.valid("param");
      const { data } = c.req.valid("json");
      await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const it = await tx.selectFrom("vault_items").select("vault_id").where("id", "=", id).executeTakeFirst();
        if (!it) throw notFound("Item");
        if (!canWrite(await membership(tx, it.vault_id, p.userId))) throw forbidden("You can view this vault but not change it");
        await tx.updateTable("vault_items").set({ data: JSON.stringify(data), updated_by: p.userId, updated_at: new Date() }).where("id", "=", id).execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "vault.item_changed", target: { type: "vault", id: it.vault_id }, details: { item_id: id } });
      });
      return c.body(null, 204);
    },
  );

  app.openapi(
    createRoute({ method: "delete", path: "/v1/vault/items/{id}", tags: ["Passwords"], summary: "Delete an item", security: bearer, request: { params: z.object({ id: Id }) }, responses: { 204: { description: "Deleted" }, ...problemResponses } }),
    async (c) => {
      const p = requireSession(c);
      const { id } = c.req.valid("param");
      await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const it = await tx.selectFrom("vault_items").select("vault_id").where("id", "=", id).executeTakeFirst();
        if (!it) throw notFound("Item");
        if (!canWrite(await membership(tx, it.vault_id, p.userId))) throw forbidden("You can view this vault but not change it");
        await tx.deleteFrom("vault_items").where("id", "=", id).execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "vault.item_deleted", target: { type: "vault", id: it.vault_id }, details: { item_id: id } });
      });
      return c.body(null, 204);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/vault/items/{id}/used",
      tags: ["Passwords"],
      summary: "Record that you revealed or copied an item's secret (no contents are sent)",
      security: bearer,
      request: { params: z.object({ id: Id }), ...body(z.object({ action: z.enum(["revealed", "copied_password", "copied_username", "copied_totp"]) })) },
      responses: { 204: { description: "Recorded" }, ...problemResponses },
    }),
    async (c) => {
      const p = requireSession(c);
      const { id } = c.req.valid("param");
      const { action } = c.req.valid("json");
      await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const it = await tx.selectFrom("vault_items").select("vault_id").where("id", "=", id).executeTakeFirst();
        if (!it) throw notFound("Item");
        await membership(tx, it.vault_id, p.userId);
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "vault.item_used", target: { type: "vault", id: it.vault_id }, details: { item_id: id, action } });
      });
      return c.body(null, 204);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/vault/people",
      tags: ["Passwords"],
      summary: "People you can share a vault with (those who've set up the password manager), with their public keys",
      security: bearer,
      responses: { 200: json(z.object({ data: z.array(z.object({ user_id: Id, email: z.string(), name: z.string(), public_key: B64 })) })), ...problemResponses },
    }),
    async (c) => {
      const p = requireSession(c);
      const rows = await c.get("deps").db.tenant(p.orgId, (tx) =>
        tx.selectFrom("vault_accounts").innerJoin("users", "users.id", "vault_accounts.user_id").select(["users.id", "users.email", "users.given_name", "users.family_name", "vault_accounts.public_key"]).where("users.status", "=", "active").orderBy("users.email").execute(),
      );
      return c.json({ data: rows.map((r) => ({ user_id: r.id, email: r.email, name: `${r.given_name} ${r.family_name}`.trim() || r.email, public_key: r.public_key })) }, 200);
    },
  );

  app.openapi(
    createRoute({ method: "get", path: "/v1/vault/vaults/{id}/members", tags: ["Passwords"], summary: "Who has a vault", security: bearer, request: { params: z.object({ id: Id }) }, responses: { 200: json(z.object({ data: z.array(z.object({ user_id: Id, email: z.string(), role: Role })) })), ...problemResponses } }),
    async (c) => {
      const p = requireSession(c);
      const { id } = c.req.valid("param");
      const rows = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        await membership(tx, id, p.userId);
        return tx.selectFrom("vault_members").innerJoin("users", "users.id", "vault_members.user_id").select(["vault_members.user_id", "users.email", "vault_members.role"]).where("vault_id", "=", id).orderBy("users.email").execute();
      });
      return c.json({ data: rows }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "put",
      path: "/v1/vault/vaults/{id}/members/{user_id}",
      tags: ["Passwords"],
      summary: "Share a vault with someone, or change their role (owners only)",
      description: "The vault key comes wrapped (in your browser) to their public key.",
      security: bearer,
      request: { params: z.object({ id: Id, user_id: Id }), ...body(z.object({ role: Role, wrapped_key: B64.optional() })) },
      responses: { 204: { description: "Shared" }, ...problemResponses },
    }),
    async (c) => {
      const p = requireSession(c);
      const { id, user_id } = c.req.valid("param");
      const input = c.req.valid("json");
      await c.get("deps").db.tenant(p.orgId, async (tx) => {
        if ((await membership(tx, id, p.userId)) !== "owner") throw forbidden("Only a vault's owners can share it");
        const v = await tx.selectFrom("vaults").select("kind").where("id", "=", id).executeTakeFirstOrThrow();
        if (v.kind === "personal") throw badRequest("personal_vault", "A personal vault can't be shared: move items to a shared vault");
        const target = await tx.selectFrom("vault_accounts").innerJoin("users", "users.id", "vault_accounts.user_id").select(["users.email", "users.status"]).where("vault_accounts.user_id", "=", user_id).executeTakeFirst();
        if (!target || target.status !== "active") throw badRequest("not_set_up", "They haven't set up the password manager yet");
        const cur = await tx.selectFrom("vault_members").select("role").where("vault_id", "=", id).where("user_id", "=", user_id).executeTakeFirst();
        if (!cur && !input.wrapped_key) throw badRequest("wrapped_key_required", "Sharing needs the vault key wrapped to their public key");
        if (cur?.role === "owner" && input.role !== "owner") {
          const owners = await tx.selectFrom("vault_members").select("user_id").where("vault_id", "=", id).where("role", "=", "owner").execute();
          if (owners.length === 1) throw conflict("last_owner", "A vault needs at least one owner");
        }
        await tx
          .insertInto("vault_members")
          .values({ vault_id: id, user_id, org_id: p.orgId, wrapped_key: input.wrapped_key ?? "", role: input.role, added_by: p.userId })
          .onConflict((oc) => oc.columns(["vault_id", "user_id"]).doUpdateSet({ role: input.role, ...(input.wrapped_key ? { wrapped_key: input.wrapped_key } : {}) }))
          .execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: cur ? "vault.member_changed" : "vault.shared", target: { type: "vault", id }, details: { user_id, email: target.email, role: input.role } });
      });
      return c.body(null, 204);
    },
  );

  app.openapi(
    createRoute({ method: "delete", path: "/v1/vault/vaults/{id}/members/{user_id}", tags: ["Passwords"], summary: "Take someone off a vault (owners; anyone can leave)", security: bearer, request: { params: z.object({ id: Id, user_id: Id }) }, responses: { 204: { description: "Removed" }, ...problemResponses } }),
    async (c) => {
      const p = requireSession(c);
      const { id, user_id } = c.req.valid("param");
      await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const role = await membership(tx, id, p.userId);
        if (user_id !== p.userId && role !== "owner") throw forbidden("Only a vault's owners can remove people");
        const owners = await tx.selectFrom("vault_members").select("user_id").where("vault_id", "=", id).where("role", "=", "owner").execute();
        if (owners.length === 1 && owners[0]!.user_id === user_id) throw conflict("last_owner", "A vault needs at least one owner: add another first, or delete the vault");
        await tx.deleteFrom("vault_members").where("vault_id", "=", id).where("user_id", "=", user_id).execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "vault.unshared", target: { type: "vault", id }, details: { user_id } });
      });
      return c.body(null, 204);
    },
  );

  app.openapi(
    createRoute({ method: "delete", path: "/v1/vault/vaults/{id}", tags: ["Passwords"], summary: "Delete a vault and its items (owners)", security: bearer, request: { params: z.object({ id: Id }) }, responses: { 204: { description: "Deleted" }, ...problemResponses } }),
    async (c) => {
      const p = requireSession(c);
      const { id } = c.req.valid("param");
      await c.get("deps").db.tenant(p.orgId, async (tx) => {
        if ((await membership(tx, id, p.userId)) !== "owner") throw forbidden("Only a vault's owners can delete it");
        await tx.deleteFrom("vaults").where("id", "=", id).execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "vault.deleted", target: { type: "vault", id } });
      });
      return c.body(null, 204);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/vault/overview",
      tags: ["Passwords"],
      summary: "How the organization uses the password manager (counts only: nothing is readable)",
      security: bearer,
      responses: { 200: json(z.object({ people_set_up: z.number().int(), vaults: z.number().int(), shared_vaults: z.number().int(), items: z.number().int() })), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "users:read");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const n = async (t: "vault_accounts" | "vaults" | "vault_items", shared = false) => {
          let q = tx.selectFrom(t).select((eb) => eb.fn.countAll<number>().as("n"));
          if (shared) q = (q as any).where("kind", "=", "shared");
          return Number((await q.executeTakeFirst())?.n ?? 0);
        };
        return { people_set_up: await n("vault_accounts"), vaults: await n("vaults"), shared_vaults: await n("vaults", true), items: await n("vault_items") };
      });
      return c.json(out, 200);
    },
  );
}

/**
 * Offboarding: the person loses every vault; vaults nobody is left in are deleted with their
 * items. A shared vault left without an owner gets one, so it can still be shared and cleaned up:
 * its longest-standing editor, or failing that its longest-standing member.
 */
export async function removeFromVaults(tx: Tx, userId: string) {
  const mine = (await tx.selectFrom("vault_members").select("vault_id").where("user_id", "=", userId).execute()).map((m) => m.vault_id);
  await tx.deleteFrom("vault_members").where("user_id", "=", userId).execute();
  await tx.deleteFrom("vault_accounts").where("user_id", "=", userId).execute();
  const promoted: { vault_id: string; user_id: string }[] = [];
  if (mine.length) {
    const rest = await tx.selectFrom("vault_members").select(["vault_id", "user_id", "role"]).where("vault_id", "in", mine).orderBy("created_at").execute();
    const orphans = mine.filter((v) => !rest.some((m) => m.vault_id === v));
    if (orphans.length) await tx.deleteFrom("vaults").where("id", "in", orphans).execute();
    for (const v of mine) {
      const members = rest.filter((m) => m.vault_id === v);
      if (!members.length || members.some((m) => m.role === "owner")) continue;
      const heir = members.find((m) => m.role === "editor") ?? members[0]!;
      await tx.updateTable("vault_members").set({ role: "owner" }).where("vault_id", "=", v).where("user_id", "=", heir.user_id).execute();
      promoted.push({ vault_id: v, user_id: heir.user_id });
    }
  }
  return { removed: mine.length, promoted };
}
