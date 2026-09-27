import { badRequest } from "./errors.js";

/**
 * Keyset pagination over UUIDv7 primary keys (newest first). The cursor is the
 * last ID of the previous page, base64url-encoded so clients treat it as opaque.
 */
export function decodeCursor(cursor: string | undefined): string | null {
  if (!cursor) return null;
  const id = Buffer.from(cursor, "base64url").toString("utf8");
  if (!/^[0-9a-f-]{36}$/.test(id)) throw badRequest("invalid_cursor", "Invalid pagination cursor");
  return id;
}

export function pageOf<T extends { id: string }>(rows: T[], limit: number) {
  const more = rows.length > limit;
  const data = more ? rows.slice(0, limit) : rows;
  const last = data[data.length - 1];
  return { data, next_cursor: more && last ? Buffer.from(last.id).toString("base64url") : null };
}
