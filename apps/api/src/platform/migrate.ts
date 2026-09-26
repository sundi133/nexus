import { createHash } from "node:crypto";
import { readdirSync } from "node:fs";
import { readdir, readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import pg from "pg";

const MIGRATIONS_DIR = fileURLToPath(new URL("../../migrations/", import.meta.url));

/** The newest migration this build ships (readiness compares it with the database). */
export const LATEST_MIGRATION = readdirSync(MIGRATIONS_DIR).filter((f) => f.endsWith(".sql")).sort().at(-1) ?? null;

// Line endings normalised, so a Windows checkout doesn't look like an edit.
const checksum = (body: string) => createHash("sha256").update(body.replace(/\r\n/g, "\n")).digest("hex");

/**
 * Applies pending SQL migrations in filename order, each in its own
 * transaction, as the owner role. Applied migrations are immutable: if one
 * was edited afterwards, the change would never reach existing databases, so
 * this refuses to continue and asks for a new migration instead.
 */
export async function migrate(ownerUrl: string, log: (msg: string) => void = () => {}) {
  const client = new pg.Client({ connectionString: ownerUrl });
  await client.connect();
  try {
    await client.query(`CREATE TABLE IF NOT EXISTS schema_migrations (
      version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`);
    // Serialize concurrent migrators (e.g. several API replicas starting at once).
    await client.query("SELECT pg_advisory_lock(727274)");
    await client.query("ALTER TABLE schema_migrations ADD COLUMN IF NOT EXISTS checksum text");
    const applied = new Map(
      (await client.query<{ version: string; checksum: string | null }>("SELECT version, checksum FROM schema_migrations")).rows.map((r) => [r.version, r.checksum]),
    );
    const files = (await readdir(MIGRATIONS_DIR)).filter((f) => f.endsWith(".sql")).sort();
    for (const file of files) {
      const body = await readFile(MIGRATIONS_DIR + file, "utf8");
      const sum = checksum(body);
      if (applied.has(file)) {
        const recorded = applied.get(file);
        if (recorded === null) {
          await client.query("UPDATE schema_migrations SET checksum = $2 WHERE version = $1", [file, sum]); // recorded before checksums existed
        } else if (recorded !== sum) {
          throw new Error(`migration ${file} was changed after it was applied to this database; put the change in a new migration instead`);
        }
        continue;
      }
      await client.query("BEGIN");
      try {
        await client.query(body);
        await client.query("INSERT INTO schema_migrations (version, checksum) VALUES ($1, $2)", [file, sum]);
        await client.query("COMMIT");
        log(`applied ${file}`);
      } catch (err) {
        await client.query("ROLLBACK");
        throw new Error(`migration ${file} failed: ${(err as Error).message}`);
      }
    }
  } finally {
    await client.query("SELECT pg_advisory_unlock(727274)").catch(() => {});
    await client.end();
  }
}
