import { readdir, readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import pg from "pg";

const MIGRATIONS_DIR = fileURLToPath(new URL("../../migrations/", import.meta.url));

/** Applies pending SQL migrations in filename order, each in its own transaction, as the owner role. */
export async function migrate(ownerUrl: string, log: (msg: string) => void = () => {}) {
  const client = new pg.Client({ connectionString: ownerUrl });
  await client.connect();
  try {
    await client.query(`CREATE TABLE IF NOT EXISTS schema_migrations (
      version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`);
    // Serialize concurrent migrators (e.g. several API replicas starting at once).
    await client.query("SELECT pg_advisory_lock(727274)");
    const applied = new Set(
      (await client.query<{ version: string }>("SELECT version FROM schema_migrations")).rows.map((r) => r.version),
    );
    const files = (await readdir(MIGRATIONS_DIR)).filter((f) => f.endsWith(".sql")).sort();
    for (const file of files) {
      if (applied.has(file)) continue;
      const body = await readFile(MIGRATIONS_DIR + file, "utf8");
      await client.query("BEGIN");
      try {
        await client.query(body);
        await client.query("INSERT INTO schema_migrations (version) VALUES ($1)", [file]);
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
