// Re-encrypt every sealed secret with the current seal key (first in NEXUS_SEAL_KEYS).
//   pnpm --filter @nexus/api reseal [--dry-run] [--org=<uuid>]
import { loadConfig } from "../config.js";
import { reseal } from "../platform/reseal.js";
import { Sealer } from "../platform/seal.js";

const cfg = loadConfig();
const dryRun = process.argv.includes("--dry-run");
const orgArg = process.argv.find((a) => a.startsWith("--org="))?.slice(6); // one tenant at a time, if you like
const sealer = new Sealer(cfg.sealKeys);
const report = await reseal(cfg.databaseOwnerUrl, sealer, { dryRun, orgId: orgArg });
for (const r of report) {
  console.log(`${r.table.padEnd(24)} checked ${String(r.checked).padStart(5)}  ${dryRun ? "would reseal" : "resealed"} ${String(r.resealed).padStart(5)}${r.failed.length ? `  UNREADABLE ${r.failed.length}: ${r.failed.slice(0, 5).join(", ")}` : ""}`);
}
const failed = report.reduce((n, r) => n + r.failed.length, 0);
console.log(failed ? `\n${failed} secret(s) couldn't be opened with the configured keys: keep the old key until they're resolved.` : `\nAll secrets are sealed with key ${sealer.currentId}${dryRun ? " after a real run" : ""}.`);
process.exit(failed ? 1 : 0);
