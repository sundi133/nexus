// Runs Nexus's connectors against your real tenants and writes a redacted report to send back.
//   pnpm --filter @nexus/api live-check [--page] [--send-events] [--only=entra_directory,intune] [--out=FILE]
// Credentials come from live-check.env at the repository root (see docs/LIVE-CHECK.md), or the environment.
// In the production image: docker run --rm --env-file live-check.env votal/nexus-api:local node dist/cli/live-check.js --out=- > report.json
import { writeFileSync } from "node:fs";
import { loadConfig } from "../config.js";
import { CHECKS, runLiveCheck } from "../livecheck/checks.js";
import { installOutboundGuard } from "../platform/outbound.js";

const arg = (name: string) => process.argv.find((a) => a.startsWith(`--${name}=`))?.slice(name.length + 3);
if (process.argv.includes("--help")) {
  console.log(`nexus live-check [--page] [--send-events] [--only=${CHECKS.map((c) => c.name).join(",")}] [--out=FILE]`);
  process.exit(0);
}
const out = process.argv.find((a) => a.startsWith("--out="))?.slice(6);
const say = out === "-" ? (l: string) => console.error(l) : (l: string) => console.log(l); // --out=-: the report on stdout
const env = process.env;
const allowPrivate = env.LIVE_ALLOW_PRIVATE === "true";
// Production rules: no private or internal addresses, except a directory when you say so.
const cfg = { ...loadConfig({ ...env, NEXUS_ENV: "dev" }), allowPrivateOutbound: allowPrivate, allowPrivateDirectory: allowPrivate || env.LIVE_ALLOW_PRIVATE_DIRECTORY === "true" };
installOutboundGuard(allowPrivate || cfg.allowPrivateDirectory);

const only = arg("only")?.split(",").map((s) => s.trim()).filter(Boolean) ?? null;
const unknown = only?.filter((o) => !CHECKS.some((c) => c.name === o)) ?? [];
if (unknown.length) {
  console.error(`unknown check: ${unknown.join(", ")}`);
  process.exit(2);
}
say("Votal Nexus live check (read-only unless --page or --send-events)\n");
const report = await runLiveCheck(env, cfg, { page: process.argv.includes("--page"), sendEvents: process.argv.includes("--send-events"), only, allowPrivate }, say);
const file = out ?? `live-check-${report.ran_at.slice(0, 19).replace(/[:T]/g, "-")}.json`;
if (file === "-") process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
else writeFileSync(file, `${JSON.stringify(report, null, 2)}\n`);
const { ok, warn, fail, skipped } = report.summary;
if (!ok && !warn && !fail) say("Nothing ran: put credentials in live-check.env at the repository root (see docs/LIVE-CHECK.md).");
say(`\n${ok} ok, ${warn} with findings, ${fail} failed, ${skipped} not configured or not run.`);
say(`Report: ${file === "-" ? "standard output" : file}. Emails, IDs, DNs and secrets are hashed or removed; read it before you send it.`);
process.exit(fail ? 1 : 0);
