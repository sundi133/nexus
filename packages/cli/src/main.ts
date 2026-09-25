import { mkdir, readFile, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname } from "node:path";
import { createInterface } from "node:readline/promises";
import { run } from "./cli.js";

const code = await run(process.argv.slice(2), {
  env: process.env,
  out: (s) => process.stdout.write(s),
  err: (s) => process.stderr.write(s),
  readFile: (p) => readFile(p, "utf8"),
  writeFile: async (p, data, mode) => {
    await mkdir(dirname(p), { recursive: true, mode: 0o700 });
    await writeFile(p, data, { mode: mode ?? 0o644 });
  },
  confirm: process.stdin.isTTY
    ? async (q) => {
        const rl = createInterface({ input: process.stdin, output: process.stdout });
        const a = await rl.question(`${q} Type "yes" to continue: `);
        rl.close();
        return a.trim().toLowerCase() === "yes";
      }
    : undefined,
  home: homedir(),
});
process.exit(code);
