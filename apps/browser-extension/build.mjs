// Builds the extension into dist/ (load it unpacked from there) and packs dist.zip.
import { build } from "esbuild";
import { cpSync, mkdirSync, readdirSync, rmSync } from "node:fs";
import { execFileSync } from "node:child_process";

rmSync("dist", { recursive: true, force: true });
mkdirSync("dist");
const common = { bundle: true, conditions: ["development"], // workspace packages bundle from source
  target: "chrome116", minify: false, sourcemap: false, logLevel: "warning", legalComments: "none" };
await build({ ...common, entryPoints: ["src/background.ts"], outfile: "dist/background.js", format: "esm" });
for (const name of ["content", "saas", "interstitial", "popup"]) {
  await build({ ...common, entryPoints: [`src/${name}.ts`], outfile: `dist/${name}.js`, format: "iife" });
}
for (const f of readdirSync("static")) cpSync(`static/${f}`, `dist/${f}`);
rmSync("dist.zip", { force: true });
execFileSync("zip", ["-qr", "../dist.zip", "."], { cwd: "dist" });
console.log("built dist/ and dist.zip");
