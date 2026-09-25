// Bundles the CLI into one ESM file. Some dependencies are CommonJS and call require(),
// which an ESM bundle doesn't have: the banner provides it.
import { build } from "esbuild";

await build({
  entryPoints: ["src/main.ts"],
  bundle: true,
  platform: "node",
  target: "node22",
  format: "esm",
  outfile: "dist/nexus.mjs",
  banner: { js: '#!/usr/bin/env node\nimport { createRequire as __nexusRequire } from "node:module";\nconst require = __nexusRequire(import.meta.url);' },
  legalComments: "none",
});
