// Prints the OpenAPI document without needing a database: the spec is derived from route schemas.
import { createApp } from "../app.js";
import { loadConfig } from "../config.js";
import type { Deps } from "../context.js";

const app = createApp({ cfg: loadConfig({ NEXUS_ENV: "test" }) } as Deps);
const res = await app.request("/v1/openapi.json");
process.stdout.write(JSON.stringify(await res.json(), null, 2) + "\n");
