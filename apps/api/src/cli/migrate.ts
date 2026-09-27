import { loadConfig } from "../config.js";
import { migrate } from "../platform/migrate.js";

const cfg = loadConfig();
await migrate(cfg.databaseOwnerUrl, (m) => console.log(m));
console.log("migrations up to date");
