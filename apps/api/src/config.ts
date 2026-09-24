import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

export type Config = {
  env: "dev" | "test" | "prod";
  port: number;
  databaseUrl: string; // runtime role: RLS always enforced
  databaseOwnerUrl: string; // migration role
  publicUrl: string; // web origin (links, CORS)
  apiPublicUrl: string; // how phones reach this API (a LAN IP in dev, the API domain in prod)
  trustProxy: boolean; // honor X-Forwarded-For (only behind our own BFF / load balancer)
  sealKey: Buffer; // 32 bytes; KMS-backed in prod
  rpId: string; // WebAuthn relying party ID (the web origin's host)
  rpName: string;
  smtpUrl: string; // Mailpit locally; a real provider (SES, Postmark) in prod
  mailFrom: string;
  sessionTtlMs: number;
  pendingMfaTtlMs: number;
  // Signed agent releases (DEV-07): <dir>/<version>/release.json + binaries. A CDN origin in prod.
  agentReleasesDir: string;
  // Base64 Ed25519 release public keys, comma-separated. Dev reads <agent/dist>/release.pub when unset.
  agentReleaseKeys: string;
  // Directory providers (overridable only for tests / sovereign clouds).
  googleTokenUrl: string;
  googleAdminBase: string;
  entraLoginBase: string;
  graphBase: string;
};

export function loadConfig(env = process.env): Config {
  const mode = (env.NEXUS_ENV ?? "dev") as Config["env"];
  let sealKey: Buffer;
  if (env.NEXUS_SEAL_KEY) {
    sealKey = Buffer.from(env.NEXUS_SEAL_KEY, "base64");
    if (sealKey.length !== 32) throw new Error("NEXUS_SEAL_KEY must be 32 bytes, base64-encoded");
  } else if (mode === "prod") {
    throw new Error("NEXUS_SEAL_KEY is required in prod");
  } else {
    // Fixed dev key so local data survives restarts. Never used in prod.
    sealKey = Buffer.from("nexus-dev-seal-key-do-not-use!!!");
  }
  return {
    env: mode,
    port: Number(env.NEXUS_PORT ?? 8080),
    databaseUrl: env.NEXUS_DATABASE_URL ?? "postgres://nexus_app:nexus_app@localhost:55432/nexus",
    databaseOwnerUrl:
      env.NEXUS_DATABASE_OWNER_URL ?? "postgres://nexus_owner:nexus_owner@localhost:55432/nexus",
    publicUrl: env.NEXUS_PUBLIC_URL ?? "http://localhost:3100",
    apiPublicUrl: env.NEXUS_API_PUBLIC_URL ?? "http://localhost:8080",
    trustProxy: (env.NEXUS_TRUST_PROXY ?? (mode === "prod" ? "false" : "true")) === "true",
    sealKey,
    rpId: env.NEXUS_RP_ID ?? new URL(env.NEXUS_PUBLIC_URL ?? "http://localhost:3100").hostname,
    rpName: "Votal Nexus",
    smtpUrl: env.NEXUS_SMTP_URL ?? "smtp://localhost:51025",
    mailFrom: env.NEXUS_MAIL_FROM ?? "Votal Nexus <no-reply@nexus.local>",
    sessionTtlMs: 12 * 60 * 60 * 1000,
    pendingMfaTtlMs: 5 * 60 * 1000,
    agentReleasesDir: env.NEXUS_AGENT_RELEASES_DIR ?? fileURLToPath(new URL("../../../agent/dist/releases", import.meta.url)),
    agentReleaseKeys: env.NEXUS_AGENT_RELEASE_KEYS ?? (mode === "prod" ? "" : devReleaseKey()),
    googleTokenUrl: env.NEXUS_GOOGLE_TOKEN_URL ?? "https://oauth2.googleapis.com/token",
    googleAdminBase: env.NEXUS_GOOGLE_ADMIN_BASE ?? "https://admin.googleapis.com",
    entraLoginBase: env.NEXUS_ENTRA_LOGIN_BASE ?? "https://login.microsoftonline.com",
    graphBase: env.NEXUS_GRAPH_BASE ?? "https://graph.microsoft.com",
  };
}

/** The dev release key made by `pnpm agent:release` (agent/dist/release.pub), if any. */
function devReleaseKey() {
  try {
    return readFileSync(fileURLToPath(new URL("../../../agent/dist/release.pub", import.meta.url)), "utf8").trim();
  } catch {
    return "";
  }
}
