import { readFileSync } from "node:fs";
import { parseSealKeys, type SealKeys } from "./platform/seal.js";
import { fileURLToPath } from "node:url";

export type Config = {
  env: "dev" | "test" | "prod";
  port: number;
  databaseUrl: string; // runtime role: RLS always enforced
  databaseOwnerUrl: string; // migration role
  publicUrl: string; // web origin (links, CORS)
  apiPublicUrl: string; // how phones reach this API (a LAN IP in dev, the API domain in prod)
  trustProxy: boolean; // honor X-Forwarded-For (only behind our own BFF / load balancer)
  sealKey: Buffer; // 32 bytes; KMS-backed in prod (key id 1)
  sealKeys: SealKeys; // rotation: current first (NEXUS_SEAL_KEYS="2:…,1:…"); defaults to [1: sealKey]
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
  // On-call paging endpoints (overridable only for tests).
  pagerdutyEventsUrl: string;
  opsgenieBase: { us: string; eu: string };
  // Allow outbound calls (SCIM, webhooks) to private/loopback addresses. Dev and test only.
  allowPrivateOutbound: boolean;
  // Directory (LDAP/AD) hosts on private networks: self-hosted deployments next to their AD set this.
  allowPrivateDirectory: boolean;
  // Have I Been Pwned range API for breached-password checks ("" = off).
  hibpBase: string;
  // Push delivery. Unset = pushes are recorded/logged only (development).
  apns: { teamId: string; keyId: string; bundleId: string; privateKey: string; production: boolean } | null;
  fcmServiceAccount: string; // JSON
  // Which parts this process runs: HTTP API, background worker, or both (small deployments, dev).
  role: "all" | "api" | "worker";
  // Bearer token Prometheus uses for /metrics ("" = no token: dev only).
  metricsToken: string;
  logFormat: "json" | "pretty";
};

/**
 * Production refuses to start on unsafe or development settings, listing
 * every problem at once so a deploy can be fixed in one go.
 */
export function validateProd(cfg: Config, env = process.env): string[] {
  if (cfg.env !== "prod") return [];
  const problems: string[] = [];
  const need = ["NEXUS_DATABASE_URL", "NEXUS_DATABASE_OWNER_URL", "NEXUS_PUBLIC_URL", "NEXUS_API_PUBLIC_URL", "NEXUS_SMTP_URL", "NEXUS_MAIL_FROM", "NEXUS_METRICS_TOKEN"];
  for (const k of need) if (!env[k]) problems.push(`${k} is required`);
  if (!env.NEXUS_SEAL_KEY && !env.NEXUS_SEAL_KEYS) problems.push("NEXUS_SEAL_KEY (or NEXUS_SEAL_KEYS for rotation) is required");
  for (const [k, v] of [["NEXUS_PUBLIC_URL", cfg.publicUrl], ["NEXUS_API_PUBLIC_URL", cfg.apiPublicUrl]] as const) {
    if (!v.startsWith("https://")) problems.push(`${k} must be https (got ${v})`);
  }
  if (/nexus_(app|owner):nexus_(app|owner)@/.test(cfg.databaseUrl + cfg.databaseOwnerUrl)) problems.push("Database URLs still use the development passwords");
  if (cfg.allowPrivateOutbound) problems.push("NEXUS_ALLOW_PRIVATE_OUTBOUND must not be enabled in production");
  if (!cfg.hibpBase) problems.push("Breached-password checks are off (NEXUS_HIBP_BASE is empty)");
  if (!["all", "api", "worker"].includes(cfg.role)) problems.push(`NEXUS_ROLE must be all, api or worker (got ${cfg.role})`);
  if (cfg.metricsToken && cfg.metricsToken.length < 24) problems.push("NEXUS_METRICS_TOKEN must be at least 24 characters");
  return problems;
}

export function loadConfig(env = process.env): Config {
  const mode = (env.NEXUS_ENV ?? "dev") as Config["env"];
  let sealKey: Buffer;
  const rotation = env.NEXUS_SEAL_KEYS ? parseSealKeys(env.NEXUS_SEAL_KEYS) : null;
  if (env.NEXUS_SEAL_KEY) {
    sealKey = Buffer.from(env.NEXUS_SEAL_KEY, "base64");
    if (sealKey.length !== 32) throw new Error("NEXUS_SEAL_KEY must be 32 bytes, base64-encoded");
  } else if (rotation) {
    sealKey = (rotation.find((k) => k.id === 1) ?? rotation[0]!).key;
  } else if (mode === "prod") {
    throw new Error("NEXUS_SEAL_KEY (or NEXUS_SEAL_KEYS) is required in prod");
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
    sealKeys: rotation ?? [{ id: 1, key: sealKey }],
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
    pagerdutyEventsUrl: env.NEXUS_PAGERDUTY_EVENTS_URL ?? "https://events.pagerduty.com/v2/enqueue",
    opsgenieBase: { us: env.NEXUS_OPSGENIE_BASE ?? "https://api.opsgenie.com", eu: env.NEXUS_OPSGENIE_EU_BASE ?? "https://api.eu.opsgenie.com" },
    allowPrivateOutbound: mode !== "prod" && env.NEXUS_ALLOW_PRIVATE_OUTBOUND !== "false",
    allowPrivateDirectory: env.NEXUS_ALLOW_PRIVATE_DIRECTORY ? env.NEXUS_ALLOW_PRIVATE_DIRECTORY === "true" : mode !== "prod",
    hibpBase: env.NEXUS_HIBP_BASE ?? (mode === "test" ? "" : "https://api.pwnedpasswords.com"),
    apns:
      env.NEXUS_APNS_KEY && env.NEXUS_APNS_KEY_ID && env.NEXUS_APNS_TEAM_ID
        ? {
            teamId: env.NEXUS_APNS_TEAM_ID,
            keyId: env.NEXUS_APNS_KEY_ID,
            bundleId: env.NEXUS_APNS_BUNDLE_ID ?? "ai.votal.nexus",
            // Accept the .p8 contents or base64 of it (easier in env files).
            privateKey: env.NEXUS_APNS_KEY.includes("BEGIN") ? env.NEXUS_APNS_KEY : Buffer.from(env.NEXUS_APNS_KEY, "base64").toString(),
            production: (env.NEXUS_APNS_ENV ?? (mode === "prod" ? "production" : "sandbox")) === "production",
          }
        : null,
    fcmServiceAccount: env.NEXUS_FCM_SERVICE_ACCOUNT ?? "",
    role: (env.NEXUS_ROLE ?? "all") as Config["role"],
    metricsToken: env.NEXUS_METRICS_TOKEN ?? "",
    logFormat: (env.NEXUS_LOG_FORMAT ?? (mode === "prod" ? "json" : "pretty")) as Config["logFormat"],
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
