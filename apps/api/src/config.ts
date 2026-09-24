export type Config = {
  env: "dev" | "test" | "prod";
  port: number;
  databaseUrl: string; // runtime role: RLS always enforced
  databaseOwnerUrl: string; // migration role
  publicUrl: string; // web origin (links, CORS)
  trustProxy: boolean; // honor X-Forwarded-For (only behind our own BFF / load balancer)
  sealKey: Buffer; // 32 bytes; KMS-backed in prod
  rpId: string; // WebAuthn relying party ID (the web origin's host)
  rpName: string;
  smtpUrl: string; // Mailpit locally; a real provider (SES, Postmark) in prod
  mailFrom: string;
  sessionTtlMs: number;
  pendingMfaTtlMs: number;
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
    trustProxy: (env.NEXUS_TRUST_PROXY ?? (mode === "prod" ? "false" : "true")) === "true",
    sealKey,
    rpId: env.NEXUS_RP_ID ?? new URL(env.NEXUS_PUBLIC_URL ?? "http://localhost:3100").hostname,
    rpName: "Votal Nexus",
    smtpUrl: env.NEXUS_SMTP_URL ?? "smtp://localhost:51025",
    mailFrom: env.NEXUS_MAIL_FROM ?? "Votal Nexus <no-reply@nexus.local>",
    sessionTtlMs: 12 * 60 * 60 * 1000,
    pendingMfaTtlMs: 5 * 60 * 1000,
  };
}
