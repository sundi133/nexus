import type { OpenAPIHono } from "@hono/zod-openapi";
import type { Config } from "./config.js";
import type { Db } from "./platform/db.js";
import type { Sealer } from "./platform/seal.js";
import type { Realtime } from "./platform/realtime.js";
import type { Mailer } from "./platform/mailer.js";
import type { PushSender } from "./platform/push.js";
import type { Permission, Role } from "./rbac.js";
import type { SessionState } from "./platform/db-types.js";

/** The authenticated caller. Every client (web BFF, mobile, CLI) resolves to one of these. */
export type Principal = {
  orgId: string;
  userId: string;
  email: string; // for audit display
  sessionId: string;
  sessionState: SessionState;
  client: string;
  mfaAt: Date | null;
  /** How the session last proved MFA. */
  mfaMethod?: "totp" | "push" | "webauthn" | "recovery_code" | null;
  /** The org requires owners to step up with a passkey (RBAC-04). */
  ownerPasskeyRequired?: boolean;
  roles: Role[];
  /** Set when the caller is an API key: its scopes replace roles, and it can't use personal (/v1/me) endpoints. */
  apiKey?: { id: string; name: string; scopes: ReadonlySet<Permission> };
};

export type RequestMeta = { ip: string; userAgent: string; requestId: string };

export type Deps = {
  cfg: Config;
  db: Db;
  sealer: Sealer;
  realtime: Realtime;
  mailer: Mailer;
  push: PushSender;
  /** TXT lookups for domain verification (injectable for tests). Defaults to the system resolver. */
  resolveTxt?: (name: string) => Promise<string[][]>;
};

export type Env = {
  Variables: {
    deps: Deps;
    meta: RequestMeta;
    principal?: Principal;
  };
};

export type App = OpenAPIHono<Env>;
