import type { OpenAPIHono } from "@hono/zod-openapi";
import type { Config } from "./config.js";
import type { Db } from "./platform/db.js";
import type { Sealer } from "./platform/seal.js";
import type { Realtime } from "./platform/realtime.js";
import type { Mailer } from "./platform/mailer.js";
import type { PushSender } from "./platform/push.js";
import type { Role } from "./rbac.js";
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
  roles: Role[];
};

export type RequestMeta = { ip: string; userAgent: string; requestId: string };

export type Deps = { cfg: Config; db: Db; sealer: Sealer; realtime: Realtime; mailer: Mailer; push: PushSender };

export type Env = {
  Variables: {
    deps: Deps;
    meta: RequestMeta;
    principal?: Principal;
  };
};

export type App = OpenAPIHono<Env>;
