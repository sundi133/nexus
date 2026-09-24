/**
 * Typed client for the Nexus /v1 API, generated from the OpenAPI contract.
 * Used unchanged by the web console (through its BFF) and Nexus Mobile.
 */
import createFetchClient, { type Middleware } from "openapi-fetch";
import type { components, paths } from "./schema.js";

export type { paths, components };
export type Schemas = components["schemas"];
export type User = Schemas["User"];
export type UserDetail = Schemas["UserDetail"];
export type Group = Schemas["Group"];
export type AuditEvent = Schemas["AuditEvent"];
export type Notification = Schemas["Notification"];
export type Overview = Schemas["Overview"];
export type Me = Schemas["Me"];
export type Session = Schemas["Session"];
export type Factor = Schemas["Factor"];
export type Role = Schemas["Role"];
export type Permission = Schemas["Permission"];
export type Problem = Schemas["Problem"] & { errors?: { path: string; message: string }[] };

/** Thrown for any non-2xx response; carries the RFC 9457 problem body. */
export class ApiProblem extends Error {
  constructor(
    readonly status: number,
    readonly problem: Problem,
  ) {
    super(problem.title);
  }
  get code() {
    return this.problem.code;
  }
}

export type ClientOptions = {
  baseUrl: string;
  /** Returns the bearer token (mobile/CLI). The web client omits this; its BFF attaches the token. */
  getToken?: () => string | null | undefined | Promise<string | null | undefined>;
  /** Identifies the client for telemetry and minimum-version enforcement, e.g. "ios/1.4.2". */
  clientId?: string;
  fetch?: typeof fetch;
};

export function createClient(opts: ClientOptions) {
  const client = createFetchClient<paths>({ baseUrl: opts.baseUrl, fetch: opts.fetch });
  const auth: Middleware = {
    async onRequest({ request }) {
      const token = await opts.getToken?.();
      if (token) request.headers.set("Authorization", `Bearer ${token}`);
      if (opts.clientId) request.headers.set("Nexus-Client", opts.clientId);
      return request;
    },
  };
  client.use(auth);
  return client;
}

export type NexusClient = ReturnType<typeof createClient>;

/** Unwraps an openapi-fetch result, throwing ApiProblem on error. */
export async function unwrap<T>(p: Promise<{ data?: T; error?: unknown; response: Response }>): Promise<T> {
  const { data, error, response } = await p;
  if (!response.ok) {
    // A proxy or crash can answer with an empty or non-JSON body: still give callers a message.
    const problem =
      error && typeof error === "object" && "title" in error
        ? (error as Problem)
        : { type: "about:blank", status: response.status, code: "http_error", title: `Something went wrong (${response.status}${response.statusText ? ` ${response.statusText}` : ""}). Please try again.` };
    throw new ApiProblem(response.status, problem);
  }
  return data as T;
}

/** Events on GET /v1/me/stream. Payloads carry IDs only; refetch details via the REST API. */
export type StreamEvent =
  | { event: "ready"; data: { session_id: string } }
  | { event: "notification"; data: { id: string; op: "insert" | "update" } }
  | { event: "challenge"; data: { id: string; status: string } }
  | { event: "ping"; data: Record<string, never> };
