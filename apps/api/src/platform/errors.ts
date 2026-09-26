import type { Context } from "hono";
import type { ContentfulStatusCode } from "hono/utils/http-status";

/** An error rendered as RFC 9457 application/problem+json with a stable machine-readable code. */
export class ApiError extends Error {
  constructor(
    readonly status: ContentfulStatusCode,
    readonly code: string,
    message: string,
    readonly extra: Record<string, unknown> = {},
  ) {
    super(message);
  }
}

export const badRequest = (code: string, msg: string, extra?: Record<string, unknown>) =>
  new ApiError(400, code, msg, extra);
export const unauthorized = (msg = "Authentication required") => new ApiError(401, "unauthenticated", msg);
export const forbidden = (msg = "You don't have permission to do that") => new ApiError(403, "forbidden", msg);
export const notFound = (what = "Resource") => new ApiError(404, "not_found", `${what} not found`);
export const conflict = (code: string, msg: string) => new ApiError(409, code, msg);

export function problem(c: Context, err: ApiError) {
  return c.body(
    JSON.stringify({ type: "about:blank", status: err.status, code: err.code, title: err.message, ...err.extra }),
    err.status,
    { "Content-Type": "application/problem+json" },
  );
}
