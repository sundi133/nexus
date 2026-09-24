import { NextResponse, type NextRequest } from "next/server";

const PUBLIC = ["/login", "/signup", "/invite", "/sso/error"];

/** Cheap presence check only: real authentication happens at the API on every call. */
export function proxy(req: NextRequest) {
  const has = req.cookies.has("nexus_session");
  const isPublic = PUBLIC.some((p) => req.nextUrl.pathname.startsWith(p));
  if (!has && !isPublic) {
    const url = new URL("/login", req.url);
    if (req.nextUrl.pathname !== "/") url.searchParams.set("next", req.nextUrl.pathname + req.nextUrl.search);
    return NextResponse.redirect(url);
  }
  return NextResponse.next();
}

export const config = {
  matcher: ["/((?!bff|oidc|_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|ico)$).*)"],
};
