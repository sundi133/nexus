import { fileURLToPath } from "node:url";
import type { NextConfig } from "next";

// Security headers for production builds (dev keeps Next's HMR working).
const common = [
  { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains; preload" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=(), payment=(), usb=()" },
];
const csp = (formAction: string) =>
  [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline'", // Next inlines its bootstrap; move to nonces with the edge runtime
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self' data:",
    "connect-src 'self' http://127.0.0.1:47823", // browser device checks talk to the local Nexus agent
    "frame-ancestors 'none'",
    "base-uri 'self'",
    `form-action ${formAction}`,
    "object-src 'none'",
  ].join("; ");

const nextConfig: NextConfig = {
  // The shared API client ships as TypeScript source.
  transpilePackages: ["@nexus/api-client"],
  poweredByHeader: false,
  output: "standalone", // small production image (see deploy/)
  outputFileTracingRoot: fileURLToPath(new URL("../../", import.meta.url)), // monorepo: trace workspace packages too
  async headers() {
    if (process.env.NODE_ENV !== "production") return [];
    return [
      { source: "/((?!saml/).*)", headers: [...common, { key: "X-Frame-Options", value: "DENY" }, { key: "Content-Security-Policy", value: csp("'self'") }] },
      // SAML hands the browser a form that posts the signed response to the app's ACS URL.
      { source: "/saml/:path*", headers: [...common, { key: "X-Frame-Options", value: "DENY" }, { key: "Content-Security-Policy", value: csp("'self' https:") }] },
    ];
  },
};

export default nextConfig;
