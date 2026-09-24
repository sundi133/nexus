import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // The shared API client ships as TypeScript source.
  transpilePackages: ["@nexus/api-client"],
  poweredByHeader: false,
};

export default nextConfig;
