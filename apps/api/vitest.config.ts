import { defineConfig } from "vitest/config";

export default defineConfig({
  // Workspace packages export their TypeScript source under "development" (production uses their build).
  resolve: { conditions: ["development"] },
  ssr: { resolve: { conditions: ["development"], externalConditions: ["development"] } },
  test: {
    include: ["test/**/*.test.ts", "src/**/*.test.ts"],
    testTimeout: 20_000,
    hookTimeout: 30_000,
    fileParallelism: false,
    env: {
      NEXUS_ENV: "test",
      NEXUS_DATABASE_URL: "postgres://nexus_app:nexus_app@localhost:55432/nexus_test",
      NEXUS_DATABASE_OWNER_URL: "postgres://nexus_owner:nexus_owner@localhost:55432/nexus_test",
    },
  },
});
