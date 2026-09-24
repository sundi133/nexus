import { defineConfig } from "vitest/config";

export default defineConfig({
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
