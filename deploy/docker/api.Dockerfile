# Votal Nexus API (and background worker: same image, NEXUS_ROLE=worker).
#   docker build -f deploy/docker/api.Dockerfile -t votal/nexus-api .
FROM node:24-bookworm-slim AS base
RUN corepack enable
WORKDIR /repo

FROM base AS build
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.base.json ./
COPY apps/api/package.json apps/api/
RUN pnpm install --frozen-lockfile --filter @nexus/api...
COPY apps/api apps/api
RUN pnpm --filter @nexus/api build \
 && pnpm --filter @nexus/api deploy --prod /out \
 && cp -r apps/api/dist apps/api/migrations /out/

FROM node:24-bookworm-slim
ENV NODE_ENV=production NEXUS_ENV=prod NEXUS_PORT=8080
WORKDIR /app
COPY --from=build --chown=node:node /out ./
USER node
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s CMD node -e "fetch('http://127.0.0.1:'+(process.env.NEXUS_PORT||8080)+'/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
# Migrations run as a separate step before a rollout: node dist/cli/migrate.js
CMD ["node", "--disable-warning=ExperimentalWarning", "dist/main.js"]
