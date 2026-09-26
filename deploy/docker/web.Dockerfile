# Votal Nexus console (Next.js standalone server with the BFF).
#   docker build -f deploy/docker/web.Dockerfile -t votal/nexus-web .
FROM node:24-bookworm-slim AS base
RUN corepack enable
WORKDIR /repo

FROM base AS build
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.base.json ./
COPY apps/web/package.json apps/web/
COPY packages/api-client/package.json packages/api-client/
RUN pnpm install --frozen-lockfile --filter @nexus/web...
COPY packages/api-client packages/api-client
COPY apps/web apps/web
ENV NEXT_TELEMETRY_DISABLED=1
RUN pnpm --filter @nexus/web build

FROM node:24-bookworm-slim
ENV NODE_ENV=production PORT=3100 HOSTNAME=0.0.0.0 NEXT_TELEMETRY_DISABLED=1
WORKDIR /app
COPY --from=build --chown=node:node /repo/apps/web/.next/standalone ./
COPY --from=build --chown=node:node /repo/apps/web/.next/static ./apps/web/.next/static
USER node
EXPOSE 3100
HEALTHCHECK --interval=10s --timeout=3s CMD node -e "fetch('http://127.0.0.1:3100/login').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "apps/web/server.js"]
