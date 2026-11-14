# syntax=docker/dockerfile:1
#
# Broker API image. Build context: the repository root.
#   docker build -f infra/docker/broker-api.Dockerfile -t aab/broker-api:local .
#
# Status: built and run on 2026-11-13 (Docker 28.5) as part of infra/compose.yaml.
#

# Base images are pinned by tag and digest. Dependabot proposes digest updates
# (.github/dependabot.yml); the weekly scan reports known vulnerabilities in the built image.

# ---------------------------------------------------------------------------------------
FROM node:24-bookworm-slim@sha256:dc26ae92c9fb15cf6b1d63e20f0944b2efe0f115b20e00be48fb23fceb061c54 AS build

ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=0 \
    CI=true
WORKDIR /app
RUN corepack enable

# Manifests first, so the dependency layer is rebuilt only when dependencies change.
# Only the API and the workspace packages it depends on are listed. When
# services/broker-api/package.json gains or loses a workspace dependency, update both
# COPY blocks in this stage.
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY packages/contracts/package.json packages/contracts/
COPY packages/crypto/package.json packages/crypto/
COPY packages/audit/package.json packages/audit/
COPY packages/policy-engine/package.json packages/policy-engine/
COPY packages/database/package.json packages/database/
COPY packages/adapter-sdk/package.json packages/adapter-sdk/
COPY packages/adapters/northstar/package.json packages/adapters/northstar/
COPY services/broker-api/package.json services/broker-api/

# The workspace root is included because `tsx`, which runs the TypeScript sources, is a
# root devDependency today. Once `tsx` is a dependency of @aab/broker-api, drop
# --include-workspace-root and add --prod to shrink the image.
RUN pnpm install --frozen-lockfile --filter "@aab/broker-api..." --include-workspace-root

COPY tsconfig.base.json ./
COPY packages/contracts packages/contracts
COPY packages/crypto packages/crypto
COPY packages/audit packages/audit
COPY packages/policy-engine packages/policy-engine
COPY packages/database packages/database
COPY packages/adapter-sdk packages/adapter-sdk
COPY packages/adapters/northstar packages/adapters/northstar
COPY services/broker-api services/broker-api

# ---------------------------------------------------------------------------------------
FROM node:24-bookworm-slim@sha256:dc26ae92c9fb15cf6b1d63e20f0944b2efe0f115b20e00be48fb23fceb061c54 AS runtime

# AAB_HOST is 0.0.0.0 here because other containers reach the API over the Compose
# network. Nothing publishes this port on the host; see infra/compose.yaml.
ENV NODE_ENV=production \
    AAB_HOST=0.0.0.0 \
    AAB_PORT=4000 \
    HOME=/tmp \
    npm_config_cache=/tmp/.npm \
    npm_config_update_notifier=false

# Application files are owned by root and read-only to the runtime user.
COPY --from=build --chown=root:root /app /app
WORKDIR /app/services/broker-api

USER node
EXPOSE 4000

HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=5 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:' + (process.env.AAB_PORT || 4000) + '/v1/health').then((r) => process.exit(r.ok ? 0 : 1), () => process.exit(1))"]

# Single Node process (no wrapper), so signals reach the server directly.
CMD ["node", "--import", "tsx", "src/main.ts"]
