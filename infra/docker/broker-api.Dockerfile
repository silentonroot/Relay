# syntax=docker/dockerfile:1
#
# Broker API image. Build context: the repository root.
#   docker build -f infra/docker/broker-api.Dockerfile -t aab/broker-api:local .
#
# Status: built and run on 2026-11-13 (Docker 28.5) as part of infra/compose.yaml.
#

# Base images are pinned by tag and digest. Dependabot proposes digest updates
# (.github/dependabot.yml); the nightly scan reports known vulnerabilities in the built image.

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

# Production dependencies only, and not the workspace root: the development toolchain
# (drizzle-kit and its esbuild binaries, vitest, eslint, typescript) is not needed to run
# the TypeScript sources, and `tsx` is a dependency of @aab/broker-api. Note that
# `src/scripts/dev-memory.ts` needs PGlite, a devDependency, and does not work in this image.
RUN pnpm install --frozen-lockfile --prod --filter "@aab/broker-api..."

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

# The Node base image bundles npm, corepack and yarn. This container runs `node` directly and
# never uses them, and the scanner flags the dependencies inside npm. This layer hides them
# from the image's filesystem; the files remain in the base image's layer (the image is not
# smaller), but they are not visible in the final image, so nothing there can run them.
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack \
      /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack \
      /usr/local/bin/yarn /usr/local/bin/yarnpkg /opt/yarn-v*

# AAB_HOST is 0.0.0.0 here because other containers reach the API over the Compose
# network. Nothing publishes this port on the host; see infra/compose.yaml.
ENV NODE_ENV=production \
    AAB_HOST=0.0.0.0 \
    AAB_PORT=4000 \
    HOME=/tmp

# Application files are owned by root and read-only to the runtime user.
COPY --from=build --chown=root:root /app /app
WORKDIR /app/services/broker-api

USER node
EXPOSE 4000

HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=5 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:' + (process.env.AAB_PORT || 4000) + '/v1/health').then((r) => process.exit(r.ok ? 0 : 1), () => process.exit(1))"]

# Single Node process (no wrapper), so signals reach the server directly.
CMD ["node", "--import", "tsx", "src/main.ts"]
