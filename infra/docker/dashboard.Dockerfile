# syntax=docker/dockerfile:1
#
# Dashboard image: static Vite build served by nginx, which also proxies /v1 to the API
# so the browser sees a single origin. Build context: the repository root.
#   docker build -f infra/docker/dashboard.Dockerfile -t aab/dashboard:local .
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
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY packages/contracts/package.json packages/contracts/
COPY apps/dashboard/package.json apps/dashboard/
# The workspace root is included because apps/dashboard/vite.config.ts imports
# `vitest/config`, and vitest is a root devDependency. The build stage is discarded; none
# of this reaches the runtime image. Once the dashboard declares vitest itself (or the
# config imports from `vite`), drop --include-workspace-root.
RUN pnpm install --frozen-lockfile --filter "@aab/dashboard..." --include-workspace-root

COPY tsconfig.base.json ./
COPY packages/contracts packages/contracts
COPY apps/dashboard apps/dashboard

# Vite is invoked directly so the build does not depend on the package script's wording.
# Type checking is CI's job (`pnpm run typecheck`), not the image build's.
WORKDIR /app/apps/dashboard
RUN ./node_modules/.bin/vite build

# ---------------------------------------------------------------------------------------
FROM nginxinc/nginx-unprivileged:1.31-alpine@sha256:b5047b9b76845eac124358373c6852377c52e4b05834a47647e955dd91cb8f1e AS runtime

# nginx-unprivileged runs as uid 101 and listens on 8080. No secrets live in this image:
# it holds static files and proxy configuration only.

# The pinned base image can lag behind Alpine's security fixes, so installed packages are
# upgraded at build time (the nightly scan found fixed HIGH/CRITICAL findings in curl,
# libexpat, libxslt, musl, zlib and others on 2026-11-14). The upgrade needs root; the image
# then returns to the base image's unprivileged user.
#
# Trade-off: the package versions in this image now depend on the build date as well as on the
# pinned base digest, so two builds from the same commit can differ. The scan of each build is
# the gate, and the SBOM records what was installed. nginx itself is version-pinned by the base
# image, so only Alpine's own packages move.
USER root
RUN apk upgrade --no-cache
USER 101

COPY infra/docker/nginx/security-headers.conf /etc/nginx/snippets/security-headers.conf
COPY infra/docker/nginx/default.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/apps/dashboard/dist /usr/share/nginx/html

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=5 \
  CMD ["wget", "-q", "-O", "/dev/null", "http://127.0.0.1:8080/healthz"]
