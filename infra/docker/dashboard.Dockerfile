# syntax=docker/dockerfile:1
#
# Dashboard image: static Vite build served by nginx, which also proxies /v1 to the API
# so the browser sees a single origin. Build context: the repository root.
#   docker build -f infra/docker/dashboard.Dockerfile -t aab/dashboard:local .
#
# Status: built and run on 2026-11-13 (Docker 28.5) as part of infra/compose.yaml.
#

# Base images are pinned by tag and digest. Dependabot proposes digest updates
# (.github/dependabot.yml); the weekly scan reports known vulnerabilities in the built image.

# ---------------------------------------------------------------------------------------
FROM node:25-bookworm-slim@sha256:81db02c4b671288a03915da9534dbd54f96d0e7c24d80ccc54f5b36b2e684370 AS build

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
FROM nginxinc/nginx-unprivileged:1.30-alpine@sha256:f5116ed4606f3eb015dd4a8e28cb9b351476dc0ad4bc6e9f93b19cec130cdf03 AS runtime

# nginx-unprivileged runs as uid 101 and listens on 8080. No secrets live in this image:
# it holds static files and proxy configuration only.
COPY infra/docker/nginx/security-headers.conf /etc/nginx/snippets/security-headers.conf
COPY infra/docker/nginx/default.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/apps/dashboard/dist /usr/share/nginx/html

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=5 \
  CMD ["wget", "-q", "-O", "/dev/null", "http://127.0.0.1:8080/healthz"]
