# syntax=docker/dockerfile:1
#
# Browser runner image: the sandbox for ONE browser-worker job (ADR-013). The supervisor starts
# one container per job with `docker run --rm -i --network none --read-only --cap-drop ALL
# --security-opt no-new-privileges` plus memory, CPU and process limits (see
# services/browser-worker/src/sandbox/docker.ts). Build context: the repository root.
#   docker build -f infra/docker/browser-runner.Dockerfile -t aab/browser-runner:local .
#
# Status: built and run on 2026-11-13 (Docker 28.5) in the launcher's default mode, which keeps
# Docker's own seccomp and AppArmor profiles and runs Chromium with its own sandbox off
# (services/browser-worker/test/integration/docker.test.ts). The opt-in mode that keeps
# Chromium's sandbox on needs a seccomp profile and an AppArmor profile that both permit user
# namespaces; infra/docker/seccomp/browser-runner.json is an unreviewed draft of the first and
# the second does not exist yet. Do not use that mode (backlog AAB-017).
#
# The image holds code only: no configuration, no keys. The job (including the session
# snapshot) arrives on stdin and the egress socket is bind-mounted per job at /run/aab.

# Base images are pinned by tag and digest. Dependabot proposes digest updates
# (.github/dependabot.yml); the nightly scan reports known vulnerabilities in the built image.

# ---------------------------------------------------------------------------------------
FROM node:24-bookworm-slim@sha256:dc26ae92c9fb15cf6b1d63e20f0944b2efe0f115b20e00be48fb23fceb061c54 AS build

ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=0 \
    CI=true
WORKDIR /app
RUN corepack enable

# Manifests first. When services/browser-worker/package.json gains or loses a workspace
# dependency, update both COPY blocks in this stage.
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY packages/contracts/package.json packages/contracts/
COPY packages/adapter-sdk/package.json packages/adapter-sdk/
COPY packages/adapters/northstar/package.json packages/adapters/northstar/
COPY packages/audit/package.json packages/audit/
COPY packages/crypto/package.json packages/crypto/
COPY packages/database/package.json packages/database/
COPY packages/policy-engine/package.json packages/policy-engine/
COPY services/browser-worker/package.json services/browser-worker/

# Production dependencies only, and not the workspace root: `tsx`, which runs the TypeScript
# sources, is a dependency of @aab/browser-worker, and the development toolchain is not needed.
RUN pnpm install --frozen-lockfile --prod --filter "@aab/browser-worker..."

# The launcher starts the runner with the working directory /app (services/browser-worker/src/
# sandbox/docker.ts), where `node --import tsx` looks for `tsx` in /app/node_modules. Without
# the workspace root there is no `tsx` there, so link the service's copy.
RUN ln -s ../services/browser-worker/node_modules/tsx node_modules/tsx

COPY packages/contracts packages/contracts
COPY packages/adapter-sdk packages/adapter-sdk
COPY packages/adapters/northstar packages/adapters/northstar
COPY packages/audit packages/audit
COPY packages/crypto packages/crypto
COPY packages/database packages/database
COPY packages/policy-engine packages/policy-engine
COPY services/browser-worker/src services/browser-worker/src

# ---------------------------------------------------------------------------------------
FROM node:24-bookworm-slim@sha256:dc26ae92c9fb15cf6b1d63e20f0944b2efe0f115b20e00be48fb23fceb061c54 AS runtime

# The Node base image bundles npm, corepack and yarn. This container runs `node` directly and
# never uses them, and the scanner flags the dependencies inside npm. This layer hides them
# from the image's filesystem; the files remain in the base image's layer (the image is not
# smaller), but they are not visible in the final image, so nothing there can run them.
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack \
      /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack \
      /usr/local/bin/yarn /usr/local/bin/yarnpkg /opt/yarn-v*

# Debian's Chromium (the runner always passes executablePath; Playwright downloads nothing)
# and fonts. No other packages.
RUN apt-get update \
 && apt-get install -y --no-install-recommends chromium fonts-liberation fonts-dejavu-core ca-certificates \
 && rm -rf /var/lib/apt/lists/*

ENV NODE_ENV=production \
    HOME=/home/runner \
    TMPDIR=/tmp

# Application files are owned by root and read-only to the runtime user. The supervisor runs
# the container with --user <its own uid:gid> (never root) so the runner can open the
# per-job egress socket, which lives in a 0700 directory owned by the supervisor.
COPY --from=build --chown=root:root /app /app
RUN mkdir -p /home/runner /run/aab && chmod 0755 /home/runner /run/aab

WORKDIR /app
USER node

# One job per container; the runner reads the job on stdin and exits.
CMD ["node", "--import", "tsx", "/app/services/browser-worker/src/runner/main.ts"]
