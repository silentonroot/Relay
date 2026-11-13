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
# (.github/dependabot.yml); the weekly scan reports known vulnerabilities in the built image.

# ---------------------------------------------------------------------------------------
FROM node:25-bookworm-slim@sha256:81db02c4b671288a03915da9534dbd54f96d0e7c24d80ccc54f5b36b2e684370 AS build

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

# `tsx` is a root devDependency today, hence --include-workspace-root.
RUN pnpm install --frozen-lockfile --filter "@aab/browser-worker..." --include-workspace-root

COPY packages/contracts packages/contracts
COPY packages/adapter-sdk packages/adapter-sdk
COPY packages/adapters/northstar packages/adapters/northstar
COPY packages/audit packages/audit
COPY packages/crypto packages/crypto
COPY packages/database packages/database
COPY packages/policy-engine packages/policy-engine
COPY services/browser-worker/src services/browser-worker/src

# ---------------------------------------------------------------------------------------
FROM node:25-bookworm-slim@sha256:81db02c4b671288a03915da9534dbd54f96d0e7c24d80ccc54f5b36b2e684370 AS runtime

# Debian's Chromium (the runner always passes executablePath; Playwright downloads nothing)
# and fonts. No other packages.
RUN apt-get update \
 && apt-get install -y --no-install-recommends chromium fonts-liberation fonts-dejavu-core ca-certificates \
 && rm -rf /var/lib/apt/lists/*

ENV NODE_ENV=production \
    HOME=/home/runner \
    TMPDIR=/tmp \
    npm_config_update_notifier=false

# Application files are owned by root and read-only to the runtime user. The supervisor runs
# the container with --user <its own uid:gid> (never root) so the runner can open the
# per-job egress socket, which lives in a 0700 directory owned by the supervisor.
COPY --from=build --chown=root:root /app /app
RUN mkdir -p /home/runner /run/aab && chmod 0755 /home/runner /run/aab

WORKDIR /app
USER node

# One job per container; the runner reads the job on stdin and exits.
CMD ["node", "--import", "tsx", "/app/services/browser-worker/src/runner/main.ts"]
