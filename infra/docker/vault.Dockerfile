# syntax=docker/dockerfile:1
#
# Vault image (ADR-014). Build context: the repository root.
#   docker build -f infra/docker/vault.Dockerfile -t aab/vault:local .
#
# Status: written in step B3b and NOT built or run yet (no image build was done in that step).
#
# The vault is the only process that holds the key-encryption key. The image holds code only: the
# key directory is a volume that infra/compose.yaml mounts into this container and no other.

# Base images are pinned by tag and digest. Dependabot proposes digest updates
# (.github/dependabot.yml); the nightly scan reports known vulnerabilities in the built image.

# ---------------------------------------------------------------------------------------
FROM node:24-bookworm-slim@sha256:dc26ae92c9fb15cf6b1d63e20f0944b2efe0f115b20e00be48fb23fceb061c54 AS build

ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=0 \
    CI=true
WORKDIR /app
RUN corepack enable

# Manifests first. When services/vault/package.json gains or loses a workspace dependency,
# update both COPY blocks in this stage.
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY packages/contracts/package.json packages/contracts/
COPY packages/crypto/package.json packages/crypto/
COPY packages/audit/package.json packages/audit/
COPY packages/database/package.json packages/database/
COPY services/vault/package.json services/vault/

# Production dependencies only; `tsx` is a dependency of @aab/vault.
RUN pnpm install --frozen-lockfile --prod --filter "@aab/vault..."

COPY tsconfig.base.json ./
COPY packages/contracts packages/contracts
COPY packages/crypto packages/crypto
COPY packages/audit packages/audit
COPY packages/database packages/database
COPY services/vault services/vault

# ---------------------------------------------------------------------------------------
FROM node:24-bookworm-slim@sha256:dc26ae92c9fb15cf6b1d63e20f0944b2efe0f115b20e00be48fb23fceb061c54 AS runtime

# The Node base image bundles npm, corepack and yarn; this container runs `node` directly.
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack \
      /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack \
      /usr/local/bin/yarn /usr/local/bin/yarnpkg /opt/yarn-v*

ENV NODE_ENV=production \
    AAB_KEK_DIR=/var/lib/aab/keys \
    AAB_VAULT_SOCKET_DIR=/run/aab-vault \
    HOME=/tmp

# Application files are owned by root and read-only to the runtime user. The key directory is
# owned by the runtime user and closed to everyone else (a named volume copies this on first use);
# the socket directory is created by the vault's user too, and compose mounts one volume per role
# below it.
COPY --from=build --chown=root:root /app /app
RUN install -d -o node -g node -m 0700 /var/lib/aab/keys \
 && install -d -o node -g node -m 0700 /run/aab-vault /run/aab-vault/api /run/aab-vault/supervisor /run/aab-vault/admin
WORKDIR /app/services/vault

USER node

# Single Node process (no wrapper), so signals reach the vault directly.
CMD ["node", "--import", "tsx", "src/main.ts"]
