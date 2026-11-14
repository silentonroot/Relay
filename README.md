# Agent Access Broker

Agent Access Broker (AAB) lets AI agents run narrowly granted operations on web applications
without passwords, cookies, OAuth refresh tokens or other authentication secrets ever entering the
language model's context. A user connects applications through a dashboard, grants an agent a
specific set of actions on a specific connection, and the broker checks the grant before every
execution, optionally asks a human to approve the exact action, and records the outcome in an
audit trail. The agent works through a catalog of approved tools, not through unrestricted browser
control.

What AAB claims, and what it does not: the model receives no credentials or session tokens through
the documented tool interface, and the broker rejects operations the agent was not granted. From
Phase 2 there is a third, bounded claim: a compromised browser or adapter inside a job's sandbox
can use only the one session that job was given, only until the job ends, and can talk only to
that application's allowed origins; it cannot read the key-encryption key, the database or another
connection's session. This holds for the bubblewrap sandbox only, not for a compromised supervisor,
host, kernel or sandbox escape, and not for the Docker launcher, which runs Chromium with its own
sandbox off; it does not mean the runner stays on the operation's allowed paths or returns true data. See
[ADR-013](docs/adr/ADR-013-per-job-sandbox-egress-proxy.md), the
[threat model](docs/threat-model.md) (section 6 says what was verified and by which test) and
specification [section 13.4](docs/spec/aab-spec.md). AAB also cannot reduce what the target
application itself allows; broker permissions constrain broker-mediated actions only.

## Status

Phases 1 and 2 are built. This is still not a usable product: it works on one synthetic demo
application, for read operations only, called by the signed-in owner acting as one of their agents,
on a Linux machine with bubblewrap and Chromium. The cryptographic code has not been externally
reviewed, and nothing here may be used with real accounts or data.

Exists today:

- Shared contracts, canonical JSON, and the error contract (`packages/contracts`).
- Envelope-encryption and KEK provider library (`packages/crypto`).
- Audit hash chain, redaction and verification library (`packages/audit`).
- Grant evaluation (`packages/policy-engine`).
- Adapter interfaces and the Northstar demo adapter (`packages/adapter-sdk`,
  `packages/adapters/northstar`).
- PostgreSQL schema, migrations and repositories (`packages/database`).
- A dashboard shell (`apps/dashboard`).
- The Fastify control-plane API (`services/broker-api`), with `migrate` and `create-owner` scripts,
  `POST /v1/operations/execute` (reads only) and the login handoff routes.
- The browser worker (`services/browser-worker`): a long-lived supervisor that holds the database
  connection and the key, and one sandboxed runner per job that drives the browser and the adapter
  with no network, no key and no database access, reaching the application only through a
  per-job egress proxy ([ADR-013](docs/adr/ADR-013-per-job-sandbox-egress-proxy.md)).
- The Northstar adapter's read operations `orders.list` and `orders.get`, with sign-in handoff and
  session check.
- Encrypted session snapshots in the database, sealed by the worker with a local key file.
- Packaging: Compose file (no worker service), Dockerfiles and a CI baseline. The three images were
  built and the Compose stack was started once by hand on 2026-11-13; CI does not do either.

Does not exist yet: vault service (the worker's supervisor reads the key directly until Phase 3),
approvals, write operations, workflows, agent credentials, agent gateway or MCP integration. The
plan is in specification section 15.

### What is verified, and what is not

Verified on 2026-11-13, by the tests named in the
[acceptance test matrix](docs/acceptance-test-matrix.md) and the
[threat model](docs/threat-model.md): type checking, linting and formatting are clean; the package
test suites pass; and an end-to-end test (`AAB_E2E=1`, run three times) drives the real API, the
real worker with the bubblewrap sandbox, a real PostgreSQL 18 database and the Northstar demo
through two sign-ins, isolated reads, an expired session, a restart, revocation, a leak scan and
an audit-chain check. With a Docker engine and the runner image present, the browser-worker package
has 236 tests instead of 231: five more test the Docker launcher.

Also run on 2026-11-13, by hand and not by automated tests (Docker 28.5.2, Compose 2.40.3): the three
container images build, and the Compose stack started on the first attempt and passed the manual
checks listed in the [threat model](docs/threat-model.md) (section 6.1), among them the API
container's read-only root, no key mount, no outbound connection, the 421 answer to an unexpected
`Host` header and a login burst that stayed under the memory limit. The stack was then removed. The
Docker launcher was also run (see the first item below).

Not verified, or known gaps (each is listed in the threat model and the [backlog](docs/backlog.md)):

- The Docker launcher (`AAB_WORKER_SANDBOX=docker`) works only in its default mode, which keeps
  Docker's own seccomp and AppArmor profiles and runs Chromium with its own sandbox **off**: the
  container is the only boundary around the browser, so a compromised renderer is a compromised
  runner inside the container. bubblewrap has two layers (the sandbox and Chromium's own sandbox)
  but no resource limits and no seccomp filter; the Docker default mode has one layer and has
  memory, CPU and process-count limits. The launcher cannot show the sign-in window, so a worker
  that has only Docker cannot connect a new account, and the end-to-end test has not been run with
  it. It needs access to the Docker socket, which is root-equivalent on the host. The opt-in mode
  that keeps Chromium's sandbox on is not usable: its seccomp profile is an unreviewed draft and no
  AppArmor profile exists. The Compose file has no worker service.
- bubblewrap applies no memory, CPU or process-count limit, and no seccomp filter; a job is bounded
  by its timeout only.
- The sign-in window runs on the owner's display. With X11 a compromised login browser could see
  input to other windows. It was tested on a private Xvfb display, not on a desktop session or on
  Wayland.
- Secrets inside the mounted code directories are hidden by file name pattern only.
- A compromised runner can make any request the session allows on the allowed origins, can send the
  session there, and can return false data that passes the output schema.
- A compromised supervisor, host, kernel or sandbox is out of scope. The supervisor holds the key
  until Phase 3.
- Continuous integration does not run the sandbox tests or the end-to-end test, and CI has never
  run on a hosting service. It does not build the container images or start the Compose stack
  either; those were checked once by hand, and base images are pinned by tag and digest.
- The dashboard's Phase 2 screens are tested against a mock API only, not in a browser against the
  real API.
- Job results are stored unencrypted in the database for 60 minutes by default.
- Lease recovery can leave a job without its audit event if the worker stops at the wrong moment.
- The rule that a job may reach only origins in both the adapter's and the application's lists is
  provisional.

## Prerequisites

- Node.js 24 and Corepack (bundled with Node 24). The pnpm version is pinned in `package.json`
  (`packageManager`); do not install pnpm separately.
- PostgreSQL for running the API and the worker outside Docker. The unit tests do not need it: they
  use in-process PGlite.
- Docker with Compose, only for the Compose route. Compose runs the API, the database and the
  dashboard, not the worker.
- For the browser worker (Phase 2), on Linux: bubblewrap at `/usr/bin/bwrap` with unprivileged user
  namespaces enabled, Node at `/usr/bin/node`, Chromium at `/usr/lib/chromium/chromium` (or
  `AAB_CHROMIUM_PATH`), and a display for the sign-in window. The end-to-end test also needs Xvfb,
  xdotool, xauth, PostgreSQL 18 tools and the Northstar demo. See the
  [operations guide](docs/operations.md).
- `openssl`, for generating the database password.

pnpm's minimum-release-age guard is active and only esbuild's install script is allowlisted. Do not
disable either to make an install pass; see [operations](docs/operations.md).

## Quickstart without Docker

```sh
# 1. Install. --frozen-lockfile refuses to change the lockfile.
corepack pnpm install --frozen-lockfile

# 2. Configuration. Edit .env: set DATABASE_URL, and set AAB_COOKIE_SECURE=false because the
#    local dashboard runs on plain HTTP on loopback. Leave AAB_KEK_DIR blank (see below).
cp .env.example .env
```

The API uses no key and refuses to start if `AAB_KEK_DIR` is set in its environment, so leave it
blank for the API. The browser worker needs a key, which
you create with the worker's `init-kek` command (see "Run the browser worker" below and the
[operations guide](docs/operations.md)).

Create a local PostgreSQL role and database, then put the connection string in `.env`
(`postgres://aab:<password>@127.0.0.1:5432/aab`, password URL-encoded):

```sh
createuser --login --pwprompt aab
createdb --owner aab aab
```

```sh
# 3. Load the configuration into this shell, apply migrations, create the owner.
set -a; . ./.env; set +a
corepack pnpm --filter @aab/broker-api run migrate
corepack pnpm --filter @aab/broker-api run create-owner  # prompts for email and password

# 4. Start the API (port 4000) and, in a second shell, the dashboard dev server.
corepack pnpm --filter @aab/broker-api run start
corepack pnpm --filter @aab/dashboard run dev
```

The dashboard is at `http://127.0.0.1:5173` and proxies `/v1` to the API at `127.0.0.1:4000`, so
the browser sees one origin. There is deliberately no environment variable for the owner's
password; `create-owner` asks for it on the terminal.

### Run the browser worker (Phase 2)

The default sandbox is bubblewrap. `AAB_WORKER_SANDBOX=docker` also works, in its default mode only:
build `aab/browser-runner:local` first (see the Compose section), accept that Chromium's own sandbox
is off in it, and note that it cannot show the sign-in window, so connect accounts with a bubblewrap
worker.

Operations and sign-in need the worker. In a third shell, load `.env` as for the API, then set
`AAB_KEK_DIR` in that shell only (keep it blank in `.env` and for the API). Create a key once and
back it up separately from the database, then start the worker. The worker reads `DATABASE_URL`,
`AAB_KEK_DIR` and the `AAB_WORKER_*` variables in `.env.example`.

```sh
export AAB_KEK_DIR=$HOME/.config/aab/keys
corepack pnpm --filter @aab/browser-worker run init-kek
corepack pnpm --filter @aab/browser-worker run start
```

Then register the Northstar application with origin `http://localhost:4100` (the only origin its
adapter allows; run the demo from its own repository on port 4100), create a connection, press
"Sign in" on the connections page, sign in to the demo in the window that opens, press "I’ve signed
in", grant an agent `orders.list`, and run it from the agent's page. The
[operations guide](docs/operations.md) has the details, the meaning of each status and
troubleshooting. These commands are taken from the package scripts; the end-to-end test runs the
same scripts under `node --import tsx` rather than through `pnpm`.

## Quickstart with Docker Compose

Status: validated with `docker compose config` in CI. On 2026-11-13 the images built and the stack
started on the first attempt (PostgreSQL healthy, `migrate` exited 0, API and dashboard healthy, only
`127.0.0.1:8080` published) and the checks in the [threat model](docs/threat-model.md) (section 6.1)
passed by hand; the stack was then removed. That was a manual check, not an automated test, and CI
does not build the images or start the stack.

The Compose file runs PostgreSQL, a one-shot migration, the API, and an nginx container that serves
the dashboard build and proxies `/v1` to the API. Only the dashboard is published on the host, on
`127.0.0.1:8080`. Nothing from the Northstar demo is built or referenced.

Secrets are files you create outside the repository. Nothing sensitive has a committed default.

```sh
umask 077
mkdir -p ~/.config/aab/compose-secrets

# The database password, and the connection string that embeds it (hex is URL-safe).
openssl rand -hex 24 > ~/.config/aab/compose-secrets/postgres_password
printf 'DATABASE_URL=postgres://aab:%s@postgres:5432/aab\n' \
  "$(cat ~/.config/aab/compose-secrets/postgres_password)" \
  > ~/.config/aab/compose-secrets/broker-api.env

# Compose-only settings.
printf 'AAB_HOST_SECRETS_DIR=%s\nAAB_UID=%s\nAAB_GID=%s\n' \
  "$HOME/.config/aab/compose-secrets" "$(id -u)" "$(id -g)" \
  > ~/.config/aab/compose.env

docker compose --env-file ~/.config/aab/compose.env -f infra/compose.yaml up --build -d
docker compose --env-file ~/.config/aab/compose.env -f infra/compose.yaml \
  run --rm broker-api npm run create-owner
```

Compose does not run the browser worker, and no key directory is mounted into any container; the
key directory will be mounted only into the vault service when it exists (Phase 3). Run the worker
on the host as above. The Docker launcher for sandboxed jobs is a separate matter: it needs the
`aab/browser-runner:local` image (`docker build -f infra/docker/browser-runner.Dockerfile -t
aab/browser-runner:local .`), and its limits are described under Status above and in the
[operations guide](docs/operations.md). The API container is limited
to 768 MiB because each owner login uses about 128 MiB of scrypt memory and up to two run at once.

Then open `http://127.0.0.1:8080`. The Compose file sets the session cookie to non-Secure because
the dashboard is plain HTTP on loopback; do not expose it beyond loopback without TLS in front and
`AAB_COOKIE_SECURE=true`. The dashboard's nginx accepts only the Host values `localhost:8080`, `127.0.0.1:8080` and
`[::1]:8080` and answers anything else with 421, as a defence against DNS rebinding. If you set
`AAB_DASHBOARD_PORT` to another port, or want another name, edit the `map` and the `server_name`
line in `infra/docker/nginx/default.conf` (both are marked in that file) and rebuild with
`up --build`. Stop with `docker compose --env-file ... -f infra/compose.yaml down`
(add `--volumes` only to delete the database). The migration runs as the `migrate` service on every
`up`; it runs `npm run migrate`.

## Configuration

`.env.example` lists every variable with safe defaults and no usable secrets. API: `DATABASE_URL`,
`AAB_HOST`, `AAB_PORT`, `AAB_SESSION_TTL_MINUTES`, `AAB_COOKIE_SECURE`, `AAB_LOG_LEVEL`,
`AAB_TRUST_PROXY`, `AAB_PASSWORD_CONCURRENCY`, `AAB_PASSWORD_QUEUE_LIMIT`, `AAB_JOB_WAIT_MS`. Worker:
`DATABASE_URL`, `AAB_KEK_DIR` (worker only), `AAB_WORKER_SANDBOX`, `AAB_WORKER_CONCURRENCY`,
`AAB_CHROMIUM_PATH`, `AAB_WORKER_RUNTIME_DIR`, `AAB_JOB_RESULT_TTL_MINUTES`, and
`AAB_WORKER_POLL_MS` and `AAB_WORKER_LEASE_MS` (read by the worker, not listed in `.env.example`).
`.env` is git-ignored and excluded from images.

## Run the checks

```sh
corepack pnpm run lint
corepack pnpm run format:check
corepack pnpm run typecheck
corepack pnpm run test                              # in-process PGlite; no database needed
corepack pnpm --filter @aab/dashboard run build     # static files in apps/dashboard/dist
corepack pnpm run check                             # lint + format:check + typecheck + test
```

The browser worker's sandbox integration tests run with the normal test command and skip, saying so
in the test title, when bubblewrap or Chromium is missing. The end-to-end test runs only on request
and needs more (see the [operations guide](docs/operations.md)):

```sh
AAB_E2E=1 node_modules/.bin/vitest run --root services/browser-worker test/e2e   # about 85 seconds
```

Three workflows and a Dependabot configuration are written for the repository's home on GitHub
([CI/CD and maintenance](docs/ci-cd.md)):

- `ci.yml` on every pull request and push to `main`: the checks above, the database suite on a real
  PostgreSQL, the image builds with a Compose smoke test and the Docker launcher tests, a secret
  scan and a dependency audit.
- `nightly.yml` every day: the bubblewrap sandbox tests and the end-to-end test with skipping turned
  into failure, an image vulnerability scan, and an issue when a scheduled run fails.
- `release.yml` on a version tag: images on GitHub's registry with an SBOM and a signed provenance
  attestation, and a GitHub release. There is no deployment workflow, because AAB runs on its
  owner's machine.

None of them has run on GitHub yet. The commands behind the `ci.yml` jobs were run on a developer
machine; the nightly runner preparation and the release workflow were not.

## Documentation

- [Specification](docs/spec/aab-spec.md)
- [Architecture decision records](docs/adr/)
- [Architecture](docs/architecture.md)
- [Threat model](docs/threat-model.md)
- [Security notes](docs/security.md)
- [Adapter development guide](docs/adapter-development.md)
- [Operations guide](docs/operations.md)
- [CI/CD and maintenance](docs/ci-cd.md)
- [Acceptance test matrix](docs/acceptance-test-matrix.md)
- [Backlog](docs/backlog.md)
- [Specification changelog and open questions](docs/spec/CHANGELOG.md)

## Synthetic data only

Use synthetic applications, accounts and data. Do not connect AAB to company systems or to real
third-party accounts, and do not put real credentials in `.env`, fixtures, issues or logs. Using
AAB with real data would first need organizational authorization and a review of data handling
(specification section 13.4).

## Running the Northstar demo alongside

Northstar is a synthetic target application in a separate repository, `northstar-demo`, which
listens on port 4100. Clone and run it from its own repository, following its own README, and keep
it a separate process: AAB's images and Compose file never build it. The Northstar adapter allows
exactly one origin, `http://localhost:4100`, and a job may reach only origins that both the adapter
and the registered application list, so register the application as `http://localhost:4100` (not
`127.0.0.1`) and keep port 4100 free. The end-to-end test starts the demo itself from
`../northstar-demo` (override with `AAB_E2E_DEMO_DIR`).
