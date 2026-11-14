# Operations guide: local operation (Phase 1 and Phase 2)

This guide covers running AAB on one machine with synthetic data. Items marked **planned** are
described in the specification or an ADR but are not implemented; do not rely on them.

Since Phase 2 the browser worker stores encrypted browser session snapshots, so the key and backup
practices below protect real session material, still of synthetic accounts only. There is no vault
service yet: the worker's supervisor reads the key directly, and the cryptography has not been
externally reviewed. The Compose setup does not run the worker and does not mount or configure a
key directory. On 2026-11-13 the container images were built and the Compose stack was started once
by hand and checked (see "Run with Docker Compose" below); that was a manual check, not an automated
test, and CI does not build the images or start the stack. The Docker launcher for sandboxed jobs was
also run that day. It works only in its default mode, with Chromium's own sandbox off, and it cannot
show the sign-in window (see `AAB_WORKER_SANDBOX` below). On a local machine the worker uses
bubblewrap by default.

## Running Phase 2 locally

The pieces, all on one host: PostgreSQL, the API (port 4000), the browser worker (no port), the
dashboard (Vite on 5173, or the Compose nginx on 8080) and the Northstar demo (port 4100, from its
own repository). The worker is a supervisor that holds the database connection and the key, plus one
sandboxed runner per job (ADR-013); see [architecture](architecture.md).

### Prerequisites (Linux)

- **bubblewrap** at `/usr/bin/bwrap`, with unprivileged user namespaces allowed. A quick check:
  `bwrap --unshare-all --ro-bind / / true` exits 0. Some distributions restrict unprivileged user
  namespaces (the Dockerfile for the runner image mentions Ubuntu's AppArmor restriction); if the
  worker cannot create a sandbox it refuses to start and says so.
- **Node** at `/usr/bin/node`. The sandbox runs that path and no setting changes it.
- **Chromium** at `/usr/lib/chromium/chromium`, or set `AAB_CHROMIUM_PATH`. The worker uses
  `playwright-core` with this binary and downloads no browser.
- **A display for the sign-in window**, read from the worker's own environment: X11 (`DISPLAY`,
  local displays of the form `:N` only, with `XAUTHORITY` or `~/.Xauthority`) or Wayland
  (`WAYLAND_DISPLAY` with `XDG_RUNTIME_DIR`). Wayland is preferred when both are set. Operations
  need no display. Without one, starting a sign-in fails with the dashboard message "The browser
  worker could not complete the login; try again." With X11 the sandboxed browser can see input to
  other windows of the same display while the window is open (threat model SB-11); this was tested
  on a private Xvfb display only, not on a desktop session and not on Wayland.
- **PostgreSQL**, migrated by the API's `migrate` script. The worker does not migrate.
- **The Northstar demo**, from its own repository, on port 4100.

### Create and back up the key

The worker needs a key directory (mode 0700) holding `kek-v1.key` (mode 0600, 32 bytes). The
`init-kek` script creates both, never overwrites an existing key, and prints only the file's path:

```sh
AAB_KEK_DIR=$HOME/.config/aab/keys corepack pnpm --filter @aab/browser-worker run init-kek
```

The script takes the directory as its first argument or from `AAB_KEK_DIR`. The end-to-end test
runs it as `node --import tsx src/scripts/init-kek.ts <directory>` from `services/browser-worker`;
the `pnpm run` form above is taken from the package scripts and was not itself run for this guide.
Back the directory up as described in the next section before you store a session you care about.
Set `AAB_KEK_DIR` for the worker only. The API uses no key and refuses to start if the variable is set in its environment (`services/broker-api/test/config-and-startup.test.ts`, "refuses to start when a key directory is configured, without opening it").

### Start the services

1. `migrate` and `create-owner` as in the README. The `create-owner` script reads the password from
   the terminal, or from the first line of standard input when it is not a terminal.
2. The API: `corepack pnpm --filter @aab/broker-api run start`.
3. The worker, with `DATABASE_URL`, `AAB_KEK_DIR` and the variables below in its environment:
   `corepack pnpm --filter @aab/browser-worker run start`. Before it claims any job it checks the
   database, the key and the sandbox, and exits with a one-line reason if one fails (see
   troubleshooting). The sandbox check starts a real sandbox and Chromium, so start-up takes a few
   seconds. On success it logs "supervisor started" with the sandbox kind and the concurrency.
4. The dashboard (`corepack pnpm --filter @aab/dashboard run dev`).

Worker variables (from `services/browser-worker/src/config.ts`; rows say where a variable is not
in `.env.example`):

| Variable                     | Default                       | Meaning                                                                                                                                                                                            |
| ---------------------------- | ----------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `DATABASE_URL`               | required                      | PostgreSQL connection string. Shown nowhere in errors.                                                                                                                                             |
| `AAB_KEK_DIR`                | required                      | Absolute path of the key directory.                                                                                                                                                                |
| `AAB_WORKER_SANDBOX`         | `bubblewrap`                  | `bubblewrap`, `docker` or `unsafe-process` (no isolation at all: development only, warns on every job, no security claim applies). `docker` is usable in its default mode, with limits: see below. |
| `AAB_WORKER_CONCURRENCY`     | `2`                           | Jobs at once, 1 to 16. Each starts its own browser, roughly 300 to 500 MiB.                                                                                                                        |
| `AAB_WORKER_POLL_MS`         | `1000`                        | How often the worker looks for queued jobs, 50 to 60000. Not in `.env.example`.                                                                                                                    |
| `AAB_WORKER_LEASE_MS`        | `60000`                       | Lease on a claimed job, 5000 to 3600000. A heartbeat extends it every third of this time. Not in `.env.example`.                                                                                   |
| `AAB_WORKER_RUNTIME_DIR`     | `$XDG_RUNTIME_DIR/aab-worker` | Short, private directory for per-job sockets. Falls back to `/tmp/aab-worker-<uid>` when `XDG_RUNTIME_DIR` is unset.                                                                               |
| `AAB_CHROMIUM_PATH`          | `/usr/lib/chromium/chromium`  | Chromium binary used inside the sandbox.                                                                                                                                                           |
| `AAB_WORKER_DOCKER_IMAGE`    | `aab/browser-runner:local`    | Only for the Docker launcher. Not in `.env.example`.                                                                                                                                               |
| `AAB_JOB_RESULT_TTL_MINUTES` | `60`                          | Minutes a job's stored result is kept, 1 to 10080 (see below).                                                                                                                                     |
| `AAB_LOG_LEVEL`              | `info`                        | `fatal`, `error`, `warn`, `info`, `debug`, `trace` or `silent`.                                                                                                                                    |

**`AAB_WORKER_SANDBOX=docker`.** Build the image first, from the repository root:
`docker build -f infra/docker/browser-runner.Dockerfile -t aab/browser-runner:local .`. The worker
then needs access to a Docker engine; access to the Docker socket is root-equivalent on the host.
The launcher was run on 2026-11-13 (Docker 28.5.2, a Linux kernel with AppArmor) and works in its
default mode only. That mode keeps Docker's own seccomp and AppArmor profiles unchanged and runs
Chromium with its own sandbox **off**, so the container is the only boundary around the browser: one
layer, where bubblewrap has two (the sandbox and Chromium's own sandbox). In exchange it has memory
(1 GiB), CPU and process-count limits, which bubblewrap does not (bubblewrap also has no seccomp
filter). Two limits to know before choosing it:

- Chromium's own sandbox is off, so a compromised renderer is a compromised runner inside the
  container (threat model SB-12).
- It cannot show the sign-in window. A worker that uses only Docker cannot connect a new account;
  connect accounts with a bubblewrap worker. The end-to-end test, which needs the sign-in window, has
  not been run with the Docker launcher.

The opt-in mode that keeps Chromium's sandbox on is not usable: it needs both a seccomp profile and an
AppArmor profile that permit user namespaces, the seccomp file in the repository is an unreviewed draft,
no AppArmor profile exists, and no environment variable selects it (AAB-017).

The API's variable `AAB_JOB_WAIT_MS` (default 20000, in `.env.example`) is how long
`POST /v1/operations/execute` and `/auth/complete` wait for the worker before answering `202` with a
job to poll.

### Run with Docker Compose

The README has the commands. What has been checked, and how: on 2026-11-13 (Docker 28.5.2, Compose
2.40.3) the three images (`aab/broker-api:local`, `aab/dashboard:local`, `aab/browser-runner:local`)
built, and `infra/compose.yaml` started on the first attempt: PostgreSQL healthy, `migrate` exited 0,
the API and the dashboard healthy, and only `127.0.0.1:8080` published. By hand, against that running
stack: `GET /v1/health` through nginx answered ok with the database ok; the dashboard index carried
the security headers; a request with an unexpected `Host` got 421; an unauthenticated API request got
401; the database had the 14 expected tables; the API container ran as uid 1000 with a read-only root
filesystem, no capabilities, no bind mounts and no `AAB_KEK_DIR`, and could not open an outbound
connection; `create-owner` worked with the password on standard input; login set an HttpOnly cookie;
an ungranted `POST /v1/operations/execute` got 403 `denied` with no job row, and the same call without
the CSRF header got 403 `csrf_failed`; and 30 concurrent wrong-password logins gave 4 responses of 401
and 26 of 429 with a peak of 365 MiB against the 768 MiB limit. The stack was then removed.

These were manual checks, not automated tests. CI does not build the images or start the stack, so a
change can break them unnoticed (AAB-031). Compose still has no worker service and no container holds
a key; run the worker on the host. Base images are pinned by tag and digest. Two Dockerfiles needed
a fix on that first build: the API and runner images did not copy the workspace packages added in
Phase 2 (`packages/adapter-sdk`, `packages/adapters/northstar`, `packages/policy-engine`). If a build
fails on a missing workspace package, check that its directory is copied in the Dockerfile.

### Sign in to a connection

1. Register the application (adapter `northstar`, version `0.1.0`, allowed origin
   `http://localhost:4100`) and create a connection. The adapter allows only that origin, and a job
   may reach only origins that both the adapter and the application list.
2. On the connections page press "Sign in". The connection becomes `authenticating` and a browser
   window opens on your display at the application's login page. Sign in there, including any
   verification step. AAB does not read what you type.
3. Press "I’ve signed in" in the dashboard. The worker checks the session through the adapter, reads
   the account name, keeps only cookies and storage for the allowed origins, seals them and stores
   the ciphertext, closes the window and activates the connection. If you close the window, press
   the button too early, or the handoff passes 10 minutes, nothing is stored and the connection
   returns to `authentication_required`.
4. In the end-to-end runs a whole handoff (start, typing by xdotool, completion) took about 5 to 6
   seconds.

### Run a read

Grant the agent `orders.list` (or `orders.get`) on the connection, then use "Run a read operation"
on the agent's page. Policy is checked when the request arrives and again when the worker picks the
job up. An operation takes about 3.4 to 5 seconds from request to result (one sandbox and browser
start per job, plus up to a second of polling), measured in the end-to-end runs. The API answers
`200` with the job when it finishes within `AAB_JOB_WAIT_MS`, otherwise `202`; read it later with
`GET /v1/operations/:jobId`.

### What the statuses mean

Connection status:

| Status                    | Meaning                                                                                                                                                                                         |
| ------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `created`                 | Never signed in.                                                                                                                                                                                |
| `authentication_required` | Waiting for a sign-in, or the last handoff failed. No operations run.                                                                                                                           |
| `authenticating`          | A sign-in window is open or being checked.                                                                                                                                                      |
| `active`                  | A session is stored and was verified. Granted callers can run reads.                                                                                                                            |
| `expired`                 | The application stopped accepting the stored session (job outcome `reauth_required`). The stored ciphertext was deleted. A granted caller gets `409 reauth_required` and no job. Sign in again. |
| `reconnect_required`      | A job found a different account signed in than the one recorded (`identity_mismatch`). The ciphertext was deleted. Sign in again as the recorded account, or create a new connection.           |
| `degraded`                | In the lifecycle table; Phase 2 does not set it.                                                                                                                                                |
| `revoked`                 | Final. Revocation deletes the stored ciphertext and cancels queued jobs.                                                                                                                        |

Job status: `queued` and `running` are in progress. `succeeded` carries a result that passed the
operation's output schema twice. `failed` carries an error code. `denied` means the worker's own
policy check refused the job (grant revoked, agent disabled, connection no longer active, or an
operation that is not a read). `reauth_required` and `cancelled` are as named. `outcome_unknown`
means the worker could not confirm the outcome, for example after its lease expired on a job that is
not safe to retry; no Phase 2 operation changes anything in the application.

Job error codes: `invalid_arguments`, `adapter_unavailable` (no adapter for the connection's
application in this worker), `origin_not_allowed` (the adapter and the application share no
origin), `navigation_blocked` (the browser tried to leave the operation's allowed paths or
origins), `output_rejected` (the result did not match its schema), `not_found` (the application has
no such resource for this account), `unexpected_page`, `session_expired`, `identity_mismatch`,
`timeout`, `cancelled`, `worker_failure` (anything else, including a sandbox that could not start),
`login_not_completed`, `login_window_closed`. The message is fixed text per code and never contains
text from a page.

### Job result retention

A succeeded job's result (declared fields only, for example order notes and customer names) is
stored in `execution_jobs.result` in plaintext, and the worker sets it to null once the job is
older than `AAB_JOB_RESULT_TTL_MINUTES` (default 60). Cleanup runs about every minute. Lower the
value if 60 minutes is too long. A database backup taken inside that window holds the results. Audit
events hold key names and byte counts, never result values.

## The key-encryption key (KEK)

Background: [ADR-003](adr/ADR-003-local-vault-root-key.md) and specification section 6.4.

### Generate

A KEK is 32 random bytes in a file named `kek-v<N>.key`, in a directory outside the repository and
outside the database.

```sh
umask 077
mkdir -p ~/.config/aab/keys
chmod 700 ~/.config/aab/keys
openssl rand 32 > ~/.config/aab/keys/kek-v1.key
chmod 600 ~/.config/aab/keys/kek-v1.key
```

The preferred way is the worker's `init-kek` script (above). The commands above do the same by hand.
**The browser worker reads the key at start-up and refuses to start** if the directory is not mode
0700, a key file is accessible to group or others, a key file is not exactly 32 bytes, or no key is
present. The key never goes in an environment variable, an image, the repository, a log line or the
database. Compose does not mount the directory into any container; when the vault service exists
(Phase 3), the directory will be mounted read-only into that service only. In Phase 2 the worker's
supervisor is the only process that reads it; the sandbox does not mount it. Keep it outside the
repository: nothing enforces that.

### Back up

Back up the key directory **separately from the database**. A backup that holds both in the clear
gives up the protection the design exists to provide. Reasonable options: an encrypted archive or
password-manager attachment kept offline, or a second encrypted volume. Re-back-up whenever a key
version is added. Do not put keys in cloud-synced folders, issue trackers or chat.

### What losing it means

If every copy of a KEK version is lost, every secret wrapped under it is unrecoverable. There is no
back door and no escrow. Nothing else is lost: the owner generates a new key and **reconnects every
affected connection** (each stored session becomes unreadable, so jobs for it fail until you sign in
again). A database backup without the key directory restores metadata, not sessions.
The key files protect against disclosure of the database alone; they do not protect against anyone
who can read files as the service's user, or against root.

### Rotate

**Planned.** The design is to add `kek-v<N+1>.key`, re-wrap existing data keys, and delete the old
file only after every record reports the new version. There is no re-wrap command yet.

## Database backup and restore

AAB uses PostgreSQL. Migrations are applied by the `migrate` script (`corepack pnpm --filter @aab/broker-api run migrate`; in Compose, the `migrate` service).

Backup, custom format, written with owner-only permissions:

```sh
umask 077
pg_dump --format=custom --file=aab-$(date +%Y%m%d).dump "$DATABASE_URL"
```

Compose (the database port is not published, so run it inside the container):

```sh
umask 077
docker compose --env-file ~/.config/aab/compose.env -f infra/compose.yaml \
  exec -T postgres pg_dump --format=custom --username=aab aab > aab-$(date +%Y%m%d).dump
```

Restore into an empty database with the API stopped:

```sh
createdb --owner aab aab_restored
pg_restore --no-owner --role=aab --dbname=aab_restored aab-20260101.dump
```

Notes:

- A dump holds password hashes, session-token hashes and audit events. Protect it like the
  database. It holds no key material.
- Restoring an older dump rewinds the audit chain and revives sessions that were later revoked. It
  also brings back stored session ciphertext that AAB deleted after a revocation or an expiry; with
  the key it opens. After any restore, revoke all sessions (below), revoke or sign out the
  connections you no longer want, and verify the chain.
- Restore tests belong in routine practice. Restore into a scratch database, not over a live one.
- Scheduled backups, retention and point-in-time recovery: **planned**.

## Owner password

The first owner is created with the interactive `create-owner` command (`corepack pnpm --filter @aab/broker-api run create-owner`). It prompts on the terminal; the
password is not accepted from an environment variable, an argument or a file, and must not be
echoed or logged.

Rotating the owner's password: **planned**. No change-password endpoint or command exists yet.
Until one does, treat a suspected password compromise as a reason to revoke all sessions and,
because this is a synthetic-data installation, rebuild the database from migrations.

## Revoking sessions

Sessions are rows in `user_sessions`. The API stores only hashes of the session and CSRF tokens,
and a session is valid only while `revoked_at` is null and `expires_at` is in the future
(`AAB_SESSION_TTL_MINUTES`, default 480).

- A user logging out through `POST /v1/auth/logout`: part of the Phase 1 API.
- Revoking every session at once has no command yet (**planned**). Until then, with the API
  stopped or running, it is a direct database update:

```sql
UPDATE user_sessions SET revoked_at = now() WHERE revoked_at IS NULL;
```

Run it with `psql "$DATABASE_URL"` (in Compose, through `exec postgres psql --username=aab aab`).
Direct edits are not audited by AAB; note them yourself.

## Verifying the audit chain

Each organization has a hash chain over its audit events (specification section 11.2). The library
function `verifyChain` in `@aab/audit` and the audit repository's verification method recompute the
chain and report the first modified, removed or reordered event.

There is **no operator command or API endpoint for this yet** (**planned**). Until there is, verification
is available only from code and the tests in `packages/database/test/audit.test.ts`.

Limits to keep in mind: the chain is evidence against partial edits, not prevention. Removing the
newest events leaves a shorter, valid chain, and someone who can write the whole table can rewrite
a consistent one. Detecting those needs the chain's head hash recorded somewhere the database
writer cannot reach; exporting checkpoints is **planned** (ADR-009).

## Logs

The API writes structured JSON logs to standard output. Outside Docker that is your terminal or
whatever supervises the process; in Compose use
`docker compose --env-file ... -f infra/compose.yaml logs broker-api`. Set verbosity with
`AAB_LOG_LEVEL` (`fatal`, `error`, `warn`, `info`, `debug`, `trace`; default `info`). nginx in the
dashboard container writes its access and error logs to its container output. Log rotation and
shipping are left to Docker or your supervisor; none is configured.

The browser worker writes structured JSON logs to standard output in the same way. Besides job and
lifecycle lines it logs every egress decision of every job: the origin, whether it was allowed or
denied, and a reason code, never headers or bodies. Chromium's own background requests show up as
denied origins; that is expected. Text a runner writes to its own standard error is not forwarded:
only a fixed list of event names is logged. A job running under `unsafe-process` logs a warning.

Logs must never contain, at any level: passwords, password hashes, session or CSRF tokens,
cookies, `Authorization` headers, API keys, key-encryption keys or data keys, the `DATABASE_URL`
(it embeds the database password), raw HTML that may contain secrets, or full model prompts. Code
is meant to log only through the structured logger with allowlisted fields. If you find any of
these in a log, treat the value as compromised, rotate or revoke it, and file a defect. Do not paste
logs into public issues without reading them first.

## Running the end-to-end test

The Phase 2 end-to-end test starts the Northstar demo, a fresh database on a PostgreSQL server that
you run, the API (with no key directory) and the worker with the bubblewrap sandbox and a private
Xvfb display, and checks the behaviour listed in the threat model (section 6.1). It takes about 85
seconds. It is not part of `pnpm run test` and CI does not run it.

```sh
AAB_E2E=1 node_modules/.bin/vitest run --root services/browser-worker test/e2e
```

It needs: bubblewrap, Chromium, `Xvfb`, `xdotool` and `xauth` at `/usr/bin`; `psql`, `createdb` and
`dropdb` from PostgreSQL 18 (`AAB_E2E_PG_BIN`, default `/usr/lib/postgresql/18/bin`); a PostgreSQL
server already listening on the socket `$AAB_E2E_PG_DIR/.s.PGSQL.$AAB_E2E_PG_PORT` (defaults
`/run/user/<uid>/aab-pg` and `54329`), in which the test creates and drops its own database; the
Northstar demo installed at `../northstar-demo` next to the repository (`AAB_E2E_DEMO_DIR`); the
repository's dependencies; `/run/user/<uid>`; and port 4100 free, because the Northstar adapter
allows only `http://localhost:4100`. The test checks all of these first and lists what is missing.
`AAB_E2E_KEEP_LOGS` keeps its logs. The sandbox integration tests in
`services/browser-worker/test/integration/` need only bubblewrap and Chromium (the login test also
`Xvfb`, `xdotool` and `xauth`) and skip, saying so in the test title, when they are missing.
`integration/docker.test.ts` (five tests of the Docker launcher) needs a reachable Docker engine and
the image `aab/browser-runner:local`, and skips, saying so in the test title, without them. With both
present the browser-worker package has 236 tests, 231 without the Docker tests; the end-to-end steps
are separate and do not use the Docker launcher.

## Troubleshooting the worker

| Symptom                                                                                                                                         | Cause and fix                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| ----------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `invalid configuration:` and a list of variable names                                                                                           | A variable is missing or out of range. The message names the variable and never its value. `DATABASE_URL` and `AAB_KEK_DIR` are required, and `AAB_KEK_DIR` must be absolute.                                                                                                                                                                                                                                                                                                                                         |
| `refusing to start: the sandbox self-check failed: bubblewrap not found ...`                                                                    | `/usr/bin/bwrap` is missing or not executable. Likewise for `node not found ... at /usr/bin/node` and `Chromium not found ... at <path>` (set `AAB_CHROMIUM_PATH`).                                                                                                                                                                                                                                                                                                                                                   |
| `... the sandbox has a network interface besides lo` or `... can reach the host's loopback`                                                     | The sandbox is not isolating. Do not run jobs. Check the bubblewrap version and how it was installed.                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `... Chromium could not start inside the sandbox`                                                                                               | Chromium needs unprivileged user namespaces for its own sandbox. Check the `bwrap` command in the prerequisites, the distribution's restriction on user namespaces, and that the Chromium path is right.                                                                                                                                                                                                                                                                                                              |
| `... Chromium could not start inside the sandbox` with `AAB_WORKER_SANDBOX=docker`, or Chromium reports that it cannot write its home directory | The container's tmpfs mounts were owned by root, so the job's non-root user could not write its home directory. This was fixed in the launcher by setting owner and mode on the tmpfs mounts; if you see it again, check that the worker is current and that the image is rebuilt (`docker build -f infra/docker/browser-runner.Dockerfile -t aab/browser-runner:local .`).                                                                                                                                           |
| `... Chromium could not start inside the sandbox` with the Docker launcher's opt-in mode (set in code) that keeps Chromium's own sandbox on     | Chromium's own sandbox cannot run under Docker's defaults: the default seccomp profile blocks user-namespace creation, and Docker's default AppArmor profile denies it as well on kernels where AppArmor mediates user namespaces, even with the repository's custom seccomp profile. It started only with AppArmor confinement removed, which the launcher refuses. Use the default mode, which runs Chromium with its own sandbox off, or use bubblewrap. No AppArmor profile exists for the opt-in mode (AAB-017). |
| `egress socket path would be N bytes, over the 100-byte Unix socket limit`                                                                      | `AAB_WORKER_RUNTIME_DIR` (or the default) is too long. Unix socket paths are limited to about 100 bytes. Use a short directory such as `/run/user/<uid>/aab`.                                                                                                                                                                                                                                                                                                                                                         |
| `runtime base directory ... must not be accessible to other users` or `... is not owned by this user`                                           | The runtime base directory must be a real directory, owned by the worker's user, with no access for group or others (mode 0700). Remove it or fix its mode.                                                                                                                                                                                                                                                                                                                                                           |
| `a KEK already exists ...; refusing to overwrite` from `init-kek`                                                                               | The directory already has a key. That is intended. Never delete it unless you accept reconnecting every connection.                                                                                                                                                                                                                                                                                                                                                                                                   |
| The worker exits on start with a key-store error                                                                                                | The key directory is not mode 0700, a key file is accessible to group or others, or no `kek-v<N>.key` of 32 bytes is present.                                                                                                                                                                                                                                                                                                                                                                                         |
| Port 4100 is busy, or jobs fail with `origin_not_allowed`                                                                                       | The Northstar adapter allows only `http://localhost:4100`. Run the demo on that port and register the application with that origin, not `127.0.0.1`.                                                                                                                                                                                                                                                                                                                                                                  |
| Sign-in fails at once with the "could not complete the login" message                                                                           | No display reached the worker (`DISPLAY` with its authority file, or `WAYLAND_DISPLAY` with `XDG_RUNTIME_DIR`), the display is not a local `:N` display, or the sandbox could not start. Check the worker log for `login window could not be opened` and its `errorCode`.                                                                                                                                                                                                                                             |
| A request stays `queued` or answers `202`                                                                                                       | The worker is not running, is at its concurrency, or the connection has another job. Look at the worker log. `GET /v1/operations/:jobId` shows the state.                                                                                                                                                                                                                                                                                                                                                             |
| A connection fell back to `authentication_required` after a worker restart                                                                      | The worker stopped during a sign-in. The lease expired and recovery reset the connection. Sign in again.                                                                                                                                                                                                                                                                                                                                                                                                              |

## Upgrading dependencies under the release-age guard

pnpm refuses to install package versions younger than its minimum release age, and only esbuild's
install script is allowed to run. Both are security controls against malicious releases (spec
section 13.2). Do not lower the age, add exclusions, or extend the build allowlist to get past an
error. If a wanted version is too new, wait, or use the newest version that is old enough.

Routine upgrade:

```sh
corepack pnpm outdated -r
corepack pnpm update --latest --filter <workspace-package> <dependency>
corepack pnpm run check && corepack pnpm run format:check
corepack pnpm --filter @aab/dashboard run build
corepack pnpm audit --prod --audit-level high
```

Commit `pnpm-lock.yaml` with the change. Reviewing the diff of the lockfile for unexpected new
packages or new install scripts is part of the upgrade. CI installs with `--frozen-lockfile`, so a
lockfile that disagrees with `package.json` fails. Node and pnpm versions move through the
`engines` and `packageManager` fields in `package.json`; image base tags are in
`infra/docker/*.Dockerfile` and `infra/compose.yaml` and are not yet pinned by digest (follow-up).
Automated and scheduled upgrades are **planned**.
