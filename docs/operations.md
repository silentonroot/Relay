# Operations guide: local operation (Phase 1 to Phase 3)

This guide covers running AAB on one machine with synthetic data. Items marked **planned** are
described in the specification or an ADR but are not implemented; do not rely on them.

Since Phase 2 the browser worker stores encrypted browser session snapshots, so the key and backup
practices below protect real session material, still of synthetic accounts only. Since Phase 3 step
B3b the key is read by the **vault service** only (ADR-014): the API and the browser worker's
supervisor hold no key, refuse to start when `AAB_KEK_DIR` is set, and reach the vault over Unix
sockets. The cryptography has not been externally reviewed. The Compose setup runs the vault and
gives it the key volume (and nothing else); it does not run the worker. On 2026-11-13 the container images were built and the Compose stack was started once
by hand and checked (see "Run with Docker Compose" below); that was a manual check, not an automated
test; the `containers` job in CI now builds the images and starts the stack, and passed on its
first run on GitHub (2026-11-13). The Docker launcher for sandboxed jobs was
also run that day. It works only in its default mode, with Chromium's own sandbox off, and it cannot
show the sign-in window (see `AAB_WORKER_SANDBOX` below). On a local machine the worker uses
bubblewrap by default.

## Running Phase 2 locally

The pieces, all on one host: PostgreSQL, the API (port 4000), the browser worker (no port), the
dashboard (Vite on 5173, or the Compose nginx on 8080) and the Northstar demo (port 4100, from its
own repository), plus the vault (Unix sockets, no port). The worker is a supervisor that holds the
database connection and a vault client but no key, plus one sandboxed runner per job (ADR-013,
ADR-014); see [architecture](architecture.md).

### Prerequisites (Linux)

- **bubblewrap** at `/usr/bin/bwrap`, with unprivileged user namespaces allowed. A quick check:
  `bwrap --unshare-all --ro-bind / / true` exits 0. Some distributions restrict unprivileged user
  namespaces (the Dockerfile for the runner image mentions Ubuntu's AppArmor restriction); if the
  worker cannot create a sandbox it refuses to start and says so.
- **Node** at `/usr/bin/node`. The sandbox runs that path and no setting changes it.
- **Chromium** at `/usr/lib/chromium/chromium`, or set `AAB_CHROMIUM_PATH`. The worker uses
  `playwright-core` with this binary and downloads no browser. Keep the binary outside your home
  directory: the sandbox mounts its directory at the same path, so a Chromium under `$HOME` makes
  that path visible inside every job's sandbox.
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

The vault needs a key directory (mode 0700, owned by the vault's user) holding `kek-v1.key` (mode 0600,
32 bytes). The vault's `init-kek` script creates both, never overwrites an existing key, and prints
only the file's path (run it as the vault's user, see "The vault and its admin command" below):

```sh
AAB_KEK_DIR=$HOME/.config/aab/keys corepack pnpm --filter @aab/vault run init-kek
```

The old entry point `corepack pnpm --filter @aab/browser-worker run init-kek` still works: it runs the
vault's script with the same arguments (it imports no key code itself). The end-to-end test runs it
that way. Back the directory up as described in the next section before you store a session you care
about. **Do not set `AAB_KEK_DIR` for the API or the worker:** both refuse to start if it is set
(`services/browser-worker/test/supervisor/config.test.ts`, "refuses to start when a key directory is
configured"; `services/broker-api/test/config-and-startup.test.ts`, "refuses to start when a key
directory is configured, without opening it").

### Start the services

1. `migrate` and `create-owner` as in the README. The `create-owner` script reads the password from
   the terminal, or from the first line of standard input when it is not a terminal.
2. The vault ("The vault and its admin command" below): `corepack pnpm --filter @aab/vault run start`.
3. The API: `corepack pnpm --filter @aab/broker-api run start`, with `AAB_VAULT_SOCKET` set to the vault's
   api-role socket.
4. The worker, with `DATABASE_URL`, `AAB_VAULT_SOCKET` (the vault's **supervisor**-role socket) and the
   variables below in its environment: `corepack pnpm --filter @aab/browser-worker run start`. Before
   it claims any job it checks the database, asks the vault `hello` and checks the sandbox, and exits
   with a one-line reason if one fails (see troubleshooting). A vault that does not answer does not
   stop it: it starts, claims nothing and checks again before every claim, so a job waits in the queue
   until the vault is back. The sandbox check starts a real sandbox and Chromium, so start-up takes a
   few seconds. On success it logs "supervisor started" with the sandbox kind and the concurrency.
5. The dashboard (`corepack pnpm --filter @aab/dashboard run dev`).

Worker variables (from `services/browser-worker/src/config.ts`; rows say where a variable is not
in `.env.example`). `AAB_KEK_DIR` is not a worker variable: the worker refuses to start if it is set.

| Variable                     | Default                       | Meaning                                                                                                                                                                                                                                                                                                   |
| ---------------------------- | ----------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `DATABASE_URL`               | required                      | PostgreSQL connection string. Shown nowhere in errors.                                                                                                                                                                                                                                                    |
| `AAB_VAULT_SOCKET`           | required                      | Absolute path of the vault's supervisor-role socket, `$AAB_VAULT_SOCKET_DIR/supervisor/vault.sock`.                                                                                                                                                                                                       |
| `AAB_VAULT_ISOLATION`        | `separate-uid`                | `separate-uid` or `shared-uid`; must match the vault's. In `separate-uid` the worker refuses to start if it can open the vault's key directory.                                                                                                                                                           |
| `AAB_VAULT_CALL_TIMEOUT_MS`  | `5000`                        | Per vault call, connect included, 100 to 60000.                                                                                                                                                                                                                                                           |
| `AAB_WORKER_SANDBOX`         | `bubblewrap`                  | `bubblewrap`, `docker` or `unsafe-process` (no isolation at all: development only, warns on every job, no security claim applies; refused unless `AAB_VAULT_ISOLATION=shared-uid`, because the runner would share the supervisor's user). `docker` is usable in its default mode, with limits: see below. |
| `AAB_WORKER_CONCURRENCY`     | `2`                           | Jobs at once, 1 to 16. Each starts its own browser, roughly 300 to 500 MiB.                                                                                                                                                                                                                               |
| `AAB_WORKER_POLL_MS`         | `1000`                        | How often the worker looks for queued jobs, 50 to 60000. Not in `.env.example`.                                                                                                                                                                                                                           |
| `AAB_WORKER_LEASE_MS`        | `60000`                       | Lease on a claimed job, 5000 to 3600000. A heartbeat extends it every third of this time. Not in `.env.example`.                                                                                                                                                                                          |
| `AAB_WORKER_RUNTIME_DIR`     | `$XDG_RUNTIME_DIR/aab-worker` | Short, private directory for per-job sockets. Falls back to `/tmp/aab-worker-<uid>` when `XDG_RUNTIME_DIR` is unset.                                                                                                                                                                                      |
| `AAB_CHROMIUM_PATH`          | `/usr/lib/chromium/chromium`  | Chromium binary used inside the sandbox.                                                                                                                                                                                                                                                                  |
| `AAB_WORKER_DOCKER_IMAGE`    | `aab/browser-runner:local`    | Only for the Docker launcher. Not in `.env.example`.                                                                                                                                                                                                                                                      |
| `AAB_JOB_RESULT_TTL_MINUTES` | `60`                          | Minutes a job's stored result is kept, 1 to 10080 (see below).                                                                                                                                                                                                                                            |
| `AAB_LOG_LEVEL`              | `info`                        | `fatal`, `error`, `warn`, `info`, `debug`, `trace` or `silent`.                                                                                                                                                                                                                                           |

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

Step B3b added a `vault` service (image `aab/vault:local`, `infra/docker/vault.Dockerfile`), a one-shot
`vault-init-kek` that creates the first key in the `vault-keys` volume when there is none, and one
socket volume per role (`vault-api`, `vault-supervisor`, `vault-admin`). The key volume is mounted
into those two containers only; the API mounts `vault-api` only and is started with
`AAB_VAULT_SOCKET=/run/aab-vault/api/vault.sock` and `AAB_VAULT_ISOLATION=shared-uid` (the vault's
term for one user inside a container: the container and volume boundaries keep the roles apart
there). `infra/ci/compose-smoke.sh` has new checks for it (the vault runs as a non-root user, the API
container cannot see the key volume or the other roles' socket directories, and
`GET /v1/vault/status` answers). The vault reads its own `vault.env` in the secrets directory (create it beside `broker-api.env`; it holds the same `DATABASE_URL`, so the vault shares the API's database role for now). The vault and the API run as the same `AAB_UID:AAB_GID` on purpose: the `shared-uid` sockets are mode 0600, so an API under another uid would start degraded. **The B3b Compose changes were validated with `docker compose config`
only: the vault image was not built and the stack was not started in that step.** The Compose vault
has no worker beside it; a worker on the host reaches the supervisor-role socket only if you publish
that volume's directory to the host yourself, which this file does not do. To run a host worker,
run the vault on the host as well (below).

These were manual checks. The `containers` job in CI now builds the images, starts the stack and
asserts the main ones, so a change that breaks them fails CI (AAB-031; first GitHub run passed on
2026-11-13). Compose still has no worker service; run the worker on the host. Base images are pinned by tag and digest. Two Dockerfiles needed
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

The preferred way is the vault's `init-kek` script (above). The commands above do the same by hand,
but make the directory and file owned by the vault's user. **The vault reads the keys at start-up and
refuses to start** if the directory is not mode 0700, a key file is accessible to group or others, a
key file is not exactly 32 bytes, or no key is present. The key never goes in an environment
variable, an image, the repository, a log line or the database. Compose mounts the key volume into
the vault (and the one-shot that creates the first key) only. No other process reads it: not the
API, not the worker's supervisor, not the sandbox (which does not mount it, P3-14). Keep it outside
the repository: nothing enforces that.

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

Add `kek-v<N+1>.key`, re-wrap the existing data keys, and delete the old file only after no stored
version references it. The vault does the re-wrap (`vault rewrap`); the exact order of steps is in
"Rotating the key" under "The vault and its admin command (Phase 3)" below.

## The vault and its admin command (Phase 3)

Status: steps B1 to B6 are built. The vault service (`services/vault`) answers every operation of
ADR-014 section 4, the API and the browser worker's supervisor use it, and neither holds a key. Key
rotation (below) works, and the dashboard (step B5) has a **Vault** page with the key status, shown to
owners only (`GET /v1/vault/status`: KEK versions, how many stored versions each wraps, the vault's
counters), and, per connection, the vault metadata of its secrets and the last 24 hours of capabilities
(`GET /v1/connections/:id/vault`), with two actions that need no vault because they only remove
authority: "delete stored session" (`POST /v1/connections/:id/vault/delete-session`) and "revoke unused
capabilities" (`POST /v1/connections/:id/vault/revoke-capabilities`). Local tests ran with a real vault on
temporary sockets, and the Phase 3 end-to-end test ran the whole stack locally on one machine (not in CI); the
`separate-uid` setup below, the systemd unit and the Compose vault have not been run on a real host or in
containers by the people who wrote them, and nothing has had an independent review.

Start it (one user, a developer laptop; for `separate-uid` see "Separate-uid setup" below):

```sh
export DATABASE_URL=postgres://...            # a migrated database (the API's migrate script)
export AAB_KEK_DIR=$HOME/.config/aab/keys     # owned by the vault's user, mode 0700
export AAB_VAULT_SOCKET_DIR=$XDG_RUNTIME_DIR/aab-vault
export AAB_VAULT_ISOLATION=shared-uid         # explicit; refused unless set
corepack pnpm --filter @aab/vault run init-kek     # first key, kek-v1.key
corepack pnpm --filter @aab/vault run start
```

Vault settings (all strict decimal integers where numeric: `1e2`, `0x10`, blanks and signs are refused;
an error names the variable, never the value):

| Variable                                       | Default        | Meaning                                                                                              |
| ---------------------------------------------- | -------------- | ---------------------------------------------------------------------------------------------------- |
| `DATABASE_URL`                                 | required       | A `postgres://` string for a migrated database. The vault does not migrate.                          |
| `AAB_KEK_DIR`                                  | required       | Absolute, normalized path of the key directory, owned by the vault's user, mode 0700.                |
| `AAB_VAULT_SOCKET_DIR`                         | required       | Absolute, normalized path; the vault creates `api/`, `supervisor/` and `admin/` below it.            |
| `AAB_VAULT_ISOLATION`                          | `separate-uid` | `separate-uid` or `shared-uid`.                                                                      |
| `AAB_VAULT_GROUP_API`, `_SUPERVISOR`, `_ADMIN` | none           | A group name or numeric gid per role; all three required in `separate-uid`, refused in `shared-uid`. |
| `AAB_VAULT_MAX_CONNECTIONS`                    | `16`           | Open connections per role socket, 1 to 256.                                                          |
| `AAB_VAULT_IDLE_TIMEOUT_MS`                    | `60000`        | A connection with no traffic for this long is closed, 1000 to 3600000.                               |
| `AAB_VAULT_REQUEST_TIMEOUT_MS`                 | `10000`        | A request line must complete and be answered within this long, 100 to 120000.                        |
| `AAB_VAULT_ADMIN_REQUEST_TIMEOUT_MS`           | `120000`       | The admin socket's request timeout, 1000 to 600000.                                                  |
| `AAB_LOG_LEVEL`                                | `info`         | `fatal`, `error`, `warn`, `info`, `debug`, `trace` or `silent`. The vault logs little at any level.  |

The vault takes no authorization lifetime (the API sends one with every request, see below).
`AAB_VAULT_TOKEN_TTL_SECONDS` (1 to 120, default 30) is still parsed and range-checked by the vault, but
by reading `services/vault/src` no code uses the parsed value: the token lifetime comes from the
supervisor's request. Leave it unset.

The vault refuses to start when it cannot read its tables through `DATABASE_URL` (it does not
migrate), when the key or socket directory is unsafe, or off Linux. Sockets are
`$AAB_VAULT_SOCKET_DIR/{api,supervisor,admin}/vault.sock`. The worker's `init-kek` script still
works: it runs the vault's script. In `shared-uid` mode point the API at the `api` socket and the worker
at the `supervisor` socket, both with `AAB_VAULT_ISOLATION=shared-uid`.

**Run `init-kek` (and `init-kek --next`) as the vault's user**, in `separate-uid` mode too, for example
`sudo -u aab-vault env AAB_KEK_DIR=... corepack pnpm --filter @aab/vault run init-kek`. The vault
refuses a key directory owned by another user, so a key created as root or as the worker's user
would stop it from starting. Every directory above `AAB_VAULT_SOCKET_DIR` must be owned by root or
the vault's user and not writable by group or other (a sticky directory owned by root, like `/tmp`,
is accepted); otherwise the vault refuses to start.

Requests are time-limited in the database first: every vault transaction sets `statement_timeout` to
80% and `lock_timeout` to 50% of the role's request timeout (`AAB_VAULT_REQUEST_TIMEOUT_MS`, 10 s;
`AAB_VAULT_ADMIN_REQUEST_TIMEOUT_MS`, 120 s for the admin socket), so a request answered as failed
has rolled back. A request still running at the full timeout (for example one waiting for a
database connection) closes its connection without an answer: its outcome is then unknown, and the
caller must check state before it retries. At most 4 (api), 8 (supervisor) and 1 (admin) requests
run in the database at once; the rest wait.

**The API and the vault.** The API takes `AAB_VAULT_SOCKET` (required: the api-role socket,
`$AAB_VAULT_SOCKET_DIR/api/vault.sock`), `AAB_VAULT_ISOLATION` (default `separate-uid`; it must match the
vault's), `AAB_VAULT_AUTHORIZATION_TTL_SECONDS` (default 600, 10 to 3,600) and `AAB_VAULT_CALL_TIMEOUT_MS`
(default 5000, 100 to 60,000). It never takes `AAB_KEK_DIR`. At start it asks the vault `hello` and
refuses to start if the vault answers as another role or isolation mode, or, in `separate-uid` mode, if the
API's user can open the vault's key directory (the message names the path: fix the directory's owner and
mode, or run the API as another user). A vault that does not answer does not stop the API: it starts
degraded and logs a warning, revocation works, and jobs fail with `vault_unavailable` until the vault is
back (`services/broker-api/test/config-and-startup.test.ts`). `dev:memory` wires no vault.

**The worker and the vault.** The supervisor takes `AAB_VAULT_SOCKET` (required: the supervisor-role
socket), `AAB_VAULT_ISOLATION` (default `separate-uid`; it must match the vault's) and
`AAB_VAULT_CALL_TIMEOUT_MS` (default 5000). It never takes `AAB_KEK_DIR` (it refuses to start if set).
At start it asks the vault `hello` and refuses to start if the vault answers as another role or
isolation mode, or, in `separate-uid` mode, if the worker's user can open the vault's key directory
(`services/browser-worker/test/supervisor/startup-vault.test.ts`). Before **every** claim it checks the
vault again, so while the vault is down or wrong no job is claimed and queued jobs wait (log lines "the
vault is unreachable; no job is claimed" and, once it is back, "the vault answers; claiming jobs").
A job that was already claimed when the vault went away ends `vault_unavailable`, and one the vault
refuses ends `vault_denied`; neither is retried automatically, and nothing falls back to opening a secret
in the worker. A login's duration and sandbox kind, which Phase 2 wrote on `connection.auth_completed`,
are logged by the supervisor instead (the vault writes that event and cannot know them).

### Separate-uid setup (Linux host)

`separate-uid` is the isolation the design relies on: the kernel decides which user may call which
operation, because the socket of each role belongs to its own group. Not run on a real host by the
authors; check each step on yours. Names are examples.

1. **Users and groups.** One user for the vault, one for the API, one for the worker, and one group per
   role. The vault's user must be a member of all three role groups (it hands each socket to its group
   without being root); each caller is a member of its own role's group only; the operator who runs the
   admin command is in the admin group.

   ```sh
   sudo useradd --system --no-create-home --shell /usr/sbin/nologin aab-vault
   sudo useradd --system --no-create-home --shell /usr/sbin/nologin aab-api
   sudo useradd --system --no-create-home --shell /usr/sbin/nologin aab-worker
   sudo groupadd --system aab-vault-api
   sudo groupadd --system aab-vault-supervisor
   sudo groupadd --system aab-vault-admin
   sudo usermod --append --groups aab-vault-api,aab-vault-supervisor,aab-vault-admin aab-vault
   sudo usermod --append --groups aab-vault-api aab-api
   sudo usermod --append --groups aab-vault-supervisor aab-worker
   sudo usermod --append --groups aab-vault-admin "$USER"
   ```

   The vault's primary group must not be one of the role groups, and two roles must not share a group;
   it refuses to start otherwise.

2. **Directories.** The key directory belongs to the vault and nobody else (mode 0700). The socket
   directory belongs to the vault, is not writable by group or other and not readable by other (0711 lets
   the three role groups search it); the vault creates `api/`, `supervisor/` and `admin/` below it (mode
   0750, group = the role's group) and sockets with mode 0660. Every directory above the socket directory
   must be owned by root or the vault's user and not writable by group or other, and the socket directory
   must not be inside the repository (the sandbox mounts the repository).

   ```sh
   sudo install -d -o aab-vault -g aab-vault -m 0700 /var/lib/aab/keys
   sudo install -d -o aab-vault -g aab-vault -m 0711 /run/aab-vault      # systemd can do this, see below
   sudo -u aab-vault env AAB_KEK_DIR=/var/lib/aab/keys corepack pnpm --filter @aab/vault run init-kek
   ```

   The repository (the vault's code) must not be writable by the API or worker users; code they can
   change is code that runs as the vault. The worker must not be able to read `/var/lib/aab/keys`: check
   with `sudo -u aab-worker ls /var/lib/aab/keys` (must fail).

3. **The vault**, as `aab-vault`, with `AAB_VAULT_ISOLATION=separate-uid` and one group variable per
   role (`AAB_VAULT_GROUP_API=aab-vault-api`, `AAB_VAULT_GROUP_SUPERVISOR=aab-vault-supervisor`,
   `AAB_VAULT_GROUP_ADMIN=aab-vault-admin`; all three are required in this mode and refused in
   `shared-uid`). **Core dumps are off for the vault**: a core file of the vault holds keys and
   plaintext sessions. With systemd, an example unit (a sketch, not tested):

   ```ini
   [Service]
   User=aab-vault
   Group=aab-vault
   SupplementaryGroups=aab-vault-api aab-vault-supervisor aab-vault-admin
   WorkingDirectory=/opt/aab/services/vault
   EnvironmentFile=/etc/aab/vault.env        # DATABASE_URL and the AAB_VAULT_* settings; mode 0600, owner aab-vault
   ExecStart=/usr/bin/node --import tsx src/main.ts
   RuntimeDirectory=aab-vault
   RuntimeDirectoryMode=0711
   LimitCORE=0
   NoNewPrivileges=yes
   PrivateTmp=yes
   ProtectHome=yes
   ```

   Without systemd, run `ulimit -c 0` in the shell that starts the vault (and check
   `/proc/sys/kernel/core_pattern` does not pipe cores to a collector that stores them).
   `LimitCORE=0` is the same limit; it is worth setting for the API and the worker too, because their
   memory holds plaintext sessions while a job runs.

4. **The API and the worker** run as `aab-api` and `aab-worker`, with `AAB_VAULT_SOCKET` set to their own
   role's socket (`/run/aab-vault/api/vault.sock`, `/run/aab-vault/supervisor/vault.sock`) and the default
   `AAB_VAULT_ISOLATION=separate-uid`. Each asks the vault `hello` at start and, in this mode, tries to
   open the key directory the vault names; if it can, it refuses to start and tells you which path. That
   check is what catches a wrong owner or mode on the key directory.

5. **Verify** with `sudo -u aab-api test -S /run/aab-vault/supervisor/vault.sock` (must fail: the API
   cannot search the supervisor directory) and the same for the worker against the `api` and `admin`
   directories.

Admin command (talks to the admin socket only; it reads no key and no database). Type it exactly like
this, from the repository root: with `--filter`, pnpm turns the command's exit codes 2 and 3 into 1, and the
rotation steps below depend on exit 3. `--dir services/vault` keeps the exit code and `--silent` keeps
pnpm's own lines out of the JSON. Whatever you type, decide from the JSON fields (`remaining`, `failed`,
`safeToRemove`), not from the exit code alone.

```sh
corepack pnpm --silent --dir services/vault run vault status
corepack pnpm --silent --dir services/vault run vault rewrap [--batch-size N] [--max-batches N]
corepack pnpm --silent --dir services/vault run vault kek-retirement-check <kekVersion>
```

### Rotating the key

Do the steps in this order. `<dir>` is the vault's key directory (`AAB_KEK_DIR`), `<old>` the KEK
version you are retiring (for example 1), and the admin commands need `AAB_VAULT_SOCKET_DIR` set to the
vault's socket directory (the user running them must be allowed to open the `admin` socket). Run
the key commands as the vault's user.

1. **Back up the key directory** (see "Back up" above) before you change anything. This copy holds the
   current key. Keep it until the end.
2. **Generate the next KEK** as the vault's user. It adds `kek-v<N+1>.key` (mode 0600) and never
   overwrites or removes a file:

   ```sh
   sudo -u aab-vault env AAB_KEK_DIR=<dir> corepack pnpm --filter @aab/vault run init-kek --next
   ```

   (Without `sudo`, in `shared-uid` mode: `AAB_KEK_DIR=<dir> corepack pnpm --filter @aab/vault run
init-kek --next`. It prints the path of the new file; `init-kek --next <dir>` takes the directory
   as an argument instead of the variable. It refuses a directory the vault would refuse, and
   creates nothing then.)

   **Back up the key directory again now, before the restart.** The vault starts using the new key at
   the restart, so from then on data keys are wrapped under a key that exists only in this directory. Once
   rewrap has run, the new key is what you cannot lose: the first backup does not hold it, and a backup
   taken only at the end would leave a window with a single copy. Keep both backups until step 9 is done.

3. **Restart the vault.** Keys are read only at start. From now on new data keys and new capability
   MACs use the highest version; the old file is still loaded, so everything stored keeps opening.
4. **Check the state** with `vault status`:

   ```sh
   corepack pnpm --silent --dir services/vault run vault status
   ```

   `kekVersions` must list both versions, `currentKekVersion` the new one, `versionsByKek` how many stored
   versions each KEK still wraps, and `missingKekVersions` must be empty. If it is not empty, stop and see
   "If rewrap exits 3" below.

5. **Re-wrap** until the command exits 0. It calls the vault repeatedly (at most 500 rows per call, each
   call continuing after the last row the previous one looked at) and prints one JSON line with
   `rewrapped`, `skipped`, `failed` and `remaining`:

   ```sh
   corepack pnpm --silent --dir services/vault run vault rewrap [--batch-size N] [--max-batches N]
   ```

   Each row is one transaction with its `vault.secret_rewrapped` audit event; only the wrapped key and
   its KEK version change, never the ciphertext. It is safe to interrupt (even to kill the vault) and to
   run again: rows already done are not touched, and a row replaced or revoked meanwhile is skipped.
   Exit 0 means nothing remains; exit 3 means rows `remaining` or `failed`; exit 1 means the vault
   refused (for example another rewrap is running) or is unreachable; exit 2 is bad usage.

6. **Ask whether the old version can go:**

   ```sh
   corepack pnpm --silent --dir services/vault run vault kek-retirement-check <old>
   ```

   It prints `{"referencingVersions":0,"safeToRemove":true}` only when no stored version is wrapped
   under `<old>` and `<old>` is not the current version. Anything else: do not continue.

7. **Wait out the capabilities.** A capability authorized before the restart in step 3 is bound to a MAC
   under the old key and is refused (`key_unavailable`) once that file is gone. Wait one hour after step 3
   (the contract maximum for any capability: the API's `AAB_VAULT_AUTHORIZATION_TTL_SECONDS` defaults to 10
   minutes and may be set up to 3,600 s, and a login's authorization lasts 900 s). Then run step 6 once more.
8. **Remove the old file yourself**, as the vault's user: `rm <dir>/kek-v<old>.key`. The vault never
   deletes a key file, and neither does `init-kek` or `vault`. The running vault keeps the old key in
   memory and `status` reports no missing version, because nothing references it; restart the vault at
   your next convenience so that its memory no longer holds the old key.
9. **Back up the key directory once more** (it now holds the new key only). Keep the step 1 and step 2
   backups by your own retention rules, and for as long as you keep any database backup taken before the
   rewrap: such a backup holds data keys wrapped under the old key and needs it to be restored.

**If rewrap exits 3.** Read the JSON line. `remaining` above 0 with `failed` above 0 means some stored
versions could not be re-wrapped: the usual cause is a KEK file missing from `<dir>` (`vault status` lists
the version under `missingKekVersions`, and the vault refuses reads of those sessions with
`key_unavailable` until the file is back, while it keeps serving every other secret). Restore the missing
`kek-v<N>.key` from your backup into `<dir>` with its original owner and mode (0600, vault's user),
restart the vault, and run `vault rewrap` again. `failed` can also mean a row's wrapped key does not
open (damaged data): `vault` never changes such a row; the connection must sign in again. `remaining` above 0
with `failed` 0 means rows were skipped because they changed while the command ran: run it again.

**Never.**

- Never delete a KEK file while `kek-retirement-check` says `referencingVersions` is above 0, or before you
  have a backup of it. Every session wrapped under it becomes unrecoverable (there is no escrow).
- Never remove the current (highest) version.
- Never edit, rename or copy over a key file in place, and never put one where the API, the worker or
  the repository can reach it.
- Never run `init-kek --next` as root or as another user than the vault's: the vault refuses a key
  directory owned by someone else, and every directory above it must be owned by root or the vault's
  user and not writable by group or other (a sticky root-owned directory such as `/tmp` is accepted),
  or the vault will not start.
- Never skip step 7 on a busy installation: jobs that hold an old-key capability fail and must be queued
  again.

`status` lists KEK versions that stored versions still need but that are missing
(`missingKekVersions`): those sessions cannot be opened until the file is back.

Tests: `corepack pnpm --filter @aab/vault run test` (PGlite, temporary sockets under
`$XDG_RUNTIME_DIR`, no root). The process-level start test in `test/main.test.ts` needs a reachable
PostgreSQL and runs only when `AAB_TEST_DATABASE_URL` is set.

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
you run, the vault (shared-uid, temporary sockets), the API and the worker (neither with a key
directory) with the bubblewrap sandbox and a private Xvfb display, and checks the behaviour listed in the threat model (section 6.1). It takes about 85
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
| `invalid configuration:` and a list of variable names                                                                                           | A variable is missing or out of range. The message names the variable and never its value. For the worker `DATABASE_URL` and `AAB_VAULT_SOCKET` (absolute) are required, and `AAB_KEK_DIR` must not be set. For the vault `AAB_KEK_DIR` and `AAB_VAULT_SOCKET_DIR` are required.                                                                                                                                                                                                                                      |
| `refusing to start: the sandbox self-check failed: bubblewrap not found ...`                                                                    | `/usr/bin/bwrap` is missing or not executable. Likewise for `node not found ... at /usr/bin/node` and `Chromium not found ... at <path>` (set `AAB_CHROMIUM_PATH`).                                                                                                                                                                                                                                                                                                                                                   |
| `... the sandbox has a network interface besides lo` or `... can reach the host's loopback`                                                     | The sandbox is not isolating. Do not run jobs. Check the bubblewrap version and how it was installed.                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `... Chromium could not start inside the sandbox`                                                                                               | Chromium needs unprivileged user namespaces for its own sandbox. Check the `bwrap` command in the prerequisites, the distribution's restriction on user namespaces, and that the Chromium path is right.                                                                                                                                                                                                                                                                                                              |
| `... Chromium could not start inside the sandbox` with `AAB_WORKER_SANDBOX=docker`, or Chromium reports that it cannot write its home directory | The container's tmpfs mounts were owned by root, so the job's non-root user could not write its home directory. This was fixed in the launcher by setting owner and mode on the tmpfs mounts; if you see it again, check that the worker is current and that the image is rebuilt (`docker build -f infra/docker/browser-runner.Dockerfile -t aab/browser-runner:local .`).                                                                                                                                           |
| `... Chromium could not start inside the sandbox` with the Docker launcher's opt-in mode (set in code) that keeps Chromium's own sandbox on     | Chromium's own sandbox cannot run under Docker's defaults: the default seccomp profile blocks user-namespace creation, and Docker's default AppArmor profile denies it as well on kernels where AppArmor mediates user namespaces, even with the repository's custom seccomp profile. It started only with AppArmor confinement removed, which the launcher refuses. Use the default mode, which runs Chromium with its own sandbox off, or use bubblewrap. No AppArmor profile exists for the opt-in mode (AAB-017). |
| `egress socket path would be N bytes, over the 100-byte Unix socket limit`                                                                      | `AAB_WORKER_RUNTIME_DIR` (or the default) is too long. Unix socket paths are limited to about 100 bytes. Use a short directory such as `/run/user/<uid>/aab`.                                                                                                                                                                                                                                                                                                                                                         |
| `runtime base directory ... must not be accessible to other users` or `... is not owned by this user`                                           | The runtime base directory must be a real directory, owned by the worker's user, with no access for group or others (mode 0700). Remove it or fix its mode.                                                                                                                                                                                                                                                                                                                                                           |
| `a KEK already exists ...; refusing to overwrite` from `init-kek`                                                                               | The directory already has a key. That is intended. Never delete it unless you accept reconnecting every connection.                                                                                                                                                                                                                                                                                                                                                                                                   |
| The worker exits on start with `AAB_KEK_DIR: must not be set` or `refusing to start: ... vault`                                                 | The worker holds no key: unset `AAB_KEK_DIR`. For a vault message: `AAB_VAULT_SOCKET` points at another role's socket, `AAB_VAULT_ISOLATION` differs from the vault's, or (separate-uid) the worker's user can open the key directory the vault reports: fix its owner and mode, or run the worker as another user. A vault that does not answer is not a start-up error: see the next row.                                                                                                                           |
| Jobs stay `queued` and the worker log says `the vault is unreachable; no job is claimed`                                                        | The supervisor checks the vault before every claim. Start the vault, check that `AAB_VAULT_SOCKET` is the supervisor-role socket and that the worker's user may search its directory. Jobs resume by themselves. A job that fails `vault_unavailable` was claimed just before the vault went away; start it again from the dashboard or the API.                                                                                                                                                                      |
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
