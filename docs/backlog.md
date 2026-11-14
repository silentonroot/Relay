# Backlog

Statuses for the ten original tickets were set from the repository's contents on 2026-11-12 and updated on 2026-11-13 after Phase 2, and are maintained by the project lead. "Evidence" names a test file and test; worker tests are under `services/browser-worker/test/`, abbreviated `W:` below, broker-api tests under `services/broker-api/test/` (`A:`) and database tests under `packages/database/test/` (`D:`).

## Phase 0 and Phase 1 tickets

| Ticket  | Title                                                                                       | Status                                                                                                                                                                                                                                                                                                                                                                                     |
| ------- | ------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| AAB-001 | Write ADR-001 trust boundaries and non-negotiable security invariants                       | Done. `docs/adr/ADR-001-trust-boundaries-worker-isolation.md` exists and states the invariants.                                                                                                                                                                                                                                                                                            |
| AAB-002 | Initialize TypeScript/pnpm monorepo, lint/test/CI                                           | Done, except that the CI workflow (`.github/workflows/ci.yml`) has never run on a hosting service. Lint, typecheck and tests ran locally.                                                                                                                                                                                                                                                  |
| AAB-003 | Define shared entities and database migrations for users, apps, connections, agents, grants | Done. Contracts in `packages/contracts`; schema and migrations in `packages/database` (`drizzle/0000` to `0002`).                                                                                                                                                                                                                                                                          |
| AAB-004 | Implement local owner authentication and authenticated API skeleton                         | Done. `services/broker-api` has owner login, sessions, CSRF checks, the resource routes, and the `migrate` and `create-owner` scripts.                                                                                                                                                                                                                                                     |
| AAB-005 | Build dashboard shell and connection/agent list views                                       | Done. `apps/dashboard` has login, overview, connections, agents, grants and activity pages with tests.                                                                                                                                                                                                                                                                                     |
| AAB-006 | Create standalone Northstar demo with synthetic accounts/orders                             | Done, in the separate `northstar-demo` repository (server, seed data and `tests/app.test.ts`).                                                                                                                                                                                                                                                                                             |
| AAB-007 | Define application adapter SDK and read-only Northstar adapter                              | Done (2026-11-13). The SDK, the Northstar manifest and, since Phase 2, `execute` and `checkSession` for `orders.list` and `orders.get` (with `loginPath` and `sessionCheckPaths`) exist. Evidence: `packages/adapters/northstar/test/execute.test.ts`; see AAB-014.                                                                                                                        |
| AAB-008 | Implement isolated Playwright worker and interactive login handoff                          | Done (2026-11-13), as `services/browser-worker` with a per-job sandbox (ADR-013). See AAB-011 and AAB-012 for evidence and limits. The Docker launcher was run on 2026-11-13 and works in its default mode only, with Chromium's own sandbox off; see AAB-017.                                                                                                                             |
| AAB-009 | Implement protected session snapshot storage abstraction and secret-free logging            | Done (2026-11-13). `services/browser-worker/src/session-store/index.ts` seals and opens snapshots; the worker's logger redacts secret-shaped fields. Evidence: `services/browser-worker/test/session-store/session-store.test.ts`, `supervisor/config.test.ts` ("redacts secret-shaped fields and logs only the type of an error"), `e2e/phase2.e2e.test.ts` steps I1 and I2. See AAB-013. |
| AAB-010 | End-to-end test: connect two accounts, restore session, read orders, confirm isolation      | Done (2026-11-13), as `services/browser-worker/test/e2e/phase2.e2e.test.ts` (`AAB_E2E=1`). It passed three consecutive times. See AAB-016.                                                                                                                                                                                                                                                 |

## Phase 2 tickets

### AAB-011 Browser worker process

- **Scope:** Run the browser worker as a separate operating-system process from the API. The worker runs Playwright with one isolated browser profile per connection. Agents are given no debugging endpoint.
- **Depends on:** AAB-007
- **Status (2026-11-13):** Done. The scope went beyond the ticket: the worker is a supervisor plus one sandboxed runner per job (ADR-013).
  - A separate process from the API: `W:e2e/phase2.e2e.test.ts` step F asserts that after the restart the worker's and the API's process IDs differ from each other and from their IDs before it.
  - Distinct browser profiles: every job starts a fresh browser and context loaded with one connection's snapshot (`W:integration/operations.test.ts` "two jobs with two storage states each see only their own account"; end-to-end step D).
  - No debugging endpoint reachable: the browser has no network interface except its own loopback and sits in its own network namespace (`W:integration/isolation.test.ts`; end-to-end step J). No test probes for a debugging port as such.
- **Done when:**
  - The worker runs as a process whose ID differs from the API process ID.
  - Two connections use two distinct browser profiles.
  - No debugging endpoint is reachable from agent-facing interfaces.

### AAB-012 Login handoff

- **Scope:** The worker opens a headed browser at the application's allowlisted login URL. The owner signs in directly in that browser. The worker then verifies the signed-in identity through the adapter's session check.
- **Depends on:** AAB-011
- **Status (2026-11-13):** Done, with limits.
  - Opens at the allowlisted login URL: the runner opens `loginPath` on the job's first allowed origin and checks it with the navigation guard (`W:integration/login.test.ts` opens the fixture's login page and signs in). No test checks that the login window refuses to leave the allowed origins.
  - The session check returns the expected identity: `W:e2e/phase2.e2e.test.ts` step C asserts the recorded account name for both accounts; `W:integration/login.test.ts` "the owner signs in; complete() returns the session cookie and account hint".
  - A failed check does not mark the connection signed in: step C ("complete before sign-in stores nothing"), `W:integration/login.test.ts` "complete() before signing in reports login_not_completed", `W:supervisor/login.test.ts`.
  - Limits: tested on a private Xvfb display, not on a desktop session or on Wayland (AAB-026). An X11 login window can see input to other windows of the display (threat model SB-11).
- **Done when:**
  - The browser opens only at the allowlisted login URL.
  - After sign-in, the adapter session check returns the expected identity.
  - When the session check fails, the connection is not marked as signed in.

### AAB-013 Encrypted session snapshot storage

- **Scope:** Captured browser storage state is limited to the adapter's allowed origins. It is sealed with the crypto package and then stored. Nothing readable is written to disk or to logs.
- **Depends on:** AAB-012, packages/crypto
- **Status (2026-11-13):** Done, with one difference from the ticket text.
  - Ciphertext, and the wrong key fails: `W:session-store/session-store.test.ts` "stores ciphertext only and opens it again with the same key", "fails to open with a different KEK".
  - Only the allowed origins: `W:session-store/session-store.test.ts` "keeps cookies whose domain is an allowed host and origin storage that is exactly allowed"; `W:supervisor/login.test.ts` "stores a snapshot filtered to the allowed origins and activates the connection".
  - No plaintext cookie or token in logs: `W:e2e/phase2.e2e.test.ts` steps I1 and I2 scanned the API and worker logs, every HTTP response and every database column, with a positive control. The scan did not read PostgreSQL's data files, so "a scan of the data directory" is covered through the database's columns only.
  - Known gaps: AAB-022 (failed re-login, no-label identity rule, parent-domain cookies).
- **Done when:**
  - The stored snapshot is ciphertext, and decryption with the wrong key fails.
  - The snapshot contains storage state only for the adapter's allowed origins.
  - A scan of the data directory and the logs finds no plaintext cookie or token values.

### AAB-014 Northstar adapter execute for orders.list and orders.get

- **Scope:** Implement execute for the orders.list and orders.get operations in the Northstar adapter. The implementation uses the adapter SDK's BrowserSession facade. Output passes through schema sanitisation before it is returned.
- **Depends on:** AAB-011, packages/adapters/northstar
- **Status (2026-11-13):** Done.
  - Results pass sanitisation: `packages/adapters/northstar/test/execute.test.ts` ("returns only declared fields as displayed text", "reads the detail with integer quantity and version"); `W:e2e/phase2.e2e.test.ts` step D (every result has exactly the output schema's keys).
  - Undeclared fields are absent: step D, and `W:integration/operations.test.ts` "oversized text is rejected by the output schema, and reads are bounded".
- **Done when:**
  - orders.list and orders.get return results that pass schema sanitisation.
  - Fields not declared in the schema are absent from the returned output.

### AAB-015 Read path for POST /v1/operations/execute

- **Scope:** Implement the read path of POST /v1/operations/execute. The path validates arguments and evaluates policy with the policy engine. It then enqueues or runs the read, returns a sanitised result, and writes an audit event.
- **Depends on:** AAB-014, packages/policy-engine
- **Status (2026-11-13):** Done. The audit trail differs from the ticket text: one request writes a `policy.evaluated` event (API), a `vault.secret_read` event and an outcome event (worker), not one event.
  - Invalid arguments are rejected before execution: A:execution.test.ts "rejects invalid arguments with field paths only", "rejects unknown argument keys and does not echo their names", "rejects \_\_proto\_\_ in arguments".
  - A read no grant permits is denied before any worker runs: A:execution.test.ts "denies an ungranted read with no job row and a deny audit event (exit criterion)"; `W:e2e/phase2.e2e.test.ts` step B.
  - A permitted read returns a sanitised result and its events: A:execution.test.ts "creates a job for a granted read: 202 without a worker, 200 with the result after it"; `W:supervisor/operation.test.ts` "runs an allowed read operation with the stored snapshot and records the outcome"; end-to-end steps D and K.
  - The caller is the signed-in owner acting as one of their agents; agent credentials are Phase 6. Writes and approvals are refused (A:execution-adapters.test.ts).
- **Done when:**
  - A request with invalid arguments is rejected before any execution.
  - A read that no grant permits is denied before worker execution.
  - A permitted read returns a sanitised result and writes one audit event.

### AAB-016 Two-account isolation end-to-end test

- **Scope:** Connect two Northstar accounts and restart the broker. Restore both sessions, then read orders through each connection. The test proves that neither connection sees the other's orders. It also covers the case of an expired session.
- **Depends on:** AAB-013, AAB-015
- **Status (2026-11-13):** Done, as `W:e2e/phase2.e2e.test.ts`. It passed three consecutive times (about 85 seconds each; the author twice, the project lead once).
  - After a restart each connection returns only its own orders: step F ("restart API and worker; read again without signing in").
  - Neither connection returns the other account's orders: step D (disjoint sets; a cross-account `orders.get` looks like a missing order).
  - An expired session returns `reauth_required`: step G.
  - Not in CI: the test needs bubblewrap, Chromium, Xvfb, xdotool, PostgreSQL 18 and the Northstar demo (AAB-020).
- **Done when:**
  - After a broker restart, each connection returns only its own orders.
  - Neither connection returns any order belonging to the other account.
  - A connection with an expired session returns `reauth_required`.

## Follow-up tickets from the Phase 2 review (2026-11-13)

These record gaps that Phase 2 left. They add no Phase 3 scope: Phase 3 moves the key behind the vault service (specification section 15) and is not repeated here. The threat model row that describes each gap is named in its entry.

### AAB-017 Finish the Docker launcher: its opt-in mode and the end-to-end test

- **Status (2026-11-13):** Partly done. The images build (two Dockerfiles needed a fix: they did not copy the Phase 2 workspace packages). The launcher was run for the first time and, as written, did not work: the container's tmpfs mounts were owned by root (fixed by setting owner and mode), and Chromium's own sandbox cannot run under Docker's defaults on a kernel where AppArmor mediates user namespaces (the default seccomp profile blocks them, and with the repository's custom seccomp profile Docker's default AppArmor profile still denies them; Chromium started only with AppArmor confinement removed, which the launcher refuses). Its default mode now keeps Docker's own seccomp and AppArmor profiles and runs Chromium with its own sandbox off: the self-check passes, a real `orders.list` job against the Northstar demo succeeded by hand, and `W:integration/docker.test.ts` (five tests, skipped without a Docker engine and the image) and the "docker arguments" block of `W:sandbox-args.test.ts` pass. That mode has one layer (the container) where bubblewrap has two, and has resource limits where bubblewrap has none.
- **Scope (what is left):**
  - Review `infra/docker/seccomp/browser-runner.json`, an unreviewed draft written from memory and never compared with Docker's published default profile, against that published default, or replace it with the default plus the smallest addition Chromium's own sandbox needs.
  - Write and review an AppArmor profile that permits user namespaces. None exists. The launcher refuses a seccomp profile without one, and refuses `apparmor=unconfined`. No environment variable selects the opt-in mode; add one only if the mode is kept.
  - Decide whether the opt-in mode (Chromium's sandbox on in the container) is wanted at all, given that the default mode has one layer. If not, remove the draft profile and the opt-in code.
  - Headed login is refused under Docker, so a worker that has only Docker cannot connect a new account. Decide whether that stays. Run the end-to-end test with the Docker launcher once a login path exists for it (the test has not been run with Docker for that reason).
  - Decide whether the isolation and operation tests in `W:integration` should also run against the Docker launcher, since only `W:integration/docker.test.ts` does.
  - A one-off manual job is not a test: keep a test that runs a real job under Docker against a fixture if one can run without the Northstar demo.
- **Depends on:** AAB-011
- **Done when:**
  - The opt-in mode is removed, or its seccomp profile's difference from Docker's default is documented and reviewed by a second person, an AppArmor profile exists and was reviewed, and a test shows Chromium starting with its own sandbox on in the container.
  - The end-to-end test, or a Docker-specific equivalent, has run with the Docker launcher.
  - The documents state the final trade-off between the two modes.
- **Threat model:** SB-7, SB-12. **Matrix:** AT-057.

### AAB-018 Resource limits for bubblewrap jobs

- **Scope:** bubblewrap applies no memory, CPU or process-count limit. Add limits that work without root (for example `systemd-run --user --scope` properties or cgroup v2 delegation, whichever is available), or document why none can be added and keep the timeout as the only bound.
- **Depends on:** AAB-011
- **Done when:** a test shows that a job that allocates memory or forks without bound is stopped before it affects the host, or the limitation is recorded as accepted with the owner's decision.
- **Threat model:** SB-5. **Matrix:** AT-058.

### AAB-019 Make lease recovery atomic with its audit event

- **Scope:** `recoverExpiredLeases` commits before the audit event is written in a second transaction (`services/browser-worker/src/supervisor/supervisor.ts`, `runMaintenance`). A crash between the two leaves a job ended without an outcome event. Write the event in the same transaction as the recovery, or record recovery in a way that a later run completes.
- **Depends on:** AAB-011
- **Done when:** a test that fails the audit write shows the job is not left ended without an event, and the existing recovery tests in `W:supervisor/lifecycle.test.ts` still pass.
- **Threat model:** SB-10.

### AAB-020 CI job for the sandbox and end-to-end tests

- **Status (2026-11-13):** Written, not run. `.github/workflows/nightly.yml` runs the sandbox suite with `AAB_REQUIRE_INTEGRATION=1` and the end-to-end test, and `ci.yml` runs the Docker tests with `AAB_REQUIRE_DOCKER=1`; both variables turn a skip into a failure. The runner preparation (`infra/ci/sandbox-prereqs.sh`) has never run, the end-to-end job needs the repository variable `NORTHSTAR_DEMO_REPOSITORY`, and the fixed fixture port and shared runtime directory are unchanged. Open until the jobs have run green on GitHub.

- **Scope:** Continuous integration runs neither the sandbox integration tests nor the end-to-end test; the integration tests skip when bubblewrap or Chromium is missing (the login test also needs Xvfb, xdotool and xauth) and the Docker tests skip without a Docker engine and the image, and the end-to-end test runs only with `AAB_E2E=1` and needs PostgreSQL too. Add a job on a runner that has them, and make the job fail when the tests skip. Continuous integration has also never run on a hosting service; that comes first.
- **Depends on:** AAB-002
- **Done when:** the job runs `W:integration` (including `W:integration/docker.test.ts`) and `W:e2e` with `AAB_E2E=1`, fails if any of them is skipped, and has run at least once.
- **Threat model:** HO-8. The `W:integration/login.test.ts` "the owner signs in; complete() returns the session cookie and account hint" assertion on the runtime directory listing failed once when two runs of the worker suite overlapped on one machine: the suite uses a fixed fixture port (47813) and the shared runtime directory, so two runs cannot overlap. Make both per-run before adding the job.

### AAB-021 Check the dashboard's Phase 2 screens against the real API

- **Scope:** The sign-in panel, the session status display and the run-a-read panel are tested against a mock API only. Run the dashboard in a browser against the real API, worker and demo, and record what differs.
- **Depends on:** AAB-005, AAB-015
- **Done when:** the three screens were used end to end in a browser, differences are fixed or recorded, and the relevant tests are updated.
- **Threat model:** UI-10. **Matrix:** AT-059.

### AAB-022 Snapshot handling on failed re-login

- **Scope:** Three gaps in session handling. (1) A failed re-login leaves the previous snapshot ciphertext stored until the next login or revocation; decide whether to delete it at the failure. (2) A connection verified with no account label that later signs in with one is treated as an identity mismatch (`services/browser-worker/src/supervisor/login.ts`); decide the rule and add a test. (3) Cookies scoped to a parent domain are dropped by the allowed-origin filter; decide whether an adapter may declare that it needs them.
- **Depends on:** AAB-013
- **Done when:** each of the three has a decision recorded in an ADR or the adapter guide and a test.
- **Threat model:** VA-15.

### AAB-023 Worker service in Compose

- **Scope:** The Compose file has no worker service, so the worker runs as a host process, and no container holds a key. The Compose stack itself was started by hand on 2026-11-13 and works without a worker. A Compose worker would need: the key directory mounted into it only (read-only, mode 0700 on the host, never into the API); the database connection string; the container engine's socket, which is root-equivalent on the host (so only the supervisor may have it, and the stack's other services must not); a decision on how the worker's own container runs per-job containers with `--network none` and still reaches the egress proxy socket (bind-mount paths must be valid on the host, not inside the worker's container); and a way to connect a new account, because neither the Docker launcher nor a container can show the login window in Phase 2. With the Docker launcher in its default mode the job's browser has no sandbox of its own (AAB-017). Decide whether this is worth doing before the vault service (Phase 3) moves the key out of the supervisor.
- **Depends on:** AAB-017
- **Done when:** `docker compose config` validates the file, the worker starts under Compose, and the README and operations guide describe it. Until then they say Compose has no worker.
- **Threat model:** HO-3.

### AAB-024 Evaluate a seccomp filter for bubblewrap jobs

- **Scope:** No seccomp filter is applied under bubblewrap, and nested user namespaces stay available because Chromium's own sandbox needs them. Evaluate a filter that keeps Chromium working and removes what it does not need.
- **Depends on:** AAB-011
- **Done when:** a filter is applied and the isolation and operation tests pass under it, or the owner accepts the limitation in writing.
- **Threat model:** SB-6.

### AAB-025 Mount code by allowlist, not by hiding secret names

- **Scope:** Secrets inside the mounted code directories (`packages`, the worker's `src`, `node_modules`) are hidden by file-name pattern only. Mount an explicit list of source and dependency directories, or build a minimal tree for the sandbox.
- **Depends on:** AAB-011
- **Done when:** a secret under any name placed inside the repository is invisible to the runner, shown by a test like `W:integration/isolation.test.ts` with an unusual file name.
- **Threat model:** SB-4.

### AAB-026 Test the login handoff on a desktop session and on Wayland

- **Scope:** The handoff was tested only on a private Xvfb display. Run it on the owner's real X11 and Wayland sessions and record the result. With X11 the sandboxed browser can see input to other windows; decide whether sign-in should require Wayland where available.
- **Depends on:** AAB-012
- **Done when:** both display types were exercised by hand or by test, and the operations guide says which work.
- **Threat model:** SB-11.

### AAB-027 Decide whether to re-check long-lived CONNECT tunnels

- **Scope:** A CONNECT tunnel or WebSocket has its resolved address checked when it opens and not again. Decide whether a maximum tunnel lifetime or a periodic re-resolution is worth it.
- **Depends on:** AAB-011
- **Done when:** the decision is recorded and, if adopted, tested.
- **Threat model:** SB-9.

### AAB-028 Test hostile runners through the whole path

- **Scope:** No test replaces the runner with a hostile one and drives a job through the supervisor, so the supervisor's second sanitisation pass, its size and shape checks on login results and its handling of a runner that writes after it was told to stop are tested only at the parsing layer. Add a test runner that returns schema-valid wrong data, undeclared fields, a storage state for an operation job, and floods of output.
- **Depends on:** AAB-011
- **Done when:** each behaviour has a test that goes through `createJobRunner` and the supervisor.
- **Threat model:** SB-1, TA-14.

### AAB-029 Decide how long job results are kept

- **Scope:** Sanitized results are stored in `execution_jobs.result` in plaintext until `AAB_JOB_RESULT_TTL_MINUTES` (default 60) passes. Decide whether results need encryption at rest or a shorter default, and test the purge on PostgreSQL.
- **Depends on:** AAB-015
- **Done when:** the decision is recorded and the purge has a PostgreSQL test.
- **Threat model:** DB-13.

### AAB-030 Confirm the allowed-origins rule and check adapters at registration

- **Scope:** A job may reach only the origins in both the adapter's and the application definition's lists. This is provisional (specification changelog, open question 8 and version 0.3 item 36). Confirm or relax it with the owner. Registration still does not check that the named adapter id and version exist.
- **Depends on:** AAB-015
- **Done when:** the owner has decided, registration rejects an application whose adapter is not registered, and a test covers it.
- **Threat model:** TA-13, F-6.

### AAB-031 Build the images and start the Compose stack in CI

- **Status (2026-11-13):** Written and run locally, not yet on GitHub. `infra/ci/compose-smoke.sh` builds the images, starts the stack with generated secrets, asserts the items under "Done when" plus owner bootstrap, login, a denied operation and the single loopback port, and removes everything; the `containers` job in `ci.yml` runs it. Base images are now pinned by digest. Open until the job has run on GitHub.

- **Scope:** The three images (`aab/broker-api:local`, `aab/dashboard:local`, `aab/browser-runner:local`) and the Compose stack were built and started once by hand on 2026-11-13, and the checks that followed (health through nginx, security headers, 421 for a wrong `Host`, 401 and 403 responses, the API container's read-only root, dropped capabilities, no mounts and no key variable, no outbound connection, the login burst against the memory limit) were manual. CI only validates the Compose file with `docker compose config` and has never run on a hosting service. Two Dockerfiles had already drifted from the workspace (they did not copy the Phase 2 packages) without CI noticing. Add a CI job that builds all three images and starts the stack, and turn the manual checks into assertions. Also decide whether to pin base images by digest (threat model F-14).
- **Depends on:** AAB-002
- **Done when:** a CI job builds the three images, starts the stack, waits for healthy, and asserts at least the health route, the security headers, 421 for an unexpected `Host`, 401 for an unauthenticated API request, and the API container's user, read-only root and absence of `AAB_KEK_DIR` and bind mounts, and the job has run at least once on a hosting service.
- **Threat model:** HO-3, HO-8, F-4, F-5, F-9, F-14.
