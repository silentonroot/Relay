# ADR-014: Vault service, service identity and worker capabilities

- **Status:** Accepted (2026-11-16, by the owner, with the recommended answers to the open questions in [docs/phase-3.md](../phase-3.md) section 4)
- **Date:** 2026-11-16
- **Needed by:** Phase 3
- **Relates to:** [ADR-001](ADR-001-trust-boundaries-worker-isolation.md) (INV-6, INV-8, INV-10,
  INV-11), [ADR-002](ADR-002-login-handoff-session-snapshots.md),
  [ADR-003](ADR-003-local-vault-root-key.md), [ADR-004](ADR-004-job-queue.md),
  [ADR-009](ADR-009-audit-integrity.md), [ADR-010](ADR-010-tenant-ready-schema.md),
  [ADR-012](ADR-012-synthetic-only-dependency-review.md),
  [ADR-013](ADR-013-per-job-sandbox-egress-proxy.md)

## Context

At the end of Phase 2 the worker's supervisor loads the key-encryption keys (KEKs) at start
(`services/browser-worker/src/main.ts`, `loadLocalKek`) and calls `sealSecret` and `openSecret`
directly through its session store (`src/session-store/index.ts`). Nothing but the supervisor's own
code decides which snapshot it opens. ADR-001 and ADR-013 record this as the known weakness of the
first slice: a compromised supervisor has the KEK and every session.

Specification Phase 3 asks for four things: sealing and unsealing move into a vault service and the
worker loses the KEK; secrets get versions, revocation and scoped, single-use, expiring worker
capabilities; the vault API is separate from the agent and public API and enforces service identity;
and key versioning, rewrap and crash-safe replacement exist. Its exit criterion is "workers can use
only secrets for authorized jobs; database-only theft yields ciphertext".

What exists and constrains the design (read in the code on 2026-11-16):

- `packages/crypto` already binds every sealed secret to organization, owner, connection, secret id,
  secret type and secret version through AAD format version 1 (`src/aad.ts`), and binds each wrapped
  data-encryption key (DEK) to that AAD plus the KEK version (`src/kek.ts`, `wrapAad`).
  `rewrapSecret` re-wraps a DEK without producing plaintext. No change to the construction is
  needed.
- `vault_secrets` and `vault_secret_versions` exist since migration
  `0003_phase2_execution`. `vault_access_capabilities` does not. `execution_jobs.capability_ref` exists
  as an unused `text` column.
- `vault_secrets.status` is `pending`, `active` or `deleted`. `deleted` is not terminal: a reconnect
  after a `reauth_required` outcome reuses the row, and `putVersion` sets it back to `active` without
  looking at the previous status. There is no secret-level state that can never become active again;
  today only the connection's `revoked` status, checked in the supervisor's transaction, stops a
  revoked connection's secret from being written again.
- The vault repository functions (`ensureSecret`, `putVersion`, `getActive`, `touchAccessed`,
  `deleteForConnection`, `describeForConnection`) take no `Scope` and are not in ADR-010's list of
  unscoped functions.
- There is one database role. Every process that has `DATABASE_URL` can write every table, including
  the audit chain's predecessors and anything the vault would store (ADR-009).
- Lease recovery requeues a retry-safe read whose lease expired (`recoverExpiredLeases`).
- Node.js has no built-in way to read a Unix socket peer's credentials (`SO_PEERCRED`).
- Under the Docker launcher the supervisor has access to the container engine's socket, which is
  root-equivalent on the host (ADR-013).

## Decision

### 1. A separate vault process on Unix sockets

The vault is a new service, `services/vault`, run as its own operating-system process. It is the
only process that loads a KEK provider and the only code that calls `sealSecret`, `openSecret` or
`rewrapSecret`. It has its own database connection, used only through the vault repositories and
`audit.append`.

It listens on Unix-domain sockets only, one per caller role, and never on TCP:

| Role         | Socket (example path)                  | Caller                                 |
| ------------ | -------------------------------------- | -------------------------------------- |
| `api`        | `/run/aab-vault/api/vault.sock`        | broker API                             |
| `supervisor` | `/run/aab-vault/supervisor/vault.sock` | browser worker supervisor              |
| `admin`      | `/run/aab-vault/admin/vault.sock`      | `vault` admin command run by the owner |

The base directory is set by `AAB_VAULT_SOCKET_DIR` (an absolute path; no default under the
repository). The protocol is newline-delimited JSON, one request and one response per line, with a
request id, a 4 MiB line cap, strict schemas from `packages/contracts` and `checkPlainJson` on every
input, the same discipline the supervisor applies to runner output. Binary fields (plaintext,
nothing else) are base64url strings. The vault never puts plaintext, ciphertext, wrapped keys,
tokens or MAC values in a log line or an error.

### 2. Service identity: one socket per role, enforced by the kernel at connect time

On Linux, connecting to a Unix socket requires write permission on the socket file and search
permission on every directory above it. The vault uses that as its identity check instead of reading
peer credentials:

- Each role's directory is created once by the installer, owned by the vault's user and by a group
  for that role (`aab-vault-api`, `aab-vault-supervisor`, `aab-vault-admin`), mode `2750` (setgid, so
  the socket inherits the group). The vault sets its umask to `0117` before listening, so each socket
  is `0660`. The caller's user is the only member of its role's group.
- At start the vault checks every directory and socket: owner, group, mode, not a symbolic link. It
  refuses to start if any is accessible to others, if a role directory is writable by its group, or if
  two roles share a directory or a group. The check uses the same `lstat`/`fstat` discipline as the
  KEK loader.
- The role of a request is the socket it arrived on. No request field names a role, a user or a
  caller, and the vault ignores nothing silently: a request with an unknown field is refused.
- Each operation has a fixed set of allowed roles (section 4). A request from any other role is
  refused with `forbidden` and audited as `vault.request_refused`.

The trade-off against the alternatives:

- **Peer credentials through a native module.** Gives uid and, for audit, pid. Costs a native addon
  with a build step and an install script in the most sensitive process, which ADR-012 item 3 asks us
  to avoid where an alternative exists. The uid it reports is fixed at connect time, as with socket
  permissions, so it adds pid for audit, not a stronger identity. **Not adopted in Phase 3.** If the
  owner wants pid in vault audit records, a candidate module goes through the ADR-012 review first.
- **A small privileged helper** that accepts connections and passes them on with the peer's
  credentials. A second sensitive process and a file-descriptor-passing channel that Node does not
  support for arbitrary descriptors. Rejected.
- **Socket permissions plus a per-role bearer secret.** With separate users the secret adds nothing
  the file permissions do not already give; with one user every process of that user can read the
  secret file. Rejected as the identity mechanism.

Linux is the only supported platform for the vault in Phase 3. On other platforms the vault refuses
to start, because not every platform enforces permissions on socket files.

#### What this means for each deployment shape

- **Separate users (`AAB_VAULT_ISOLATION=separate-uid`, the default).** The vault runs as its own
  user, which alone owns the key directory. The API, the supervisor and the owner's shell run as
  other users, each a member of one role group. Gains: the supervisor and the API cannot read the KEK
  files or ptrace the vault; a compromised supervisor cannot call API-only operations, and a
  compromised API cannot redeem a capability. Setting it up needs root once (users, groups,
  directories). The operations guide will describe it; the Compose file gains a vault service with
  the key directory mounted into it only (AAB-023 is where the worker service is added).
- **One user (`AAB_VAULT_ISOLATION=shared-uid`, explicit only).** For a developer laptop. Every role
  socket lives in one `0700` directory of that user. The kernel then cannot tell the roles apart: any
  process of that user can connect to any socket and can read the KEK files directly. What still
  holds: the KEK is not loaded into the supervisor's or the API's memory, so a bug in their code
  cannot leak it; well-behaved code is held to the capability checks; the sandboxed runner reaches
  neither the sockets nor the key (ADR-013). What does not hold: **nothing in this ADR protects
  against code running as that user, a compromised supervisor or a compromised API included.** The
  setting is refused unless set explicitly; the vault, the API and the supervisor log a warning at
  start, and the dashboard's key-status panel shows the mode. No claim in section "What a compromised
  component can and cannot do" beyond the runner row applies to it.
- **Docker launcher.** The supervisor has the container engine's socket, which is root-equivalent on
  the host. With that launcher a compromised supervisor can read the key directory whatever the
  users are. The separate-uid gains for the supervisor row therefore apply to the bubblewrap launcher
  only, and the documents must say so.

### 3. The KEK only in the vault

- The vault loads `LocalFileKekProvider` from `AAB_KEK_DIR` at start, with the ADR-003 checks
  unchanged. It refuses to start if the directory is not owned by its own user (the existing check
  also accepts root; the vault narrows that to its own user).
- The supervisor and the API **refuse to start** if `AAB_KEK_DIR` is set in their environment (the
  API does this today; the worker's configuration currently requires the variable and is inverted).
- At start both ask the vault for `hello` (section 4), which returns the vault's key directory path
  and isolation mode. Each then tries to open that directory for reading. If it can, and the mode is
  `separate-uid`, it refuses to start, naming the path. In `shared-uid` mode it starts with the
  warning above.
- An import-boundary test extends the existing one: no module under `services/browser-worker` or
  `services/broker-api` imports `sealSecret`, `openSecret`, `rewrapSecret` or a KEK provider.
- The vault process disables core dumps through its service definition (`LimitCORE=0` or the
  equivalent), is not run as root, and is started with an empty environment apart from its settings.

### 4. Vault operations

Every response is either a result or an error with a code from `ErrorCode` in `packages/contracts`
(`forbidden`, `not_found`, `validation_failed`, `conflict`, `service_unavailable`, `internal_error`).
A capability that is refused for any reason returns `forbidden` with no detail; the reason goes to
the audit event (section 8). The caller cannot learn from the response which check failed.

| Operation               | Roles          | Request fields                                                                           | Result fields                                                                                    |
| ----------------------- | -------------- | ---------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| `hello`                 | all            | `protocolVersion`                                                                        | `protocolVersion`, `isolation`, `keyDirectory`, `role`                                           |
| `authorizeJobAccess`    | `api`          | `jobId`, `ttlSeconds`                                                                    | `capabilityId`, `expiresAt`                                                                      |
| `issueAccessCapability` | `supervisor`   | `capabilityId`, `jobId`, `workerId`, `attempt`, `ttlSeconds`                             | `token`, `tokenExpiresAt`, `secretVersion`                                                       |
| `readForWorker`         | `supervisor`   | `token`, `jobId`, `connectionId`, `operation`                                            | `secretType`, `secretVersion`, `kekVersion`, `argumentsHash`, `plaintext`                        |
| `completeLogin`         | `supervisor`   | `token`, `jobId`, `connectionId`, `plaintext`, `externalAccountHint`, `sessionExpiresAt` | `secretId`, `secretVersion`, `kekVersion`                                                        |
| `status`                | `api`, `admin` | none                                                                                     | `isolation`, `kekVersions`, `currentKekVersion`, `versionsByKek`, `missingKekVersions`, counters |
| `rewrap`                | `admin`        | `batchSize`, `maxBatches`                                                                | `rewrapped`, `skipped`, `failed`, `remaining`                                                    |
| `kekRetirementCheck`    | `admin`        | `kekVersion`                                                                             | `referencingVersions`, `safeToRemove`                                                            |

There is no operation that returns plaintext to the `api` or `admin` role, no listing of secrets with
values, and no operation that accepts ciphertext from a caller. `plaintext` in `completeLogin` is the
origin-filtered storage state the supervisor captured, size-capped at the existing 2 MiB; the vault
treats it as opaque bytes of type `browser_session` and does not parse it.

Revocation and deletion are **not** vault operations; see section 7.

### 5. Capabilities: authorized at policy time, issued at claim time

A capability has two stages, both recorded on one `vault_access_capabilities` row.

**Stage 1, authorization (API, right after the job commits).** The execute route already commits the
`policy.evaluated` event, the job and the idempotency record in one transaction. After that commit
the API calls `authorizeJobAccess(jobId, ttlSeconds)`. The vault, in one transaction:

1. loads the job and requires `status = 'queued'`, `capability_ref IS NULL` and no cancellation;
2. for an operation job, loads the audit event named by `policy_decision_id` and requires event type
   `policy.evaluated`, decision `allow`, and the job's organization, agent, connection and operation;
3. requires the connection to be `active` (operation) or `authenticating` (login), and finds or
   creates the connection's `browser_session` secret row (`pending` when new), refusing if it is
   `revoked`;
4. inserts the capability row with purpose `read` (operation job) or `seal` (login job), the binding
   (organization, job, connection, operation, agent, secret id, the job's `arguments_hash`), `issued_at`
   and `expires_at`, and an authorization MAC over all of them (section 6);
5. sets `execution_jobs.capability_ref` to the capability id with a conditional update
   (`WHERE id = $job AND capability_ref IS NULL AND status = 'queued'`);
6. appends `vault.capability_authorized`.

The claim query gains `capability_ref IS NOT NULL`, so a job without an authorization is never
claimed. If the call fails or the vault is unreachable, the API ends the job as `failed` with
`vault_unavailable` (conditional on it still being queued without a capability) and its audit event,
and the response carries that outcome. If the API stops between the commit and the call, the API's
maintenance loop ends queued jobs that have had no capability for more than 60 seconds the same way.

**Stage 2, issue (supervisor, at claim time).** For an operation job the supervisor claims the job,
re-evaluates policy as it does today (INV-3) and, immediately before it needs the session, calls
`issueAccessCapability`. For a login job it calls it after the owner has signed in and the storage
state has been captured and filtered, immediately before `completeLogin`. The vault, in one
transaction:

1. requires the job to be `running` under that `workerId` with that `attempt`, with no cancellation
   requested;
2. verifies the authorization MAC;
3. for a `read` capability, requires the secret to be `active` and binds its current active version;
   for a `seal` capability, binds the current active version, or 0 when there is none, as the version
   the login is expected to replace;
4. generates a 256-bit token (`generateToken`), and sets `token_hash`, `token_issued_at`,
   `token_expires_at`, `worker_id`, `attempt` and `secret_version` with one conditional update that
   also requires `token_hash IS NULL`, `revoked_at IS NULL` and `expires_at > now()`, then writes the
   token MAC (section 6);
5. appends `vault.capability_issued`;

and returns the token once. The token is never written anywhere in plaintext: not to the database,
the job row, a log, the audit trail or a file. It lives in the supervisor's memory from this call to
the next one.

**Stage 3, redeem.** `readForWorker` or `completeLogin`, called straight after, consumes the token in
one conditional update (section 6) and either returns the plaintext or seals the new version.

**Why this split.** The raw token never needs to travel between processes through the database: the
API never sees a token, and the supervisor holds one for the milliseconds between two calls on one
socket, bounded by `token_expires_at` (default 30 seconds). The authorization stage is what makes the
capability meaningful against a compromised supervisor in a separate-uid deployment: the supervisor
can write job rows (one database role), but only the `api` socket can make the vault authorize one,
and a capability row the supervisor writes itself fails the MAC check. The token stage matches the
specification's `issueAccessCapability`/`readForWorker` pair, records exactly which worker attempt
read which secret version, and keeps the redeeming call a possession check, which a later executor
in another process (API workers, Phase 8) needs. Within one supervisor it adds little over the
socket identity, and this record does not claim more.

**Lifetimes.** `ttlSeconds` is required in both requests; there is no default inside the vault.
It must be a safe integer. Authorization lifetime: 10 to 3,600 seconds; the API sends
`AAB_VAULT_AUTHORIZATION_TTL_SECONDS` (default 600) for operations and the login timeout plus 60
seconds for logins. Token lifetime: 1 to 120 seconds; the supervisor sends
`AAB_VAULT_TOKEN_TTL_SECONDS` (default 30). Each service refuses to start if its setting is missing
after defaults are applied, not an integer, or out of range. The token's expiry never exceeds the
authorization's. Database `CHECK` constraints repeat both upper bounds, so a row written around the
vault cannot be "forever" either.

**Expiry before claim.** A job still queued when its authorization expires is claimed and then fails
at stage 2 with `vault_denied`. The agent submits a new request.

**Retries.** A capability serves one attempt. Lease recovery changes in Phase 3: a retry-safe read is
requeued only if its capability was never issued (the supervisor stopped before contacting the vault).
Otherwise recovery revokes the capability and ends the job as `failed` with `worker_failure`; the
agent submits a new request, which is evaluated by policy again. This removes automatic retries of
reads after a session has been handed out, which Phase 2 allowed.

### 6. Consuming a capability: one conditional update, inside the authenticated binding

**The consume is one statement.** In the vault's transaction, after taking the locks of section 7,
`readForWorker` runs one `UPDATE vault_access_capabilities ... SET used_at = now() ... RETURNING`
whose `WHERE` clause holds every validity condition: `token_hash` equals the hash of the presented
token, `purpose`, `job_id`, `connection_id` and `operation` equal the request, `used_at IS NULL`,
`revoked_at IS NULL`, `token_expires_at > now()`, `expires_at > now()`, the job is `running` under the
bound worker and attempt with no cancellation, the secret is `active` with the bound version as its
active version, and the connection is `active`. `completeLogin` uses the same form with `purpose =
'seal'` and the connection `authenticating`. There is no read-then-write path: no code reads a
capability, decides, and then marks it used. Zero rows means refused. Only then does the vault
read the row by token hash to choose the reason code for the audit event; that read labels the
refusal and never changes the outcome.

**Freshness and uniqueness are inside the MAC.** The vault derives a MAC key from the current KEK
with HKDF-SHA-256 (`node:crypto`, info `aab.vault.capability-mac.v1`) and records the KEK version it
used. The authorization MAC is HMAC-SHA-256 over the canonical JSON of a layout version, capability
id, purpose, organization, job, agent, connection, operation, secret id, arguments hash, `issued_at`
and `expires_at`. The token MAC covers all of those plus the token hash, worker id, attempt, bound
secret version, `token_issued_at` and `token_expires_at`. After the consume returns the row, the
vault verifies both MACs with a constant-time comparison before it opens anything. A row inserted or
edited by a database writer, or a binding changed after issue, fails here; the consumed row stays
consumed and the rejection is audited with reason `integrity`. Used capability ids stay in the table
with `used_at` set; rows are purged only seven days after `expires_at`.

**After the consume.** `readForWorker` opens the bound version with the AAD rebuilt from the
connection row and the capability's binding (never from columns stored beside the ciphertext),
returns the plaintext and the bound `argumentsHash`, and appends `vault.secret_read` and updates
`last_accessed_at` in the same transaction as the consume. If a MAC check or the open fails, the
transaction commits the consume together with a `vault.capability_rejected` event and nothing else:
the capability is spent, no `vault.secret_read` is written and no plaintext is returned. The
supervisor checks that the hash of the job's
`arguments` equals `argumentsHash` before it starts the runner (threat model PE-14).

### 7. Revocation and crash-safe writes

**Revocation is a database transaction, not a vault call.** Revoking a connection already runs in
one API transaction (`routes/resources.ts`). Phase 3 extends it, keeping one lock order: lock the
connection row `FOR UPDATE`; set it `revoked`; set its secrets to the new terminal status `revoked`
and delete their versions; set `revoked_at` on every unused capability of the connection; cancel or
flag its jobs (as today); append `connection.revoked`, `vault.secret_revoked` and
`vault.capability_revoked`. Revoking a grant or disabling an agent sets `revoked_at` on the unused
capabilities of that agent and connection in the same transaction as the grant change. The vault is
not needed for any of this, so revocation works while the vault is down. This deviates from
specification §6.3, which lists `revokeSecret` and `deleteSecret` as vault operations: removing
authority needs no key, and must commit atomically with the connection change and its audit event.
"Delete stored session" for the dashboard (B5) is the same transaction without the connection
becoming `revoked`: versions deleted, secret `deleted`, capabilities revoked, connection to
`reconnect_required`.

**Revocation wins over in-flight work.** Every vault transaction that reads or writes a connection's
secret first locks that connection row: `FOR SHARE` to read, `FOR UPDATE` to seal. Revocation takes
the same row `FOR UPDATE` first. Whichever commits first is what the other sees: a read or login
completion that starts after a committed revocation finds the connection, secret or capability
revoked and changes nothing; a revocation that starts after a committed read or seal deletes what
was written and cancels the job. Revocation also writes the capability rows the consume writes, so
even a statement that did not take the lock re-checks `revoked_at` on the conflicting row. A
`revoked` secret can never become active again: the vault's writes require a status other than
`revoked`, and a database trigger rejects any update that moves a `vault_secrets` row out of
`revoked` (the same kind of backstop as the audit trigger in migration 0002, with the same limit: the
table owner can disable it).

**Replacement (login completion).** `completeLogin` runs one transaction: lock the connection
`FOR UPDATE` and require `authenticating`; consume the seal capability (section 6); lock the secret
row and require that it is not `revoked` and that its active version is the version bound at issue
(compare-and-set; 0 means none); re-apply the existing identity rule for the account hint; seal the
plaintext as version `last_version + 1`; insert it; move the active pointer with a conditional update
on the expected previous version; delete the previous version; move the connection to `active` and
record the session metadata; append `vault.secret_stored` and `connection.auth_completed`; complete
the login job under the bound worker. A failure at any point rolls back everything, and the previous
version stays the active one. Sealing, connection activation and job completion are in one
transaction because separating them would leave a stored session on a connection the broker
considers unauthenticated, or the reverse (INV-10).

**Rewrap (KEK rotation).** A rewrap changes two columns of one version row, never the ciphertext,
and is a compare-and-set on what was read:
`UPDATE vault_secret_versions SET wrapped_dek = $new, kek_version = $to WHERE id = $id AND kek_version = $from AND wrapped_dek = $old`,
with `vault.secret_rewrapped` appended in the same transaction. A version replaced, deleted or
revoked while it was being rewrapped matches no row and is counted as skipped. A single-row update is
atomic, so a crash leaves each version wrapped under either the old or the new KEK, and both are
readable while both files are present. Running `rewrap` again continues where it stopped. No step of
a rewrap inserts a row or changes a status, so a rewrap cannot resurrect a revoked secret.

### 8. Key versions and retirement

1. The owner generates the next KEK with the existing `init-kek` script, run as the vault's user. It
   moves from the worker to `services/vault`. Generation never overwrites a file (ADR-003).
2. The owner restarts the vault. It loads every version and wraps new DEKs under the highest. Keys
   are read only at start.
3. The owner runs `vault rewrap` through the admin socket until `remaining` is 0. `vault status`
   shows how many versions each KEK version still wraps.
4. `vault kekRetirementCheck` reports `safeToRemove` when no version references the old KEK. The
   owner then removes the file. The vault never deletes a key file.
5. A version whose KEK file is missing cannot be opened. The vault starts anyway, lists the missing
   versions in `status`, and refuses reads of those versions with a defined error (`vault_denied` for
   the job, `vault.capability_rejected` with reason `key_unavailable`). It does not refuse to start,
   because revocation and the other secrets must keep working.

DEK rotation is a replacement: a new login seals a new version under a new DEK. Phase 3 adds no
re-encryption of an existing version.

The capability MAC key is derived from the current KEK. A capability authorized under the previous
KEK version stays verifiable while that file is loaded, and capabilities live at most one hour, so
retirement after a rewrap cannot strand a live capability that matters.

### 9. Fail closed

- If the vault is unreachable, returns an error or times out (5 seconds per request), the API ends
  the job with `vault_unavailable`, and the supervisor ends a claimed job with `vault_unavailable`.
  The supervisor does not claim jobs while its last `hello` failed. There is no fallback to opening a
  secret in the caller, and the caller has no KEK to fall back to.
- A refused capability ends the job with `vault_denied`. A missing active secret at stage 2 ends an
  operation job as `reauth_required`, as a missing snapshot does today.
- Both job error codes are new (`JobErrorCode` and the `execution_jobs_error_code_check` constraint).
  Agent-visible results map them to `service_unavailable` and `denied` respectively.
- A misconfigured vault (unsafe key directory, unsafe socket directory, bad lifetime setting, unknown
  isolation mode, non-Linux platform) refuses to start, naming the setting or path and never a value.

### 10. Audit

The vault appends events with `actor_type = 'system'` and `actor_id = 'vault'`, in the same
transaction as the change they describe. The events it adds: `vault.capability_authorized`,
`vault.capability_issued`, `vault.capability_rejected`, `vault.request_refused`,
`vault.secret_rewrapped`; the API adds `vault.secret_revoked` and `vault.capability_revoked`;
`vault.secret_read`, `vault.secret_stored` and `vault.secret_deleted` keep their names and are now
written by the vault (read, stored) or by the revocation transaction (deleted). Metadata holds ids,
version numbers, the role, the reason code and counts; never a token, a hash of a token, a MAC, a
wrapped key or plaintext.

`vault.capability_rejected` is the theft signal and is kept separate from ordinary failures. Its
`reason` is one of `unknown_token`, `used`, `revoked`, `expired`, `binding_mismatch`, `integrity`,
`job_not_running`, `secret_not_active`, `connection_not_active`, `key_unavailable`. A vault that
cannot reach the database, or fails internally, logs `vault request failed` and writes no rejection
event. A rejected request whose job id does not resolve to an organization cannot be put on a
per-organization chain (ADR-009); it is logged by the vault and counted in `status`, and this is a
known gap. Expiry can also be honest slowness; the dashboard shows the reasons separately so that an
owner can tell a slow worker from replayed tokens.

A rejection where nothing was consumed (an unknown, used, revoked or expired token, a binding that
does not match) and a `vault.request_refused` event are written in their own transaction, because
there is no state change to join; a rejection after a consume commits with the consume (section 6). Everything else follows the rule that backlog
AAB-019 exists to restore for lease recovery: no state change commits without its event.

### 11. Schema changes

Two migrations, both written to run on an empty database and on a database holding Phase 2 rows.
`0003` is already taken by the Phase 2 execution migration, so they are `0004` and `0005`.

- `0004_job_arguments_hash` (step B0.5): `execution_jobs.arguments_hash` (hex SHA-256 of the canonical
  JSON of the arguments the policy engine judged, obligations applied; required for operation jobs
  created from now on; existing rows backfilled from their stored arguments). As built (2026-11-16): the hashed text is
  `aab.job-arguments.v1\n` followed by the canonical JSON of `{agentId, arguments, connectionId,
operation, organizationId, policyDecisionId, retrySafe, timeoutMs}` (`jobArgumentsHashInput` in
  `packages/contracts`, `hashJobArguments` in `packages/database`, outside `@aab/crypto` so the
  supervisor keeps the ADR-013 import boundary), so the hash also binds the job row the arguments
  were judged for; a check constraint requires it on operation jobs and forbids it on login jobs;
  the backfill reproduces the canonical JSON in SQL with temporary functions that the migration
  drops again. The hash is **not** written to the `policy.evaluated` metadata: an unkeyed SHA-256 of
  low-entropy arguments can be brute-forced from the audit log. It may be added to audit once B3
  keys it (the capability MAC binds it). The supervisor also refuses a job whose arguments policy
  would change at run time (`arguments_changed_by_policy`), so the runner receives exactly the
  hashed arguments.
- `0005_phase3_vault` (step B1):
  - `vault_access_capabilities`: id, organization_id, job_id, agent_id (null for login), connection_id,
    secret_id, purpose (`read` or `seal`), operation (null for login), arguments_hash, issued_at,
    expires_at, authorization_mac, mac_kek_version, worker_id, attempt, secret_version, token_hash
    (unique, hex), token_issued_at, token_expires_at, token_mac, used_at, revoked_at, revoked_reason,
    created_at. Foreign keys to the job, connection and secret. `CHECK`s: `expires_at > issued_at`,
    `expires_at <= issued_at + interval '1 hour'`, token expiry at most 120 seconds after issue and
    not after `expires_at`, `used_at` only with a token. A partial unique index allows one unused,
    unrevoked capability per job.
  - `execution_jobs.capability_ref` becomes `uuid` with a foreign key to the capability (the column
    holds no values in Phase 2; the migration fails loudly if a non-UUID value is present).
  - `vault_secrets.status` gains `revoked`, with the trigger of section 7. Secrets of connections that
    are already `revoked` move from `deleted` to `revoked`.
  - `execution_jobs_error_code_check` gains `vault_unavailable` and `vault_denied`.
- Existing sealed snapshots stay as they are. AAD version 1 already binds organization, owner,
  connection, secret id, type and version, and the envelope is unchanged, so no row is re-encrypted.
  The migration test seals a synthetic Phase 2 snapshot with the Phase 2 code, migrates, and opens it
  through the vault.

The vault repository functions stay unscoped, because the vault acts for the broker, not for a
signed-in user. They are added to ADR-010's list by name when ADR-010 is next corrected, together
with the new capability functions; the dashboard's metadata reads (B5) get scoped versions.

### 12. Dashboard metadata (step B5)

Metadata only, through scoped repository reads and the vault's `status` (role `api`): per connection,
the secret type, status, active version number, KEK version, last access, and the counts of
capabilities authorized, used, revoked and rejected (by reason) in the last 24 hours; for the
installation, the KEK versions present, versions per KEK version, missing KEK versions, the isolation
mode and the ADR-003 statement of what the key protects. Actions: revoke the connection (exists),
delete the stored session, revoke outstanding capabilities. Rewrap and key retirement stay on the
admin command; the `api` role cannot start them. Nothing on the dashboard or in an API response
carries plaintext, ciphertext, a wrapped key, a token, a token hash or a MAC.

Accepted limitation (step B5a): `GET /v1/vault/status` reports installation-wide values (versions
per KEK version, the vault's counters, including rejection counters over all organizations) to the
owner of any organization, because there is one vault and one key per installation. This is accepted
for a single-owner or single-organization installation. Follow-up: restrict the route to an
installation administrator before multi-tenant use. The per-connection reads are scoped to the
connection's owner and organization. "Delete stored session" cancels the connection's jobs as
revoking a connection does, so no worker is refused for a capability the owner revoked; "revoke
outstanding capabilities" cancels the queued jobs of the capabilities it revoked and leaves running
jobs alone (their read was already consumed).

### Implementation notes

- The vault caches no plaintext, no policy decision and no capability. (B0.5 (c), 2026-11-16: the
  only in-process cache in the code base is the adapter registry, keyed by adapter id and exact
  version; `packages/adapter-sdk/test/define.test.ts` shows two versions of one id never resolve to
  each other.) Every read goes to the database and the KEK, and a plaintext lives only for the one
  call that needs it.

### As built in step B1 (2026-11-16)

Migration `0005_phase3_vault` and the repositories in `packages/database` follow section 11. Where
the code differs from, or is more exact than, the text above:

- **Clock.** Every function takes `now: Date` from its caller (the vault passes `new Date()` just
  before the call), as the rest of the package does, but the database clock is the authority over
  it. A consume compares expiry with `now` and also with `statement_timestamp()`
  (`token_expires_at > statement_timestamp() AND expires_at > statement_timestamp()`, no grace
  interval), so a caller with a stale `now` cannot extend a capability. `insertAuthorization` and
  `issueToken` refuse a `now` more than `MAX_CLOCK_SKEW_SECONDS` (5) away from `statement_timestamp()`,
  computed in SQL. (`expires_at > statement_timestamp()` is implied by the token check and the
  `token_expires_at <= expires_at` CHECK; it stays as a second line.) `describeForRejection` labels
  `expired` when either clock says so. `authorizationWindow(now, ttlSeconds)` returns the exact
  `issued_at` and `expires_at` strings the database will store, so the vault can compute the
  authorization MAC before it calls `insertAuthorization`.
- **Lifetimes** are validated in the repository as well as in the vault (a safe integer in 10 to
  3,600 for an authorization and 1 to 120 for a token; no default); the token expiry is
  `least(now + ttl, expires_at)` in SQL.
- **`insertAuthorization`** receives the binding the vault computed its MAC over and requires each
  value to equal the job row's own column in the same `INSERT ... SELECT`; for an operation it also
  requires the `policy.evaluated` event named by `policy_decision_id` (decision `allow`, same
  organization, agent, connection and `operation` metadata, written within one hour of the job's
  `created_at`) and that what the decision rested on still holds: the agent is `active`, at least
  one grant listed in the event's `matchedGrantIds` is still an `allow` grant of exactly that agent,
  connection and operation, not revoked and not expired (at `now` and at `statement_timestamp()`),
  and no `deny` grant of that agent, connection and operation that is live was created after the
  decision (conservative: the grant's constraints are not re-evaluated in SQL). A decision that
  names no grant is refused. For a read it locks the agent row `FOR SHARE` before the connection
  row; `grants.revoke` and `agents.disable` take the agent row `FOR NO KEY UPDATE` before they
  revoke, so an authorization either commits before the revocation (and is revoked by it) or waits
  and is refused. `grants.revoke` does not cancel queued jobs: a queued job whose grant is revoked is
  refused at authorization (the vault fails it `vault_denied`), unlike a revoked connection, whose
  queued jobs the route cancels because they have no other path to end. `execution_jobs` has a
  partial unique index on `policy_decision_id` (one decision authorizes one job). It sets
  `capability_ref` with the conditional update of section 5 in the same transaction.
- **`issueToken`** is one conditional `UPDATE ... RETURNING` plus a second statement that stores the
  token MAC: it takes a `computeTokenMac(row)` callback, runs it inside the transaction on the row the
  first statement returned (which holds the bound secret version and the token times) and refuses
  to commit without it. The statement also requires `authorization_mac` to equal the MAC the vault
  verified. A consume additionally requires `token_mac IS NOT NULL`. `issueToken` locks the job row
  `FOR SHARE` in a statement of its own before the `UPDATE`: an `UPDATE ... FROM` does not re-read the
  joined job after waiting for the capability row, so without that lock a lease recovery that
  committed in the meantime would be judged from a stale snapshot and a token issued for a requeued
  job. Lease recovery reads the capability `FOR UPDATE`.
- **Consume** (`consumeRead`, `consumeSeal`) is one `UPDATE ... FROM job, connection, secret
(LEFT JOIN active version) ... RETURNING`, after taking the connection row `FOR SHARE` (read) or
  `FOR UPDATE` (seal), in the caller's transaction when it is called inside one (no savepoint of its
  own, so the lock is held until the caller commits). For a seal capability the bound version (0 when none) must still be the
  secret's active version, so a moved pointer is refused at the consume as well as at `putVersion`.
  The function writes **no** audit event: the event depends on the MAC and open checks that follow
  (`vault.secret_read`, or `vault.capability_rejected` when one fails), so the vault appends it inside
  the same `repositories.transaction`; a failure of any later step rolls the consume back, which the
  tests show. `describeForRejection` labels a refusal afterwards; its order is `unknown_token`,
  `binding_mismatch` (purpose, job, connection, operation, a different worker or attempt, a job that
  no longer points at the capability), `integrity` (no token MAC), `revoked`, `used`, `expired`,
  `job_not_running` (not running, or cancellation requested), `connection_not_active`,
  `secret_not_active` (secret status or a moved version). `key_unavailable` is set by the vault only.
  Presented ids are echoed into the event only when they exist (and the connection when it is the
  job's), so an unknown token cannot name an arbitrary id into the chain.
- **Revocation** sets `revoked_at` and a `revoked_reason` (a closed list, repeated by a CHECK) on
  _unused_ capabilities only; a capability consumed before the revocation committed stays `used`, and
  the revocation deletes what the read or seal left, per section 7. A multi-row revocation first
  locks its target rows with `SELECT id ... ORDER BY id FOR UPDATE`, then updates them, so two
  overlapping revocations (an agent disabled while one of its connections is revoked) cannot
  deadlock. `connections.revoke`,
  `grants.revoke` and `agents.disable` call the capability revocation inside their own transactions;
  a revoked grant of any effect revokes the agent's unused capabilities for that connection. The
  `vault.capability_revoked` event is written inside, only when something changed. The
  `vault.secret_revoked` event and the route-level test stay with B3.
- **`vault_secrets.status`.** `deleteForConnection` marks the secrets `revoked` when the connection
  is `revoked` and `deleted` otherwise ("delete stored session"); it locks the connection row first.
  The trigger also refuses a revoked secret with a non-null `active_version_id`, and a second
  trigger refuses inserting a version for a revoked secret (SQLSTATE `check_violation`). The data
  migration changes only `status`; it does not delete any row.
- **Migration guards.** `0005` refuses to run when _any_ `execution_jobs.capability_ref` is non-null
  (not only a non-UUID), with an error naming the column and no value; when two jobs share one
  `policy_decision_id` (before it creates the unique index); and when a revoked connection's secret
  still has an active version pointer or version rows (Phase 2 revocation deleted them; the status
  change is not applied over ciphertext that is still there).
- **`ensureSecret` and `putVersion`** also refuse a `revoked` connection (the connection row is
  locked `FOR SHARE` first), which closes the window between `connections.revoke` and the
  `deleteForConnection` that follows it. **`putVersion`** refuses a `revoked` secret and takes an optional `expectedActiveVersion` (0 for
  none): the pointer moves only from that version, as a conditional update under the row lock.
  `rewrapVersion` also takes the connection `FOR SHARE` and skips revoked secrets and connections.
- **Audit metadata** names its keys `vaultEntryId`, `entryVersion`, `accessTtlSeconds`,
  `accessExpiresAt`, `keyVersionFrom` and `keyVersionTo`, because the audit redactor replaces the
  value under any key containing `secret`, `token` or `kek`. `actor_id` is null for `system`
  events (the column is a UUID, so section 10's `'vault'` cannot be stored there).
- **Retention.** `purge` deletes capabilities of finished jobs more than seven days after
  `expires_at` and clears the job's `capability_ref` in the same statement; it writes no event.
- **Phase 3 claim and recovery rules** exist as the options `requireCapability` and
  `capabilityAware`, defaulting to the Phase 2 behaviour; B3 switches them on (section 5 describes
  the rules). Under `capabilityAware` an unissued retry-safe read is requeued with its capability
  kept; an issued one, a non-retry-safe operation and a login have their unused capability revoked
  (`lease_recovery`) in the same transaction, and the job ends `failed`, `outcome_unknown` and
  `failed` respectively. The capability is read `FOR UPDATE` so the decision cannot be overtaken by
  an `issueToken`.
- **What B2 must guarantee** (the repositories cannot): see "B2 must guarantee" in
  [`docs/phase-3.md`](../phase-3.md).

### As built in step B2a (2026-11-17)

`services/vault` (`@aab/vault`) exists as a skeleton: configuration, socket safety, listeners, the
wire protocol, `hello`, KEK loading and MAC key derivation. Every other operation validates the role
and its parameters and answers `not_implemented`; B2b replaces the stubs. The service does not open a
database connection yet (it validates `DATABASE_URL` only). Where the code differs from, or is more
exact than, the text above:

- **Contracts first.** `packages/contracts/src/vault.ts` holds every request and result schema
  (all `.strict()`), the role names, `VAULT_OPERATION_ROLES` (the section 4 table as data), the limits
  and `VAULT_ERROR_TO_ERROR_CODE`. Wire shape: request `{ id, operation, params }`, response
  `{ id, ok: true, result }` or `{ id, ok: false, error: { code } }`. The error codes are the
  section 4 ones plus two protocol-level codes: `malformed` (framing, envelope, unknown operation or
  bad parameters; reads as `validation_failed` in the error contract) and `not_implemented` (reads as
  `service_unavailable`). `id` is `null` in a response when the line gave no usable one. Order of
  checks: line cap, `JSON.parse`, `checkPlainJson`, strict envelope, known operation, role allowed
  (`forbidden` before parameters are looked at, so a refused call learns nothing about the schema),
  strict parameters, handler, result schema.
- **Line cap by role.** Section 1 says one 4 MiB cap. As built: 64 KiB on the `api` and `admin`
  sockets, 4 MiB on the `supervisor` socket only, the one socket that carries a session
  (`completeLogin`, `readForWorker`; plaintext is base64url of at most 2 MiB). A longer line is
  answered `malformed` once and the connection is closed. Requests on one connection are answered in
  order and one at a time; an empty line is `malformed`.
- **Limits.** Per role: connections (default 16, 1 to 256; the next one is answered
  `service_unavailable` and closed), idle timeout (default 60 s), request timeout (default 10 s; it also
  bounds how long a partial line may take to complete, and a request that outlives it is answered
  `service_unavailable` once, with its result discarded). Settings: `AAB_VAULT_MAX_CONNECTIONS`,
  `AAB_VAULT_IDLE_TIMEOUT_MS`, `AAB_VAULT_REQUEST_TIMEOUT_MS`.
- **Configuration.** `AAB_KEK_DIR`, `AAB_VAULT_SOCKET_DIR` (absolute, normalized, at most 100 bytes
  once `/supervisor/vault.sock` is appended), `AAB_VAULT_ISOLATION` (`separate-uid` by default),
  `AAB_VAULT_GROUP_API`, `AAB_VAULT_GROUP_SUPERVISOR` and `AAB_VAULT_GROUP_ADMIN` (a group name or a
  numeric gid; required and distinct in `separate-uid`, refused in `shared-uid`),
  `AAB_VAULT_AUTHORIZATION_TTL_SECONDS` (10 to 3,600, default 600), `AAB_VAULT_TOKEN_TTL_SECONDS`
  (1 to 120, default 30), `DATABASE_URL`. Numbers are strict decimal integers (`1e2`, `0x10`, ` 5`,
  `5.0` and a blank value are refused). A blank `AAB_VAULT_ISOLATION` is refused, not defaulted.
- **Socket safety** (`src/socket-safety.ts`). Checked before any key is read: Linux only; not root;
  the socket directory is absolute, has no symbolic link in any component (its `realpath` equals the
  configured path), exists, is owned by the vault's user, is not under the repository root (best
  effort; the root is this checkout) and does not contain or sit inside the key directory. The
  **base** directory is checked more loosely than section 2's "no access for others": it must not be
  writable by group or other and not readable by other, because in `separate-uid` the three role
  groups share no common group and need search (`x`) on it; in `shared-uid` it must be 0700. Each
  **role** directory must be a real directory owned by the vault's user, with no `other` bits;
  `separate-uid`: mode exactly 0750 or 2750 and the role's group (the group may search, never write);
  `shared-uid`: exactly 0700. A missing role directory is created (mode set explicitly, because the
  umask would otherwise strip the search bit) and given to its group, so the vault user must belong to
  that group; the installer may also create them. Roles must resolve to distinct groups, none of them
  the vault's own primary group, and to distinct directories (`dev:ino`). A path at a socket location
  is removed only if it is a socket owned by the vault's user that nothing is listening on (a probe
  connect); a symbolic link, a regular file, a directory, another owner's socket or a live socket
  refuses the start. After `listen` the vault sets the socket's group and mode (0660, 0600 in
  `shared-uid`) explicitly and checks them again; `main.ts` also sets the umask to 0117. Shutdown
  closes the listeners, destroys connections and removes only sockets that are still its own.
  `separate-uid` with real groups is tested where the user has three supplementary groups; the same
  rules are tested without groups on fake `stat` results. Not testable without root: two role
  directories that are one inode (a bind mount).
- **No TCP.** Each listener is `listen({ path })`; a test compares the TCP `LISTEN` entries of
  `/proc/net/tcp` and `tcp6` before and after start and checks every `server.address()` is a path.
- **`hello`.** Returns `protocolVersion`, `serviceVersion`, `isolation`, `role` (the socket's),
  `keyDirectory` and `currentKekVersion`.
- **Keys.** `LocalFileKekProvider.load` with the ADR-003 checks, plus the narrowing of section 3
  (the directory must belong to the vault's own user, not root). The capability MAC key of each KEK
  version is `deriveKey(kek, { info: 'aab.vault.capability-mac.v1' })` (`@aab/crypto`: `deriveKey`,
  `macSha256`, `verifyMac`, tested against RFC 5869 and RFC 4231 vectors), computed through
  `LocalFileKekProvider.deriveKeyFor(version, purpose)` so the KEK bytes never leave the crypto
  package, and held as `KeyObject`s in `VaultKeys`; every MAC records the KEK version it used.
  The vault keeps a key for every loaded version (section 8 says verification must work while the
  file is loaded), not only the current one.
- **Logging.** pino with a redactor that replaces the value under any key containing a secret word
  (token, mac, hash, kek, dek, key, secret, plaintext, ciphertext, storage state, cookie, password,
  authorization, database, arguments, params, result, request, response and the like) at any depth,
  in any letter case, in log objects and in `child` bindings; bytes are never printed; errors log type and
  code only. A few numeric or path fields are allow-listed (`kekVersion`, `keyDirectory`,
  `requestId`). It is a key-name redactor: a secret written into a message string is not caught, so
  the code never does that.
- **Refusal audit.** A request refused for its role is logged as `vault.request_refused` (role,
  operation, request id) and passed to an `onRequestRefused` hook; the audit append in its own
  transaction (section 10) is B2b's, marked `TODO(B2b)` in `src/server.ts`.

### As built in step B2b (2026-11-19)

`services/vault` serves every operation of section 4 (`src/operations.ts`); `startVault` connects to
`DATABASE_URL` (or an injected handle in tests) and reads its own tables before it listens, so a
vault without a database, or without the migrated schema, refuses to start. `hello` and the role
checks are unchanged. Where the code differs from, or is more exact than, the text above:

- **Secret type.** The stored secret type, and the AAD secret type, is `session_snapshot`
  (`SESSION_SNAPSHOT_SECRET_TYPE`), the Phase 2 value, so Phase 2 rows open unchanged; the sections
  above call it `browser_session`. The `secretType` of the `readForWorker` result is that value
  (`packages/contracts/src/vault.ts` changed from the literal `browser_session`).
- **Refusal versus internal failure (P3-12).** A refused capability is `forbidden` with no detail.
  Anything else that goes wrong (database, key, a bug) is answered `service_unavailable` (the vault
  has no `vault_unavailable` wire code; callers map it to the job error), logged as
  `vault request failed` (error type and code only), counted in `status` and writes no rejection
  event. `internal_error` stays reserved for a result that fails its own schema.
- **After the consume (resolves section 6 against the B1 note).** A refusal found after the consume
  (a MAC mismatch, a missing KEK file, an open that fails) commits the consume together with
  `vault.capability_rejected` (reason `integrity` or `key_unavailable`) in the one transaction and
  returns `forbidden`: the capability is spent. An exception (database error, a failing audit
  append) rolls the whole transaction back, the consume included, and answers `service_unavailable`;
  the capability is then still usable until it expires. A consume that matches no row changed
  nothing: `describeForRejection` and `recordRejection` run afterwards in their own transaction.
- **MACs.** `src/mac.ts`: HMAC-SHA-256 over canonical JSON with a layout label of its own per MAC
  (`aab.vault.capability-authorization.v1`, `aab.vault.capability-token.v1`); the token MAC embeds the
  whole authorization payload. Both use the key of `mac_kek_version` (the table has one column), so a
  capability authorized under a KEK version cannot be used once that file is gone (`key_unavailable`).
  A forged authorization MAC is reason `integrity` (the closed list has no `forged`).
- **authorizeJobAccess** ensures the secret row first in its own transaction (a `pending` row is
  inert), because `insertAuthorization` takes the agent lock before the connection lock and
  `ensureSecret` takes the connection lock; one transaction would invert the order. The
  authorization row, its MAC, `capability_ref` and `vault.capability_authorized` are then one
  transaction (inside `insertAuthorization`). `conflict` for a job that is not queued, already
  authorized, cancelled or refused by the statement; `not_found` for an unknown job.
- **issueAccessCapability** verifies the authorization MAC before it generates the token; the
  conditional update, the token MAC and `vault.capability_issued` are one transaction (inside
  `issueToken`). A refusal is labelled for the audit event only (`unknown_token` for an unknown
  capability, `binding_mismatch`, `integrity`, `used`, `revoked`, `expired`, `job_not_running`,
  `connection_not_active`, `secret_not_active`, `key_unavailable`).
- **readForWorker** is one transaction: consume, version load, both MACs, open (AAD from the
  connection row and the capability), `last_accessed_at` and `vault.secret_read`.
- **completeLogin** is one transaction: consume (connection `FOR UPDATE`), MACs, identity rule,
  seal, `putVersion` with the bound version as the expected active version, connection to `active`
  with its status event, `recordSession`, `vault.secret_stored`, `connection.auth_completed`
  (actor `system`; adapter id and version from the application row) and the job completed under the
  bound worker with that event. A different account than the verified one answers `conflict` and
  rolls everything back (the capability stays unused; the supervisor ends the job
  `identity_mismatch` itself). A moved active pointer is refused at the consume (`secret_not_active`)
  or, if it moves later, by `putVersion` (`conflict`).
- **rewrap** lists versions below the current KEK version in batches (`listForRewrap`, cursor by
  id), rewraps only the wrapped key (the ciphertext fields are never passed in), and applies each row
  with the compare-and-set `rewrapVersion` (own transaction with `vault.secret_rewrapped`). A row
  whose KEK version is not loaded or that no longer unwraps counts as `failed`, a lost
  compare-and-set as `skipped`. One rewrap runs at a time (`conflict` otherwise). `remaining` counts
  every stored version below the current KEK. `status` counters are in memory:
  `rejectedUnattributed`, `refusedUnattributed`, `rejectedAudited`, `internalFailures`.
  `kekRetirementCheck` is `safeToRemove` only when no version references the KEK version and it is not
  the current one; it does not consider capabilities that still carry that version's MAC.
- **`vault.request_refused`** is appended in its own transaction to the chain of the job whose
  `jobId` the refused request's params carried (only a UUID naming an existing job; the role check
  runs before parameter validation, so that is the only handle), at most 60 per minute; otherwise it
  is logged and counted. `src/refusals.ts`.
- **`init-kek`** moved to `services/vault/src/scripts/init-kek.ts` (new: `--next` adds the next
  version; without it an existing key still refuses the run). The worker's script runs it as a
  child process, so the worker imports no key code. The admin command is
  `services/vault/src/scripts/vault-cli.ts` (`status`, `rewrap`, `kek-retirement-check`) over the
  admin socket.
- **Test seams.** `startVault` options `database` (an open handle) and `operations` (`clock`,
  `afterRewrapRow` for the crash test); protocol tests pass `handlers: DEFAULT_HANDLERS` (stubs, no
  database). `@aab/database/testing` re-exports drizzle's `sql` for tests that edit rows.

### As built in the B2 review fixes (2026-11-19)

Changes after the review of B2a and B2b; where they differ from the text above, this wins.

- **Backpressure (section 1).** A connection stops being read while its unsent response bytes are
  over 1 MiB or `write()` returned false, until `'drain'`; it is destroyed when it stays blocked for
  30 s, or over 4 MiB for 2 s. An empty line is `malformed` and closes the connection (it used to be
  answered each time). At most 4 complete lines may be buffered or in handling per connection; the
  next one is answered `service_unavailable` once and the connection closes. Requests on one
  connection are still answered one at a time, in order. The caps are `RoleServerLimits`
  (`writeBufferSoftBytes`, `writeBufferHardBytes`, `writeGraceMs`, `writeStallMs`,
  `maxInFlightPerConnection`), not environment settings.
- **Over-cap connections** are destroyed 1 s after their one answer (`closeGraceMs`) whether or not
  the client closes, and are tracked (`refusedConnections`) until closed. The same unconditional
  destroy applies after any `abort` that writes an error line. The idle timeout no longer closes a
  connection while a request is being handled (admin requests outlast it).
- **Timeouts (resolves the "request timeout" wording of section 9).** Every vault transaction runs
  `SET LOCAL statement_timeout` (80% of the role's request timeout) and `SET LOCAL lock_timeout` (50%),
  applied by `withTransactionTimeouts` (`packages/database/src/client.ts`) around the repositories'
  database handle, with the limits taken from the request being handled (`src/request-scope.ts`,
  AsyncLocalStorage). A request ended by those limits rolled back and is answered
  `service_unavailable` from the handler's failure. The server's own timer (the full request
  timeout) is a last resort: it closes the connection and sends **no answer**, because the handler
  may still commit; the caller learns "unknown" and checks state. Known gaps: the limits are per
  statement, not per transaction (a transaction of several statements can outlast the timer), and a
  statement outside a transaction (single reads) and a wait for a pool connection are not covered
  by them. The admin socket has its own timeout, `AAB_VAULT_ADMIN_REQUEST_TIMEOUT_MS` (default 120 s).
- **Handler caps.** At most 4 (api), 8 (supervisor) and 1 (admin) handlers run at once per role,
  across connections; further requests wait in order (counted against their request timeout, and not
  started if it has fired). The slot is held until the handler settles even after the timer closed
  the connection. `hello` takes no slot.
- **rewrap** does at most 500 rows per call (`REWRAP_MAX_ROWS_PER_CALL`) and the batch comparison now
  uses the effective page size (`min(batchSize, 500)`; it used the requested size and stopped after
  one page when that was above 500). Deviation from the review text: the result keeps its four
  fields (`rewrapped`, `skipped`, `failed`, `remaining`); there is no `processed` field (it would equal
  `rewrapped + skipped + failed`, and the existing assertions pin the shape). The `vault rewrap`
  command calls again while `remaining > 0` and the last call rewrapped something, and sums the
  results; rows that cannot be rewrapped (a missing KEK) end the loop with exit 3. There is no
  cursor between calls, so more than 500 permanently failing rows would hide the rest.
- **`vault.capability_rejected` is rate limited** per organization (60 per minute, in memory, like
  `vault.request_refused`); the overflow is logged and counted (`status` counter
  `rejectedRateLimited`). The refusal itself is unchanged. Note that `refusals.ts` still limits
  `vault.request_refused` with one window for the whole vault, not per organization.
- **Socket directory ancestors.** Every directory above `AAB_VAULT_SOCKET_DIR` must be owned by root
  or the vault's user and must not be writable by group or other, except a sticky directory owned by
  root (like `/tmp`). The review text said to reuse the KEK directory's ancestor check; no such
  check exists in `packages/crypto` (ADR-003 and `LocalFileKekProvider` check the key directory and
  files only), so `ancestorProblem` in `src/socket-safety.ts` is new and the KEK directory's
  ancestors are still unchecked.
- **Framing** keeps the chunks of a partial line and scans only each new chunk for the newline; the
  line is joined once, when it completes.
- **completeLogin** refuses (`validation_failed`, transaction rolled back, capability unspent) a
  payload that is empty, over 2 MiB decoded, not JSON, or not `{ cookies: [...], origins: [...] }`
  of objects, and one with no cookies and no origins; an `sessionExpiresAt` in the past is refused
  and one beyond 400 days is stored as 400 days. `vault.secret_stored` also carries
  `snapshotVersion` (alias of `entryVersion`, the Phase 2 name) and `originCount` (origins in the
  stored state; Phase 2's was the number of allowed origins). A `cookieCount` was dropped because
  the audit redactor replaces any value under a key containing `cookie`. Actor attribution stays
  `system` per section 10; `durationMs` and `sandbox` of `connection.auth_completed` are not known
  to the vault (docs/phase-3.md B3 lists what the supervisor must keep).
- **Tests changed on purpose.** `protocol.test.ts` "answers service_unavailable to a request that
  outlives the request timeout, once" pinned the old timer behaviour and is replaced by "closes,
  without claiming an outcome, ...". `audit-atomic.test.ts` "a failing audit append rolls back the login
  completion" sent an empty storage state as its payload, which the vault now refuses; it sends a
  valid one (the assertions are unchanged). Nothing else was changed or loosened.

### As built in step B3a (2026-11-19, partly done)

The API side of the wiring, as far as it is done. Where it differs from the text above, this wins.

- **`packages/vault-client`** (`@aab/vault-client`; depends on `@aab/contracts` only, imports no
  crypto) is the caller's client: one connection per request, one request line, a response line capped
  at 4 MiB, a 5 s default timeout over the whole exchange, the response checked against the contracts
  schemas and its id against the request's. Errors are `VaultCallError` with a kind and a short code
  and nothing from the request or the reply: `unavailable` (connect failed, timeout, connection closed,
  malformed, oversize or mismatched reply, and the vault's own `service_unavailable`, `internal_error`
  and `not_implemented`) and `denied` (`forbidden` and every other refusal: `not_found`,
  `validation_failed`, `conflict`, `malformed`, and a request that fails the contracts schema, which is
  not sent). `internal_error` and `not_implemented` are read as `unavailable` because they are
  failures, not refusals; both fail the job closed either way. `services/vault/src/admin-client.ts` was
  not refactored onto it (that needs a dependency in `services/vault/package.json`).
- **Start-up (section 3).** The API reads `AAB_VAULT_SOCKET` (the api-role socket, required by
  `main.ts`, not by `loadConfig`, so tests and `dev:memory` run without a vault), `AAB_VAULT_ISOLATION`
  (default `separate-uid`, mirrors the vault's), `AAB_VAULT_AUTHORIZATION_TTL_SECONDS` (10 to 3,600,
  default 600) and `AAB_VAULT_CALL_TIMEOUT_MS` (100 to 60,000, default 5,000). Numbers are strict
  decimal integers. It still refuses `AAB_KEK_DIR`. It then sends `hello` and refuses to start when the
  vault answers with a role other than `api`, with an isolation mode other than the configured one, or
  (in `separate-uid` mode) when it can open the directory `hello` names as `keyDirectory`; the message
  names the path, as section 3 says. No separate probe-path variable exists: the directory is the one
  the vault reports.
- **A vault that does not answer at start is not a refusal.** The ADR does not say. Revocation must work
  while the vault is down (section 7) and each job fails closed (section 9), so the API starts degraded
  and logs a warning. Every authorization and status call first runs the same `hello` check until it
  passes once, so no capability is authorized through an unchecked vault, and a vault that later answers
  wrongly is refused for good. (The check runs until it passes once, not before every call; the
  supervisor, by contrast, checks before every claim. B3 review L4: the API logs one error line when
  the check turns to a refusal.) Changing this to a refusal is one line in `main.ts`.
- **Status.** `GET /v1/vault/status` (route `vaultStatus` added to `packages/contracts` `Routes`; the
  response schema is the existing `StatusResult`) is owner-only, answers 503 without detail when the vault
  is unreachable. The `api` role may call `status` (section 4), so nothing was skipped.
- **Revocation (section 7).** `connections.revoke`, `grants.revoke` and `agents.disable` already revoke
  the unused capabilities in their own transaction (B1); the route test proves it end to end with a real
  vault. The connection route now also appends `vault.secret_revoked` (ids and the number of versions
  deleted) when the connection has secret rows, in the same transaction; `vault.secret_deleted` is
  unchanged.
- **authorizeJobAccess and failure (sections 5 and 9).** After the execute commit (only for the job this
  request created, not an idempotent replay) and after the connect commit, the API calls the vault with
  `AAB_VAULT_AUTHORIZATION_TTL_SECONDS` (operations) or the login timeout plus 60 s (logins). On
  `unavailable` or `denied` the job ends `failed` with `vault_unavailable` or `vault_denied` through
  `jobs.failQueuedWithoutCapability` (one conditional UPDATE: still `queued`, `capability_ref IS NULL`),
  with `operation.failed` or `connection.auth_failed` as `actor_type = 'system'` (metadata `source`
  `authorize` or `sweep`) in the same transaction; a login also returns its connection to
  `authentication_required`. A call that timed out after the vault committed therefore does not fail the
  job. The sweep (`sweepUnauthorizedJobs`, every 15 s, at most 50 jobs per run, stopped on app close) ends
  queued jobs with no capability older than 60 s the same way, using `listQueuedWithoutCapability`. Both
  repository functions are additive, in `packages/database` (`test/job-vault-failure.test.ts`).

### As built in step B3b (2026-11-19, reviewed)

The supervisor side of the wiring. Where it differs from the text above, this wins.

- **No key in the worker (section 3, P3-1).** `@aab/crypto` is no longer a dependency of
  `services/browser-worker`; no source file imports it or names `sealSecret`, `openSecret`,
  `rewrapSecret` or a KEK provider (`test/session-store/import-boundary.test.ts`). `AAB_KEK_DIR`, if set
  and not blank, is a configuration error checked before any other variable. The worker takes
  `AAB_VAULT_SOCKET` (supervisor-role socket, required), `AAB_VAULT_ISOLATION` (default `separate-uid`)
  and `AAB_VAULT_CALL_TIMEOUT_MS` (default 5,000). The session store keeps parsing, validation, the size
  cap, origin filtering and `dispose()` (`encodeSnapshot`, `parseSnapshot`); `storeSnapshot`,
  `openSnapshot` and `loadLocalKek` are gone.
- **The gateway is mirrored, not generalised.** `services/browser-worker/src/vault/gateway.ts` repeats the
  API's `hello` check with the supervisor role (role, isolation, and in `separate-uid` an `opendir` probe
  of the reported key directory). Moving it into `packages/vault-client` would have needed a role
  parameter and a different operation surface for each caller; the API's gateway and tests were left as
  they are.
- **Start and claim (sections 3 and 9, P3-11).** A vault that answers wrongly refuses the start
  (`SupervisorStartError`); one that does not answer does not (as the API, section 7: nothing here may
  depend on the vault being up to start). Before **every** claim the supervisor repeats the full
  `hello` check; while it fails nothing is claimed and the state change is logged once. It claims with
  `requireCapability: true` and recovers expired leases with `capabilityAware: true`, as B1 prepared.
- **Operations (sections 4 to 6).** After claim and the supervisor's own checks (step 0 hash, policy,
  obligations) it calls `issueAccessCapability` (the job's `capability_ref`, its own `workerId`, the job's
  `attempt_count`, token lifetime 30 s) and immediately `readForWorker`. The `argumentsHash` the vault
  returns is compared with `job.arguments_hash`; a null or different value denies the job
  (`arguments_hash_mismatch`, `operation.denied`) before anything runs (P3-17). This closes the residual
  risk Phase 2 recorded (a writer who replaces the arguments and recomputes the hash): the test that
  documented it now asserts the job is refused. The capability is spent by then (the vault returns the
  hash only on a read), which is acceptable because the job ends. `unavailable` ends the job
  `vault_unavailable`, `denied` ends it `vault_denied`; a claimed job without a `capability_ref`
  (should not exist) ends `vault_denied`. Nothing falls back to opening a secret locally.
- **The read is audited by the vault only.** The worker's `touchAccessed` and `vault.secret_read` are
  gone (the vault writes `vault.secret_read` as `system`, section 10).
- **Logins.** After capture the supervisor still filters by origin, fails `login_not_completed` itself
  when nothing is left (no vault call at all, not even a token), runs the identity pre-check, derives
  `sessionExpiresAt` with `sessionExpiry(filtered)` and then calls `issueAccessCapability` and
  `completeLogin`. The vault seals, activates, records, audits (`vault.secret_stored`,
  `connection.auth_completed`, `system`) and completes the job in its transaction; the supervisor writes
  none of that and no worker-attributed copy. A failure ends the login through the existing
  `connection.auth_failed` path with `vault_unavailable` or `vault_denied`.
- **Decision: login `durationMs` and `sandbox`.** Phase 2 put them on `connection.auth_completed`. The
  vault writes that event and cannot know them, and no audit event type exists for a supervisor-side
  copy (adding one touches `packages/contracts`). They are dropped from the audit trail and logged by the
  supervisor at info level (`login job finished`). Operation events (`operation.*`) still carry both.
- **Behaviour changes to know.** (1) An `active` connection with no stored session still ends
  `reauth_required` / `expired` (`no_snapshot`), as in Phase 2: the supervisor reads the secret
  metadata (`describeForConnection`, no ciphertext, no key) before asking for a token, and with no
  active version it records that outcome and makes no vault call (B3 review M3; the first B3b version
  let the vault refuse the read and ended `vault_denied` silently). (2) The vault refuses a `sessionExpiresAt` in the past
  and caps one beyond 400 days, so a login whose earliest cookie already expired fails `vault_denied`,
  and a long-lived cookie records an expiry 400 days out. (3) A job whose lease expired after its token was
  issued is ended by recovery, not requeued (the B1 rule, now switched on).
- **Left as Phase 2 had it.** When a job's outcome invalidates the session (`reauth_required`,
  `identity_mismatch`) the supervisor still deletes the stored versions through the database
  (`vault.deleteForConnection`) and appends `vault.secret_deleted` as `worker`. That is a database write,
  not key handling; routing it through the vault is a later decision.
- **Review fixes (B3 review, 2026-11-19).** M1: a login's token is issued only after the owner
  completes, so the supervisor reads the capability's `expires_at` (metadata) at claim and gives the
  window `min(job timeout, remaining - 45 s)`; under 5 s it fails the login `timeout` before a window
  opens. The API's login lifetime is now the handoff timeout plus 300 s (queue time shares the budget).
  M2: `jobs.extendLease` and `jobs.complete` take the attempt and match `attempt_count`; the
  supervisor's handlers pass theirs, a stale handler returns early on `lease_lost`, and a claim for a
  job id that still has a handler is refused. L1: in `separate-uid` both gateways also try the other
  roles' sockets and refuse to start if one connects. L5: invalidating a session also revokes the
  connection's unused capabilities (`session_deleted`). L6: expiries within 5 minutes of now are
  ignored when deriving `sessionExpiresAt`. L3: the sweep's age uses the database clock.
- **Infra.** `infra/docker/vault.Dockerfile`, a `vault` service and a one-shot `vault-init-kek` in
  `infra/compose.yaml`, one socket volume per role (`vault-api`, `vault-supervisor`, `vault-admin`),
  the key volume in the vault containers only, the API on `vault-api` only. Compose runs the vault in
  `shared-uid` terms (one user in the container; the volumes are the separation). Both Dockerfiles that
  copy workspace packages were updated (`vault-client` added to the API image, which B3a had missed;
  `crypto` replaced by `vault-client` in the runner image). Validated with `docker compose config` only;
  nothing was built or started. `docs/operations.md` has the `separate-uid` setup and `LimitCORE=0`.

### As built in step B4 (2026-11-19, reviewed)

Most of section 8 existed from B2 (the rewrap batches, `kekRetirementCheck`, `status`, `init-kek --next`).
B4 closed what was left:

- **A rewrap cursor (deviation from "the command calls the vault again while rows remain and the last call
  made progress").** The B2 loop stopped when a call rewrapped nothing, and every call listed from the
  first row again, so 500 or more rows that cannot be rewrapped (a missing KEK, a wrapped key that does
  not open) starved every good row behind them. `RewrapParams` now takes an optional `afterId` (a
  version id) and `RewrapResult` an optional `nextAfterId`, both strictly validated as UUIDs in
  `packages/contracts`. A call that stopped at its bound (rows per call or `maxBatches`) with more
  candidates behind it returns the id of the last row it examined; the next call starts after it. The
  field is absent when the call reached the end of the list. `vault rewrap` passes it through and ends at
  the first result without one, so it always ends (each call starts strictly after the previous one) and
  it visits every row once per run. `remaining` still counts every stored version below the current KEK,
  so exit 3 is unchanged: rows `remaining` or `failed`. No migration: `listForRewrap` already took
  `afterVersionId`.
- **The key directory's path (tightened in the B4 review).** `requireSafeKeyPath` in `keys.ts` runs
  before any key file is read, and the keys load from the verified path. The path must be real
  (`realpath` equals the path, so no symbolic link in it) and every directory above it must pass the
  socket directory's `ancestorProblem` rule: owned by root or the vault's user and not writable by group
  or other, a sticky directory exempt only when root owns it. `init-kek` (also with `--next`) runs the
  same check first, through the nearest existing ancestor when the directory does not exist yet, so it
  never creates a key the vault would refuse. Without it, whoever can rename an ancestor or replace a
  link can swap the key directory after the check. Not tested: an ancestor owned by a third user (the
  tests run unprivileged and cannot `chown`); that branch is the shared `ancestorProblem`, tested with
  the socket directory.
- **The vault takes no authorization lifetime (review L2).** `AAB_VAULT_AUTHORIZATION_TTL_SECONDS` was
  parsed by the vault and never used; the API sends the lifetime with every `authorizeJobAccess`
  (default 600 s, logins 900 s, at most 3,600 s). It is removed from the vault's configuration; a value
  still set in the vault's environment is ignored, not an error, so existing unit files keep working.
  The rotation guide therefore waits one hour.
- **The admin command's exit codes (review M1).** `pnpm --filter ... run` turns the command's exit codes
  2 and 3 into 1. The documented invocation is `corepack pnpm --silent --dir services/vault run vault ...`
  from the repository root, which keeps them (`cli.test.ts` runs that exact line against a vault with a
  missing KEK and expects 3). The guide also says to decide from the JSON fields.
- **No change to the transaction or the audit.** `rewrapVersion` (B1) and the single-row transaction with
  `vault.secret_rewrapped` stay as they were. The mutation checks showed that a revoked secret is
  protected twice on the rewrap path (the status predicates and the deletion of its versions by the
  revocation transaction); the race tests assert the outcome, not which of the two did the work.
- **Tests.** `services/vault/test/rewrap-kill.test.ts` kills the real vault process (`src/main.ts`) with
  SIGKILL inside a row's transaction: a trigger makes the transaction of the 31st row wait on an advisory
  lock the test holds, after the row was updated and before its audit event was written. After the kill 30
  rows are on the new KEK with 30 events, none is half-applied, the ciphertext digest is unchanged, and
  every version opens with the key files; after a restart and `vault rewrap` every row has exactly one
  event and reads work through the vault. `revocation-race.test.ts` interleaves the vault operations with
  a revocation on a second connection, ordering them with the revocation transaction held open or with
  the same kind of advisory-lock trigger in front of the vault's audit append and `pg_locks` to know the
  vault is waiting. Both are PostgreSQL only. `key-files.test.ts` hashes the key directory (contents,
  modes, inodes, change times) around every operation and the admin command.
  `services/broker-api/test/import-boundary.test.ts` is the API half of the import boundary: the API may
  use `@aab/crypto` for password hashing and tokens, so the test forbids the key-handling names anywhere
  in its source and requires every name imported from the package to be on a short allow list.
- **Not covered.** Power loss or a kernel crash (SIGKILL of the process is what was tested; PostgreSQL's
  own durability is assumed). A kill of the vault while PostgreSQL itself is on a slow disk. The
  separate-uid setup. The rotation procedure of `docs/operations.md` was checked command by command
  against the real scripts but not run end to end on a host.

## What a compromised component can and cannot do after Phase 3

These statements are the design. They become claims only when the tests named in
[`docs/phase-3.md`](../phase-3.md) exist and pass; until then they are written, not run. The
supervisor and API rows assume `separate-uid` and the bubblewrap launcher.

- **Runner.** Unchanged from ADR-013: the one session of its job, until the job ends, to the job's
  allowed origins. It cannot reach the vault sockets (not mounted) or the key.
- **Supervisor.** Cannot read the KEK or the vault's memory. Can read the plaintext session of every
  job it claims while it is compromised, because it must hand that session to the runner, and can
  send it anywhere the host's network allows. Cannot obtain a session for a connection that has no
  job authorized by the API: a job row it writes is never authorized, and a capability row it writes
  fails the MAC. Can deny service (fail jobs, delete ciphertext through its database access) and can
  write false audit events. Under the Docker launcher it is root-equivalent and none of this holds.
- **API.** Cannot read the KEK or any plaintext session; it has no operation that returns one. It is
  the policy authority, so it can authorize capabilities for jobs it creates on any connection, and an
  honest supervisor will then run them; it sees operation results, not sessions. With the shared
  database role it can also write grants, jobs and audit rows. It can deny service.
- **Database-only thief (a dump or backup without the key directory).** Gets ciphertext, wrapped
  keys, token hashes of 256-bit tokens that expire in seconds, MACs it cannot forge, and metadata. No
  plaintext. Operation results stored in `execution_jobs.result` until purged are plaintext business
  data (DB-13; AAB-029), which Phase 3 does not encrypt.
- **Database writer without vault access.** Cannot redeem anything (no socket). Can delete or corrupt
  rows (denial of service), cannot forge a capability. Can restore an earlier complete state of a
  secret from a backup (a version row and its pointer); the vault would open it, because it keeps no
  record of the newest version outside the database. Rollback (threat model VA-11) is therefore only
  partly addressed: the audit chain records each `vault.secret_stored`, with ADR-009's limits.
- **Local user with the same uid as the services (`shared-uid`), or root.** Everything. Phase 3 adds
  nothing against them.
- **Another local user without a role group.** Cannot connect to any vault socket or read the key
  directory.

## Out of scope for Phase 3

- An external KMS or HSM, a passphrase-wrapped KEK, an operating-system keyring (ADR-003 deferrals).
- More than one host; a vault reachable over a network; TCP with mutual TLS.
- Separate database roles per service. Recommended later (open question in `docs/phase-3.md`); the
  capability MAC exists because there is one role today.
- Encrypting `execution_jobs.result` at rest (AAB-029).
- Handing the plaintext to the runner without the supervisor seeing it (would need descriptor passing).
- Writing a refreshed session back after an operation (ADR-013).
- OAuth tokens and API keys (Phase 8).
- External review of the vault boundary. Required before any real credential (specification Phase 3
  caution); scheduled as part of step B6, not a property of this design.

## Alternatives considered

- **Keep the crypto in the supervisor and add capabilities only.** The supervisor would check a
  capability against the database before calling `openSecret`. Rejected: the process that checks the
  capability holds the KEK, so a compromised supervisor skips the check, which is the Phase 2
  weakness unchanged. It would satisfy the wording "single-use, expiring" without moving the boundary.
- **A vault thread or worker thread inside the supervisor.** Same address space and same user as the
  supervisor; the KEK is readable by the supervisor's code. Rejected for the same reason.
- **TCP on loopback with mutual TLS.** Gives a cryptographic caller identity that would also work
  across hosts. Rejected for Phase 3: a certificate authority and per-role private keys to issue,
  store and rotate, each of which is a file the caller's user can read, so on one host it is no
  stronger than socket permissions; it opens a loopback port that any local user can reach and that
  DNS rebinding and other local attacks target; and multi-host is out of scope. Revisit for a hosted
  deployment, where a managed KMS would be used anyway.
- **Peer credentials (`SO_PEERCRED`) as the identity check.** The recommended starting point. Not adopted
  because Node has no built-in support and the only practical route is a native module (section 2); the
  per-role sockets give the same uid-level identity, enforced by the kernel at connect time, without a
  new dependency. It remains the way to add the caller's pid to audit records.
- **Issue the token at policy time and hand it to the supervisor.** The API would need to pass the raw
  token to the supervisor. The only channel between them is the database, where the token must not be
  stored, so this would need a new API-to-supervisor channel and would keep a live token for as long as
  the job waits in the queue. Rejected in favour of authorization at policy time and the token at
  claim time.
- **Issue at claim time only, with no authorization stage.** Simpler, and the window is the same. But
  the vault would then rely on job rows and policy events that any database writer, the supervisor
  included, can write. The API-only authorization with a vault MAC is what limits a compromised
  supervisor to jobs the API created.
- **One call that checks and returns the plaintext, with no token.** Equivalent for one supervisor.
  Kept as a two-call protocol to match specification §6.3 and to allow a redeemer that is not the
  caller of stage 2.
- **Revocation through the vault.** Would make revocation depend on the vault being up and split the
  connection change from the ciphertext deletion across two transactions. Rejected (section 7).
- **A separate MAC key file.** Clean separation, but one more file to back up and rotate. Rejected in
  favour of an HKDF-derived key; revisit if the KEK moves to a KMS that cannot export derived keys.

## Consequences

- One more long-lived process, three sockets and, for the default isolation, three groups and a user
  created by root once. The `shared-uid` mode keeps a one-user laptop setup possible at the cost stated
  in section 2.
- Every operation job gains two socket round trips; login completion gains two. Latency is small next
  to a browser start.
- Automatic retry of a read after its session was handed out goes away (section 5).
- The vault writes connection status and completes login jobs, so the login completion logic moves out
  of the supervisor. The supervisor keeps capture, origin filtering, the size cap and the identity
  pre-check.
- The specification changes in four places, to be recorded in its changelog: the two-stage capability,
  revocation outside the vault API, the version bound at issue rather than at authorization, and the
  `vault_access_capabilities` columns beyond §11's list.
- Linux only for the vault. macOS development uses `shared-uid` only if a later check shows socket
  permissions are enforced there; until then the vault refuses to start on it.
- ADR-001's Phase 3 row (container for the worker) is unchanged by this record; container isolation
  was superseded by ADR-013, and the vault boundary is now this record.

## Revisit when

- A real credential is to be stored (external review first).
- A second host, a hosted deployment or a KMS is planned.
- The owner wants caller pids in vault audit records (native module review).
- Separate database roles are introduced; the capability MAC may then become defence in depth only.
- An operation needs session write-back or a retry after a session was handed out.
