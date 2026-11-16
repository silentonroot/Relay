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
  created from now on; existing rows backfilled from their stored arguments). The `policy.evaluated`
  event's metadata gains the same hash.
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
