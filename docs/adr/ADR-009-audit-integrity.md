# ADR-009: Audit integrity

- **Status:** Accepted
- **Date:** 2026-11-11

## Context

AAB records who did what: sign-ins, connection changes, grants, policy decisions and, from Phase 2,
operation outcomes. The owner relies on that record to understand what an agent did on their
accounts. The specification asks for "append-only logical events + integrity checks", and warns that
this is "useful traceability, not a claim of immutable storage" (§4, §11.1).

Three requirements shape the design.

- **Concurrent writers.** The API handles requests in parallel. Two events written at once must
  not take the same position in the log or link to the same predecessor.
- **Atomicity with the change.** A state-changing call and its audit event commit together or not at
  all (INV-10 in [ADR-001](ADR-001-trust-boundaries-worker-isolation.md)). An audit event for a change
  that was rolled back is false, and a change with no event is unaccountable.
- **No secrets in the record.** The audit table is readable by anyone who can read the dashboard and
  is copied into backups. Metadata must not carry credentials (INV-1).

The audit event shape (`AuditEvent` in `packages/contracts`) and the table (`audit_events` in
`packages/database`) exist, together with the hash and redaction library (`packages/audit`) and the
repository functions that append, list and verify. The broker API calls append; no audit read route exists yet. What
follows describes the library and repository as they are.

## Decision

### A hash chain per organization over canonical JSON

Each organization has its own chain. The first event has `sequence` 1 and a null `previousHash`.
Every later event has the previous event's `sequence` plus one and that event's `eventHash` as its
`previousHash`.

`eventHash` is the lowercase hexadecimal SHA-256 of the canonical JSON of one object. The object
holds a hash-layout version (`v`, currently 1), `previousHash`, and these fields of the event: `id`,
`sequence`, `timestamp`, `organizationId`, `actorType`, `actorId`, `agentId`, `runId`,
`connectionId`, `eventType`, `decision` and `metadata`. `computeEventHash` in `packages/audit` lists
the fields explicitly, so a stray property on its input cannot change the hash, and a missing field
fails instead of hashing as nothing.

Canonical JSON is `canonicalJson` in `packages/contracts`. It follows the RFC 8785 rules that matter
here: object keys sorted by UTF-16 code unit, no insignificant whitespace, ECMAScript number
formatting. It is "in the style of" the RFC, not a conformance-tested implementation of it. It
rejects, rather than converts, `undefined`, non-finite numbers, big integers, dates, class
instances and cycles, because a silent conversion would let two different payloads produce one hash.
The same function serializes approval payloads, idempotent request bodies and encryption
associated data, so one serializer is reviewed for all of them.

A chain per organization, and not one global chain, keeps one tenant's writes from queuing behind
another's and lets one tenant's chain be exported and checked without the others'.

### Appends are serialized by an advisory lock, in one transaction

`audit.append` runs inside a transaction. Its first statement takes a transaction-scoped PostgreSQL
advisory lock keyed on the organization (`pg_advisory_xact_lock` over a hash of `aab.audit:` and the
organization ID). With the lock held it reads the organization's latest event, computes the next
sequence number and hash, and inserts the row. The lock is released when the outermost transaction
commits or rolls back. A unique index on `(organization_id, sequence)` is the backstop: if the lock
were ever bypassed, a second event with the same sequence number would fail instead of forking the
chain.

`repositories.transaction` runs a block of repository calls in one database transaction. An
`append` made inside it joins that transaction, so the event commits or rolls back with the change it
describes. This is how the API is meant to write: the change and its event in one block. If the
append fails, the change is rolled back and the caller receives an error.

### Metadata is redacted before it is persisted

`append` passes `metadata` through `redactMetadata` before computing the hash, so the stored value
and the hashed value are the same redacted value. The function, in `packages/audit`:

- replaces the value under any key whose name looks like authentication material (password,
  secret, token, cookie, authorization, API key, session identifier, credential, private key, storage
  state, bearer, and the short words `dek`, `kek`, `sid`, `jwt`, `otp`) with `[REDACTED]`, at any
  depth, inside arrays, whatever the value's type;
- scrubs bearer and basic credentials and JWT-shaped strings out of string values;
- caps string length (500), nesting depth (8), array length (100), keys per object (100) and key
  length (120), and marks what it dropped;
- turns anything that is not plain JSON into a marker or drops it, and removes characters that the
  `jsonb` type rejects.

Redaction is a safety net. Callers are required to pass summaries, not raw requests or page content.
The function cannot recognize a secret stored under an innocuous key name or written into prose, and
the code says so in its documentation. Because the hash covers the redacted value, redaction cannot
be undone later and the chain still verifies.

### Verification on demand

`verifyChain` in `packages/audit` takes a run of one organization's events in ascending order and
recomputes the chain. It reports the first event that fails and one of these reasons: the chain does
not start at sequence 1, a sequence gap, a previous-hash mismatch, a content-hash mismatch, an event
from another organization, or an event that cannot be hashed. `audit.verify` in the repository reads
an organization's events in batches of 500 and runs the same check, carrying an anchor from one batch
to the next. A successful result includes the head of the chain (sequence and hash).

Verification runs when someone asks for it. Nothing runs it on a schedule. **No HTTP route and no
command-line tool exposes chain verification yet.** It is a repository function (`audit.verify`),
reachable from code and from tests only. Exposing it to the owner, as a route or a command, is
follow-up work.

## What this proves, and what it does not

If `verify` returns success for an organization, then the events that exist for it form a consistent
chain from sequence 1: each event's stored hash matches its contents, and each event names the hash
of the event before it. It follows that anyone who changed a stored field, deleted an event from the
middle or from the front, inserted an event, or reordered events **without also recomputing every
later hash** is detected, and the first affected event is named. Tests for this exist, using direct
SQL edits to the table.

It does **not** prove any of the following, and no document may claim it.

- **The tail has not been removed.** Deleting the newest N events leaves a shorter chain that is
  still internally consistent. Verification cannot know how long the chain should be. Detecting
  truncation needs the head hash recorded somewhere the database administrator cannot write.
- **The chain has not been rewritten.** A database administrator, or anyone who can write to the
  table and run the public hash function, can alter an event and recompute every later hash. The
  result verifies. The hashes carry no key and no signature, so they show that a chain is
  consistent, not who made it.
- **The whole chain has not been deleted.** An empty trail is indistinguishable from an
  organization that has done nothing.
- **The events are true.** The broker writes what it believes happened. A compromised broker can
  write false events, and a bug can write wrong ones. The chain protects the record after it is
  written.
- **The timestamps are accurate.** They come from the clock of the host that appended the event.
  They are hashed, not independently attested.
- **Secrets are absent.** Redaction is heuristic, as described above.
- **Verification itself is trustworthy.** It runs against the same database, in code that the same
  administrator can change.

### The mitigation, and its status

The mitigation for truncation and rewrite is to **export the chain head to a sink that the database
administrator cannot modify**, on a schedule and after significant events, and to compare it with the
database when verifying. Suitable sinks are an append-only object store with retention locking, a
second machine under different control, or a signed log kept by a different party. A rewrite then
fails the comparison, and a truncation shows as a head that is behind the last exported one.

**This is not built.** There is no export, no checkpoint table, no signing key and no scheduled
verification. The specification lists "audit export" under Phase 5 and assigns no phase to a
protected sink. Until then the correct statement is: the audit trail gives tamper evidence against
partial edits by someone who verifies it, and gives nothing against a database administrator.

A cheaper partial measure is built: a database trigger (migration `0002_audit_events_append_only`)
rejects `UPDATE`, `DELETE` and `TRUNCATE` on `audit_events`, whoever issues them. This stops a
mistaken script or an injected statement from silently rewriting history. It is not immutability: a
database superuser or the table's owner can disable or drop the trigger (for example `ALTER TABLE
... DISABLE TRIGGER`, or `session_replication_role = replica`) and then edit rows. A database role
for the API that does not own the table and has no `UPDATE` or `DELETE` privilege is not built: the
Compose file creates one database role (`aab`) as the database's initial user, and that role owns
the table, so it can disable the trigger. Detecting such an edit still depends on the hash chain and
an exported head, which are not built either.

## Alternatives considered

- **No hash chain; rely on database permissions.** Simple. Gives no evidence of edits made by anyone
  with the right privileges, and owners cannot check anything themselves.
- **A keyed hash (HMAC) per event.** Stops an attacker who has the data but not the key from
  forging a chain. Rejected for now: the key would have to live where the broker can read it, which is
  usually where the database administrator can reach, and key custody and rotation become part of the
  audit design. It becomes useful once the key lives in a KMS (Phase 10).
- **Asymmetric signatures per event or per checkpoint.** Gives non-repudiation and lets third
  parties verify. Rejected for now for the same key-custody reason. It is the natural form of the
  exported checkpoint, with the signing key held outside the database host.
- **One global chain.** Simpler to reason about. Rejected: tenants would serialize behind one lock and
  one tenant's export would expose the others' event volume and ordering.
- **Optimistic appends: read the latest event, insert, retry on a unique violation.** Avoids holding
  a lock. Rejected: it turns concurrency into retry storms under load and puts retry logic into every
  caller. The lock makes the ordering rule one statement.
- **`SERIALIZABLE` transactions for appends.** Correct, and failures would still need retries. The
  advisory lock is narrower and affects only one organization.
- **A Merkle tree or batched checkpoints.** Stronger and allows compact proofs. Deferred: it adds
  structure before there is anywhere to export a root.
- **A separate audit service with its own database.** Would put the record outside the API's reach.
  Rejected for the local product (more services), and worth revisiting with the protected sink.

## Consequences

- Appends for one organization are strictly serialized. The lock is held until the surrounding
  transaction ends, not until the append returns, so a slow transaction that has already appended
  blocks every other audited change in that organization. Callers should append last, after their
  own writes. Throughput is bounded by one commit at a time per organization, which is adequate for
  human-scale use and should be measured when every policy decision becomes an event (Phase 2).
- Every policy evaluation is intended to be an audit event (`policy.evaluated`), and job rows refer to
  that event's ID. This puts the audit chain on the path of every operation request.
- The hash format version (`v`) is part of the hashed input, but **it is not stored per row**. The library's comment says old events keep verifying because a verifier can branch on
  the version, and that cannot work as the schema stands: the verifier has nothing to read the
  version from, and `verifyChain` always recomputes with the current layout. Changing the hashed
  fields, or the version, therefore needs a stored version column and a migration that backfills it
  first. This is recorded here so that it is not discovered in the middle of a change.
- Events must be written with fields the contracts allow. The set of event types is a closed list in
  `packages/contracts`, extended deliberately as phases add behavior. The table also checks the shape
  of the type name and the hash format.
- `agent_id`, `run_id`, `connection_id` and `actor_id` have no foreign keys, so that the trail can
  outlive rows that retention later deletes. The cost is that nothing in the database stops an event
  from naming an ID that never existed. `append` validates only that they are well-formed UUIDs.
- Verification is not a consistent snapshot. It reads in batches while appends continue. Appends only
  add to the end, so it verifies what existed, but a rewrite that lands during a run can be missed
  until the next run.
- Lock contention has been tested on PGlite, which runs one connection and executes transactions one
  after another. The test of 25 concurrent appends shows that the sequence is gapless and verifiable,
  and does not stress the lock. A test against a real PostgreSQL server with several connections does
  not exist.
- Retention that deletes old events would break verification from sequence 1. Verification already
  accepts an anchor to start from, so retention has to keep and publish an anchor for the new start.
  Retention is not implemented.

## Revisit when

- The audit export or checkpoint sink is designed (Phase 5 at the earliest). That work should produce a new
  record that says where heads are sent and who can read them.
- The hashed field set must change. Add the version column first.
- Chain verification needs to be reachable by the owner (a route or a command); this is open
  follow-up work.
- Real credentials or real third-party data are to be handled, since the trail then becomes evidence
  that the owner may need to rely on.
- Several organizations are hosted (Phase 10), which calls for keyed or signed checkpoints.
- Measurements show that serialized appends limit throughput.
