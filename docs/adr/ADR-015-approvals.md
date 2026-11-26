# ADR-015: Approval of the exact action

- **Status:** Accepted by the owner on 2026-11-26 (drafted in Phase 4 step C0, commit `faad876`). The
  owner accepted every default of decisions D1 to D15 in [docs/phase-4.md](../phase-4.md) section 5
  on 2026-11-25; this record states those decisions and what they cost. Nothing below is implemented
  except the contract types, the hash functions and the descriptor rule of step C0.
- **Date:** 2026-11-26
- **Needed by:** Phase 4
- **Relates to:** [ADR-001](ADR-001-trust-boundaries-worker-isolation.md) (INV-9, INV-10, INV-11,
  INV-12), [ADR-004](ADR-004-job-queue.md), [ADR-005](ADR-005-policy-representation.md),
  [ADR-006](ADR-006-adapter-packaging-trust.md), [ADR-009](ADR-009-audit-integrity.md),
  [ADR-010](ADR-010-tenant-ready-schema.md), [ADR-013](ADR-013-per-job-sandbox-egress-proxy.md),
  [ADR-014](ADR-014-vault-service.md)

Wording follows [`security.md`](../security.md) section 2: everything here is a design until its
test exists and has passed in a recorded run. Test names are the planned names of
[docs/phase-4.md](../phase-4.md) section 2 (P4-1 to P4-22).

## Context

Specification §8.2 asks that a write is approved as the exact action: the approval binds user, agent,
run, connection, operation, final arguments and the expected version of the target; it is single
use, redeemed atomically in the transaction that creates the job; it expires; policy is checked again
at execution and wins; and a changed target needs a new proposal. INV-9 in ADR-001 says the same.

What exists (read in the code at commit `b16e81d`, as recorded in phase-4.md section 1):

- The policy engine already answers `approval_required` for a destructive or `requiresApproval`
  operation and never `allow` (ADR-005). It is pure and has no clock. The execute route and the
  supervisor refuse writes by hard-coded checks, and `approval_required` answers 403 with no row.
- `execution_jobs.approval_request_id` is an unused `uuid` with no foreign key. There is no approval
  table, repository, route, audit event type or contract type.
- The job arguments hash (PE-14) is an unkeyed SHA-256 of `aab.job-arguments.v1\n` plus canonical JSON
  that includes `policyDecisionId`. The vault binds that hash into the capability's authorization MAC,
  which is keyed (ADR-014 section 6), so editing a job row and its hash together is caught.
- A capability is consumed with one conditional `UPDATE ... RETURNING`; `used_at` and `revoked_at` on
  the capability row are outside both MACs (the Phase 3 residual).
- Lease recovery already ends a job that is not retry-safe as `outcome_unknown`. No write has ever run.
- There is one database role shared by the services (ADR-014 section 1), so a writer to the database
  is a realistic adversary and a compromised API or supervisor holds that role.

The problem this record solves: approval must authorize one action and nothing else, must not be
creatable or editable by a database writer, must not be spendable twice by any interleaving, and
must not create a second meaning for the same input between the component that checked it and the one
that runs it.

## Decision

### 1. The record and its states

`approval_requests` (specification §11, written by migration `0006`; section 2 of this record) holds one
row per proposed action. Status is one of `pending`, `approved`, `denied`, `expired`, `revoked`,
`consumed`.

```
pending --approve--> approved --redeem--> consumed
   |                    |
   |--deny--> denied    |--revoke--> revoked
   |--expire--> expired |--expire--> expired
   |--revoke--> revoked
```

A terminal state (`denied`, `expired`, `revoked`, `consumed`) never goes back. The `ApprovalStatus`
enum is in `@aab/contracts`. The execute route creates the row (D1): an allowed write whose policy
outcome is `approval_required` creates one `pending` approval, in the same transaction as the
`policy.evaluated` event and the idempotency record, and no job (P4-2). The HTTP answer is 202 with
`{status: "approval_required", approvalId, expiresAt}` (D11; specification §12.2 changes accordingly).
`orders.proposeUpdate` is a read that previews the change and writes nothing (P4-17). Approving never
runs anything (D2): the caller resubmits with the approval id and the broker creates the job then.

The owner decides: only the signed-in owner of the agent and of the connection can approve or deny
(P4-7). The approver id comes from the session, never from a body field or header; the decide bodies
are strict objects that contain only the presented action hash; another owner's approval looks
missing.

### 2. The action hash

`action_hash` is the lowercase hex SHA-256 of the text `aab.approval-action.v1\n` followed by the
canonical JSON (specification §11.2) of one object with exactly nine keys:

```
agentId, arguments, connectionId, expectedResourceVersion, operation,
organizationId, ownerUserId, runId, targetResourceId
```

`arguments` are the final arguments (obligations applied) as the approval stores them; `runId` is
null when the request has no run; `targetResourceId` and `expectedResourceVersion` are the values of
the operation descriptor's `resourceArgument` and `versionArgument` in those arguments. The
implementation is `actionHashInput` and `computeActionHash` in `@aab/contracts` (the digest function
is at `@aab/contracts/hashing` because it imports `node:crypto` and the package index is bundled
into the dashboard). The API, the vault and the supervisor use that one function (P4-20).

**Why a new layout and why no later-created id.** The layout is a layout of its own, not the job
hash. The job hash includes `policyDecisionId`, which exists only after the approval, so an approval
cannot carry the job's hash. Backlog ticket AAB-032 ("the hash on the approval equals the
hash on the job it releases") cannot hold literally; the property this design is designed to provide is that the job
hash binds the approval's action hash (section 7), and that the action hash recomputed from the job's
own columns equals the approval's. The owner accepted this change of wording (D5).

**What the hash covers and what it does not.** It covers the nine fields above and nothing else.
`before_json` (the display-only before-values, D6), the approval id, the decision, the expiry and the
`policy_decision_id` are outside it. The dashboard shows what is hashed (operation, connection,
order id, expected version, every changed field) and sends the hash it displayed when deciding, so a
proposal that changed after it was shown is refused (P4-18).

**Strict input.** Before hashing or storing, approval inputs pass `checkApprovalInput`, and the raw
request body passes `findRawJsonIssue` (section 9). `actionHashInput` itself takes the descriptor's argument names and refuses (`argument_mismatch`) a
`targetResourceId` or `expectedResourceVersion` that is not exactly the value of that argument in
`arguments`; it also refuses an input the strict check refuses, with a stable code, so a caller that forgot the check still cannot hash an
ambiguous value. `canonicalJson` is unchanged for every other caller.

### 3. The vault MAC and what it covers

Approvals carry a MAC produced by the vault with the machinery of the capability MACs
(`services/vault/src/mac.ts`: HKDF-SHA-256 from the current KEK, HMAC-SHA-256 through `@aab/crypto`,
canonical JSON, constant-time comparison, a layout label of its own, `aab.vault.approval.v1`). No new
primitive and no hand-written cryptography. The API and the worker cannot import the KEK, so the MAC
can only come from the vault (D3).

A new vault operation `decideApproval`, on the `api` socket only, does in one transaction: lock the
approval row, require `pending` and unexpired, require the presented action hash to equal the stored
one and a recomputation from `proposal_json`, set status and approver, append the `approval_decisions`
row and the audit event, and, for an approval, write the MAC. A denial gets no MAC: forging a denial
can only remove authority.

**The MAC covers exactly these fields** (the explicit list of phase-4.md 3.3; a test edits each one):
`id`, `organization_id`, `owner_user_id`, `agent_id`, `connection_id`, `operation`, `run_id`,
`target_resource_id`, `expected_resource_version`, `action_hash`, `approver_user_id`, `decided_at`
and `expires_at`, with the layout label and the KEK version used. The MAC key version is stored in
`mac_kek_version`.

**What the MAC does not cover**, stated plainly, and why that is acceptable:

| Not covered                                                          | What a database writer can do                                 | Why this is acceptable                                                                                                                                                                                                                                                                                      |
| -------------------------------------------------------------------- | ------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `consumed_at`, `consumed_by_job_id`, and `status` after the decision | Clear them, to make a consumed approval look `approved` again | One job per approval is a partial unique index on `execution_jobs.approval_request_id`, and the job row outlives the approval, so clearing `consumed_at` cannot produce a second job. The approval's expiry (covered) still bounds the window. A writer who also deletes the job row is outside the design. |
| Revocation fields (`status` = `revoked` and its time)                | Clear them, to revive a revoked approval                      | Reviving gives back at most the exact approved action until its covered `expires_at`, and it still passes the three policy rechecks (section 6), so it cannot exceed current grants. A revocation of a grant is also a grant change that the recheck sees.                                                  |
| `proposal_json` and `before_json` as columns                         | Edit them                                                     | `proposal_json` is bound through `action_hash`, which is covered, and `decideApproval`, the redemption and the supervisor's claim recompute the hash from it; an edit of the proposal after the decision yields no capability. `before_json` is display only and outside every hash by design.              |
| `created_at`, `policy_decision_id`                                   | Edit them                                                     | Neither grants authority. `policy_decision_id` is re-derived when the job is created and is part of the job hash, which the capability MAC covers.                                                                                                                                                          |

In the capability row of Phase 3, `used_at` and `revoked_at` are outside the MACs, and the plan does
not repeat the pattern silently: the only state that grants authority (`approved` with its binding) is
MAC-covered, so authority cannot be created; the three points in the table are what remains and they
are named. `authorizeJobAccess` for a write job verifies the MAC, requires `consumed_by_job_id` to
equal the job, and caps the capability's lifetime at the approval's expiry. The capability's
authorization MAC already covers the job's arguments hash, and the job hash of layout 2 covers the
approval id and action hash, so approval and capability are chained.

**Who approves.** The signed-in owner only. Until agent credentials exist (Phase 6) the owner is also
the caller who names the agent, so the same person proposes and approves, and nothing authenticates the
difference. The controls that exist are the exact-action binding, the explicit approve step and the
audit trail. This record does not claim separation of duties (D9).

### 4. Redemption: one conditional update, and the lock order

In the transaction that creates the job, after locks taken in a fixed order (the agent row
`FOR NO KEY UPDATE`, then the approval row `FOR UPDATE`, mirroring `insertAuthorization` for
capabilities):

```sql
UPDATE approval_requests
   SET status = 'consumed', consumed_at = statement_timestamp(), consumed_by_job_id = $job
 WHERE id = $approval AND status = 'approved'
   AND organization_id = $org AND owner_user_id = $owner AND approver_user_id = $owner
   AND agent_id = $agent AND connection_id = $connection AND operation = $operation
   AND run_id IS NOT DISTINCT FROM $run
   AND action_hash = $recomputed AND mac IS NOT NULL
   AND consumed_at IS NULL AND expires_at > statement_timestamp()
RETURNING ...
```

`$recomputed` is the action hash computed from the request with the shared function. Zero rows is a
refusal. Only afterwards may the code read the row to choose the audit reason (`not_found`,
`not_approved`, `expired`, `consumed`, `revoked`, `binding_mismatch`, or an input-check code); that read
labels the refusal and never changes it. No code path reads an approval, decides and then writes
(P4-4). The job insert, the idempotency record and the audit event share the transaction, so a
failing insert rolls the consume back. The job's arguments are copied from the approval's
`proposal_json`, never from the resubmitted body; the body must hash equal to it (P4-20). The database
clock is the only clock for expiry: `expires_at > statement_timestamp()`, no grace, whether the
approval is `pending` or `approved`; the injected `now` must be within 5 seconds of the database
clock, as in Phase 3 (P4-6).

The approval is consumed in every outcome that follows: a success, a failure, `stale_version`,
`outcome_unknown`, a cancellation or a worker crash. A new proposal is the only way forward (P4-5).

### 5. Policy is re-evaluated, and the engine has no approval input

The engine stays unchanged and pure. It does not take an "approved" flag, because the simulator and
execution must call one function on one input shape (specification §8.1 rule 6, PE-16). "Approval
satisfied" is a separate check made after the engine answered `approval_required` with that reason
code, in a small pure helper (`approvalSatisfies`) tested on its own. It accepts only a decision whose
outcome is `approval_required` for the same operation; a deny from any grant stays a deny, and an
`allow` for a non-read operation is impossible because `defineOperation` refuses any operation whose sensitivity is not `read` unless it requires approval and declares both `resourceArgument` and `versionArgument`. Step C1 also refuses an `allow` outcome for a non-read operation at the approval layer, as defence in depth (implemented in C1 and C3, not in C0).

`OperationDescriptor` gains optional `versionArgument`. `defineOperation` throws when an operation of
sensitivity `write` or `destructive` does not require approval, lacks `resourceArgument` or
`versionArgument`, names an argument that is not a key of its input schema, names the same key for both, or declares either as optional or of a type the approval cannot hold (the resource must be a required string of 1 to 200 characters; the version a required string of 1 to 200 characters or a required non-negative safe integer). A change to either field
in an adapter upgrade is a re-review event under ADR-006 (PE-15).

### 6. Where the rechecks happen

| Point                        | Where                                      | What is checked                                                                                                                                                                                                                            |
| ---------------------------- | ------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Request time                 | API                                        | Plain JSON, strict input check, adapter schema, engine, obligations, then (with `approvalId`) the conditional update of section 4.                                                                                                         |
| Authorization (stage 1)      | Vault, `authorizeJobAccess`                | Existing checks (matched grant still an unrevoked, unexpired allow; agent active; no newer deny), plus the approval MAC, `consumed_by_job_id` and the expiry cap.                                                                          |
| Claim                        | Supervisor, `runOperationJob` step 0 and 3 | Arguments hash (layout 2), approval row consumed by this job and its action hash recomputed from the job, fresh grants through the engine (`approval_required` for a write, `allow` for a read), obligations unchanged, connection status. |
| Immediately before the write | Runner, inside the adapter                 | The live order version equals the approved version. Only the runner can see the target; the API holds no session and no network path.                                                                                                      |
| At the target                | Demo application                           | Rejects an edit submitted with a stale version (specification §3). Defence in depth against the gap between the runner's read and its submit.                                                                                              |

The runner never receives the approval row, only the arguments and the expected version, which are in
the arguments. The supervisor already recomputes the arguments hash, so the approval check sits beside
it at no new trust boundary. Policy wins over any approval: a revoked or expired grant, a new deny, a
disabled agent or a non-active connection refuses the job at each of the first three points (P4-10).

### 7. Job hash layout 2

`jobArgumentsHashInputV2` (in `@aab/contracts`) is `aab.job-arguments.v2\n` plus canonical JSON of the
layout-1 fields plus `approvalRequestId` and `actionHash`, both null for a read and both set for a
write; a job bound to only one of them cannot be hashed. Layout 1 is byte-identical to before, and its
pinned vector is unchanged. `execution_jobs.arguments_hash_layout` (1 backfilled, 2 for new rows)
tells the supervisor which layout to use, so a writer cannot move a job to the layout that omits the
approval; a write job with layout 1 is refused. The capability MAC already covers the hash, so no MAC
layout change is needed. The job hash does not equal the action hash; it covers it.

### 8. Write semantics and outcomes

- The adapter's order of work for `orders.applyApprovedUpdate` (sensitivity `write`,
  `requiresApproval`, not idempotent, side effects stated, allowed paths the order and its edit page):
  validate; open the order; compare the version; fill only the declared fields; submit once; re-read;
  compare the version (exactly the next version the demo defines, not merely greater) and every changed
  field to the proposed value. A match is `succeeded`; a greater version with matching fields is
  `outcome_unknown`. A stale version before the submit is `failed` with the new job error code
  `stale_version`. Anything unconfirmed, and any error after the submit click was issued, is
  `outcome_unknown`. Nothing resubmits and the adapter has no retry loop (INV-12, P4-12).
- The supervisor appends `operation.write_dispatched` in its own transaction immediately before it
  invokes the runner for a write, so a job that ended `outcome_unknown` with no such event can be told
  from one that may have reached the target.
- Lease recovery ends a non-retry-safe job as `outcome_unknown` and revokes the capability in the same
  transaction. This is pessimistic: a crash before the submit also ends as unknown. A precise pre-submit
  marker needs a handshake with the sandboxed runner and is left to Phase 7 (D8).
- A write job uses the existing `read` capability purpose, which names what the vault does (open the
  session), not what the operation does.

### 9. Parsing, canonical form and route matching (phase-4.md 3.11)

- **Run what was approved.** The approval stores the parsed, validated arguments; the hash covers that
  stored form; the job copies it. The resubmitted request only has to match. Nothing re-serializes the
  request and runs the result.
- **Refuse ambiguous values at the edge.** `canonicalJson` accepts integers beyond
  `Number.MAX_SAFE_INTEGER` (two different decimal strings parse to one number), `-0` (written as `0`)
  and lone surrogates, and the JSON body parser keeps the last of two equal keys. For approval inputs
  `checkApprovalInput` refuses, with stable codes, `unsafe_integer`, `negative_zero`, `lone_surrogate`
  (in a value or a key), `non_finite_number`, `not_json` and `too_deep`; `findRawJsonIssue` scans the raw
  body and refuses `duplicate_key` (keys compared after decoding escapes, so `"a"` and `"\u0061"`
  collide), `invalid_json` and `too_deep`. The scanner is a small parser over the RFC 8259 grammar, not
  cryptography, and carries its own tests. Two spellings that mean the same value (`1` and `1.0`) are
  the same value: same hash, same execution.
- **Boundaries agree.** Expiry is decided by the database clock alone, in one predicate, so no two
  components disagree about one instant.
- **Match what the handler serves.** The approve and deny routes and the write's allowed paths are
  authorized after normalization; trailing slashes, case, encoded or dot segments, an added suffix and a
  method-override header reach the same check or nothing. Identity, approver and role never come from a
  request header or body field. A `GET` never decides an approval. A redirect during the write that
  leaves the allowed paths stops the job before the submit (P4-22).
- **Positive control first.** A refusal test proves nothing until the same fixture is shown to accept the
  valid request, in the same test or the same `describe` (P4-21).
- **Approvals are decided in the dashboard only.** The approval view renders no agent-supplied URL as a
  link, and no link carries a decision.

### 10. Revocation, expiry and the sweeper

`grants.revoke`, `agents.disable` and `connections.revoke` already run in one transaction, take the agent
row `FOR NO KEY UPDATE`, and revoke capabilities. In the same transactions and the same lock order they
now also move `pending` and unconsumed `approved` approvals of the scope to `revoked` (with
`approval.revoked` events) and end the scope's queued write jobs with their capabilities. A running
write is stopped by the supervisor's heartbeat as in Phase 3; a browser action already sent cannot be
recalled (WK-6). Expiry is applied lazily by the redemption predicate and eagerly by a sweeper in the
API's maintenance loop, which sets `expired` and writes `approval.expired`; correctness never depends
on the sweeper. Pending approvals are capped at 20 per agent and connection and 100 per owner, as
settings; a request over the cap is denied with a stable code (D10). Lifetime is 15 minutes by default,
within 1 minute to 24 hours, with a database `CHECK` at the upper bound (D7).

### 11. Fail closed

When the approval store, the vault or the audit append fails, no approval is created or consumed, no
job is created and no write runs (P4-16). If the vault fails after the approval was consumed in the
job's transaction, the job ends `vault_unavailable` and the approval stays consumed: it is not
reusable. Each state change commits with its audit event or not at all (P4-14).

## Schema (migration `0006_phase4_approvals`)

To be written in step C1; hand-written SQL where drizzle cannot express it, like migrations 0002 and 0005. It adds:

- `approval_requests` (specification §11, plus agent, owner, target resource, `before_json`,
  `policy_decision_id`, `mac` and `mac_kek_version`). `CHECK`s: status in the six values; `approver_user_id`
  equals `owner_user_id` when set; `action_hash` is 64 lowercase hex digits; lifetime at most 24 hours; a
  consumed row was approved (decision fields and MAC present); a MAC is present when `approved` or
  `consumed`; `target_resource_id` and `expected_resource_version` equal the values in `proposal_json`
  (also checked by the repository).
- `approval_decisions`: append-only; triggers refuse `UPDATE` and `DELETE`, as for the audit table.
- A foreign key on `execution_jobs.approval_request_id` and a partial unique index on it where it is not
  null (the "one job per approval" guarantee of section 3).
- `execution_jobs.arguments_hash_layout` (1 backfilled, 2 for new rows), `stale_version` in the job error
  code constraint, and the new audit event types.

The migration adds no approval row and changes no existing job, grant or capability (P4-19).

## Audit events

Written in the same transaction as the change they describe (INV-10). Metadata holds ids, key names,
codes and the approval id. It holds no argument value, no action hash and no MAC. No audit record, log, list response or agent-facing response holds an argument value, an action hash or a MAC. The owner-only `GET /v1/approvals/:id` returns `actionHash`, an unkeyed digest of fields the same response shows, so the dashboard can present it when deciding (P4-18). (P4-14).

| Event                        | Written by  | When                                                                                                                   |
| ---------------------------- | ----------- | ---------------------------------------------------------------------------------------------------------------------- |
| `approval.proposed`          | API         | The execute route created a pending approval (with the `policy.evaluated` event).                                      |
| `approval.approved`          | Vault       | `decideApproval` approved it.                                                                                          |
| `approval.denied`            | Vault       | `decideApproval` denied it.                                                                                            |
| `approval.expired`           | API sweeper | The maintenance loop set `expired` (lazy expiry at redemption needs no event of its own).                              |
| `approval.revoked`           | API         | A grant, agent or connection revocation revoked it.                                                                    |
| `approval.redeemed`          | API         | The conditional update consumed it in the job's transaction.                                                           |
| `approval.refused`           | API         | A redemption was refused; `reason` is an `ApprovalRefusalReason`.                                                      |
| `operation.write_dispatched` | Supervisor  | Immediately before the runner is started for a write.                                                                  |
| `vault.approval_sealed`      | Vault       | `decideApproval` wrote the MAC.                                                                                        |
| `vault.approval_rejected`    | Vault       | `authorizeJobAccess` refused a write job because the approval failed its checks (MAC, binding, consumption or expiry). |

`ApprovalRefusalReason` is `not_found`, `not_approved`, `expired`, `consumed`, `revoked`,
`binding_mismatch`, plus the input-check codes of section 9. Only the audit event carries the reason;
the caller learns that the request was refused. A refusal that names the approval's other binding (for
example the connection it was approved for) must not leak it to a caller who does not own it (P4-9).

## What a compromised component can and cannot do

These statements are the design. They become claims only when the tests named in phase-4.md exist and
pass; until then they are written, not run. They assume `separate-uid` and the bubblewrap launcher, as in
ADR-014.

| Component                                     | Cannot                                                                                                                                                                                                                                      | Can                                                                                                                                                                                                                                                                                                                    |
| --------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Database writer without vault access**      | Mint an approval (an `approved` row, or an edit of any MAC-covered field, yields no capability: P4-8). Obtain a second job from one approval (unique index). Exceed current grants with a revived approval (rechecks). Forge a vault event. | Delete rows (denial of service, including the job row of a consumed approval, which is outside this design). Clear `consumed_at` and revocation fields. Revive a revoked approval within its covered expiry, for the exact approved action only. Edit uncovered columns such as `before_json`, which are display only. |
| **API process**                               | Read the KEK or any plaintext session. Redeem an approval without the vault's MAC. Make the supervisor run a job whose arguments hash or approval it cannot verify.                                                                         | Approve: the API reaches the vault's `api` socket, so a compromised API can call `decideApproval` for any pending approval. This is an accepted limit, as in ADR-014 for authorization of capabilities. Create approvals and jobs for any agent, and deny service.                                                     |
| **Supervisor**                                | Redeem an approval (no socket role for it). Create authority: an approval or capability row it writes fails the MAC. Run a job the vault did not authorize.                                                                                 | Run jobs the vault authorized, read the sessions of the jobs it claims (ADR-014), write false audit events, deny service.                                                                                                                                                                                              |
| **Runner (sandbox)**                          | See the approval row, the vault or the database. Reach origins outside the job's list.                                                                                                                                                      | Act inside the one session of its job until the job ends, within the allowed origins and paths; report a false outcome (a compromised runner's output is not trustworthy, ADR-013).                                                                                                                                    |
| **Local user with the services' uid, root**   | Nothing is claimed against them (ADR-014 `shared-uid`).                                                                                                                                                                                     | Everything.                                                                                                                                                                                                                                                                                                            |
| **The same person who proposes and approves** | Nothing separates them until agent credentials exist (D9).                                                                                                                                                                                  | Propose and approve their own request. The exact-action binding, the explicit step and the audit trail are the controls; there is no separation of duties.                                                                                                                                                             |

## Out of scope for Phase 4

- Multi-step workflows and approval chains (Phase 7), and a precise pre-submit marker with the runner (D8).
- Agent credentials and distinct principal types (Phase 6, AAB-033).
- Sealing `proposal_json` at rest: proposals hold argument values in plaintext, as job rows do today
  (D14; synthetic data only; revisit before real data).
- Separate database roles per service (AAB-036).
- Approvals for operations that name no target resource.
- A second factor on approval (D9).

## Alternatives considered

- **Approval without a MAC (database constraints only).** Simpler. Rejected: with one database role,
  a writer inserts an `approved` row and the supervisor runs the write. The MAC is what makes authority
  uncreatable by a writer (D3).
- **Auto-run when approved.** Fewer round trips. Rejected: the approver's request would then create the
  job, so the redemption transaction, the recheck at that moment and the idempotency record would hang
  off the owner's click, and a stale proposal could run before the caller sees it. The caller
  resubmits (D2).
- **An "approved" input to the policy engine.** Rejected: the simulator and execution must call one
  function with one input shape (PE-16), and an engine that takes an approval flag could be called with
  a forged one. The check is a separate helper after the engine has answered.
- **Storing the approval inside the job row.** Rejected: the job needs `policyDecisionId`, created after
  the approval, and an approval must exist and be decided before any job. A unique index on a separate
  table is also what stops a second job.
- **Reusing the job arguments hash as the action hash.** Rejected for the `policyDecisionId` reason in
  section 2.
- **A keyed action hash.** Considered. The hash is a binding for comparison, not a credential; the MAC
  is the keyed part. A keyed hash would force every site that recomputes it to hold a key.
- **Rejecting approvals that include any non-ASCII text.** Rejected as too blunt; lone surrogates and
  the other ambiguities of section 9 are refused instead.
- **Making `canonicalJson` strict for every caller.** Rejected: audit hashing and idempotency use it and
  existing stored hashes must keep verifying. The strict check is a separate function used for approval
  inputs.

## Consequences

- One more vault operation on the `api` socket and one more MAC layout. Every write costs a decision
  round trip, an authorization round trip and a browser run.
- `approval_required` becomes HTTP 202 with a body (D11): a documented change to a Phase 2 behavior, in
  specification §12.2 and the changelog.
- The approval view must show the action hash to the owner (the owner's detail response carries it,
  `ApprovalDetail`); the list and any agent-facing response do not.
- `execution_jobs` gains a column; supervisor code must pick the hash layout from the row.
- An adapter upgrade that changes `resourceArgument` or `versionArgument` of a write is a re-review event.
- The same-person limit (D9) is real until Phase 6 and is written into `security.md` when step C7 lands.
- Approval proposals sit in the database in plaintext (D14).
- Contracts expose a second entry point (`@aab/contracts/hashing`) so that the browser bundle never
  reaches `node:crypto`.

## Revisit when

- Agent credentials exist (Phase 6): separate the proposer from the approver, and revisit D9.
- A second write adapter is added: check that `resourceArgument` and `versionArgument` express its
  targets, and that the dispatch event and outcome mapping still fit.
- Per-service database roles are introduced (AAB-036): the MAC may become defence in depth only.
- A real credential or real data is to be handled: seal `proposal_json` (D14) and obtain the independent
  review of the approval path first.
- The pre-submit handshake with the runner exists (Phase 7): replace the pessimistic `outcome_unknown`.
