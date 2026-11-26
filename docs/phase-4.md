# Phase 4: policy engine, grants and approval workflow

- **Status:** Plan approved by the owner on 2026-11-25 with every recommended default of section 5
  (D1 to D15). Nothing in this file is implemented, and no step has started. Written on
  2026-11-25 from the specification, the documents named below and a read of the code at commit
  `b16e81d`. No test was run to write it, so every statement about existing code is "read", not "run".
  The plan is for the owner to approve (section 5) before any code is written.
- **Specification:** §7 (adapter operations, §7.1 write safety), §8 (policy and approval design,
  §8.2 in particular), §11 (`approval_requests`, `approval_decisions`, `execution_jobs.approval_request_id`),
  §11.2 (canonical JSON), §12.2 (execute), §15 Phase 4. Goal: authorization covers writes, with
  approval of the exact action. Deliverables: a read is allowed, an ungranted write is denied, an
  approved write succeeds once. Exit criteria: replay, a modified payload, a stale version, a revoked
  grant and a cross-connection attempt are all rejected.
- **Threat model:** rows PE-10, PE-11, PE-14, PE-16, WK-2 to WK-6, WK-9, AG-7, AG-8 and UI-1, UI-7,
  UI-9, UI-10. Section 4 proposes new rows AP-1 to AP-18 (not yet added to
  [`threat-model.md`](threat-model.md)).
- **Backlog:** AAB-032 is this phase's core ticket (see 3.9 for one change to its wording). AAB-021
  and AT-059 are discussed in 3.9. AAB-033 (distinct principal types) stays in Phase 6.

Wording follows [`security.md`](security.md) §2: a property below is a design until its test exists and
has passed in a recorded run. Every invariant is **Planned** until some test exists. Test names are
planned names, not existing tests.

## 1. What exists today (read, not run)

These facts shape the plan. Each was read in the code on 2026-11-25.

- **The policy engine already returns `approval_required`** and never `allow` for a destructive or
  `requiresApproval` operation (`packages/policy-engine/src/evaluate.ts`, step 11). It is pure, has no
  clock and no I/O. Phase 4 needs no change to it; section 3.2 explains why that is deliberate.
- **Writes are refused in two places by hard-coded checks:** the execute route
  (`services/broker-api/src/routes/execution.ts`, "Phase 2 runs reads only") and the supervisor
  (`services/browser-worker/src/supervisor/operation.ts`, "Phase 2 runs read operations only").
  `approval_required` currently answers 403 with no row anywhere. Tests that assert the refusal
  (`execution-adapters.test.ts`, `supervisor/operation.test.ts` "a write operation is refused in phase
  2 even with an allow grant") must be rewritten to "a write without a valid approval is refused", not
  deleted.
- **Job arguments hash (PE-14).** `execution_jobs.arguments_hash` is an unkeyed SHA-256 of
  `aab.job-arguments.v1\n` plus canonical JSON of `{agentId, arguments, connectionId, operation,
organizationId, policyDecisionId, retrySafe, timeoutMs}`. The supervisor recomputes it, and the vault
  binds it into the capability's authorization MAC, which is keyed (ADR-014 section 6), so an edit of
  row and hash together is still caught at `readForWorker`. The layout includes `policyDecisionId`,
  which does not exist when an approval is created, so an approval cannot carry the job's hash
  (section 3.9).
- **`execution_jobs.approval_request_id` exists as an unused `uuid` with no foreign key.** There is no
  approval table, repository, route, audit event type or contract type. `PlannedPages.tsx` holds
  placeholder Approvals and Policies pages. The grant editor exists per agent
  (`apps/dashboard/src/pages/AgentDetailPage.tsx`: constraints, expiry); there is no simulator and no
  `/v1/approvals` route.
- **Capability consume is one conditional `UPDATE ... RETURNING`** with every condition in the `WHERE`
  clause, after locks taken in a fixed order; a revocation of a grant or agent takes the agent row
  `FOR NO KEY UPDATE` (`packages/database/src/repositories/capabilities.ts`, `grants.ts`). Phase 4 copies
  this form for approvals. In the capability row, `used_at` and `revoked_at` are not covered by either
  MAC (the Phase 3 residual; section 3.3 says how Phase 4 avoids repeating it).
- **Lease recovery already ends a job that is not retry-safe as `outcome_unknown`**
  (`recoverExpiredLeases`; a write has `retrySafe = false` because the route sets it to
  `idempotent && sensitivity === 'read'`). The supervisor maps a runner outcome `outcome_unknown` to
  the job status. No write operation has ever exercised either, so WK-2 and AT-013 are untested for
  writes.
- **`BrowserSession` already has `fill` and `click`** (`packages/adapter-sdk/src/types.ts`), and
  `defineOperation` already demands side effects for a write and approval for a destructive operation.
  Northstar has only `orders.list` and `orders.get`; `orders.get` returns `version`, with a comment that
  later writes bind approvals to it.
- **`OperationDescriptor` has no field that names the argument holding the expected resource version.**
  Section 3.2 adds one.
- **The demo.** `northstar-demo` is a separate repository (`silentonroot/northstar-demo`). No local
  checkout exists on this machine (searched under the home directory to depth 6; the end-to-end guide
  expects `../northstar-demo` and the nightly workflow checks it out from GitHub). What the plan needs
  from it is therefore not verified; section 3.7 lists it. The specification (§3) says orders carry a
  version and a stale edit is rejected.

## 2. Phase 4 invariants

Test paths are relative to the repository root. "Planned" everywhere; the status column is filled from
runs, as in Phase 3.

| #     | Invariant                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | How it is proven (planned tests)                                                                                                                                                                                                                                                                                                                                                                      |
| ----- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| P4-1  | **An ungranted write is denied.** No allow grant, an expired or revoked one, an explicit deny, or an unsatisfied constraint gives `denied`, no approval row, no job and a `policy.evaluated` deny event. Reads are unchanged.                                                                                                                                                                                                                                                                                                                           | `services/broker-api/test/execution-writes.test.ts` "denies a write with no grant, an expired grant, a revoked grant and an explicit deny, creating no approval and no job"; the Phase 2 read tests still pass.                                                                                                                                                                                       |
| P4-2  | **A write needs an approval and creates no side effect before it.** An allowed write whose policy outcome is `approval_required` creates one `pending` approval and no job. A grant with `approvalMode: none` on a `requiresApproval` operation still needs one (ADR-005).                                                                                                                                                                                                                                                                              | `execution-writes.test.ts` "an allowed write answers approval_required with a pending approval and no job"; "approvalMode none does not remove the approval for a requiresApproval operation"; `services/browser-worker/test/e2e/phase4.e2e.test.ts` step 2 reads the order after the request: unchanged.                                                                                             |
| P4-3  | **Approval of the exact action (INV-9, PE-14, WK-4).** The approval binds a SHA-256 over canonical JSON of organization, owner, agent, run, connection, operation, final arguments (obligations applied), target resource id and expected version. Any difference at redemption is refused.                                                                                                                                                                                                                                                             | `packages/database/test/approvals.test.ts` "refuses redemption when the %s differs" (arguments, one key added, key reordered is accepted as equal, `1.0` for `1` is accepted as equal and runs the stored value, operation, connection, agent, organization, run, target id, expected version); `packages/contracts/test/approval-hash.test.ts`.                                                      |
| P4-4  | **Single use, atomic (A5 for approvals).** Every redemption condition and the mark that the approval is used are one conditional `UPDATE ... RETURNING` in the transaction that creates the job. No code path reads an approval, decides and then writes.                                                                                                                                                                                                                                                                                               | `packages/database/test/approval-concurrency.test.ts` (PostgreSQL, real parallel connections) "20 simultaneous redemptions of one approval create exactly one job"; `approvals.test.ts` "a failing job insert rolls back the consume".                                                                                                                                                                |
| P4-5  | **Replay is rejected whatever happened to the first use.** A second redemption after success, failure, `stale_version`, `outcome_unknown`, cancellation or a worker crash is refused. A unique index allows one job per approval, so clearing `consumed_at` by SQL cannot produce a second job.                                                                                                                                                                                                                                                         | `approvals.test.ts` "a consumed approval is refused after each terminal status of its job (%s)"; "clearing consumed_at by SQL still cannot create a second job (unique index)"; e2e step 5.                                                                                                                                                                                                           |
| P4-6  | **Approvals expire.** An approval is unusable from the instant of `expires_at` (database clock, no grace), whether `pending` or `approved`. Lifetime is a setting inside fixed bounds; a database `CHECK` repeats the upper bound.                                                                                                                                                                                                                                                                                                                      | `approvals.test.ts` "is refused at exactly expires_at and one millisecond before it is accepted"; `services/broker-api/test/config-and-startup.test.ts` "refuses a missing or out-of-range approval lifetime"; `packages/database/test/migration-0006.test.ts` "refuses a lifetime above the bound".                                                                                                  |
| P4-7  | **Only the owner decides, as themself.** Approve and deny require the signed-in owner of the agent and the connection; the approver id comes from the session, never from the body; another owner's approval looks missing. CSRF applies. No agent credential exists until Phase 6; the plan states what that leaves (3.3).                                                                                                                                                                                                                             | `services/broker-api/test/approvals.test.ts` "refuses approve and deny without a session, without a CSRF token, and for another owner's approval (404)"; "ignores an approverUserId in the body"; "refuses an agentId in the approve request".                                                                                                                                                        |
| P4-8  | **A database writer cannot mint an approval.** The `approved` state carries a vault MAC over the binding and the decision. A row inserted as approved, or edited after the decision (arguments hash, connection, target, version, expiry, approver), yields no capability, so no session and no write.                                                                                                                                                                                                                                                  | `services/vault/test/approval-integrity.test.ts` "an approved row inserted by a database writer yields no capability", "an edit of %s after the decision yields no capability and is audited as integrity" (eight fields), "a cleared MAC yields no capability".                                                                                                                                      |
| P4-9  | **Cross-binding attempts are rejected.** An approval for connection A cannot release a job on connection B; likewise another agent, operation, organization, owner, run or order.                                                                                                                                                                                                                                                                                                                                                                       | `approvals.test.ts` and `execution-writes.test.ts` "an approval for connection A is refused on connection B (and the refusal is audited without naming A)", and one test per other field; e2e step 6.                                                                                                                                                                                                 |
| P4-10 | **Policy is re-evaluated at three points and wins over any approval:** when the approval is redeemed (API), when the vault authorizes the job, and when the supervisor claims it. A revoked or expired grant, a new deny, a disabled agent or a non-active connection refuses the job.                                                                                                                                                                                                                                                                  | `execution-writes.test.ts` "a revoked grant after approval refuses redemption"; `services/vault/test/approval-authorize.test.ts` "authorization re-checks the grant"; `services/browser-worker/test/supervisor/write-operation.test.ts` "grant revoked after enqueue: denied, no browser started".                                                                                                    |
| P4-11 | **Stale target state is rejected before the write.** The runner reads the live version of the target and refuses to submit unless it equals the approved version; the demo also rejects a stale submit. The outcome is `failed` (`stale_version`), the approval stays consumed, and a new proposal is required.                                                                                                                                                                                                                                         | `packages/adapters/northstar/test/writes.test.ts` "reads the version first and does not touch the form when it differs (fake browser records every call)"; e2e step 4 (the order is edited by another route between approval and redemption).                                                                                                                                                         |
| P4-12 | **Succeeded only after verification; unknown otherwise; never retried (INV-12, WK-2, WK-9).** After submit the adapter re-reads the order and checks version and fields. An unconfirmed result, a thrown error after submit, a worker kill or a lost lease ends `outcome_unknown`; nothing resubmits.                                                                                                                                                                                                                                                   | `writes.test.ts` "reports outcome_unknown when the re-read shows neither the old nor the new state, and when the page throws after submit"; `write-operation.test.ts` "a killed worker leaves outcome_unknown and the next claim attempt finds no job"; e2e step 7 (SIGKILL the worker after the demo accepts).                                                                                       |
| P4-13 | **Revocation cascades in one transaction (INV-11, WK-6).** Revoking a grant, disabling an agent or revoking a connection revokes that scope's `pending` and unconsumed `approved` approvals, revokes the capabilities of queued write jobs and ends those jobs; a running write is stopped as in Phase 3.                                                                                                                                                                                                                                               | `services/broker-api/test/lifecycle-audit.test.ts` (extended) "revoking a grant, disabling an agent and revoking a connection revoke their open approvals and cancel their queued write jobs"; `packages/database/test/approvals.test.ts` block "revocation".                                                                                                                                         |
| P4-14 | **Audit in the same transaction (INV-10), without values.** Propose, approve, deny, expire, redeem and refuse each commit with their event or not at all. Metadata holds ids, key names, codes and the approval id; no argument values, no action hash, no MAC. No audit record, log, list response or agent-facing response holds an argument value, an action hash or a MAC. The owner-only `GET /v1/approvals/:id` returns `actionHash`, an unkeyed digest of fields the same response shows, so the dashboard can present it when deciding (P4-18). | `execution-writes.test.ts` and `approvals.test.ts` "a failing audit append rolls back the %s"; `services/vault/test/secrets-scan.test.ts` (extended) "no audit record, log, list response or agent-facing response holds an argument value, an action hash or an approval MAC", with the owner-only detail response the one place the action hash appears.                                            |
| P4-15 | **The simulator is the engine (PE-16).** The simulator route and the execute route call the same `evaluate` function with the same inputs builder; no second implementation exists.                                                                                                                                                                                                                                                                                                                                                                     | `services/broker-api/test/simulator.test.ts` "answers exactly what execution decides for 40 generated requests"; a lint-level import test: only one module outside the engine imports `evaluate` for requests.                                                                                                                                                                                        |
| P4-16 | **Fail closed (INV-10).** When the approval store, the vault or the audit append fails, no approval is created or consumed, no job is created and no write runs.                                                                                                                                                                                                                                                                                                                                                                                        | `execution-writes.test.ts` "a failing vault authorization ends the write job vault_unavailable, and the approval is consumed (not reusable)"; "a failing approval insert answers 503 and creates nothing".                                                                                                                                                                                            |
| P4-17 | **`proposeUpdate` never writes.** The proposal operation is a read: its adapter code never calls `fill` or `click` on a form control, and its grant does not authorize `applyApprovedUpdate`.                                                                                                                                                                                                                                                                                                                                                           | `writes.test.ts` "orders.proposeUpdate performs no fill and no click (fake browser)"; `execution-writes.test.ts` "a proposeUpdate grant does not allow applyApprovedUpdate".                                                                                                                                                                                                                          |
| P4-18 | **The dashboard shows what will run.** The approval view renders the server's exact proposal (operation, connection, order id, expected version, every changed field), escapes all text (UI-10), and sends the displayed action hash back so that approving a changed proposal fails.                                                                                                                                                                                                                                                                   | `apps/dashboard/test/approvals.test.tsx` "shows the exact changes and approves with the displayed hash", "renders a script-looking value as text"; `broker-api/test/approvals.test.ts` "approve with a stale actionHash answers 409 and changes nothing".                                                                                                                                             |
| P4-19 | **Migration `0006` is safe** on an empty database and on a Phase 3 database with jobs, grants and capabilities, and it adds no approval row.                                                                                                                                                                                                                                                                                                                                                                                                            | `packages/database/test/migration-0006.test.ts` "migrates an empty database", "migrates a Phase 3 database and leaves jobs, grants and capabilities unchanged".                                                                                                                                                                                                                                       |
| P4-20 | **One meaning per approved action.** The job runs the approval's stored `proposal_json`, never the resubmitted request body; the request must hash equal to it. Approval inputs refuse values that two parsers or two hash sites could read differently: integers outside the safe range, `-0`, lone surrogates, and duplicate keys in the raw body. The API, the vault and the supervisor compute the action hash with one shared function.                                                                                                            | `packages/contracts/test/approval-hash.test.ts` "refuses 2^53+1, -0, a lone surrogate and a duplicate key"; "two spellings that parse to the same value hash the same, and the job runs the stored value"; a corpus test that the three call sites import the same function and agree on every case; `execution-writes.test.ts` "the job's arguments are the approval's proposal_json byte for byte". |
| P4-21 | **Every refusal test has a passing twin.** Each negative test in the approval, redemption and write suites runs against a fixture on which the valid request is shown to succeed in the same test or the same `describe`, so a refusal cannot come from broken setup.                                                                                                                                                                                                                                                                                   | A lint-level test that lists the negative tests of `approvals.test.ts`, `execution-writes.test.ts` and `write-operation.test.ts` and checks that each block has a positive control; mutation checks in C7.                                                                                                                                                                                            |
| P4-22 | **Routes and paths are matched as the handler sees them.** The approve and deny routes, and the write operation's allowed paths, are authorized after normalization; a variant spelling (trailing slash, case, encoded or dot segments, an added suffix, a method-override header) reaches the same check or nothing. Identity, approver and role never come from a request header or body field. A `GET` never decides an approval.                                                                                                                    | `broker-api/test/approvals.test.ts` "every spelling variant of the approve route is refused without a session and checked like the canonical one"; "an X-HTTP-Method-Override or a user-id header changes nothing"; "GET on the decide routes is 404 or 405"; `northstar/test/writes.test.ts` "a redirect or link to a path outside the allowed set during the write stops the job before submit".    |

## 3. Design

### 3.1 The flow

1. The caller (the signed-in owner acting as one of their agents, spec §8.3) may run
   `orders.proposeUpdate`: a read that returns the order's current version and fields and, for the
   proposed `changes`, what would differ. Nothing is written to the target or to the approval store.
2. The caller sends `POST /v1/operations/execute` for `orders.applyApprovedUpdate` with `orderId`,
   `expectedVersion` and `changes`. The route validates, evaluates policy, and on `approval_required`
   creates a `pending` approval in the same transaction as the `policy.evaluated` event and the
   idempotency record. The response is the normalized code `approval_required` with the approval id and
   expiry. No job exists.
3. The owner opens the approval in the dashboard and approves or denies it. Approving sends the action
   hash the page displayed. The vault records the decision and seals it with a MAC (3.3).
4. The caller sends the same request again with `approvalId` and a new idempotency key. In one
   transaction the API re-evaluates policy, recomputes the action hash from the request, consumes the
   approval with one conditional update, and inserts (with the job's arguments copied from the
   approval's `proposal_json`, never from the request body, P4-20) the `policy.evaluated` event (allow, with the
   approval id), the queued job and the idempotency record. It then asks the vault to authorize the job
   (stage 1 of ADR-014 section 5), which verifies the approval MAC.
5. The supervisor claims the job, re-verifies approval, arguments hash and policy, takes a capability
   token, opens the session, and the runner checks the live version, submits, re-reads and reports.
   `succeeded`, `failed` (including `stale_version`) or `outcome_unknown` is recorded with its audit
   event in one transaction.

### 3.2 What the policy engine does and does not do

The engine stays unchanged and pure. It does not take an "approved" flag, because the simulator and
execution must call one function on one input shape (spec §8.1 rule 6, PE-16). "Approval satisfied" is
a separate check made after the engine has answered `approval_required` with reason code
`approval_required`, in a small pure helper next to the engine's callers (`approvalSatisfies(decision,
approval, binding)`), tested on its own. An `allow` decision for a write is impossible by the
descriptor rule (`defineOperation` makes every non-read operation require approval), and a job for a write whose recheck gives any other outcome is refused. The helper
only accepts a decision whose outcome is `approval_required` for the same operation; a deny from any
grant stays a deny.

One contract change: `OperationDescriptor` gains optional `versionArgument` (the argument holding the
expected resource version). `defineOperation` requires it, and `resourceArgument`, on every operation whose
sensitivity is not `read`, and requires such an operation to require approval, so an `allow` for a write is impossible by construction (C1 also refuses an `allow` outcome for a non-read operation, as defence in depth). A change to either field in an
adapter upgrade is a re-review event under ADR-006 (PE-15).

### 3.3 The approval record

`approval_requests` (spec §11, written in migration `0006`):

| Column                                                                              | Notes                                                                                                                                                                                                                                              |
| ----------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `id`, `organization_id`, `owner_user_id`                                            | The owner is the owner of the agent and of the connection; both must match at creation (a `CHECK` and the repository).                                                                                                                             |
| `agent_id`, `connection_id`, `operation`, `run_id`                                  | As requested. `run_id` is nullable; a redemption must present the same value.                                                                                                                                                                      |
| `target_resource_id`, `expected_resource_version`                                   | Copied from the arguments by the descriptor's `resourceArgument` and `versionArgument`; the repository refuses a row where they differ from `proposal_json`.                                                                                       |
| `proposal_json`                                                                     | The final arguments (obligations applied). Plain JSON, size-capped.                                                                                                                                                                                |
| `before_json`                                                                       | Optional, display only, labelled "as read at version N" (owner decision D6). Not covered by the hash.                                                                                                                                              |
| `action_hash`                                                                       | Lowercase hex SHA-256 of `aab.approval-action.v1\n` plus canonical JSON of `{agentId, arguments, connectionId, operation, organizationId, ownerUserId, runId, targetResourceId, expectedResourceVersion}`. A new layout, never v1 of the job hash. |
| `policy_decision_id`                                                                | The `policy.evaluated` event that created the request.                                                                                                                                                                                             |
| `status`                                                                            | `pending`, `approved`, `denied`, `expired`, `revoked`, `consumed`.                                                                                                                                                                                 |
| `approver_user_id`, `decided_at`, `expires_at`, `consumed_at`, `consumed_by_job_id` | `approver_user_id` must equal `owner_user_id` (`CHECK`).                                                                                                                                                                                           |
| `mac`, `mac_kek_version`                                                            | Written by the vault with the decision (below). Null unless `approved` or `consumed`.                                                                                                                                                              |

`approval_decisions` (spec §11) is an append-only record of each decision with the approver, the
decision and the time. Triggers refuse `UPDATE` and `DELETE`, as for the audit table.

**Integrity against a database writer.** Approvals carry a MAC, produced by the vault with the same
machinery as the capability MACs (`services/vault/src/mac.ts`: HKDF from the current KEK, HMAC-SHA-256
through `@aab/crypto`, canonical JSON, constant-time compare, a layout label of its own,
`aab.vault.approval.v1`). No new primitive and no hand-written cryptography. The API and the worker
cannot import the KEK, so the MAC can only come from the vault. A new vault operation `decideApproval`
on the `api` socket does, in one transaction: lock the row, require `pending`, unexpired, the
presented action hash equal to the stored one and to a recomputation from `proposal_json`, set status
and approver, append the `approval_decisions` row and the audit event, and (for an approval) write the
MAC over every binding column plus the decision fields (at least `id`, `organization_id`,
`owner_user_id`, `agent_id`, `connection_id`, `operation`, `run_id`, `target_resource_id`,
`expected_resource_version`, `action_hash`, `approver_user_id`, `decided_at` and `expires_at`; a
test edits each one). A denial needs no MAC: forging a denial can
only remove authority. `authorizeJobAccess` for a write job verifies the MAC, requires
`consumed_by_job_id` to equal the job, and caps the capability's lifetime at the approval's expiry.
The capability's authorization MAC already covers the job's arguments hash, and the new job hash
layout (3.9) covers the approval id and action hash, so approval and capability are chained.

**What Phase 4 does not repeat from Phase 3.** The capability row's `used_at` and `revoked_at` are
outside the MACs, so a writer can clear them. For approvals, the same is true of `consumed_at`,
`status` after approval and revocation fields, and the plan does not hide that. What differs: (a) the
only state that grants authority (`approved`) is MAC-covered, so authority cannot be created; (b)
clearing `consumed_at` cannot yield a second job, because one job per approval is a unique index on
`execution_jobs.approval_request_id` and the job row outlives the approval; (c) reviving a revoked
approval gives back at most the exact approved action until its expiry, and it still passes the three
policy rechecks, so it cannot exceed current grants. A writer who deletes the job row, or who can call
the `api` socket (that is, the API process itself), is outside this design; the second case is an
accepted limit as in ADR-014 and is stated in the ADR (section 3.10).

**Who approves.** The signed-in owner only. Until agent credentials exist (Phase 6) the owner is also
the caller who names the agent, so the same person proposes and approves; no authentication separates
them. The controls that exist are the exact-action binding, the explicit approve step and the audit
trail. Phase 4 states this and does not claim separation of duties (owner decision D9).

### 3.4 Redemption (single use, concurrency)

In the transaction that creates the job, after locks taken in a fixed order (agent row `FOR NO KEY
UPDATE`, then the approval row `FOR UPDATE`, mirroring `insertAuthorization`):

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

Zero rows is a refusal. Only afterwards may the code read the row to choose the audit reason
(`not_found`, `not_approved`, `expired`, `consumed`, `revoked`, `binding_mismatch`); that read labels the
refusal and never changes it, as in Phase 3. The job insert, the idempotency record and the audit event
share the transaction, so a failing insert rolls the consume back (P4-4). The database clock is the
authority; the injected `now` must be within 5 seconds of it, as in Phase 3.

### 3.5 Where the rechecks happen

| Point                        | Where                                      | What is checked                                                                                                                                                                                                                                     |
| ---------------------------- | ------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Request time                 | API                                        | Plain JSON, adapter schema, engine, obligations, then (with `approvalId`) the conditional update of 3.4.                                                                                                                                            |
| Authorization (stage 1)      | Vault, `authorizeJobAccess`                | Existing checks (matched grant still an unrevoked, unexpired allow; agent active; no newer deny), plus approval MAC, `consumed_by_job_id`, expiry cap.                                                                                              |
| Claim                        | Supervisor, `runOperationJob` step 0 and 3 | Arguments hash (layout v2), approval row consumed by this job and its action hash recomputed from the job, fresh grants through the engine (must be `approval_required` for a write, `allow` for a read), obligations unchanged, connection status. |
| Immediately before the write | Runner, inside the adapter                 | The live order version equals the approved version. Only the runner can see the target; the API holds no session and no network path, so the target-state recheck cannot be in the API.                                                             |
| At the target                | Demo application                           | Rejects an edit submitted with a stale version (spec §3). Defence in depth against the gap between the runner's read and its submit.                                                                                                                |

The supervisor already recomputes the arguments hash, so the approval check sits beside it at no new
trust boundary. The runner never receives the approval row, only the arguments and the expected
version, which are in the arguments.

### 3.6 Write semantics in the worker

- `orders.applyApprovedUpdate`: sensitivity `write`, `requiresApproval: true`, `idempotent: false`,
  side effects stated, timeout bounded, allowed paths the order page and its edit page only,
  `resourceArgument: orderId`, `versionArgument: expectedVersion`. Input `changes` is a strict object of
  the writable fields (D4). The output schema is `{orderId, version, status}` and nothing else.
- The adapter order of work: validate; open the order; compare the version; fill only the declared
  fields; submit once; re-read; compare the version (exactly the next version the demo contract defines, not merely
  greater, so that a concurrent edit after the submit is not mistaken for this one) and every changed
  field to the proposed value. A match is `succeeded`; a greater version with matching fields is
  `outcome_unknown`. A stale version before the submit is `failed` with the new
  code `stale_version`. Anything unconfirmed, and any error after the submit click has been issued, is
  `outcome_unknown`. There is no loop around the submit and no retry inside the adapter.
- The supervisor appends `operation.write_dispatched` immediately before it invokes the runner for a
  write, in its own transaction. A job that ends `outcome_unknown` with no such event can be told from
  one that may have reached the target. A crash before this event leaves a `running` job whose lease
  expires.
- Lease recovery ends a non-retry-safe job as `outcome_unknown` (existing code), and the capability is
  revoked in the same transaction (existing Phase 3 behavior). This is pessimistic: a crash before the
  submit also ends as unknown. A precise pre-submit marker needs a handshake with the sandboxed
  runner; it is left to Phase 7 (D8).
- The approval is consumed in every one of these cases. The only way forward after `stale_version` or
  `outcome_unknown` is a new proposal, which is what spec §8.2 requires. After `outcome_unknown`
  the owner reconciles by reading the order. A repeated proposal at the old version is safe in both
  worlds: if the write happened the version moved and the check fails, if it did not the write is
  legitimate.
- A write job uses the existing `read` capability purpose, because the purpose names what the vault
  does (open the session), not what the operation does. No vault schema change is needed for that.

### 3.7 What the demo must provide (separate repository, not read)

Written from the specification (§3), to be checked against the repository by the owner or in step C5.
The demo must have: an order edit form reachable by a stable path, with `data-testid` entries for each
writable field and a submit control; the order `version` shown on the order page and carried in the
form; an edit with a stale version rejected with a distinguishable page (so the adapter can map it to
`stale_version`, never by reading free text); a version that increases on a successful edit; the edited
values and the new version visible afterwards. The `data-testid` contract in the demo's README is the
only coupling. If the demo lacks any of these, the change is made in `silentonroot/northstar-demo`,
which is not part of this repository's commits; the broker's end-to-end test then pins the demo
revision. The demo's own tests prove its stale-edit rejection, not this repository's.

### 3.8 Revocation

`grants.revoke`, `agents.disable` and `connections.revoke` already run in one transaction, take the
agent row `FOR NO KEY UPDATE`, and revoke capabilities. Phase 4 adds, in the same transactions and the
same lock order: `pending` and unconsumed `approved` approvals of the scope become `revoked` (with
`approval.revoked` events); queued write jobs of the scope are ended and their capabilities revoked
(for connections `cancelForConnection` already exists; for grants and agents `cancelQueuedForCapabilities`
exists). A running write is stopped by the supervisor's heartbeat as in Phase 3; a browser action
already sent cannot be recalled (WK-6). Expiry is applied lazily by the redemption predicate and
eagerly by a sweeper in the API's maintenance loop, which sets `expired` and writes `approval.expired`
(the sweeper is for the inbox and the audit trail; correctness never depends on it).

### 3.9 Hashes, AAB-032 and AT-059

- **Job hash layout v2.** `jobArgumentsHashInput` gains `approvalRequestId` and `actionHash` (both null
  for a read). A new domain label `aab.job-arguments.v2\n`; v1 is never reused. `execution_jobs` gets an
  `arguments_hash_layout` column (1 backfilled, 2 for new rows) so the supervisor picks the layout from
  the row and a writer cannot move a job to the layout that omits the approval; a write job with layout 1 is
  refused. The capability MAC already covers the hash, so no MAC layout change is needed.
- **AAB-032's "the hash on the approval equals the hash on the job it releases" cannot hold literally:**
  the job hash includes `policyDecisionId`, created after the approval. The plan proves the intended
  property instead: the job hash binds the approval's action hash, and a test recomputes the action
  hash from the job's own columns and compares it with the approval's. The owner is asked to accept
  this change of wording (D5); `backlog.md` is updated in step C7.
- **AAB-021 and AT-059.** AAB-021 (and the matching matrix row AT-059) asks for the Phase 2 dashboard
  screens to be used in a browser against the real stack. Phase 4 touches it only incidentally: step C6
  adds screens that will be exercised in the same kind of manual browser run, and the run-a-read panel
  (the part still unchecked) can be included. It is recorded in step C6; it is not claimed to close
  either item unless the run-a-read panel is used. There is no AAB-059 in `backlog.md` (the highest
  ticket is AAB-037); the owner may mean AT-059. Any new tickets are added to `backlog.md` in step C7.

### 3.11 Parsing, canonical form and route matching

Three generic failure patterns shape this phase: two components that parse or normalize the same input
differently, so that what was checked is not what runs; access rules matched against a path or
spelling other than the one the handler serves; and negative tests that pass because their setup is
broken. The answers are in P4-20 to P4-22:

- **Run what was approved.** The approval stores the parsed, validated arguments; the hash covers
  that stored form; the job copies it. The resubmitted request only has to match. Nothing
  re-serializes the request and runs the result.
- **Refuse ambiguous values at the edge.** `canonicalJson` today rejects non-finite numbers but
  accepts integers beyond `Number.MAX_SAFE_INTEGER` (two different decimal strings can parse to one
  number), `-0` (serialized as `0`) and lone surrogates; and the JSON body parser keeps the last of
  duplicate keys. For approval inputs these are refused before validation, with a stable code. Two
  spellings that mean the same value (`1` and `1.0`) are the same value: same hash, same execution;
  AP-4 is worded that way.
- **Boundaries agree.** Expiry is decided by the database clock alone, at the exact instant, in one
  predicate (P4-6), so no two components disagree about the same instant.
- **Match what the handler serves.** Route authorization and the write's allowed paths are tested
  against spelling variants, and against redirects during the write, not only the canonical path.
- **Positive control first.** A refusal proves nothing until the same fixture is shown to accept the
  valid request (P4-21).
- **Approvals are decided in the dashboard only.** The approval view renders no agent-supplied URL as
  a link, and no link carries a decision: a `GET` never approves or denies (P4-22).

### 3.10 ADR-015: approvals (outline, not yet written)

Drafted in step C0, accepted by the owner before C1. Sections: Context (spec §8.2, INV-9, what exists);
Decision (the record and its states; the action hash layout and why it excludes ids created later; the
vault MAC, with the writer model and what is and is not MAC-covered; redemption as one conditional
update with the lock order; job hash v2; recheck points; revocation cascade; write outcomes and the
dispatch event; fail closed); Schema (migration 0006); Audit events; What a compromised component can
and cannot do (database writer: cannot mint, can delete rows, can revive a revoked approval within its
expiry; compromised API: can approve; compromised supervisor: cannot redeem, can only run jobs the
vault authorized; the same-person limit until Phase 6); Out of scope (workflows, Phase 7 handshake,
agent credentials); Alternatives (approval without a MAC; auto-run on approve; a policy-engine
"approved" input; storing the approval in the job row); Consequences; Revisit when (agent credentials
exist; a second write adapter; per-service database roles, AAB-036).

## 4. Threat-model rows to add (proposed, not yet in `threat-model.md`)

Section 4.11 would be "Phase 4: writes and approvals". Each row follows the existing columns; the
control and test come from section 2.

| #     | Abuse case                                                                                                                                                                                                                                                      | Invariants   |
| ----- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ |
| AP-1  | An agent approves its own request (calls the approve route, or names an `approverUserId` or `agentId`).                                                                                                                                                         | P4-7         |
| AP-2  | Replay of an approval after success, failure, `stale_version`, `outcome_unknown` or a crash.                                                                                                                                                                    | P4-5         |
| AP-3  | Two simultaneous redemptions (double-submit, retry storm) of one approval.                                                                                                                                                                                      | P4-4         |
| AP-4  | Payload modification: a changed value, an added key, a different Unicode form, a longer `changes` object; and parser ambiguity (an integer past the safe range, `-0`, a duplicate key, a lone surrogate). `1` and `1.0` are one value, hashed and run the same. | P4-3, P4-20  |
| AP-5  | Target substitution: another order id, or the same order at another version, under the approval.                                                                                                                                                                | P4-3, P4-9   |
| AP-6  | Cross-binding: another connection, agent, organization, owner, run or operation.                                                                                                                                                                                | P4-9         |
| AP-7  | Use after expiry, including the exact instant and a long queue wait.                                                                                                                                                                                            | P4-6         |
| AP-8  | The order changes between approval and write (TOCTOU), and between the runner's read and its submit.                                                                                                                                                            | P4-11        |
| AP-9  | A grant, agent or connection is revoked after approval, while the job is queued, or while it runs.                                                                                                                                                              | P4-10, P4-13 |
| AP-10 | A database writer inserts or edits an approval (status, hash, target, version, expiry, approver), or clears `consumed_at`.                                                                                                                                      | P4-5, P4-8   |
| AP-11 | Approval flooding: an agent creates many requests to exhaust the owner's attention or hide a harmful one (extends AG-7).                                                                                                                                        | P4-2         |
| AP-12 | The dashboard shows something other than what runs: truncation, look-alike characters, markup in a value, an hidden changed field.                                                                                                                              | P4-18        |
| AP-13 | The proposal changes between the owner viewing it and approving it.                                                                                                                                                                                             | P4-18        |
| AP-14 | `outcome_unknown` is used to cause a second write (re-propose at once).                                                                                                                                                                                         | P4-12        |
| AP-15 | `orders.proposeUpdate` is used as a write, or a `proposeUpdate` grant is accepted for `applyApprovedUpdate`.                                                                                                                                                    | P4-17        |
| AP-16 | Approval ids are enumerated or probed across owners.                                                                                                                                                                                                            | P4-7         |
| AP-17 | Clock skew: an approval accepted by an application clock the database would refuse.                                                                                                                                                                             | P4-6         |
| AP-18 | A write result or an approval response leaks fields the output schema does not declare, or a MAC or hash.                                                                                                                                                       | P4-14        |
| AP-19 | The checked form and the run form differ: the job runs a re-serialized request instead of the approved bytes.                                                                                                                                                   | P4-20        |
| AP-20 | A variant spelling of the approve route, or of a path during the write, escapes the check that the canonical spelling gets.                                                                                                                                     | P4-22        |
| AP-21 | A decision through a link: an agent-supplied URL in the approval view, or a `GET` that approves.                                                                                                                                                                | P4-22        |

Existing rows whose status changes only after tests pass (not edited now): PE-10 (recheck for a write),
PE-11, PE-16, WK-2, WK-3, WK-4, WK-5, WK-6, WK-9.

## 5. Owner decisions needed

Each has a recommended default. **The owner accepted every default on 2026-11-25.**

| #   | Decision                                                                                                                                                                                                   | Recommended default                                                                                                                             |
| --- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| D1  | **Who creates the approval request.** The execute route does, on `approval_required` (the agent's `applyApprovedUpdate` request), with `proposeUpdate` a read-only preview; or `proposeUpdate` creates it. | The execute route creates it. `proposeUpdate` stays a read (P4-17).                                                                             |
| D2  | **Who redeems.** The agent resubmits with `approvalId` (spec §8.2: consumption in the transaction that creates the job); or approving runs the job.                                                        | The agent resubmits. Approving never runs anything.                                                                                             |
| D3  | **MAC on approvals through the vault** (`decideApproval`) or database constraints only.                                                                                                                    | MAC through the vault (P4-8). Constraints alone let a writer mint an approval.                                                                  |
| D4  | **Writable fields of `orders.applyApprovedUpdate`.**                                                                                                                                                       | `status` only, limited to `held`, `open` and `shipped`; no `cancelled` (destructive), no free-text field (the notes are the injection fixture). |
| D5  | **AAB-032 wording**: replace "the hash on the approval equals the hash on the job" with "the job hash binds the approval's action hash" (3.9).                                                             | Accept.                                                                                                                                         |
| D6  | **Before-values in the diff.** The apply request may name a succeeded `proposeUpdate` job of the same agent, connection, order and version; its sanitized fields are stored as display-only `before_json`. | Include, labelled with its version, outside the hash. Without it the page shows proposed values and the expected version only.                  |
| D7  | **Approval lifetime.**                                                                                                                                                                                     | 15 minutes default, setting within 1 minute to 24 hours, database `CHECK` at the upper bound.                                                   |
| D8  | **Crash handling.** Pessimistic `outcome_unknown` plus the `operation.write_dispatched` event now; a precise pre-submit marker with the runner later.                                                      | Pessimistic now; precise marker with Phase 7.                                                                                                   |
| D9  | **Same person proposes and approves until Phase 6.** Accept and document, or require a second factor on approval now.                                                                                      | Accept and document in `security.md`; revisit when agent credentials exist (AAB-033).                                                           |
| D10 | **Pending-approval caps** (AP-11).                                                                                                                                                                         | 20 pending per agent and connection, 100 per owner, settings; a request over the cap is denied with a stable code.                              |
| D11 | **Response to an approval-requiring request.** Today 403 `approval_required`; with a durable pending row, HTTP 202 with `{status: "approval_required", approvalId, expiresAt}` fits better.                | HTTP 202 with that body; update spec §12.2 and the contract (a documented change to a Phase 2 behavior).                                        |
| D12 | **Dashboard scope.** The minimum in step C6 now; the full Overview, Policies page, filters, decision history and audit detail with Phase 5.                                                                | Minimum now (section 6, C6). Phase 5 keeps its list.                                                                                            |
| D13 | **Demo changes.** Who changes `northstar-demo` if 3.7 is not met, and which revision the end-to-end test pins.                                                                                             | The owner changes it (separate repository); the nightly workflow pins a commit in a repository variable.                                        |
| D14 | **Approval proposals hold argument values in plaintext** in `proposal_json` (as job rows do today). Accept for synthetic data, or seal them.                                                               | Accept for Phase 4 (synthetic only); listed as a residual; revisit before real data.                                                            |
| D15 | **AAB-021 and AT-059** (3.9): fold the Phase 4 screens into the same manual browser run.                                                                                                                   | Yes, one recorded manual run after C6, including the run-a-read panel.                                                                          |

## 6. Implementation breakdown

Each step lists what it touches, what it depends on, when it is done and the suggested model. One
writer per package directory at a time; contracts change before any fan-out; one agent at a time. Per
the owner's rules: Sonnet implements from a self-contained brief, Opus reviews the diff of every
security-critical step (C1, C2, C3, C4, C7) before it is pushed, Haiku runs full suites (including
PostgreSQL and the end-to-end test) and makes mechanical edits. Dependency changes go through the
dependency owner; none are expected (no new package).

### C0 Decisions, ADR-015 and contracts

- ADR-015 (outline in 3.10), the contract additions, and the spec text changes the decisions need.
- Contracts: `ApprovalRequest`, `ApprovalStatus`, `ApprovalDecision`, the action hash layout and
  `actionHashInput` with canonical-JSON tests (reusing `canonicalJson`), `OperationDescriptor.versionArgument`,
  job hash layout v2, the response for `approval_required` (D11), audit event types `approval.proposed`,
  `approval.approved`, `approval.denied`, `approval.expired`, `approval.revoked`, `approval.redeemed`,
  `approval.refused`, `operation.write_dispatched`, vault events for the approval MAC, job error code
  `stale_version`, approval refusal reasons.
- Touches: `docs/adr/ADR-015-*.md`, `docs/spec/aab-spec.md` (§12.2, §11 notes), `packages/contracts`,
  `packages/adapter-sdk` (descriptor field and `defineOperation` rule).
- Depends on: owner decisions D1 to D15.
- Done when: the owner accepts ADR-015; contract tests pass (hash layout fixtures, descriptor rule);
  nothing else changes.
- Model: Sonnet drafts, Opus reviews the ADR.

### C1 Migration `0006` and the approval repository

- Migration `0006_phase4_approvals`: `approval_requests` and `approval_decisions` with their `CHECK`s
  (status, owner equals approver, hex hash, lifetime bound, consumed implies approved earlier, MAC
  present when approved), append-only trigger on decisions, partial unique index
  `execution_jobs(approval_request_id) WHERE approval_request_id IS NOT NULL`, a foreign key on that
  column, `arguments_hash_layout`, the job error code and audit types. Hand-written SQL where drizzle
  cannot express it, like migrations 0002 and 0005.
- Repository: `create` (cap check, lock order), `redeem` (3.4), `revokeForScope` (hooked into
  `grants.revoke`, `agents.disable`, `connections.revoke` in their existing transactions), `expireDue`,
  scoped reads for the dashboard, `describeForRefusal`. Every function takes a `Scope` or is listed as
  unscoped in ADR-010's table.
- Touches: `packages/database`, `packages/contracts` (types).
- Depends on: C0.
- Done when: P4-3 (database part), P4-4, P4-5, P4-6, P4-13 (database part) and P4-19 pass on the in-process
  database, and the concurrency test passes on PostgreSQL.
- Model: Sonnet implements; Opus reviews (the conditional statement is the security core).

### C2 Vault: `decideApproval`, approval MAC, authorization of write jobs

- `decideApproval` on the `api` socket; `authorizeJobAccess` extended for a job with
  `approval_request_id` (verify MAC, `consumed_by_job_id`, expiry cap, re-checked grants as today); the
  approval MAC in `mac.ts` beside the capability MACs; rejection audit with the existing reason scheme
  plus approval reasons; role table and protocol schema updated, with the socket-role tests extended.
- Touches: `services/vault`, `packages/vault-client`, `packages/contracts` (vault protocol).
- Depends on: C1.
- Done when: P4-8 passes, the P3-2 role matrix test lists the new operation and refuses it on the
  `supervisor` and `admin` sockets, and the P3-13 atomicity tests cover the new operation.
- Model: Sonnet implements; Opus reviews.

### C3 Broker API: write path, approval routes, simulator, revocation

- Execute route: remove the "reads only" refusal for approved writes (keep it for any write without a valid
  approval); create the pending approval on `approval_required`; redemption path with `approvalId`;
  job hash v2; `authorizeNewJob` for writes; request hash includes `approvalId`; stale `actionHash`.
- Routes (`Routes` constant and contracts): `GET /v1/approvals` (owner scope, status filter, cursor),
  `GET /v1/approvals/:id`, `POST /v1/approvals/:id/approve` and `/deny` (owner session, CSRF, body
  `{actionHash}`), `POST /v1/policy/simulate` (owner session; calls the same inputs builder and
  `evaluate`; no job, no approval, no audit event of kind `policy.evaluated`, one `policy.simulated`
  event without argument values). The inputs builder is extracted from the execute route so both use it.
- Maintenance loop: `expireDue`; settings (`AAB_APPROVAL_TTL_SECONDS`, caps) validated at start-up.
- Touches: `services/broker-api`, `packages/contracts`.
- Depends on: C1, C2.
- Done when: P4-1, P4-2, P4-3 (API part), P4-5, P4-7, P4-9, P4-10 (API part), P4-14, P4-15, P4-16, P4-18
  (API part) pass; `route-guards.test.ts` and the CSRF test list the new mutating routes; the Phase 2
  read tests are unchanged and pass.
- Model: Sonnet implements; Opus reviews.

### C4 Supervisor: write jobs

- `runOperationJob`: lift the reads-only refusal for a job with a verified approval; verify layout v2
  hash, approval consumed by this job and its action hash recomputed from the row; engine must answer
  `approval_required` for a write (and `allow` for a read); `operation.write_dispatched` before the
  runner; map `stale_version`; outcome and audit in one transaction; heartbeat revocation unchanged.
  `recoverExpiredLeases` test for a write; lease recovery never requeues a write.
- Touches: `services/browser-worker` (supervisor, runner protocol error code), `packages/database` (tests).
- Depends on: C2, C3 (job shape).
- Done when: P4-10 (supervisor part), P4-12 (supervisor part) pass, and the rewritten Phase 2 tests show a
  write without a verified approval refused before any snapshot is opened.
- Model: Sonnet implements; Opus reviews.

### C5 Northstar adapter operations (and the demo, if needed)

- `orders.proposeUpdate` and `orders.applyApprovedUpdate` in `packages/adapters/northstar` with output
  schemas, selectors from the demo's `data-testid` contract, the order of work in 3.6, and
  navigation limited to the order and edit paths; `adapter-development.md` gets a write-operation section.
- The demo changes in 3.7, made in its own repository if needed (D13).
- Touches: `packages/adapters/northstar`, `packages/adapter-sdk` (tests only unless a facade gap shows
  up), docs; `silentonroot/northstar-demo` (separate).
- Depends on: C0; the demo contract.
- Done when: P4-11 (adapter part), P4-12 (adapter part) and P4-17 pass against a fake browser, and a
  manual run against the real demo is recorded.
- Model: Sonnet implements; Opus reviews the adapter diff (it is the only code that submits a form).

### C6 Dashboard: minimum for Phase 4

- Approvals page replacing the placeholder: a list of pending approvals and the last decisions (status,
  time), a detail view showing operation, connection, order id, expected version, every changed field
  (and the before-values if present, labelled), expiry, and the first 12 characters of the action hash;
  Approve and Deny buttons (approve sends the displayed hash); all text escaped.
- Grant editor: `approvalMode` and expiry are shown and editable where the API already supports them;
  a plain-language note that a write operation always needs approval (UI-9).
- Policy simulator: a form (agent, connection, operation, arguments as JSON) calling
  `POST /v1/policy/simulate`, showing outcome, reason code, matched grants and obligations.
- Not in Phase 4 (Phase 5): the Policies overview across agents, filtering, decision history views,
  audit detail, responsive and accessibility polish beyond the existing components.
- Touches: `apps/dashboard`.
- Depends on: C3.
- Done when: P4-18 (dashboard part) passes; one manual browser run against the real stack is recorded
  (D15), including the run-a-read panel.
- Model: Sonnet implements; Haiku runs the dashboard suite; Opus reviews the page that renders
  untrusted text.

### C7 Negative tests, end-to-end, coverage map and review fixes

- `services/browser-worker/test/e2e/phase4.e2e.test.ts` (`AAB_E2E=1`, nightly): 1 read allowed;
  2 ungranted write denied and request creates a pending approval with the order unchanged; 3 approve
  and redeem once, order changed, `succeeded`; 4 stale version (order edited by another route
  between approval and redemption); 5 replay; 6 cross-connection (second account's connection);
  7 SIGKILL of the worker after the demo accepts, `outcome_unknown`, no second write; 8 grant revoked
  after approval; 9 modified payload; 10 no secret, token, MAC or argument value in logs, responses or
  audit.
- Coverage map in this file (as Phase 3's B6a): each invariant and each AP row to its test, with
  "proven", "partial" or "none".
- Mutation checks as in Phase 3 B6c (remove one `WHERE` condition of the redemption update, one
  binding field from the hash, the MAC check in authorization; each must fail a test).
- Proposed matrix rows AT-060 to AT-068 added to `acceptance-test-matrix.md`: cross-connection
  approval, revoked grant after approval, expired approval, concurrent redemption, `proposeUpdate` never
  writes, simulator parity, stale `actionHash`, forged approval row, `outcome_unknown` no retry. Statuses
  of AT-005, AT-006, AT-007, AT-008, AT-013 and AT-015 change only from recorded runs.
- Documents updated from evidence: threat-model section 4.11 and the changed rows, `security.md` claims
  table ("Approval of the exact action, single use"), `architecture.md` 7.1 and 7.3, `backlog.md`
  (AAB-032 wording, new tickets), ADR-015 "As built".
- Touches: tests, docs.
- Depends on: C1 to C6.
- Done when: every invariant is proven, partial (stated) or accepted-none (stated), the end-to-end test
  passes locally twice and in a nightly run, and the Phase 4 security checklist (below) is filled.
- Model: Sonnet writes tests and docs; Haiku runs every suite, PostgreSQL and the end-to-end test and
  reports counts; Opus reviews C7 as a whole.

### Draft Phase 4 security checklist

Template: [`security.md`](security.md) §7. Filled from evidence in step C7; every line starts as "not
done". Fields: scope; invariants P4-1 to P4-19 and their tests; threat rows AP-1 to AP-18 and changed
rows; negative tests listed in section 7; secrets and leakage (approval responses, audit, logs);
authorization (owner-only routes, CSRF, 404 for another owner's approval); data and tenancy (scoped
repository functions); cryptography (approval MAC reuses `@aab/crypto`, no new primitive); execution
(write semantics, no retry); audit (events and atomicity); dependencies (none added); claims review
(`security.md` rows, README); remaining risks (3.3 residuals, D9, D14); sign-off by a person who is not
the author.

## 7. Negative tests the exit criteria require

Each is a named test in the steps above. Replay: after success, failure, stale, unknown, crash and with
`consumed_at` cleared by SQL. Modified payload: every field of the action, one added key, number and
Unicode spelling. Stale version: before approval is redeemed (the order changed) and at submit.
Revoked grant: after approval, while queued, while running (stopped at the heartbeat). Cross-connection:
approval for A on B, a job moved to B by SQL (hash mismatch), a capability for A on B (Phase 3). Beyond
the exit criteria: expired approval, approval for another agent, organization, owner, run and operation;
approval id of another owner; unapproved approval (`pending`, `denied`); approval forged by a database
writer; `actionHash` stale at approve; agent field in the approve body; missing session and CSRF token;
cap on pending approvals; vault down; audit append failing; simulator versus execution for generated
requests; `proposeUpdate` performing no click.

## 8. Independent review: scope (to be scheduled by the owner)

Not started; no reviewer or date is implied. The reviewer must not be the author of the code (it will
be written by Claude models and checked by Claude models and the project lead's runs). Real credentials
and real data stay excluded until the findings are closed, as in Phase 3. In scope after C7, naming the
commit read:

- `packages/database`: migration `0006`, the approval repository, the redemption statement, the lock
  order and the revocation hooks.
- `services/vault`: `decideApproval`, the approval MAC, the extended authorization, the role table.
- `services/broker-api`: the execute route's write path, approval routes, the simulator and the shared
  inputs builder.
- `services/browser-worker`: the supervisor's write path, the dispatch event, lease recovery of writes.
- `packages/adapters/northstar`: the only code that submits a form; `packages/adapter-sdk` descriptor rule.
- `apps/dashboard`: the approval view (untrusted text, hash round trip, CSRF).
- Trust boundaries to check: the writer model of 3.3 (what a database writer can and cannot do), that
  the engine has no approval input, that every refusal changes nothing, that no code path reads an
  approval and then writes it, and the same-person limit.
- What the reviewer must produce: findings with severity, the commit read, and which rows of the coverage
  map were re-run. The review closes only when no Critical or High finding is open.
