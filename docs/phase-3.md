# Phase 3: production-shaped vault

- **Status:** Planning, with steps B0.5 and B1 implemented (2026-11-16; B1 awaits the independent
  Opus review). Written on 2026-11-16 from [ADR-014](adr/ADR-014-vault-service.md) and the code as
  it stood at commit `b714c6d`. `services/vault` and everything after B1 do not exist yet.
- **Specification:** §6 (vault), §11 (`vault_access_capabilities`, `execution_jobs.capability_ref`),
  §15 Phase 3. Exit criteria: workers can use only secrets for authorized jobs; database-only theft
  yields ciphertext; vault tests pass.
- **Threat model:** section 4.10 (rows VS-1 to VS-19), and the existing rows VA-6, VA-11, VA-12 and
  PE-14.

Wording follows [`security.md`](security.md) §2: a property below is a design until its test exists
and has passed in a recorded run. A status is **Planned** until some test exists, and **Partial**
where only the database part of an invariant (step B1) has a passing test; a Partial invariant is not
claimed to hold until the vault, API and worker parts exist.

## 1. Phase 3 invariants

Test paths are relative to the repository root. `services/vault` is the new service (step B2).

| #     | Invariant                                                                                                                                                                                                                                                                                                | Planned test                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | Status                                                                                                                                                                                                                                              |
| ----- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| P3-1  | **KEK only in the vault.** No module of the broker API or the browser worker imports `sealSecret`, `openSecret`, `rewrapSecret` or a KEK provider. The API and the supervisor refuse to start when `AAB_KEK_DIR` is set, or when they can open the vault's key directory in `separate-uid` mode.         | `services/browser-worker/test/session-store/import-boundary.test.ts` "no worker module imports sealSecret, openSecret, rewrapSecret or a KEK provider"; `services/browser-worker/test/supervisor/startup-vault.test.ts` "refuses to start when the vault's key directory is readable"; `services/broker-api/test/config-and-startup.test.ts` "refuses to start when the vault's key directory is readable"                                                                                                                                                                                                                                                                                       | Planned                                                                                                                                                                                                                                             |
| P3-2  | **Service identity.** Each vault operation is accepted only on the sockets of its allowed roles; any other request is refused with `forbidden` and audited as `vault.request_refused`. No request field selects a role.                                                                                  | `services/vault/test/roles.test.ts` "refuses every operation not allowed for the socket's role"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | Planned                                                                                                                                                                                                                                             |
| P3-3  | **Safe sockets or no start.** The vault refuses to start when a socket directory or socket is accessible to others, is a symbolic link, or is shared between roles, and on a platform other than Linux. It never listens on TCP.                                                                         | `services/vault/test/startup.test.ts` "refuses to start on unsafe socket permissions", "opens no TCP listener"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | Planned                                                                                                                                                                                                                                             |
| P3-4  | **A5: check and consume in one atomic step.** Every validity condition of a capability and the mark that it is used are one conditional `UPDATE ... RETURNING`. No code path reads a capability, decides, and then writes.                                                                               | `services/vault/test/capability-consume.test.ts` "redeems a capability exactly once under 20 concurrent redemptions", "a used capability is refused and audited as used" Database part (B1): `packages/database/test/capability-concurrency.test.ts` "redeems a capability exactly once under 20 concurrent redemptions" (also for seal, for issue and for authorization); `packages/database/test/vault-capabilities.test.ts` "refuses already used capability, changes nothing and is labelled used".                                                                                                                                                                                          | Partial: the database statements and their concurrency tests pass (B1, 2026-11-16, PGlite and PostgreSQL 18), including expiry judged by the database clock and consume inside the caller's transaction; the vault operation is B2                  |
| P3-5  | **Binding (INV-6, AT-009).** A capability opens only the bound secret version of the bound connection, for the bound job, operation, purpose, worker and attempt.                                                                                                                                        | `services/vault/test/capability-binding.test.ts` "rejects a capability presented for another job, connection, operation or version"; `services/browser-worker/test/e2e/phase3.e2e.test.ts` step "worker asks the vault for an unrelated connection" Database part (B1): `packages/database/test/vault-capabilities.test.ts` block "capabilities.consumeRead (stage 3, operation job)" (wrong job, connection, operation, purpose, secret version, worker, attempt).                                                                                                                                                                                                                              | Partial: the consume statement enforces the binding (B1); the vault and the end-to-end step are B2 and B6                                                                                                                                           |
| P3-6  | **C2: freshness and uniqueness inside the authenticated part.** The capability id, binding, issue time and expiry are covered by the authorization MAC, and the token hash, worker, attempt, secret version and token times by the token MAC; used ids are kept until seven days after expiry.           | `services/vault/test/capability-integrity.test.ts` "rejects a capability row inserted or edited by a database writer", "a job the API did not authorize yields no token"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Planned                                                                                                                                                                                                                                             |
| P3-7  | **A8: no lifetime by accident.** Every request that creates a capability or token carries a lifetime that is a safe integer within its bounds (authorization 10 to 3,600 s, token 1 to 120 s); services refuse to start on a missing or out-of-range setting; database `CHECK`s repeat the upper bounds. | `services/vault/test/capability-ttl.test.ts` "rejects every missing or out-of-range lifetime"; `packages/database/test/vault-capabilities.test.ts` "refuses a capability row whose expiry exceeds the upper bound" Database part (B1): `packages/database/test/vault-capabilities.test.ts` "refuses a capability row whose expiry exceeds the upper bound" (present, as planned) and "refuses every lifetime that is not a safe integer within 10 to 3,600 seconds (P3-7)" and the 1 to 120 second token twin.                                                                                                                                                                                   | Partial: the repository refuses bad lifetimes and the CHECKs repeat the upper bounds (B1); request and start-up refusals are B2                                                                                                                     |
| P3-8  | **A4: revocation wins over in-flight writes.** A revocation that commits first makes a concurrent read, login completion or rewrap change nothing; one that commits second removes what was written. A `revoked` secret never becomes active again.                                                      | `services/vault/test/revocation-race.test.ts` "a revocation that commits first makes a concurrent read, login completion and rewrap fail", "a revoked secret never becomes active again"; `packages/database/test/vault-capabilities.test.ts` "the trigger refuses to move a secret out of revoked" Database part (B1): `packages/database/test/vault-capabilities.test.ts` "the trigger refuses to move a secret out of revoked, whatever the new status" (present, as planned); `packages/database/test/capability-concurrency.test.ts` blocks "P3-8: revocation and in-flight work, one commit order after the other" and, on PostgreSQL only, "interleaved transactions on two connections". | Partial: database races, trigger and write refusals pass (B1), including authorization racing a grant revocation or an agent disable and issue racing lease recovery (PostgreSQL 18, interleaved transactions); vault and route parts are B2 and B3 |
| P3-9  | **A10: versioned, column-scoped writes.** Login replacement moves the active pointer only from the version bound at issue; rewrap updates only `wrapped_dek` and `kek_version`, conditional on the values it read; a crash at any point leaves every version readable.                                   | `services/vault/test/rewrap.test.ts` "rewrap skips a version replaced or revoked while it was rewrapped", "a crash after any batch leaves every version readable"; `services/vault/test/login-completion.test.ts` "a replacement whose expected version changed stores nothing" Database part (B1): `packages/database/test/vault-capabilities.test.ts` blocks "active-pointer compare-and-set (P3-9)" and "rewrap compare-and-set (P3-9)"; `packages/database/test/capability-concurrency.test.ts` "moves the active pointer for exactly one of several concurrent logins".                                                                                                                     | Partial: pointer compare-and-set and rewrap compare-and-set pass (B1); crash and vault tests are B2 and B4                                                                                                                                          |
| P3-10 | **B7: sealed versions bound to their owner record.** A version row copied to another organization, owner, connection, secret or version number fails to open through the vault.                                                                                                                          | `services/vault/test/service-boundary.test.ts` "a version copied to another connection, secret or version fails to open", "tampered ciphertext, tag, nonce and wrapped key fail at the service boundary"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Planned                                                                                                                                                                                                                                             |
| P3-11 | **D2: fail closed.** When the vault is unreachable or refuses, the job ends with `vault_unavailable` or `vault_denied`, no caller opens a secret itself, and the supervisor does not claim jobs while the vault is unreachable.                                                                          | `services/browser-worker/test/supervisor/vault-unavailable.test.ts` "a job fails with vault_unavailable and no key is read"; `services/broker-api/test/execution-vault.test.ts` "a job whose capability cannot be authorized ends with vault_unavailable"                                                                                                                                                                                                                                                                                                                                                                                                                                        | Planned                                                                                                                                                                                                                                             |
| P3-12 | **D6: theft signals are distinct.** Presenting a used, revoked, expired, mismatched, forged or unknown token writes `vault.capability_rejected` with its reason code; vault-internal failures do not.                                                                                                    | `services/vault/test/rejection-audit.test.ts` "each rejected presentation writes vault.capability_rejected with its reason", "an internal failure writes no rejection event" Database part (B1): `packages/database/test/vault-capabilities.test.ts` blocks "describeForRejection and recordRejection" and the per-condition refusal tests (reason checked for each).                                                                                                                                                                                                                                                                                                                            | Partial: the reason codes and the rejection event are produced by the repository (B1); the vault writes them in B2                                                                                                                                  |
| P3-13 | **Audit in the same transaction (INV-10).** Authorization, issue, read, login completion, rewrap and revocation commit with their audit events or not at all.                                                                                                                                            | `services/vault/test/audit-atomic.test.ts` "a failing audit append rolls back the read, the login completion and the rewrap" Database part (B1): `packages/database/test/vault-capabilities.test.ts` "commits with its audit event or not at all (P3-13)", "rolls back the capability and the job link when its audit event cannot be written", "rolls the rewrap back ...".                                                                                                                                                                                                                                                                                                                     | Partial: every repository function that changes vault state commits with its event or rolls back with it (B1); the vault read, login and rewrap flows are B2                                                                                        |
| P3-14 | **The runner cannot reach the vault.** The vault socket directory is not visible inside the sandbox.                                                                                                                                                                                                     | `services/browser-worker/test/integration/isolation.test.ts` "the vault socket directory is absent inside the sandbox"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | Planned                                                                                                                                                                                                                                             |
| P3-15 | **No plaintext, token or MAC outside the vault's transient memory** (INV-1 extended): not in any log, response, audit record, job row or database column.                                                                                                                                                | `services/browser-worker/test/e2e/phase3.e2e.test.ts` "no token, MAC or plaintext in logs, responses, audit or any column"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | Planned                                                                                                                                                                                                                                             |
| P3-16 | **Database-only theft yields ciphertext** (exit criterion). A dump of every table holds no plaintext session and no usable token.                                                                                                                                                                        | `services/browser-worker/test/e2e/phase3.e2e.test.ts` "a database dump contains no plaintext session and no live token"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | Planned                                                                                                                                                                                                                                             |
| P3-17 | **Arguments run are the arguments judged (PE-14).** The supervisor runs a job only when the hash of its arguments equals the `arguments_hash` the vault returns from the capability binding.                                                                                                             | `services/browser-worker/test/supervisor/operation.test.ts` "a job whose arguments differ from the judged hash does not run"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | Partial: the test exists and passed locally on 2026-11-16 against the hash stored in the row (B0.5 (a)); the hash returned by the vault is B3                                                                                                       |
| P3-18 | **Grant, agent and connection revocation revoke outstanding capabilities** in the same transaction.                                                                                                                                                                                                      | `services/broker-api/test/lifecycle-audit.test.ts` "revoking a grant, disabling an agent and revoking a connection revoke their unused capabilities" Database part (B1): `packages/database/test/vault-capabilities.test.ts` block "revocation (P3-8, P3-18)".                                                                                                                                                                                                                                                                                                                                                                                                                                   | Partial: the repository revokes capabilities in the same transaction for connection, grant and agent, and refuses to authorize a queued job whose grant was revoked or whose agent was disabled (B1); the route-level test is B3                    |
| P3-19 | **Migrations are safe on empty and Phase 2 databases,** and a Phase 2 sealed snapshot opens through the vault after migration.                                                                                                                                                                           | `packages/database/test/migration-0005.test.ts` "migrates an empty database", "a Phase 2 snapshot opens through the vault after migration" Database part (B1): `packages/database/test/migration-0005.test.ts` "migrates an empty database and creates the capability table, its constraints and triggers", "moves the secrets of revoked connections to revoked and leaves every other row alone"; "a Phase 2 snapshot is still readable from the repository after migration" (the planned "opens through the vault" name stays with B2).                                                                                                                                                       | Partial: migration tests pass on an empty and on a Phase 2 database, the stored snapshot is unchanged, and the migration refuses duplicate policy decisions and a revoked connection's leftover ciphertext (B1); opening it through the vault is B2 |
| P3-20 | **Only the vault and the admin command touch key files;** the vault never deletes one, and a missing KEK version fails reads of the versions it wraps without stopping the vault.                                                                                                                        | `services/vault/test/keys.test.ts` "a missing KEK version is reported and its versions are refused", "kekRetirementCheck reports safe only when nothing references the version"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | Planned                                                                                                                                                                                                                                             |

## 2. Draft Phase 3 security checklist

The template is [`security.md`](security.md) §7. This draft is filled with what is known on
2026-11-16; everything else is "not done", and the phase is not done while any line is.

```markdown
# Phase 3 security checklist

Phase: 3, production-shaped vault
Date: not done
Author: not done
Reviewer (not the author): not done
Commit or tag reviewed: not done

## 1. Scope

- [ ] What this phase adds: a separate vault process on per-role Unix sockets that alone holds the
      KEK; two-stage, single-use, expiring capabilities; KEK rotation by rewrap; revocation that wins
      over in-flight work; vault metadata on the dashboard. Deliberately not added: KMS or HSM,
      multi-host, separate database roles, encryption of job results, session write-back
      (ADR-014, "Out of scope"). Written; not yet reviewed.
- [ ] New components, endpoints, tables, tools, dependencies and trust boundaries listed:
      `services/vault`; three sockets; migrations 0004 and 0005; `vault_access_capabilities`; no new
      runtime dependency proposed. Written in ADR-014; not checked against code (no code yet).
- [ ] `docs/architecture.md` shows the vault separately from planned components. Not done.

## 2. Invariants

- [ ] ADR-001 invariants enforceable in Phase 3 (INV-6; INV-8 and INV-10 extended to the vault)
      listed with tests: P3-1 to P3-20 in `docs/phase-3.md`. Tests not written.
- [ ] Phase 1 and 2 invariants still pass. Not run.

## 3. Threat model

- [x] `docs/threat-model.md` updated for new assets, entry points and attackers (section 4.10,
      2026-11-16, all Planned).
- [ ] Each abuse case VS-1 to VS-19 has a negative test or a recorded reason. Reasons recorded for
      VS-12 and VS-19 (accepted limits); tests not written for the rest.

## 4. Negative tests

- [ ] Every vault operation: wrong role, unknown token, used, expired, revoked, wrong job, wrong
      connection, wrong operation, wrong version, forged row, malformed request. Not written.
- [ ] Exit-criteria cases: tampered ciphertext, wrong AAD, wrong connection, expired capability,
      revoked secret at the service boundary. Not written.

## 5. Secrets and leakage

- [ ] Canary scan extended to tokens, MACs and vault logs (P3-15). Not done.
- [ ] Secret scan clean. Not run for Phase 3.
- [ ] Vault logging through the structured logger only. Not done.

## 6. Authentication and authorization

- [ ] Caller identity from the socket the request arrived on, never from a request field. Designed;
      not built.
- [ ] Authorization at the API, again in the supervisor (INV-3), and the capability checked by the
      vault. Designed; not built.
- [ ] Default deny and fail closed when the vault is down (P3-11). Not done.

## 7. Data and tenancy

- [ ] `vault_access_capabilities` carries `organization_id`; owner reached through the job and
      connection. Designed.
- [x] Vault repository functions added to ADR-010's unscoped list with reasons, including the
      Phase 2 ones that were missing. Done 2026-11-16 (B1).
- [ ] Cross-owner tests for the dashboard's vault metadata reads. Written for the repository reads
      (`vault.describeForOwner`, `capabilities.summarizeForConnection`, B1,
      `packages/database/test/vault-capabilities.test.ts` block "scoped dashboard reads"); the
      routes are B5.

## 8. Cryptography and vault

- [ ] Only standard primitives: AES-256-GCM envelope unchanged; HMAC-SHA-256 and HKDF-SHA-256 from
      `node:crypto` for capability MACs; SHA-256 token hashes. No new construction. Designed; review
      not done.
- [ ] Tampered, wrong context, wrong version, expired and revoked cases tested at the service
      boundary. Not done.
- [ ] Key handling matches ADR-003 (key directory mounted into the vault only). External review: not
      done, and required before any real credential.

## 9. Network, navigation and execution

- [x] Navigation-guard tests for percent-encoded, double-encoded and embedded dot segments (B0.5).
      Done 2026-11-16: `packages/adapter-sdk/test/navigation.test.ts`, block "dot segments, encoded and
      embedded"; the guard was changed to look through up to three rounds of percent-decoding, and to
      refuse overlong or invalid UTF-8, `%u` escapes, Unicode lookalikes and dots with whitespace.
- [x] In-process caches are keyed by everything they depend on (B0.5 (c)). Done 2026-11-16:
      `packages/adapter-sdk/test/define.test.ts`, "never resolves one version of an adapter id to
      another (cache keys, PE-14 P3 B0.5 (c))".
- [ ] Prompt-injection fixture re-run with the vault in the path. Not done.
- [ ] Output passed the output schema twice. Unchanged from Phase 2; re-run not done.
- [ ] Worker isolation as ADR-013, plus: the vault socket is absent from the sandbox (P3-14). Not
      done. The separate-uid claims do not hold under the Docker launcher (ADR-014); stated.

## 10. Audit

- [ ] Every vault state change writes its event in the same transaction (P3-13). Not done.
- [ ] Metadata summaries only; redaction test covers token, MAC and hash key names. Not done.
- [ ] What the trail does not prove: rejections without a resolvable organization are not chained;
      rollback from a backup is not detected (VS-12). Stated in ADR-014.

## 11. Dependencies and supply chain

- [ ] No new runtime dependency in the design. If peer-credential pids are wanted, a native module
      needs an ADR-012 review first. Not applicable unless that changes.
- [ ] Install-script allowlist unchanged. Not checked.
- [ ] Dependency audit passes. Not run.

## 12. Claims review

- [ ] `security.md` §1, §2 and §5, `architecture.md` §2.4 and §9 and the operations guide updated so
      that no statement claims more than the tests show. Not done.
- [ ] Specification deviations (two-stage capability, revocation outside the vault API, version bound
      at issue, extra capability columns, retry change) in the specification changelog. Not done.

## 13. Remaining risks

- [ ] Known at design time: compromised supervisor reads the sessions of jobs it claims; API is the
      policy authority; shared database role; rollback from backup; Docker launcher root-equivalence;
      `shared-uid` mode protects nothing against code as that user; job results in plaintext
      (AAB-029). Owners and closing phases not assigned.
- [ ] Data this phase is safe to use with: synthetic only.

## 14. Sign-off

- [ ] Author. Not done.
- [ ] Reviewer. Not done.
- [ ] Open exceptions. None recorded.
```

## 3. Implementation breakdown

Each step lists the packages it writes, what it depends on, when it is done, and the suggested model
(specification §22.1 rule 6). One writer per package directory at a time; the contracts change before
any fan-out; dependency changes go through the dependency owner.

### B0.5 Hardening before the vault work

Three small items that close gaps the vault design relies on.

- **(a) Arguments hash (PE-14).** Migration `0004_job_arguments_hash`: `execution_jobs.arguments_hash`,
  backfilled for existing rows; the execute route stores the hash of the canonical JSON of the final
  arguments (obligations applied) together with the organization, agent, connection, operation,
  decision id, timeout and retry flag of the row (not in the audit log: unkeyed, it could be
  brute-forced); the supervisor recomputes it from the claimed row before it runs a job and refuses
  on a mismatch, and refuses a job whose arguments policy would change at run time.
  - Touches: `packages/database` (schema, migration, `createOperation`), `services/broker-api`
    (`routes/execution.ts`), `services/browser-worker` (`supervisor/operation.ts`), `packages/contracts`
    (job type field).
  - Done when: P3-17's test passes, and a direct SQL edit of `arguments` after the decision makes the
    job end as `denied` with an audit event.
- **(b) Navigation-guard tests for dot segments in paths.** Add cases for `%2e%2e`, `%2E.`, `.%2e`,
  double-encoded `%252e%252e` and `%252f`, `..;`, `.;`, and dot segments inside an otherwise allowed
  pattern. On reading `packages/adapter-sdk/src/navigation.ts`, the encoded check matches `%2e`, `%2f`
  and `%5c` but not their double-encoded forms (`%25` followed by them); whether those should be
  refused is decided in this step and the guard changed if so. Not run; the reading may be wrong.
  - Touches: `packages/adapter-sdk` (tests, possibly `navigation.ts`).
  - Done when: the new cases exist and pass, and the specification §3.2 wording matches the behaviour.
- **(c) Cache keys. Done 2026-11-16.** Confirm that every in-process cache is keyed by everything it depends on. The
  only one found by reading is the adapter registry, keyed by adapter id and exact version
  (`packages/adapter-sdk/src/registry.ts`); no session, decision or result cache was found. Record
  the result, add a test that two versions of one adapter never resolve to each other, and add a rule
  to ADR-014's implementation notes that the vault caches no plaintext, decision or capability.
  - Touches: `packages/adapter-sdk` (test), docs.
  - Done when: the test exists and passes and the result is written in the threat model (PE row).
    Met: test `AdapterRegistry never resolves one version of an adapter id to another (cache keys,
PE-14 P3 B0.5 (c))` in `packages/adapter-sdk/test/define.test.ts`; result in threat model PE-14;
    rule in ADR-014 "Implementation notes".
- **Depends on:** nothing. **Model:** Opus for (a) and (b) (already started), Sonnet for (c).

Model assignment for B1 to B6 (owner, 2026-11-16): Sonnet implements every step, including the
security-critical ones, from a self-contained brief; Haiku makes mechanical edits and runs and
reports test suites; Opus is used only for the independent review of each security-critical diff
(B1, B2, B3, B4, B6) before it is pushed.

### B1 Database migration 0005 and repositories

- Migration `0005_phase3_vault` as ADR-014 section 11: `vault_access_capabilities` with its `CHECK`s
  and partial unique index; `capability_ref` to `uuid` with a foreign key; `vault_secrets.status`
  `revoked` and its trigger; data migration of revoked connections' secrets; the two new job error
  codes. Written by hand where drizzle cannot express it (trigger), like migration 0002.
- Capability repository: `insertAuthorization`, `issueToken` (one conditional update), `consumeRead`
  and `consumeSeal` (one conditional `UPDATE ... RETURNING` each, joined to job, secret and
  connection), `revokeForConnection`, `revokeForAgentConnection`, `describeForRejection`, `purge`.
  Vault repository changes: status-aware `putVersion` that refuses `revoked`; compare-and-set pointer
  move; `rewrapVersion` compare-and-set; `listForRewrap`; `countByKekVersion`. Job repository: claim
  requires `capability_ref`; lease recovery requeues only never-issued capabilities.
- Scoped read functions for the dashboard (B5) take a `Scope`; broker-internal ones are listed in
  ADR-010's unscoped table by name.
- Touches: `packages/database`, `packages/contracts` (types, `JobErrorCode`, new audit event types).
- Depends on: B0.5 (a) for the `0004` number and the hash column.
- Done when: P3-4, P3-7, P3-8 (database part) and P3-19 pass on PGlite, the concurrency test of P3-4
  also passes against PostgreSQL, and every new function has a cross-scope or unscoped-list entry.
- Model: Opus (the conditional statements are the security core).
- **Status (2026-11-16): implemented, awaiting independent review.** Test files:
  `packages/database/test/{migration-0005,vault-capabilities,capability-concurrency}.test.ts`, with
  `capability-fixtures.ts`. The database suite passes on PGlite and on PostgreSQL 18 (counts in the
  step report; the six interleaved-transaction tests run only against PostgreSQL). Differences from
  the bullets above, all recorded in ADR-014 "As built in step B1":
  - **The claim rule and the recovery rule are options, not changes.** `jobs.claimNext({
requireCapability: true })` and `jobs.recoverExpiredLeases({ capabilityAware: true })` implement
    the Phase 3 rules and are tested; both default to the Phase 2 behaviour, because nothing
    authorizes a job before B3 and a claim that required `capability_ref` now would stop every job.
    **B3 switches both on** (the supervisor's claim and the broker's recovery loop) in the same
    change that adds `authorizeJobAccess` to the API.
  - The clock is an injected `now: Date` in every function, and the database clock is the
    authority over it: a consume also requires `token_expires_at` and `expires_at` to be after
    `statement_timestamp()` (no grace), and `insertAuthorization` and `issueToken` refuse a `now`
    more than 5 seconds from `statement_timestamp()` (review M2).
  - Authorization re-checks what the policy decision rested on (agent `active`, a matched grant
    still an unrevoked, unexpired `allow`, no newer live `deny`), under an agent-row lock that
    `grants.revoke` and `agents.disable` take `FOR NO KEY UPDATE` (review M1); a policy decision
    authorizes one job (partial unique index) and must lie within an hour of the job (review L1).
    `issueToken` locks the job row `FOR SHARE` first, and capability-aware lease recovery reads the
    capability `FOR UPDATE` (review M3). Multi-row revocations lock their rows in id order first
    (review L3). Migration 0005 refuses to run over duplicate decisions or over a revoked
    connection's leftover ciphertext (review L1, L2).
  - Grant revocation and agent disabling are wired inside `packages/database`
    (`grants.revoke`, `agents.disable`, `connections.revoke`), so no change to broker-api was made;
    the route-level test of P3-18 and the `vault.secret_revoked` event stay with B3.
  - A consume writes no audit event itself (see ADR-014 as-built): the vault appends
    `vault.secret_read` or `vault.capability_rejected` in the same transaction.

### B2 The vault service

- `services/vault`: configuration (`AAB_KEK_DIR`, `AAB_VAULT_SOCKET_DIR`, `AAB_VAULT_ISOLATION`,
  lifetime bounds, `DATABASE_URL`) with refusals; socket and directory checks; per-role listeners;
  protocol (line framing, caps, strict schemas, `checkPlainJson`, timeouts, connection caps); the
  operations of ADR-014 section 4; MAC key derivation; audit events; structured logging with
  redaction; `init-kek` moved here; the `vault` admin command (`status`, `rewrap`,
  `kekRetirementCheck`).
- Touches: `services/vault` (new), `packages/contracts` (vault request and response schemas, written
  first), `packages/crypto` only if an HKDF or HMAC helper is added there (preferred, so key material
  stays in one reviewed package).
- Depends on: B1.
- Done when: P3-2 to P3-7, P3-10, P3-12, P3-13 and P3-20 pass against a vault started on temporary
  sockets with in-memory keys; no test needs root.
- Model: Opus.
- **B2 must guarantee** (the B1 repositories rely on it and cannot enforce it):
  - The vault is the only caller of `capabilities.*`, `vault.putVersion`, `vault.getVersion` and
    `vault.rewrapVersion`; no other service holds a database role that can reach them.
  - Every call passes a fresh `new Date()` taken immediately before the call, never a value read
    from a request, a stored record or an earlier step. The database clock bounds a wrong value
    (5 seconds at issue, `statement_timestamp()` at consume), but a stale `now` still skews audit
    timestamps and the unused part of the window.
  - `consumeRead` or `consumeSeal`, `vault.getVersion` (or `putVersion` for a login), the MAC and
    open checks, and the audit append (`vault.secret_read`, `vault.secret_stored` or
    `vault.capability_rejected`) run in **one** `repositories.transaction`, so the connection lock
    taken by the consume is held until that transaction commits and a failure of any later step
    rolls the consume back.
  - The authorization MAC is verified (against `getAuthorization`) before `issueToken`, and the
    token MAC check follows the consume inside the same transaction.

### B3 Wiring: API, supervisor and login handoff

- **Switch on the B1 options:** the supervisor claims with `requireCapability: true` and the
  recovery loop runs with `capabilityAware: true`, in the same change as the API's
  `authorizeJobAccess`; until then the Phase 2 behaviour (claim without a capability, requeue after
  a lease expiry) is unchanged, and the Phase 2 end-to-end test must keep passing.
- API: `authorizeJobAccess` after the execute and connect transactions; `vault_unavailable` handling;
  maintenance sweep for jobs without a capability; revocation transactions extended (connection,
  grant, agent); start-up refusal and `hello` check; `status` for the dashboard.
- Supervisor: remove the KEK and the crypto import; vault client; no claim while the vault is down;
  `issueAccessCapability` then `readForWorker` for operations, `issueAccessCapability` then
  `completeLogin` for logins; arguments-hash check; error mapping; invert the `AAB_KEK_DIR`
  requirement into a refusal.
- Session store: keeps parsing, validation, origin filtering, size cap and `dispose()`; loses
  sealing and opening.
- Infra: Compose vault service with the key directory mounted into it only; socket volume per role;
  operations guide for the separate-uid setup (users, groups, directories, `LimitCORE=0`).
- Touches: `services/broker-api`, `services/browser-worker`, `infra/`, `docs/operations.md`.
- Depends on: B2. API and worker can be done in parallel by two writers once the contracts exist.
- Done when: P3-1, P3-11, P3-14, P3-17 and P3-18 pass, and the Phase 2 end-to-end test passes with
  the vault in the path.
- Model: Opus for the supervisor and the revocation transactions; Sonnet for the API wiring, infra and
  the operations guide.

### B4 Key versioning and rewrap

- The rewrap loop in the vault (batches, compare-and-set, audit, resumable), `kekRetirementCheck`,
  missing-key reporting and read refusal, and the operations-guide procedure: generate, restart,
  rewrap, check, remove the old file, back up the directory.
- Touches: `services/vault`, `packages/database` (rewrap queries if not in B1), `docs/operations.md`.
- Depends on: B2 (and B1's compare-and-set query).
- Done when: P3-9 and P3-20 pass, including a test that kills the vault mid-rewrap and reruns it, and
  a rewrap racing a revocation and a login completion.
- Model: Opus.

### B5 Dashboard metadata and lifecycle actions

- Routes for vault metadata per connection and the installation key-status panel (ADR-014 section
  12); "delete stored session" and "revoke capabilities" actions with CSRF and audit; dashboard
  screens. Metadata only; a response schema test that fails if any ciphertext-, key-, token- or
  MAC-named field appears.
- Touches: `services/broker-api` (routes), `packages/database` (scoped reads, if not in B1),
  `apps/dashboard`.
- Depends on: B3.
- Done when: cross-owner tests for the new reads pass, the response-schema test passes, and the
  screens are checked against the real API (not only a mock; compare AAB-021).
- Model: Sonnet; the response-schema test reviewed by Opus.

### B6 Service-boundary negative tests, end-to-end and review

- Negative tests at the socket for every exit-criteria case (tampered ciphertext, wrong AAD, wrong
  connection, expired capability, revoked secret), plus a hostile client per role; extend the
  end-to-end test to `phase3.e2e.test.ts` (vault process, canary scan including tokens and MACs,
  database dump check, revocation during a running job, AT-009); update the acceptance matrix only
  from real runs; complete the checklist above; commission the independent review of the vault
  boundary.
- Touches: `services/vault/test`, `services/browser-worker/test/e2e`, `docs/` (acceptance matrix,
  threat model statuses, `security.md`).
- Depends on: B3, B4, B5.
- Done when: P3-5, P3-15 and P3-16 pass in a recorded nightly run, every VS row has a proving test or
  a recorded reason, and the review is scheduled with its scope written down. Real credentials stay
  excluded until the review's findings are closed.
- Model: Opus for the tests and the internal review; the independent review is by a person.

## 4. Open questions for the owner

_Answered on 2026-11-16: the owner accepted the recommendation for every question below. Question 4 (separate database roles per service) becomes a Phase 9 ticket._

1. **Peer credentials versus per-role sockets.** ADR-014 uses socket file permissions per role and no
   native module. Recommendation: accept; add a peer-credential module later only if pids in vault
   audit records are wanted, after an ADR-012 review.
2. **Default isolation for local installs.** `separate-uid` needs root once to create users, groups
   and directories. Recommendation: keep it the default and documented; allow `shared-uid` only by
   explicit setting, with the warning and the dashboard indicator.
3. **Retries after a session was handed out.** ADR-014 drops automatic requeue of a read once its
   capability was issued. Recommendation: accept for Phase 3 (reads only, agent resubmits); revisit
   with Phase 7 orchestration.
4. **Separate database roles.** One role lets any service write capability rows, jobs and audit
   events. Recommendation: keep the MAC in Phase 3 and plan per-service roles (vault owns the vault
   tables; others get no access to ciphertext columns) for Phase 9; a ticket now.
5. **The vault completes login jobs and activates the connection.** This keeps the seal and the
   activation in one transaction at the cost of connection writes in the vault. Recommendation:
   accept.
6. **Authorization lifetime default (600 s).** A job queued longer fails with `vault_denied`.
   Recommendation: accept for single-owner volumes; make it a setting within the 10 s to 1 h bound.
7. **Docker launcher and uid separation.** With the Docker launcher the supervisor is
   root-equivalent. Recommendation: say so in `security.md`; treat bubblewrap as the only launcher the
   supervisor claims apply to until a rootless engine is evaluated.
8. **Migration numbering.** The Phase 3 task list named migration 0003 for B1, but `0003_phase2_execution` exists.
   Recommendation: `0004` for the arguments hash (B0.5) and `0005` for the vault (B1).
9. **Rejections that name no resolvable organization** are logged and counted, not chained.
   Recommendation: accept for a single organization; revisit with multi-tenant work.
