# Changelog of the AAB specification

| Version | Date       | Notes                                                                                        |
| ------- | ---------- | -------------------------------------------------------------------------------------------- |
| 0.1     | 2026-11-11 | The owner's original specification.                                                          |
| 0.2     | 2026-11-12 | Revised from what implementing Phase 0 and Phase 1 showed. Section numbers are unchanged.    |
| 0.3     | 2026-11-12 | Worker isolation brought forward into Phase 2 by the owner's decision. See the last section. |

Every change in 0.2 came from implementing 0.1, and where the specification and the code disagreed, the code was taken as the decision. Entries are grouped by kind: Corrections (0.1 contradicted itself or could not work as written), Gaps filled (0.1 was silent or too vague to implement), Decisions recorded (a choice that was open or unstated is now stated) and Clarifications (same meaning, clearer or more exact). The section column gives where the change lives in 0.2.

## Corrections

1. **The encryption library is built before Phase 2 (§6.1, §15 Phase 1 and 3, §16).** 0.1 said that secrets are encrypted from the first stored session and also that encryption is delivered in Phase 3. The envelope-encryption library is now a pure package finished in Phase 1 and used from the first session snapshot; Phase 3 adds the vault service boundary, capabilities, versioning, rotation and dashboard, not the cryptography.
2. **Grants can express a deny (§8.1, §11 `agent_grants`).** 0.1 required explicit denies to override allows, but a grant row had no way to say deny. Grants now carry `effect` (`allow` or `deny`), and the evaluation order, reason codes and decision shape (outcome, reason code, matched grant IDs, obligations) are specified.
3. **Garbled cryptographic rule split, and the vault API no longer takes ciphertext (§6.2 items 7 to 9, §6.3).** One 0.1 item mixed "never log plaintext" and "nonce reuse" into an unreadable sentence; it is now three rules. The vault API parameter named `encryptedInput` is gone: the vault receives plaintext over a trusted internal channel and encrypts it itself, so callers never supply ciphertext.
4. **Data model brought up to what the features need (§11).** Tables could not support what other sections require: `application_definitions` lacked `organization_id`; `audit_events` lacked organization, per-organization sequence and agent, so the chain could not be kept per organization; `approval_requests` lacked agent, owning user and a single-use marker; `execution_jobs` lacked agent, attempt count and the policy decision reference. Added tables: `user_sessions`, `connection_status_events`, `agent_credentials`, `operation_requests` (idempotency by agent and key) and `vault_access_capabilities`.

## Gaps filled

5. **Connection transition table (§5.2).** 0.1 gave one line of states. The complete table now matches `CONNECTION_TRANSITIONS` in `packages/contracts`; `revoked` is terminal; operations run only on `active` or `degraded` connections. A single line cannot say which skips are forbidden.
6. **Origin allowlist rules (§3.2, §7.1).** An allowed origin is one exact scheme, host and port; HTTPS only except loopback hosts; no wildcards or credentials; every navigation and redirect hop is checked against the adapter's origins and the operation's paths. Resolved-address checks (private ranges, DNS rebinding) are a Phase 2 worker requirement. "Allowlist" alone left every one of these open.
7. **Login handoff mechanism (§5.3, Phase 2).** The worker opens a headed browser on the owner's desktop at the allowlisted login URL, the owner signs in directly, the worker verifies identity and stores storage state limited to allowed origins. Remote or hosted handoff is out of scope until Phase 10, because it needs a different trust analysis.
8. **API surface (§12).** Added dashboard auth endpoints, `GET /v1/agents/:id`, `POST /v1/agents/:id/disable`, `GET /v1/agents/:id/grants`, and the later-phase `GET /v1/approvals` and vault metadata endpoints. Specified a uniform error body, the stable error codes including the five normalized operation outcomes, cursor pagination (`{ items, nextCursor }`), the CSRF header on cookie-authenticated mutations, and that out-of-scope resources return the same `not_found` as missing ones.
9. **Audit hashing input and redaction (§11.1, §11.2, §13).** Canonical JSON is the input to every hash; the chain is kept per organization with serialized appends; `metadata` is redacted before it is hashed and stored; the limits on what tamper evidence proves are restated.
10. **Navigation guard strictness and output schemas (§3.2, §7.1).** The guard accepts only absolute URLs already in browser-normalized form and blocks uppercase hosts, explicit default ports, backslashes, whitespace, and literal or encoded dot segments. Query strings and fragments are not inspected, so adapters must account for them. Output schemas may not contain loose or pass-through objects. Without these rules a differently spelled URL, or a schema that passes extra fields, would get past the checks.
11. **Operation arguments are plain JSON (§8.1 rule 7, §12.2).** Arguments are validated as plain JSON before policy evaluation and again before execution; `__proto__` keys, cycles and nesting beyond a fixed bound are rejected. The schema parser would otherwise drop or accept things silently, so the arguments executed could differ from the ones judged.
12. **Deny grants and grant timestamps (§8.1 rules 8 and 9).** A deny whose constrained argument is absent from the request still applies; `maxResults` never narrows a deny; timestamps are ISO strings, an unparseable one makes an allow grant be ignored and leaves a deny in force. Without these, a request could avoid a deny by omitting an argument.
13. **Wrapped DEK is one opaque value; algorithm column (§6.2 item 4, §11 `vault_secret_versions`).** The wrapped DEK is stored as a single value (nonce, ciphertext and tag together) so a KMS-backed provider can replace the local one. `algorithm` is added as a column, and `kek_version` and `aad_version` are positive integers.
14. **Owner password handling (§5.4, §12.1).** Passwords containing a NUL character are refused, because scrypt's HMAC step would treat them as equal to the same password without it. A login for an unknown account still verifies against a fixed dummy hash so response time does not reveal which accounts exist.

## Decisions recorded

15. **Closed constraint set and exact operation names (§8.1).** Constraints are `maxResults`, `argumentEquals`, `argumentOneOf` and `resourceIds` only; unknown keys are rejected at write time and fail closed at evaluation. Operation names match exactly with no wildcards. Destructive operations and operations the adapter marks `requiresApproval` need approval whatever the grant says. This keeps the policy simple enough to evaluate and test exhaustively (ADR-005).
16. **Toolchain (§4).** TypeScript 6.0.x, because `typescript-eslint` does not yet support 7; pnpm 12 with minimum-release-age enforcement and an allowlist for install scripts; Zod 4 as the single schema strategy; Drizzle; PGlite for tests so the suite needs no Docker; scrypt from `node:crypto` for the owner password.
17. **Local KEK (§6.4).** One 32-byte key file per version, outside the repository and the database, mode `0600`; the service refuses to start on looser permissions; losing the KEK means reconnecting every connection.
18. **AAD encoding (§6.2 item 3).** The associated data is the canonical JSON of the bound fields plus an AAD format version that is also stored, so the format can change without orphaning old records.
19. **Northstar demo application (§2, §14).** SQLite through `node:sqlite`; server-rendered HTML with a documented `data-testid` contract; two seeded accounts with passwords randomized on each reset; optimistic-concurrency versions on orders; configurable session lifetime; a seeded order note containing a prompt-injection string as a test fixture.
20. **Rules for parallel agent work (§22.1).** Contracts first as the only cross-package interface; one writer per package directory; one owner for dependency changes because the lockfile is shared; fan out only as wide as the dependency graph allows.
21. **Model size and concurrency (§19, §22.1 rule 6).** Running many agents on the largest model exhausted the usage allowance three times. Use the largest model for security-critical code and threat analysis, a mid-size model for application code and documentation, the smallest for mechanical tables, and keep concurrency low enough that a limit leaves finished packages.
22. **IP-literal origins (§3.2).** IP-literal hosts other than loopback are rejected as allowed origins. A literal address would bypass hostname-based reasoning about the target and is never a legitimate application origin here.
23. **Canonical JSON strictness (§11.2).** Canonical JSON rejects sparse arrays and symbol keys as well as the other non-JSON values, because neither survives serialization faithfully.
24. **Canonical-form arguments (§7, §8.1 rule 7).** Input validation is non-transforming, so operation arguments must be supplied in canonical form; a schema that defaults, coerces or transforms is rejected when the adapter is defined. Otherwise the arguments policy judged could differ from the ones executed.
25. **Output schema kinds (§7.1).** Output schemas are checked against an allowlist of schema kinds, not only against loose objects.
26. **Key directory mode (§6.4).** The key directory must be mode 0700, and the service refuses to start otherwise; 0.1 stated only the file mode.
27. **Audit events protected by a trigger (§11.2).** A database trigger rejects `UPDATE`, `DELETE` and `TRUNCATE` on audit events. A database superuser or the table owner can disable it, so it is not immutability (ADR-009).
28. **Password verification concurrency (§5.4).** Each verification costs about 128 MiB of scrypt memory, so the API limits concurrent verifications (two by default) and the Compose memory limit for the API is 768 MiB.
29. **Compose does not mount the key directory (§6.4).** The Phase 1 Compose file no longer mounts the key directory into the API container: Phase 1 stores no secrets, and ADR-001 and ADR-003 allow only the vault boundary to hold the key. It will be mounted into the vault service only (Phase 3).

## Clarifications

30. **Phase task lists and estimates (§15).** Task lists updated for everything above. The estimates are the owner's originals from 0.1 and are marked as unvalidated.
31. **Column names in §11.** `constraints` and `metadata` replace `constraints_json` and `metadata_json`, and `user_sessions` lists `csrf_token_hash`, to match `packages/database/src/schema.ts`.
32. **Redaction key list (§11.2).** The list of key names now matches `packages/audit/src/redact.ts`: `session` and `auth` count only as whole keys, so `sessionExpiresAt` is kept.
33. **Header (title block).** The version, date and a pointer to this file; a note that section numbers are unchanged from 0.1.

## Open questions for the owner

These are product decisions the specification still leaves open. None is settled by 0.2.

1. **Failed logins for unknown accounts.** Should they be recorded anywhere beyond logs, for example as audit events? The code defines an `auth.login_failed` event type; recording attempts against unknown emails creates attacker-controlled rows in the audit chain.
2. **Expiry on deny grants.** The grant schema and the engine currently accept `expiresAt` on a deny and lift the deny when it passes. A deny is a safety control; should it be allowed to lapse on its own, or only be revoked explicitly?
3. **Audit export before Phase 9.** Should the audit chain be exported to an external sink (ADR-009) before the hardening phase? Until then a database administrator who can rewrite the whole table can rewrite a consistent chain.
4. **Model providers and business data (ADR-008).** Which model providers may receive which classes of business data? It blocks Phase 6 and any use with company data.
5. **Container isolation from Phase 2.** _Decided on 2026-11-12: yes, as a per-job sandbox (version 0.3, ADR-013)._ Docker is now available on the development machine. Should browser workers be required to run in containers from Phase 2 instead of Phase 3? Note the tension with §5.3: a headed login browser on the owner's desktop is simpler outside a container.
6. **Owner password policy.** The code accepts any password of 1 to 1024 bytes without a NUL. Is a minimum length or a breached-password check wanted for the local owner?
7. **Organization-wide policies.** The `policies` table is not scheduled because per-agent grants express every rule so far. Are organization-wide rules wanted, and when?
8. **Authoritative allowed origins.** _Provisional answer in 0.3: a job may reach only origins present in both lists. This is the conservative reading; confirm or relax it._ When an adapter's allowed-origin list and a registered application definition's list differ, which is authoritative? The navigation guard currently uses only the adapter's.
9. **Audit visibility.** Should audit events be visible to every owner in an organization, or only to the acting owner? Today list and verify are organization-wide (ADR-010).
10. **Licence.** Which licence are the two repositories released under? There is no LICENSE file in either.
11. **Authentication modes per adapter.** Should the adapter contract allow more than one authentication mode per adapter, as the specification's application definition does?

## Version 0.3

The owner decided on 2026-11-12 to bring worker isolation forward from Phase 3 into Phase 2. Entries continue the numbering above.

34. **Per-job sandbox and egress proxy (§3.2, §15 Phase 2, ADR-013).** The worker service is split into a supervisor, which holds the database connection and the KEK and never runs a browser, and a runner per job, which runs the browser and adapter in a sandbox with no network, no key, no database access and a read-only filesystem. The only exit is an egress proxy in the supervisor that enforces the allowed origins and the resolved-address rules. In 0.2 every navigation control sat inside the process it was protecting.
35. **Security claims (§13.4).** A bounded claim replaces "a compromised worker is out of scope": a compromised browser or adapter reaches one session, for one job, and only that application's origins. The list of what cannot be claimed now names the supervisor, the host, sandbox escapes, path restriction under compromise and truthfulness of a compromised runner's output.
36. **Allowed origins of a job (§3.2).** A job may reach only origins in both the adapter's list and the application definition's list. This is a provisional answer to open question 8.
37. **No session write-back from operation jobs (§3.2).** The stored snapshot changes only through the login handoff. Accepting session state from a runner after it has loaded pages would let a compromised runner replace the stored session. ADR-002 allowed write-back; it is deferred until an application needs it.
38. **Address pinning (§3.2).** The proxy connects to the address it checked, which is stronger than re-checking the address on reconnect as 0.2 said.
39. **Login handoff runs in a sandbox and completes on the owner's signal (§5.3).** The login window has the display socket added and nothing else. Completion is an explicit dashboard action, `POST /v1/connections/:id/auth/complete`, which 0.2 listed as an endpoint but did not tie to the steps.
40. **Responses of the execute endpoint (§12.2).** When no job is created, the error codes; otherwise `200` with a finished job or `202` with a job to poll.
41. **Job queue (ADR-004).** The queue is a polling loop over `execution_jobs` with `FOR UPDATE SKIP LOCKED`, the fallback ADR-004 already allowed. No queue library is adopted in Phase 2.
