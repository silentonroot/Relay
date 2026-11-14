# ADR-004: Job queue and the threshold for Temporal

- **Status:** Accepted (2026-11-12, with the outcome below)
- **Date:** 2026-11-11

## Context

From Phase 2 the API hands work to a browser worker: start a login session, check a session, run
an operation. From Phase 7 the orchestrator runs multi-step workflows that pause for human approval
or re-authentication, sometimes for days. The specification asks for a PostgreSQL-backed queue
first and an evaluation of Temporal before Phase 7.

Whatever delivers the jobs, some requirements are fixed by the security design rather than by
convenience:

- A job is bound to one connection and one operation, and its lease has an expiry that revocation
  can cut short ([ADR-001](ADR-001-trust-boundaries-worker-isolation.md), INV-6 and INV-11).
- A read may be retried within limits. A write whose outcome is uncertain is never retried
  automatically (INV-12).
- Job payloads must not contain secrets, and sensitive operation inputs are stored by reference,
  not inline (specification §11.1).
- The test suite runs on PGlite, an in-process PostgreSQL, with no Docker
  ([ADR-011](ADR-011-toolchain.md)).

Nothing in Phase 1 needs a queue, so this record is a recommendation and a plan for the spike.

## Decision

1. **AAB's own `execution_jobs` table is the source of truth for job state, leases and outcome.**
   The specification already defines that table with `status` and `lease_expires_at`. Audit,
   cancellation, capability binding and the "never retry an uncertain write" rule all read and
   write that row. A queue library is only the mechanism that wakes a worker and hands it a job
   identifier.
2. **Start Phase 2 with pg-boss as that mechanism**, subject to the spike below. If the spike shows
   that the library's retry or expiry behaviour cannot be fully subordinated to the job row, use a
   small polling loop over `execution_jobs` with `FOR UPDATE SKIP LOCKED` instead and adopt no
   library.
3. **Do not adopt Temporal** unless the threshold below is met at the Phase 7 evaluation.

**Outcome (2026-11-12).** Phase 2 uses the polling loop over `execution_jobs` with
`FOR UPDATE SKIP LOCKED` and adopts no queue library. Point 1 makes the job row the source of
truth, the loop is small, and it runs unchanged on the in-process test database. The pg-boss spike
was not run; revisit if Phase 7 needs scheduling or backoff helpers.

## Alternatives considered

Verified on the npm registry on 2026-11-11 (version, licence, engine range, declared dependencies,
last publish). Statements about behaviour come from each project's documentation as known to the
author and are **not verified against these exact releases**; the spike must confirm them.

|                               | pg-boss                                                                                                            | Graphile Worker                                                                                                             |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------- |
| Release checked               | 12.38.2, published 2026-11-10                                                                                      | 0.18.0, registry entry last modified 2026-09-08; still a 0.x version                                                        |
| Licence                       | MIT                                                                                                                | MIT                                                                                                                         |
| Node engine                   | >= 22.12                                                                                                           | >= 22.18                                                                                                                    |
| Declared runtime dependencies | 4 (`pg`, a cron parser, a recurrence library, `serialize-error`)                                                   | 8, including a CLI argument parser and a configuration loader                                                               |
| Leases (unverified)           | Per-job expiry; a job active past its expiry is failed and can be retried                                          | A job locked by a worker that died is released only after a fixed lock timeout, documented as four hours                    |
| Retries (unverified)          | Retry limit, delay and backoff configurable per queue or per job; dead-letter queues                               | Maximum attempts per job with built-in exponential backoff                                                                  |
| Cancellation (unverified)     | A cancel call exists for queued and active jobs; whether a running handler is signalled must be tested             | A queued job can be removed; signalling a running task must be tested                                                       |
| Scheduling (unverified)       | Cron schedules                                                                                                     | Crontab file or configuration                                                                                               |
| Delivery (unverified)         | Polling with `SKIP LOCKED`                                                                                         | `LISTEN/NOTIFY` with polling fallback, which gives lower latency                                                            |
| Testability on PGlite         | Unverified. Documentation describes supplying a custom database executor, which would allow an adapter over PGlite | Unverified. Expects a `pg` connection pool and uses `LISTEN/NOTIFY`, which is harder to provide over an in-process database |

- **Graphile Worker.** A sound library with low latency. Not the first choice because the
  documented crash-recovery lock timeout is far longer than the browser leases AAB needs (seconds to
  minutes), because it remains pre-1.0, and because running it on PGlite looks harder. If the spike
  shows the lock timeout is configurable per task, this comparison narrows.
- **No library; poll `execution_jobs` directly.** About a hundred lines, no dependency, total
  control over lease semantics, and trivially testable on PGlite. It lacks scheduling and backoff
  helpers, which Phase 2 does not need. This is the fallback, and it may turn out to be the right
  answer outright given point 1 of the decision.
- **Redis-backed queues.** Rejected: a second stateful service, and job state would no longer
  commit in the same transaction as the audit event.
- **Temporal from the start.** Rejected for now. The registry shows the worker package depends on a
  bundler, a compiler, gRPC and a native bridge, and it needs a Temporal server with its own
  persistence. That contradicts "fewer services" for a local-first product. Workflow inputs and
  results are stored in Temporal's history, so sensitive operation inputs would need an encrypting
  payload codec to keep the guarantees in specification §11.1.

### Threshold for moving to Temporal

Adopt Temporal at or after Phase 7 only if at least two of these are true, with evidence from the
queue-based implementation:

1. The hand-written run state machine has had two or more defects in crash recovery or in resuming
   after an approval wait that a durable-execution engine would have prevented by construction.
2. Workflows need compensation across more than two applications, so that partial failure handling
   dominates the orchestrator code.
3. Workflow definitions change while runs are in flight often enough that versioned replay is
   needed.
4. A single PostgreSQL instance can no longer carry the job volume. This is not expected in a local
   install and applies to Phase 10.

## Consequences

- Keeping job state in our own table means a duplicate of some state the library also tracks. The
  job row wins on every disagreement, and the worker must check the row, not the library, before it
  executes.
- A library's automatic retry must be disabled or set to zero for write operations and for anything
  whose outcome is uncertain. That is a configuration hazard and needs a test that fails if a write
  is ever redelivered.
- If the fallback polling loop is chosen, latency is bounded by the poll interval. That is
  acceptable for human-scale approval flows.

## Evidence still missing

- Whether either library runs against PGlite without a network PostgreSQL.
- Whether lease expiry in pg-boss can be driven by, or kept consistent with,
  `execution_jobs.lease_expires_at`.
- Whether cancelling an active job delivers a signal the worker can act on, in both libraries.
- Current maintenance health of both projects beyond publish dates.

## The spike that settles it

At the start of Phase 2, in a throwaway branch, implement the same three behaviours three ways
(pg-boss, Graphile Worker, direct polling) against the Northstar read operations:

1. A worker is killed mid-read; the job is picked up again within the lease window and at most the
   configured number of times.
2. A connection is revoked while its job is queued, and again while it is active; in both cases the
   operation does not complete.
3. The whole test runs on PGlite in the standard test command.

Choose the option with the least code that passes all three, and replace this record with an
Accepted one stating the result.

## Revisit when

- Phase 2 begins (run the spike).
- The Phase 7 evaluation is due (apply the Temporal threshold).
