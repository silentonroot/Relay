import { isTerminalJobStatus, TERMINAL_JOB_STATUSES } from '@aab/contracts';
import type { JobError, JobKind, JobStatus, JsonObject } from '@aab/contracts';
import { and, asc, eq, inArray, isNotNull, isNull, lt, lte, sql } from 'drizzle-orm';
import type { Db } from '../client.js';
import { rowsOf } from '../client.js';
import { ConflictError, NotFoundError, translateDbErrors, ValidationError } from '../errors.js';
import { agents, connections, executionJobs, operationRequests } from '../schema.js';
import { isUuid, isValidScope } from '../support.js';

const NON_TERMINAL: readonly JobStatus[] = ['queued', 'running'];
const MAX_ERROR_MESSAGE_LENGTH = 300;
/** How many connections one claim attempt may find busy before it gives up. */
const MAX_CLAIM_ATTEMPTS = 25;
const SHA256_HEX = /^[0-9a-f]{64}$/;

/** An execution job as the broker's own components see it. Dates are ISO strings. */
export interface ExecutionJob {
  id: string;
  organizationId: string;
  requestedByUserId: string;
  kind: JobKind;
  agentId: string | null;
  connectionId: string;
  runId: string | null;
  operation: string | null;
  arguments: JsonObject | null;
  retrySafe: boolean;
  policyDecisionId: string | null;
  approvalRequestId: string | null;
  capabilityRef: string | null;
  status: JobStatus;
  attemptCount: number;
  timeoutMs: number;
  workerId: string | null;
  leaseExpiresAt: string | null;
  completionRequestedAt: string | null;
  cancelRequestedAt: string | null;
  startedAt: string | null;
  finishedAt: string | null;
  result: JsonObject | null;
  resultPurgedAt: string | null;
  error: JobError | null;
  auditEventId: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface OwnerScope {
  organizationId: string;
  ownerUserId: string;
}

export interface CreateOperationJobInput {
  organizationId: string;
  requestedByUserId: string;
  agentId: string;
  connectionId: string;
  runId: string | null;
  operation: string;
  arguments: JsonObject;
  retrySafe: boolean;
  policyDecisionId: string | null;
  timeoutMs: number;
}

export interface CreateLoginJobInput {
  organizationId: string;
  requestedByUserId: string;
  connectionId: string;
  timeoutMs: number;
}

export interface ClaimJobInput {
  workerId: string;
  leaseMs: number;
  now: Date;
}

export interface CompleteJobInput {
  /** Must be terminal. */
  status: JobStatus;
  /** Stored only when `status` is `succeeded`. */
  result?: JsonObject | null | undefined;
  /** Stored for every status except `succeeded`. The message is truncated to 300 characters. */
  error?: JobError | null | undefined;
  auditEventId?: string | null | undefined;
  now: Date;
}

export interface RecoverLeasesInput {
  now: Date;
  /** An operation job that has already been attempted this often is failed, not requeued. */
  maxAttempts: number;
}

const iso = (value: Date | null): string | null => (value === null ? null : value.toISOString());

export function toExecutionJob(row: typeof executionJobs.$inferSelect): ExecutionJob {
  return {
    id: row.id,
    organizationId: row.organizationId,
    requestedByUserId: row.requestedByUserId,
    kind: row.kind,
    agentId: row.agentId,
    connectionId: row.connectionId,
    runId: row.runId,
    operation: row.operation,
    arguments: row.arguments as JsonObject | null,
    retrySafe: row.retrySafe,
    policyDecisionId: row.policyDecisionId,
    approvalRequestId: row.approvalRequestId,
    capabilityRef: row.capabilityRef,
    status: row.status,
    attemptCount: row.attemptCount,
    timeoutMs: row.timeoutMs,
    workerId: row.workerId,
    leaseExpiresAt: iso(row.leaseExpiresAt),
    completionRequestedAt: iso(row.completionRequestedAt),
    cancelRequestedAt: iso(row.cancelRequestedAt),
    startedAt: iso(row.startedAt),
    finishedAt: iso(row.finishedAt),
    result: row.result as JsonObject | null,
    resultPurgedAt: iso(row.resultPurgedAt),
    error: row.errorCode === null ? null : { code: row.errorCode, message: row.errorMessage ?? '' },
    auditEventId: row.auditEventId,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
  };
}

function requirePositiveInt(value: number, field: string): void {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new ValidationError('invalid job', [
      { path: field, message: 'expected a positive integer' },
    ]);
  }
}

function requireUuids(values: Record<string, string | null>): void {
  for (const [field, value] of Object.entries(values)) {
    if (value !== null && !isUuid(value)) {
      throw new ValidationError('invalid job', [{ path: field, message: 'expected a UUID' }]);
    }
  }
}

function isPlainObject(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Execution jobs. The API creates them and reads them through owner-scoped calls; the worker
 * claims and completes them through the internal ones.
 */
export function createJobRepository(db: Db) {
  const ownedBy = (scope: OwnerScope) =>
    and(
      eq(executionJobs.organizationId, scope.organizationId),
      eq(executionJobs.requestedByUserId, scope.ownerUserId),
    );
  const validOwner = (scope: OwnerScope) =>
    isValidScope({ organizationId: scope.organizationId, userId: scope.ownerUserId });

  return {
    /**
     * Queues one adapter operation. The agent and the connection must belong to the given
     * organization (NotFoundError otherwise). Policy has already been evaluated by the caller.
     */
    async createOperation(input: CreateOperationJobInput): Promise<ExecutionJob> {
      requireUuids({
        organizationId: input.organizationId,
        requestedByUserId: input.requestedByUserId,
        agentId: input.agentId,
        connectionId: input.connectionId,
        runId: input.runId,
        policyDecisionId: input.policyDecisionId,
      });
      requirePositiveInt(input.timeoutMs, 'timeoutMs');
      if (input.operation.trim() === '') {
        throw new ValidationError('invalid job', [{ path: 'operation', message: 'required' }]);
      }
      if (!isPlainObject(input.arguments)) {
        throw new ValidationError('invalid job', [
          { path: 'arguments', message: 'expected an object' },
        ]);
      }
      return translateDbErrors('job', () =>
        db.transaction(async (tx) => {
          const [connection] = await tx
            .select({ id: connections.id })
            .from(connections)
            .where(
              and(
                eq(connections.id, input.connectionId),
                eq(connections.organizationId, input.organizationId),
              ),
            )
            .limit(1);
          if (connection === undefined) throw new NotFoundError('connection');
          const [agent] = await tx
            .select({ id: agents.id })
            .from(agents)
            .where(
              and(eq(agents.id, input.agentId), eq(agents.organizationId, input.organizationId)),
            )
            .limit(1);
          if (agent === undefined) throw new NotFoundError('agent');

          const [row] = await tx
            .insert(executionJobs)
            .values({
              organizationId: input.organizationId,
              requestedByUserId: input.requestedByUserId,
              kind: 'operation',
              agentId: input.agentId,
              connectionId: input.connectionId,
              runId: input.runId,
              operation: input.operation,
              arguments: input.arguments,
              retrySafe: input.retrySafe,
              policyDecisionId: input.policyDecisionId,
              timeoutMs: input.timeoutMs,
            })
            .returning();
          return toExecutionJob(row!);
        }),
      );
    },

    /**
     * Queues the login handoff for a connection. The connection must belong to the requesting
     * user (NotFoundError otherwise). A second non-terminal login job for the same connection
     * raises ConflictError.
     */
    async createLogin(input: CreateLoginJobInput): Promise<ExecutionJob> {
      requireUuids({
        organizationId: input.organizationId,
        requestedByUserId: input.requestedByUserId,
        connectionId: input.connectionId,
      });
      requirePositiveInt(input.timeoutMs, 'timeoutMs');
      return translateDbErrors('login job', () =>
        db.transaction(async (tx) => {
          const [connection] = await tx
            .select({ id: connections.id })
            .from(connections)
            .where(
              and(
                eq(connections.id, input.connectionId),
                eq(connections.organizationId, input.organizationId),
                eq(connections.ownerUserId, input.requestedByUserId),
              ),
            )
            .limit(1);
          if (connection === undefined) throw new NotFoundError('connection');
          const [row] = await tx
            .insert(executionJobs)
            .values({
              organizationId: input.organizationId,
              requestedByUserId: input.requestedByUserId,
              kind: 'login',
              connectionId: input.connectionId,
              timeoutMs: input.timeoutMs,
            })
            .returning();
          return toExecutionJob(row!);
        }),
      );
    },

    /**
     * The job as its requester sees it. A job that is missing, belongs to another user, or to
     * another organization raises the same NotFoundError.
     */
    async getForOwner(scope: OwnerScope, jobId: string): Promise<ExecutionJob> {
      if (!validOwner(scope) || !isUuid(jobId)) throw new NotFoundError('job');
      const [row] = await db
        .select()
        .from(executionJobs)
        .where(and(ownedBy(scope), eq(executionJobs.id, jobId)))
        .limit(1);
      if (row === undefined) throw new NotFoundError('job');
      return toExecutionJob(row);
    },

    /** Unscoped, for the broker's own components. Null when missing. */
    async getInternal(jobId: string): Promise<ExecutionJob | null> {
      if (!isUuid(jobId)) return null;
      const [row] = await db
        .select()
        .from(executionJobs)
        .where(eq(executionJobs.id, jobId))
        .limit(1);
      return row === undefined ? null : toExecutionJob(row);
    },

    /** The queued or running login job of a connection, if any. */
    async findActiveLogin(connectionId: string): Promise<ExecutionJob | null> {
      if (!isUuid(connectionId)) return null;
      const [row] = await db
        .select()
        .from(executionJobs)
        .where(
          and(
            eq(executionJobs.connectionId, connectionId),
            eq(executionJobs.kind, 'login'),
            inArray(executionJobs.status, [...NON_TERMINAL]),
          ),
        )
        .limit(1);
      return row === undefined ? null : toExecutionJob(row);
    },

    /**
     * Claims the oldest queued job whose connection has no running job, or returns null.
     *
     * Concurrent claimers are safe: the job row is taken with FOR UPDATE SKIP LOCKED, and a
     * per-connection advisory lock held until commit serializes the "no running job" check
     * with the status change, so two jobs of one connection can never both start. A claimer
     * that finds a connection busy tries the next one (at most 25) and returns null if every
     * candidate was busy.
     */
    async claimNext(input: ClaimJobInput): Promise<ExecutionJob | null> {
      requirePositiveInt(input.leaseMs, 'leaseMs');
      const leaseExpiresAt = new Date(input.now.getTime() + input.leaseMs);
      return db.transaction(async (tx) => {
        const busy: string[] = [];
        for (let attempt = 0; attempt < MAX_CLAIM_ATTEMPTS; attempt += 1) {
          const notBusy =
            busy.length === 0
              ? sql`true`
              : sql`${executionJobs.connectionId} not in (${sql.join(
                  busy.map((id) => sql`${id}::uuid`),
                  sql`, `,
                )})`;
          const running = sql`not exists (select 1 from ${executionJobs} as r where r.connection_id = ${executionJobs.connectionId} and r.status = 'running')`;
          const [candidate] = await tx
            .select({ connectionId: executionJobs.connectionId })
            .from(executionJobs)
            .where(and(eq(executionJobs.status, 'queued'), running, notBusy))
            .orderBy(asc(executionJobs.createdAt), asc(executionJobs.id))
            .limit(1);
          if (candidate === undefined) return null;

          const lock = rowsOf(
            await tx.execute(
              sql`select pg_try_advisory_xact_lock(hashtextextended(${`aab.job.connection:${candidate.connectionId}`}, 0)) as locked`,
            ),
          )[0];
          if (lock?.locked !== true) {
            busy.push(candidate.connectionId);
            continue;
          }

          // Under the connection lock the check is authoritative: any claim that committed
          // before we got the lock is visible to this new statement.
          const [target] = await tx
            .select({ id: executionJobs.id })
            .from(executionJobs)
            .where(
              and(
                eq(executionJobs.connectionId, candidate.connectionId),
                eq(executionJobs.status, 'queued'),
                running,
              ),
            )
            .orderBy(asc(executionJobs.createdAt), asc(executionJobs.id))
            .limit(1)
            .for('update', { skipLocked: true });
          if (target === undefined) {
            busy.push(candidate.connectionId);
            continue;
          }

          const [row] = await tx
            .update(executionJobs)
            .set({
              status: 'running',
              attemptCount: sql`${executionJobs.attemptCount} + 1`,
              workerId: input.workerId,
              leaseExpiresAt,
              startedAt: sql`coalesce(${executionJobs.startedAt}, ${input.now.toISOString()}::timestamptz)`,
              updatedAt: input.now,
            })
            .where(and(eq(executionJobs.id, target.id), eq(executionJobs.status, 'queued')))
            .returning();
          if (row === undefined) {
            busy.push(candidate.connectionId);
            continue;
          }
          return toExecutionJob(row);
        }
        return null;
      });
    },

    /** Pushes the lease out. False when the job is no longer running under that worker. */
    async extendLease(
      jobId: string,
      workerId: string,
      leaseMs: number,
      now: Date,
    ): Promise<boolean> {
      if (!isUuid(jobId)) return false;
      requirePositiveInt(leaseMs, 'leaseMs');
      const rows = await db
        .update(executionJobs)
        .set({ leaseExpiresAt: new Date(now.getTime() + leaseMs), updatedAt: now })
        .where(
          and(
            eq(executionJobs.id, jobId),
            eq(executionJobs.status, 'running'),
            eq(executionJobs.workerId, workerId),
          ),
        )
        .returning({ id: executionJobs.id });
      return rows.length === 1;
    },

    /**
     * Ends a running job. ConflictError unless the job is `running` under `workerId`, so a
     * worker that lost its lease cannot overwrite what recovery decided.
     */
    async complete(
      jobId: string,
      workerId: string,
      input: CompleteJobInput,
    ): Promise<ExecutionJob> {
      if (!isTerminalJobStatus(input.status)) {
        throw new ValidationError('invalid job outcome', [
          { path: 'status', message: `expected one of ${TERMINAL_JOB_STATUSES.join(', ')}` },
        ]);
      }
      if (!isUuid(jobId)) throw new ConflictError('job is not running under this worker');
      const succeeded = input.status === 'succeeded';
      if (succeeded && input.result !== undefined && input.result !== null) {
        if (!isPlainObject(input.result)) {
          throw new ValidationError('invalid job outcome', [
            { path: 'result', message: 'expected an object' },
          ]);
        }
      }
      const error = succeeded ? null : (input.error ?? null);
      const rows = await translateDbErrors('job', () =>
        db
          .update(executionJobs)
          .set({
            status: input.status,
            result: succeeded ? (input.result ?? null) : null,
            errorCode: error?.code ?? null,
            errorMessage: error === null ? null : error.message.slice(0, MAX_ERROR_MESSAGE_LENGTH),
            auditEventId: input.auditEventId ?? null,
            finishedAt: input.now,
            updatedAt: input.now,
          })
          .where(
            and(
              eq(executionJobs.id, jobId),
              eq(executionJobs.status, 'running'),
              eq(executionJobs.workerId, workerId),
            ),
          )
          .returning(),
      );
      if (rows[0] === undefined) throw new ConflictError('job is not running under this worker');
      return toExecutionJob(rows[0]);
    },

    /**
     * The owner signals that the interactive login is finished. Only a non-terminal login job
     * of the caller qualifies; anything else is NotFoundError. Keeps the first request time.
     */
    async requestLoginCompletion(
      scope: OwnerScope,
      jobId: string,
      now: Date,
    ): Promise<ExecutionJob> {
      if (!validOwner(scope) || !isUuid(jobId)) throw new NotFoundError('job');
      const [row] = await db
        .update(executionJobs)
        .set({
          completionRequestedAt: sql`coalesce(${executionJobs.completionRequestedAt}, ${now.toISOString()}::timestamptz)`,
          updatedAt: now,
        })
        .where(
          and(
            ownedBy(scope),
            eq(executionJobs.id, jobId),
            eq(executionJobs.kind, 'login'),
            inArray(executionJobs.status, [...NON_TERMINAL]),
          ),
        )
        .returning();
      if (row === undefined) throw new NotFoundError('job');
      return toExecutionJob(row);
    },

    /**
     * For revocation: queued jobs become `cancelled` at once, running jobs get
     * `cancel_requested_at` for the worker to act on. Returns every job it touched.
     */
    async cancelForConnection(connectionId: string, now: Date): Promise<ExecutionJob[]> {
      if (!isUuid(connectionId)) return [];
      return db.transaction(async (tx) => {
        const cancelled = await tx
          .update(executionJobs)
          .set({
            status: 'cancelled',
            errorCode: 'cancelled',
            errorMessage: 'The job was cancelled before it started.',
            cancelRequestedAt: now,
            finishedAt: now,
            updatedAt: now,
          })
          .where(
            and(eq(executionJobs.connectionId, connectionId), eq(executionJobs.status, 'queued')),
          )
          .returning();
        const flagged = await tx
          .update(executionJobs)
          .set({
            cancelRequestedAt: sql`coalesce(${executionJobs.cancelRequestedAt}, ${now.toISOString()}::timestamptz)`,
            updatedAt: now,
          })
          .where(
            and(eq(executionJobs.connectionId, connectionId), eq(executionJobs.status, 'running')),
          )
          .returning();
        return [...cancelled, ...flagged].map(toExecutionJob);
      });
    },

    /**
     * Decides what happens to running jobs whose lease expired: a retry-safe operation with
     * attempts left is requeued, an operation that is not retry-safe becomes
     * `outcome_unknown` (it may have changed the target application), everything else fails
     * with `worker_failure`. Returns the jobs it changed, in their new state.
     */
    async recoverExpiredLeases(input: RecoverLeasesInput): Promise<ExecutionJob[]> {
      return db.transaction(async (tx) => {
        const expired = await tx
          .select()
          .from(executionJobs)
          .where(
            and(eq(executionJobs.status, 'running'), lte(executionJobs.leaseExpiresAt, input.now)),
          )
          .orderBy(asc(executionJobs.createdAt), asc(executionJobs.id))
          .for('update', { skipLocked: true });

        const changed: ExecutionJob[] = [];
        for (const job of expired) {
          const requeue =
            job.kind === 'operation' && job.retrySafe && job.attemptCount < input.maxAttempts;
          const unknown = job.kind === 'operation' && !job.retrySafe;
          const patch = requeue
            ? {
                status: 'queued' as const,
                workerId: null,
                leaseExpiresAt: null,
                updatedAt: input.now,
              }
            : {
                status: unknown ? ('outcome_unknown' as const) : ('failed' as const),
                errorCode: 'worker_failure' as const,
                errorMessage: unknown
                  ? 'The worker stopped before the outcome could be verified.'
                  : 'The worker stopped before the job finished.',
                finishedAt: input.now,
                updatedAt: input.now,
              };
          const [row] = await tx
            .update(executionJobs)
            .set(patch)
            .where(eq(executionJobs.id, job.id))
            .returning();
          changed.push(toExecutionJob(row!));
        }
        return changed;
      });
    },

    /**
     * Retention: drops the stored result of terminal jobs that finished before `olderThan`
     * and records when. Returns how many results were purged.
     */
    async purgeResults(olderThan: Date, now: Date): Promise<number> {
      const rows = await db
        .update(executionJobs)
        .set({ result: null, resultPurgedAt: now, updatedAt: now })
        .where(
          and(
            inArray(executionJobs.status, [...TERMINAL_JOB_STATUSES]),
            isNotNull(executionJobs.result),
            isNull(executionJobs.resultPurgedAt),
            lt(executionJobs.finishedAt, olderThan),
          ),
        )
        .returning({ id: executionJobs.id });
      return rows.length;
    },
  };
}

export interface OperationRequestRecord {
  id: string;
  agentId: string;
  idempotencyKey: string;
  requestHash: string;
  jobId: string;
  createdAt: string;
}

export interface CreateOperationRequestInput {
  agentId: string;
  idempotencyKey: string;
  /** SHA-256 of the canonical request, 64 lowercase hex characters. */
  requestHash: string;
  jobId: string;
}

/** Idempotency records for operation execution (spec §11, §12.2). */
export function createOperationRequestRepository(db: Db) {
  return {
    async find(agentId: string, idempotencyKey: string): Promise<OperationRequestRecord | null> {
      if (!isUuid(agentId)) return null;
      const [row] = await db
        .select()
        .from(operationRequests)
        .where(
          and(
            eq(operationRequests.agentId, agentId),
            eq(operationRequests.idempotencyKey, idempotencyKey),
          ),
        )
        .limit(1);
      return row === undefined
        ? null
        : {
            id: row.id,
            agentId: row.agentId,
            idempotencyKey: row.idempotencyKey,
            requestHash: row.requestHash,
            jobId: row.jobId,
            createdAt: row.createdAt.toISOString(),
          };
    },

    /** A second record for the same (agent, key) raises ConflictError. */
    async create(input: CreateOperationRequestInput): Promise<OperationRequestRecord> {
      requireUuids({ agentId: input.agentId, jobId: input.jobId });
      if (!SHA256_HEX.test(input.requestHash) || input.idempotencyKey === '') {
        throw new ValidationError('invalid operation request', [
          { path: 'requestHash', message: 'expected 64 lowercase hex characters' },
        ]);
      }
      return translateDbErrors('operation request', async () => {
        const [row] = await db
          .insert(operationRequests)
          .values({
            agentId: input.agentId,
            idempotencyKey: input.idempotencyKey,
            requestHash: input.requestHash,
            jobId: input.jobId,
          })
          .returning();
        return {
          id: row!.id,
          agentId: row!.agentId,
          idempotencyKey: row!.idempotencyKey,
          requestHash: row!.requestHash,
          jobId: row!.jobId,
          createdAt: row!.createdAt.toISOString(),
        };
      });
    },
  };
}
