import { toOperationDescriptors, validateOperationInput } from '@aab/adapter-sdk';
import { canonicalJson } from '@aab/contracts';
import type { AuditDecision, JobError, JobErrorCode, JobStatus, JsonObject } from '@aab/contracts';
import { ConflictError } from '@aab/database';
import { evaluate } from '@aab/policy-engine';
import { jobError } from '../protocol.js';
import { openSnapshot } from '../session-store/index.js';
import type { OpenedSnapshot } from '../session-store/index.js';
import type { OperationJobOutcome } from '../types.js';
import { errorFacts, intersectOrigins } from './context.js';
import type { JobContext } from './context.js';
import { auditAsWorker, OPERATION_REASONS, transitionIfAllowed } from './records.js';

type OperationEvent =
  'operation.succeeded' | 'operation.failed' | 'operation.reauth_required' | 'operation.denied';

interface OperationRecord {
  status: JobStatus;
  error: JobError | null;
  eventType: OperationEvent;
  decision?: AuditDecision;
  result?: JsonObject;
  /** Extra audit metadata: codes and key names only. */
  extra?: JsonObject;
  connection?:
    | { kind: 'verified' }
    | { kind: 'invalidate'; to: 'expired' | 'reconnect_required'; reason: string; cause: string };
}

function failure(code: JobErrorCode): OperationRecord {
  return {
    status: code === 'cancelled' ? 'cancelled' : 'failed',
    error: jobError(code),
    eventType: 'operation.failed',
  };
}

function denied(reasonCode: string, extra: JsonObject = {}): OperationRecord {
  return {
    status: 'denied',
    error: jobError('denied'),
    eventType: 'operation.denied',
    decision: 'deny',
    extra: { reasonCode, ...extra },
  };
}

function reauth(reason: string, cause: string): OperationRecord {
  return {
    status: 'reauth_required',
    error: jobError('session_expired'),
    eventType: 'operation.reauth_required',
    connection: { kind: 'invalidate', to: 'expired', reason, cause },
  };
}

/** Maps what the runner returned onto the job's record. */
export function recordForOutcome(outcome: OperationJobOutcome): OperationRecord {
  switch (outcome.status) {
    case 'succeeded':
      return {
        status: 'succeeded',
        error: null,
        eventType: 'operation.succeeded',
        result: outcome.data,
        extra: {
          resultKeys: Object.keys(outcome.data).sort(),
          resultBytes: Buffer.byteLength(canonicalJson(outcome.data), 'utf8'),
        },
        connection: { kind: 'verified' },
      };
    case 'reauth_required':
      return reauth(OPERATION_REASONS.reauthRequired, 'reauth_required');
    case 'outcome_unknown':
      return {
        status: 'outcome_unknown',
        error: jobError('worker_failure'),
        eventType: 'operation.failed',
      };
    case 'failed':
      if (outcome.error.code === 'identity_mismatch') {
        return {
          ...failure('identity_mismatch'),
          connection: {
            kind: 'invalidate',
            to: 'reconnect_required',
            reason: OPERATION_REASONS.identityMismatch,
            cause: 'identity_mismatch',
          },
        };
      }
      // Fixed text for the code; the runner's own message is never stored.
      return failure(outcome.error.code);
  }
}

/**
 * Writes the job's outcome, its audit event and any connection change in one transaction.
 * Returns false when nothing was written: the job is then left to lease recovery, and no
 * result is ever visible without its audit event (INV-10).
 */
async function record(ctx: JobContext, entry: OperationRecord): Promise<boolean> {
  const { job, repos, logger } = ctx;
  const now = ctx.clock();
  const metadata: JsonObject = {
    jobId: job.id,
    operation: job.operation,
    status: entry.status,
    errorCode: entry.error?.code ?? null,
    durationMs: Math.max(0, Date.now() - ctx.startedAtMs),
    attempt: job.attemptCount,
    sandbox: ctx.runner.sandbox,
    ...entry.extra,
  };
  try {
    await repos.transaction(async (tx) => {
      const event = await auditAsWorker(tx, job, now, {
        eventType: entry.eventType,
        decision: entry.decision ?? 'not_applicable',
        metadata,
      });
      const change = entry.connection;
      if (change?.kind === 'verified') {
        const current = await tx.connections.getForExecution(job.connectionId);
        if (current !== null && current.connection.status !== 'revoked') {
          await tx.connections.recordSession(job.connectionId, {
            externalAccountHint: current.connection.externalAccountHint,
            sessionExpiresAt:
              current.connection.sessionExpiresAt === null
                ? null
                : new Date(current.connection.sessionExpiresAt),
            lastVerifiedAt: now,
          });
        }
      } else if (change?.kind === 'invalidate') {
        await transitionIfAllowed(tx, job.connectionId, change.to, change.reason);
        const deleted = await tx.vault.deleteForConnection(job.connectionId, now);
        if (deleted > 0) {
          await auditAsWorker(tx, job, now, {
            eventType: 'vault.secret_deleted',
            metadata: {
              jobId: job.id,
              connectionId: job.connectionId,
              deletedVersions: deleted,
              cause: change.cause,
            },
          });
        }
      }
      await tx.jobs.complete(job.id, ctx.settings.workerId, {
        status: entry.status,
        result: entry.status === 'succeeded' ? (entry.result ?? null) : null,
        error: entry.error,
        auditEventId: event.id,
        now,
      });
    });
    logger.info(
      { jobId: job.id, status: entry.status, errorCode: entry.error?.code ?? null },
      'operation job finished',
    );
    return true;
  } catch (error) {
    if (error instanceof ConflictError) {
      logger.warn(
        { jobId: job.id },
        'operation job is no longer held by this worker; outcome discarded',
      );
    } else {
      logger.error(
        { jobId: job.id, ...errorFacts(error) },
        'operation outcome could not be recorded; lease recovery will end the job',
      );
    }
    return false;
  }
}

/** What to do when the job was told to stop before the runner was invoked. */
async function stopped(ctx: JobContext): Promise<void> {
  if (ctx.stopReason() === 'lease_lost') {
    ctx.logger.warn({ jobId: ctx.job.id }, 'lease lost; operation job abandoned');
    return;
  }
  await record(ctx, failure('cancelled'));
}

/**
 * Runs one operation job. Each step fails closed: a failure records the job and returns, so
 * no later step (in particular, decrypting the snapshot or invoking the runner) is reached.
 */
export async function runOperationJob(ctx: JobContext): Promise<void> {
  const { job, repos, logger } = ctx;

  // 1. Load everything fresh.
  const target = await repos.connections.getForExecution(job.connectionId);
  if (target === null) {
    await record(ctx, failure('worker_failure'));
    return;
  }
  const { connection, application } = target;
  if (job.cancelRequestedAt !== null || connection.status === 'revoked') {
    await record(ctx, failure('cancelled'));
    return;
  }
  if (ctx.signal.aborted) return stopped(ctx);

  // 2. Adapter and origins.
  const adapter = ctx.adapters.get(application.adapterId, application.adapterVersion);
  if (adapter === undefined || adapter.execute === undefined) {
    await record(ctx, failure('adapter_unavailable'));
    return;
  }
  const allowedOrigins = intersectOrigins(adapter, application);
  if (allowedOrigins.length === 0) {
    await record(ctx, failure('origin_not_allowed'));
    return;
  }

  // 3. Arguments and policy, re-checked now with freshly loaded grants (INV-3).
  if (job.operation === null || job.arguments === null || job.agentId === null) {
    await record(ctx, failure('invalid_arguments'));
    return;
  }
  const operation = job.operation;
  const validation = validateOperationInput(adapter, operation, job.arguments);
  if (!validation.ok) {
    await record(
      ctx,
      failure(
        validation.error.code === 'unknown_operation' ? 'adapter_unavailable' : 'invalid_arguments',
      ),
    );
    return;
  }
  const agent = await repos.agents.getInternal(job.agentId);
  if (agent === null) {
    await record(ctx, denied('agent_not_found'));
    return;
  }
  const grants = await repos.grants.listForEvaluation({
    agentId: agent.id,
    connectionId: connection.id,
    operation,
  });
  const descriptor = toOperationDescriptors(adapter).find((entry) => entry.name === operation);
  const decision = evaluate({
    request: {
      agentId: agent.id,
      connectionId: connection.id,
      operation,
      arguments: job.arguments,
    },
    operation: descriptor,
    grants,
    agent: {
      id: agent.id,
      status: agent.status,
      ownerUserId: agent.ownerUserId,
      organizationId: agent.organizationId,
    },
    connection: {
      id: connection.id,
      status: connection.status,
      ownerUserId: connection.ownerUserId,
      organizationId: connection.organizationId,
    },
    now: ctx.clock(),
  });
  if (decision.outcome !== 'allow') {
    await record(
      ctx,
      denied(decision.reasonCode, {
        policyOutcome: decision.outcome,
        matchedGrantIds: decision.matchedGrantIds,
      }),
    );
    return;
  }
  // Phase 2 runs read operations only.
  if (descriptor === undefined || descriptor.sensitivity !== 'read') {
    await record(ctx, denied('operation_not_executable', { policyOutcome: decision.outcome }));
    return;
  }
  const finalArguments: JsonObject = { ...job.arguments, ...decision.obligations };
  if (!validateOperationInput(adapter, operation, finalArguments).ok) {
    await record(ctx, failure('invalid_arguments'));
    return;
  }
  if (ctx.signal.aborted) return stopped(ctx);

  // 4. Exactly one snapshot, for this job's connection.
  let snapshot: OpenedSnapshot | null;
  try {
    snapshot = await openSnapshot(repos, connection, ctx.kek);
  } catch (error) {
    logger.error(
      { jobId: job.id, connectionId: connection.id, ...errorFacts(error) },
      'session snapshot could not be opened',
    );
    await record(ctx, failure('worker_failure'));
    return;
  }
  if (snapshot === null) {
    await record(ctx, reauth(OPERATION_REASONS.noSnapshot, 'no_snapshot'));
    return;
  }

  // 5. Record the read, then hand the job to the sandbox.
  let outcome: OperationJobOutcome | null = null;
  try {
    try {
      const now = ctx.clock();
      await repos.transaction(async (tx) => {
        await tx.vault.touchAccessed(snapshot.vaultEntryId, now);
        await auditAsWorker(tx, job, now, {
          eventType: 'vault.secret_read',
          metadata: {
            jobId: job.id,
            connectionId: connection.id,
            vaultEntryId: snapshot.vaultEntryId,
            snapshotVersion: snapshot.version,
            keyVersion: snapshot.kekVersion,
            purpose: 'operation',
          },
        });
      });
    } catch (error) {
      logger.error({ jobId: job.id, ...errorFacts(error) }, 'snapshot read could not be audited');
      outcome = { status: 'failed', error: jobError('worker_failure') };
    }
    if (outcome === null && !ctx.signal.aborted) {
      try {
        outcome = await ctx.runner.runOperation(
          {
            jobId: job.id,
            connectionId: connection.id,
            adapterId: adapter.id,
            adapterVersion: adapter.version,
            allowedOrigins,
            operation,
            arguments: finalArguments,
            storageState: snapshot.storageState,
            expectedAccountHint: connection.externalAccountHint,
            timeoutMs: job.timeoutMs,
          },
          ctx.signal,
        );
      } catch (error) {
        logger.error({ jobId: job.id, ...errorFacts(error) }, 'job runner threw');
        outcome = { status: 'failed', error: jobError('worker_failure') };
      }
    }
  } finally {
    snapshot.dispose();
  }

  if (outcome === null) return stopped(ctx);
  if (ctx.stopReason() === 'lease_lost') {
    ctx.logger.warn({ jobId: job.id }, 'lease lost while the operation ran; outcome discarded');
    return;
  }
  // 6. One transaction for the outcome, its audit event and connection changes.
  await record(ctx, recordForOutcome(outcome));
}
