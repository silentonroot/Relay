import type { JobError } from '@aab/contracts';
import { InvalidTransitionError } from '@aab/database';
import type { FastifyBaseLogger } from 'fastify';
import { LOGIN_AUTHORIZATION_TTL_SECONDS } from '../config.js';
import type { AppContext } from '../context.js';
import { failureCodeFor } from './gateway.js';

/*
 * Stage 1 of a capability (ADR-014 section 5) and its failure path (sections 5 and 9, P3-11).
 *
 * After the execute or connect transaction commits, the API asks the vault to authorize the new
 * job. If the vault is unreachable, times out or refuses, the job ends `failed` with
 * `vault_unavailable` or `vault_denied` through ONE conditional update (still `queued`, still no
 * capability), so a job that was authorized or claimed in the meantime is never touched. The
 * audit event is written by the API as the system, in the same transaction. A login job also
 * puts its connection back to `authentication_required`, as every other login failure does.
 */

export interface NewJob {
  id: string;
  kind: 'operation' | 'login';
  organizationId: string;
  connectionId: string;
  agentId: string | null;
  operation: string | null;
  runId: string | null;
}

const MESSAGES: Record<'vault_unavailable' | 'vault_denied', string> = {
  vault_unavailable: 'The vault could not be reached; submit the request again.',
  vault_denied: 'The vault refused access for this job.',
};

/** Ends the job as failed unless it was authorized or claimed first. True when this call ended it. */
export async function failJobForVault(
  ctx: AppContext,
  job: NewJob,
  code: 'vault_unavailable' | 'vault_denied',
  source: 'authorize' | 'sweep',
): Promise<boolean> {
  const error: JobError & { code: typeof code } = { code, message: MESSAGES[code] };
  return ctx.repos.transaction(async (tx) => {
    const now = ctx.clock();
    const failed = await tx.jobs.failQueuedWithoutCapability(job.id, { error, now });
    if (failed === null) return false;
    let connectionReset = false;
    if (job.kind === 'login') {
      try {
        await tx.connections.transitionStatusInternal(job.connectionId, {
          to: 'authentication_required',
          reason: 'The sign-in could not start because the vault was not available.',
        });
        connectionReset = true;
      } catch (caught) {
        // A connection revoked meanwhile stays revoked.
        if (!(caught instanceof InvalidTransitionError)) throw caught;
      }
    }
    await tx.audit.append({
      organizationId: job.organizationId,
      actorType: 'system',
      agentId: job.agentId,
      connectionId: job.connectionId,
      runId: job.runId,
      eventType: job.kind === 'login' ? 'connection.auth_failed' : 'operation.failed',
      decision: 'not_applicable',
      timestamp: now,
      metadata: {
        jobId: job.id,
        operation: job.operation,
        status: 'failed',
        errorCode: code,
        source,
        ...(job.kind === 'login' ? { connectionId: job.connectionId, connectionReset } : {}),
      },
    });
    return true;
  });
}

/**
 * Authorizes a job the caller just committed. Returns `skipped` when no vault is wired,
 * `authorized`, or `failed` (the job is then terminal; read it again for the response).
 */
export async function authorizeNewJob(
  ctx: AppContext,
  log: FastifyBaseLogger,
  job: NewJob,
): Promise<'skipped' | 'authorized' | 'failed'> {
  if (ctx.vault === undefined) return 'skipped';
  const ttl =
    job.kind === 'login'
      ? LOGIN_AUTHORIZATION_TTL_SECONDS
      : ctx.config.vaultAuthorizationTtlSeconds;
  try {
    await ctx.vault.authorizeJobAccess(job.id, ttl);
    return 'authorized';
  } catch (error) {
    const code = failureCodeFor(error);
    log.warn({ jobId: job.id, errorCode: code }, 'job could not be authorized by the vault');
    await failJobForVault(ctx, job, code, 'authorize');
    return 'failed';
  }
}

/** How old a queued job without a capability must be before the sweep ends it (ADR-014 section 5). */
export const SWEEP_AFTER_MS = 60_000;
export const SWEEP_BATCH = 50;

/**
 * Ends queued jobs that have had no capability for more than a minute (the API stopped between
 * the commit and the call). Bounded per run. Returns how many it ended.
 */
export async function sweepUnauthorizedJobs(
  ctx: AppContext,
  log: FastifyBaseLogger,
  olderThanMs = SWEEP_AFTER_MS,
): Promise<number> {
  if (ctx.vault === undefined) return 0;
  const stale = await ctx.repos.jobs.listQueuedWithoutCapability(
    // Age is judged by the database's clock (`created_at < statement_timestamp() - age`), so this
    // host's clock cannot make a young job look old.
    olderThanMs / 1000,
    SWEEP_BATCH,
  );
  let ended = 0;
  for (const job of stale) {
    const done = await failJobForVault(
      ctx,
      {
        id: job.id,
        kind: job.kind,
        organizationId: job.organizationId,
        connectionId: job.connectionId,
        agentId: job.agentId,
        operation: job.operation,
        runId: job.runId,
      },
      'vault_unavailable',
      'sweep',
    );
    if (done) ended += 1;
  }
  if (ended > 0) log.warn({ ended }, 'ended queued jobs the vault never authorized');
  return ended;
}
