import type { JobErrorCode } from '@aab/contracts';
import { ConflictError } from '@aab/database';
import { jobError } from '../protocol.js';
import { LoginStartError } from '../sandbox/index.js';
import {
  filterStorageState,
  isEmptyStorageState,
  sessionExpiry,
  storeSnapshot,
} from '../session-store/index.js';
import type { LoginHandle, LoginOutcome } from '../types.js';
import { errorFacts, intersectOrigins } from './context.js';
import type { JobContext } from './context.js';
import { auditAsWorker, LOGIN_FAILURE_REASONS, transitionIfAllowed } from './records.js';

type LoginEvent = 'complete' | 'cancel' | 'closed' | 'timeout' | 'stopped';

/** Same normalization `connections.recordSession` applies before storing a hint. */
function normalizeHint(hint: string | null): string | null {
  const trimmed = hint?.trim().slice(0, 120);
  return trimmed ? trimmed : null;
}

/**
 * Waits for whichever comes first: the owner's completion request, a cancel request or
 * revocation, the window closing, the job timeout, or a stop (shutdown, lease loss, cancel
 * seen by the heartbeat). The lease is extended by the supervisor's heartbeat meanwhile.
 */
function waitForLoginEvent(ctx: JobContext, handle: LoginHandle): Promise<LoginEvent> {
  return new Promise<LoginEvent>((resolve) => {
    let settled = false;
    let pollTimer: NodeJS.Timeout | undefined;
    const finish = (event: LoginEvent) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeoutTimer);
      clearTimeout(pollTimer);
      ctx.signal.removeEventListener('abort', onAbort);
      resolve(event);
    };
    const onAbort = () => finish('stopped');
    const timeoutTimer = setTimeout(() => finish('timeout'), ctx.job.timeoutMs);
    ctx.signal.addEventListener('abort', onAbort, { once: true });
    if (ctx.signal.aborted) finish('stopped');
    handle.closed.then(
      () => finish('closed'),
      () => finish('closed'),
    );

    const poll = async () => {
      if (settled) return;
      try {
        const fresh = await ctx.repos.jobs.getInternal(ctx.job.id);
        if (fresh === null || fresh.cancelRequestedAt !== null) return finish('cancel');
        const target = await ctx.repos.connections.getForExecution(ctx.job.connectionId);
        if (target === null || target.connection.status === 'revoked') return finish('cancel');
        if (fresh.completionRequestedAt !== null) return finish('complete');
      } catch (error) {
        ctx.logger.warn({ jobId: ctx.job.id, ...errorFacts(error) }, 'login poll failed');
      }
      if (!settled) pollTimer = setTimeout(() => void poll(), ctx.settings.loginPollMs);
    };
    void poll();
  });
}

/**
 * Ends a login job without storing anything: job failed (or cancelled), connection back to
 * `authentication_required` with a reason, `connection.auth_failed` audited, in one
 * transaction. A connection revoked meanwhile stays revoked.
 */
async function failLogin(ctx: JobContext, code: JobErrorCode): Promise<void> {
  const { job, repos, logger } = ctx;
  if (ctx.stopReason() === 'lease_lost') {
    logger.warn({ jobId: job.id }, 'lease lost; login job abandoned');
    return;
  }
  const status = code === 'cancelled' ? 'cancelled' : 'failed';
  const now = ctx.clock();
  try {
    await repos.transaction(async (tx) => {
      const moved = await transitionIfAllowed(
        tx,
        job.connectionId,
        'authentication_required',
        LOGIN_FAILURE_REASONS[code],
      );
      const event = await auditAsWorker(tx, job, now, {
        eventType: 'connection.auth_failed',
        metadata: {
          jobId: job.id,
          connectionId: job.connectionId,
          status,
          errorCode: code,
          connectionReset: moved,
          durationMs: Math.max(0, Date.now() - ctx.startedAtMs),
          sandbox: ctx.runner.sandbox,
        },
      });
      await tx.jobs.complete(job.id, ctx.settings.workerId, {
        status,
        error: jobError(code),
        auditEventId: event.id,
        now,
      });
    });
    logger.info({ jobId: job.id, status, errorCode: code }, 'login job finished');
  } catch (error) {
    if (error instanceof ConflictError) {
      logger.warn({ jobId: job.id }, 'login job is no longer held by this worker');
    } else {
      logger.error(
        { jobId: job.id, ...errorFacts(error) },
        'login failure could not be recorded; lease recovery will end the job',
      );
    }
  }
}

function stopCode(ctx: JobContext): JobErrorCode {
  return ctx.stopReason() === 'shutdown' || ctx.stopReason() === 'cancelled'
    ? 'cancelled'
    : 'worker_failure';
}

export async function runLoginJob(ctx: JobContext): Promise<void> {
  const { job, repos, logger } = ctx;

  // 1. Connection, adapter, origins.
  const target = await repos.connections.getForExecution(job.connectionId);
  if (target === null) return failLogin(ctx, 'worker_failure');
  const { connection, application } = target;
  if (job.cancelRequestedAt !== null || connection.status === 'revoked') {
    return failLogin(ctx, 'cancelled');
  }
  if (connection.status !== 'authenticating') return failLogin(ctx, 'worker_failure');
  const adapter = ctx.adapters.get(application.adapterId, application.adapterVersion);
  if (
    adapter === undefined ||
    adapter.loginPath === undefined ||
    adapter.checkSession === undefined
  ) {
    return failLogin(ctx, 'adapter_unavailable');
  }
  const allowedOrigins = intersectOrigins(adapter, application);
  if (allowedOrigins.length === 0) return failLogin(ctx, 'origin_not_allowed');
  if (ctx.signal.aborted) return failLogin(ctx, stopCode(ctx));

  let handle: LoginHandle;
  try {
    handle = await ctx.runner.startLogin(
      {
        jobId: job.id,
        connectionId: connection.id,
        adapterId: adapter.id,
        adapterVersion: adapter.version,
        allowedOrigins,
        timeoutMs: job.timeoutMs,
      },
      ctx.signal,
    );
  } catch (error) {
    const code = error instanceof LoginStartError ? error.code : 'worker_failure';
    logger.warn({ jobId: job.id, errorCode: code }, 'login window could not be opened');
    return failLogin(ctx, code);
  }

  let finished = false;
  const closeWindow = async () => {
    if (finished) return;
    finished = true;
    await handle.cancel().catch(() => undefined);
  };

  try {
    // 2. Wait for the owner.
    const event = await waitForLoginEvent(ctx, handle);
    if (event !== 'complete') {
      await closeWindow();
      const code: JobErrorCode =
        event === 'closed'
          ? 'login_window_closed'
          : event === 'timeout'
            ? 'timeout'
            : event === 'cancel'
              ? 'cancelled'
              : stopCode(ctx);
      return failLogin(ctx, code);
    }

    // 3. Capture.
    let outcome: LoginOutcome;
    try {
      finished = true;
      outcome = await handle.complete();
    } catch (error) {
      logger.error({ jobId: job.id, ...errorFacts(error) }, 'login completion threw');
      finished = false;
      return failLogin(ctx, 'worker_failure');
    }
    if (outcome.status === 'failed') return failLogin(ctx, outcome.error.code);

    const filtered = filterStorageState(outcome.storageState, allowedOrigins);
    if (isEmptyStorageState(filtered)) return failLogin(ctx, 'login_not_completed');

    const fresh = await repos.connections.getForExecution(job.connectionId);
    if (fresh === null) return failLogin(ctx, 'worker_failure');
    if (fresh.connection.status === 'revoked') return failLogin(ctx, 'cancelled');
    if (fresh.connection.status !== 'authenticating') return failLogin(ctx, 'worker_failure');
    const hint = normalizeHint(outcome.externalAccountHint);
    // A verified connection must not silently become a different account.
    if (
      fresh.connection.lastVerifiedAt !== null &&
      normalizeHint(fresh.connection.externalAccountHint) !== hint
    ) {
      return failLogin(ctx, 'identity_mismatch');
    }
    if (ctx.signal.aborted) return failLogin(ctx, stopCode(ctx));

    // 4. Store, activate and record in one transaction.
    const now = ctx.clock();
    const expiresAt = sessionExpiry(filtered);
    try {
      await repos.transaction(async (tx) => {
        const stored = await storeSnapshot(tx, {
          connection: fresh.connection,
          storageState: filtered,
          kek: ctx.kek,
          now,
        });
        await tx.connections.transitionStatusInternal(job.connectionId, { to: 'active' });
        await tx.connections.recordSession(job.connectionId, {
          externalAccountHint: hint,
          sessionExpiresAt: expiresAt,
          lastVerifiedAt: now,
        });
        await auditAsWorker(tx, job, now, {
          eventType: 'vault.secret_stored',
          metadata: {
            jobId: job.id,
            connectionId: job.connectionId,
            vaultEntryId: stored.vaultEntryId,
            snapshotVersion: stored.version,
            keyVersion: stored.kekVersion,
            originCount: allowedOrigins.length,
          },
        });
        const event = await auditAsWorker(tx, job, now, {
          eventType: 'connection.auth_completed',
          metadata: {
            jobId: job.id,
            connectionId: job.connectionId,
            adapterId: adapter.id,
            adapterVersion: adapter.version,
            accountHintRecorded: hint !== null,
            sessionExpiresAt: expiresAt === null ? null : expiresAt.toISOString(),
            durationMs: Math.max(0, Date.now() - ctx.startedAtMs),
            sandbox: ctx.runner.sandbox,
          },
        });
        await tx.jobs.complete(job.id, ctx.settings.workerId, {
          status: 'succeeded',
          auditEventId: event.id,
          now,
        });
      });
      logger.info({ jobId: job.id, status: 'succeeded' }, 'login job finished');
    } catch (error) {
      // Everything above rolled back: nothing is stored.
      if (error instanceof ConflictError && ctx.stopReason() === 'lease_lost') {
        logger.warn({ jobId: job.id }, 'lease lost; login result discarded');
        return;
      }
      logger.error({ jobId: job.id, ...errorFacts(error) }, 'login result could not be stored');
      const latest = await repos.connections.getForExecution(job.connectionId).catch(() => null);
      return failLogin(
        ctx,
        latest?.connection.status === 'revoked' ? 'cancelled' : 'worker_failure',
      );
    }
  } finally {
    await closeWindow();
  }
}
