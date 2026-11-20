import { DEFAULT_TOKEN_TTL_SECONDS } from '@aab/contracts';
import type { JobErrorCode } from '@aab/contracts';
import { ConflictError } from '@aab/database';
import { jobError } from '../protocol.js';
import { LoginStartError } from '../sandbox/index.js';
import {
  encodeSnapshot,
  filterStorageState,
  isEmptyStorageState,
  sessionExpiry,
} from '../session-store/index.js';
import type { LoginHandle, LoginOutcome } from '../types.js';
import { failureCodeFor } from '../vault/gateway.js';
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
function waitForLoginEvent(
  ctx: JobContext,
  handle: LoginHandle,
  windowMs: number,
): Promise<LoginEvent> {
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
    const timeoutTimer = setTimeout(() => finish('timeout'), windowMs);
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
        attempt: job.attemptCount,
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

  // M1: the capability was authorized when the job was enqueued and its token is issued only
  // after the owner completes, so the window must end while the capability is still alive. Read
  // its expiry (metadata only) and cut the window to what remains less a margin; with too little
  // left, fail before a window opens (code `timeout`: the time to sign in ran out).
  if (job.capabilityRef === null) {
    logger.error({ jobId: job.id }, 'claimed login job has no capability; login refused');
    return failLogin(ctx, 'vault_denied');
  }
  let windowMs = job.timeoutMs;
  try {
    const capability = await repos.capabilities.getAuthorization(job.capabilityRef);
    if (capability === null) return failLogin(ctx, 'vault_denied');
    const remainingMs = new Date(capability.expiresAt).getTime() - ctx.clock().getTime();
    windowMs = Math.min(windowMs, remainingMs - ctx.settings.loginCapabilityMarginMs);
  } catch (error) {
    logger.error({ jobId: job.id, ...errorFacts(error) }, 'capability expiry could not be read');
    return failLogin(ctx, 'worker_failure');
  }
  if (windowMs < ctx.settings.minLoginWindowMs) {
    logger.warn({ jobId: job.id }, 'the login capability expires too soon for a sign-in window');
    return failLogin(ctx, 'timeout');
  }
  windowMs = Math.floor(windowMs);

  let handle: LoginHandle;
  try {
    handle = await ctx.runner.startLogin(
      {
        jobId: job.id,
        connectionId: connection.id,
        adapterId: adapter.id,
        adapterVersion: adapter.version,
        allowedOrigins,
        timeoutMs: windowMs,
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
    const event = await waitForLoginEvent(ctx, handle, windowMs);
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

    // 4. Hand the filtered state to the vault (ADR-014 section 4). The vault checks shape, size and
    // emptiness again, seals the state, activates the connection, records the session, writes
    // `vault.secret_stored` and `connection.auth_completed` (actor system) and completes this job,
    // all in one transaction. The supervisor writes none of that and holds no key (P3-1); it does
    // not add a second, worker-attributed copy of those events. Nothing falls back to sealing
    // locally: a vault that cannot answer or refuses ends the login.
    const expiresAt = sessionExpiry(filtered, ctx.clock());
    let plaintext: string;
    try {
      plaintext = encodeSnapshot(filtered);
    } catch (error) {
      logger.error({ jobId: job.id, ...errorFacts(error) }, 'the login state could not be encoded');
      return failLogin(ctx, 'worker_failure');
    }
    // The captured and filtered states are no longer needed once encoded.
    filtered.cookies.length = 0;
    filtered.origins.length = 0;
    outcome.storageState.cookies.length = 0;
    outcome.storageState.origins.length = 0;
    const capabilityId = job.capabilityRef;
    try {
      const issued = await ctx.vault.call('issueAccessCapability', {
        capabilityId,
        jobId: job.id,
        workerId: ctx.settings.workerId,
        attempt: job.attemptCount,
        ttlSeconds: DEFAULT_TOKEN_TTL_SECONDS,
      });
      await ctx.vault.call('completeLogin', {
        token: issued.token,
        jobId: job.id,
        connectionId: job.connectionId,
        plaintext,
        externalAccountHint: hint,
        sessionExpiresAt: expiresAt === null ? null : expiresAt.toISOString(),
      });
    } catch (error) {
      // Nothing is stored. A completion that committed but whose answer was lost leaves the job
      // `succeeded`; ending it as failed below then finds it no longer held and changes nothing.
      const code = failureCodeFor(error);
      logger.warn(
        { jobId: job.id, errorCode: code, ...errorFacts(error) },
        'the vault did not store the login',
      );
      const latest = await repos.connections.getForExecution(job.connectionId).catch(() => null);
      return failLogin(ctx, latest?.connection.status === 'revoked' ? 'cancelled' : code);
    }
    // The duration and sandbox kind Phase 2 put on `connection.auth_completed` are not in the
    // vault's event (it cannot know them); they are logged here instead (decision in B3b).
    logger.info(
      {
        jobId: job.id,
        status: 'succeeded',
        durationMs: Math.max(0, Date.now() - ctx.startedAtMs),
        sandbox: ctx.runner.sandbox,
      },
      'login job finished',
    );
  } finally {
    await closeWindow();
  }
}
