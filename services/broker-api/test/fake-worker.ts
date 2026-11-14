import type { JobError, JobStatus, JsonObject } from '@aab/contracts';
import type { ExecutionJob, Repositories } from '@aab/database';

/**
 * A test-only stand-in for the browser worker. It uses the repositories directly, the way the
 * real worker does, so tests can drive jobs to every terminal status without a browser.
 */
export class FakeWorker {
  constructor(
    private readonly repos: Repositories,
    readonly workerId = 'fake-worker',
  ) {}

  /** Claims the oldest queued job, or null. */
  claim(now = new Date()): Promise<ExecutionJob | null> {
    return this.repos.jobs.claimNext({ workerId: this.workerId, leaseMs: 60_000, now });
  }

  /** Claims a job and ends it with the given status, writing an outcome audit event. */
  async finishNext(
    status: JobStatus,
    options: { result?: JsonObject; error?: JobError } = {},
  ): Promise<ExecutionJob> {
    const job = await this.claim();
    if (job === null) throw new Error('no queued job to claim');
    return this.finish(job, status, options);
  }

  async finish(
    job: ExecutionJob,
    status: JobStatus,
    options: { result?: JsonObject; error?: JobError } = {},
  ): Promise<ExecutionJob> {
    const eventType =
      status === 'succeeded'
        ? 'operation.succeeded'
        : status === 'reauth_required'
          ? 'operation.reauth_required'
          : status === 'denied'
            ? 'operation.denied'
            : 'operation.failed';
    const event = await this.repos.audit.append({
      organizationId: job.organizationId,
      actorType: 'worker',
      agentId: job.agentId,
      connectionId: job.connectionId,
      eventType,
      decision: 'not_applicable',
      metadata: { jobId: job.id, status },
    });
    return this.repos.jobs.complete(job.id, this.workerId, {
      status,
      result: options.result ?? null,
      error: options.error ?? null,
      auditEventId: event.id,
      now: new Date(),
    });
  }

  /**
   * Ends the login handoff the way the real worker does: the connection becomes `active`
   * (recording the session) or goes back to `authentication_required`, then the job ends.
   */
  async completeLogin(
    job: ExecutionJob,
    outcome: 'active' | 'failed',
    reason = 'The sign-in was not completed.',
  ): Promise<ExecutionJob> {
    if (outcome === 'active') {
      await this.repos.connections.transitionStatusInternal(job.connectionId, { to: 'active' });
      await this.repos.connections.recordSession(job.connectionId, {
        externalAccountHint: 'n***@example.test',
        sessionExpiresAt: new Date(Date.now() + 3_600_000),
        lastVerifiedAt: new Date(),
      });
    } else {
      await this.repos.connections.transitionStatusInternal(job.connectionId, {
        to: 'authentication_required',
        reason,
      });
    }
    return this.repos.jobs.complete(job.id, this.workerId, {
      status: outcome === 'active' ? 'succeeded' : 'failed',
      error: outcome === 'active' ? null : { code: 'login_not_completed', message: reason },
      now: new Date(),
    });
  }
}
