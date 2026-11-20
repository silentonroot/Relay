import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { VaultCallError } from '@aab/vault-client';
import { jobError } from '../../src/protocol.js';
import type { SupervisorVault } from '../../src/vault/gateway.js';
import {
  createSupervisor,
  LOGIN_LEASE_EXPIRED_REASON,
  resolveSupervisorSettings,
  SupervisorStartError,
} from '../../src/supervisor/index.js';
import type { SupervisorSettings } from '../../src/supervisor/index.js';
import type { OperationJobOutcome } from '../../src/types.js';
import {
  activeConnection,
  auditEvents,
  captureLogger,
  createWorld,
  deferred,
  FakeRunner,
  loginConnection,
  queueOperation,
  testRegistry,
  waitFor,
} from './helpers.js';
import type { World } from './helpers.js';

describe('supervisor lifecycle', () => {
  let world: World;
  let runner: FakeRunner;
  let log: ReturnType<typeof captureLogger>;

  beforeEach(async () => {
    world = await createWorld();
    runner = new FakeRunner();
    log = captureLogger();
  });
  afterEach(async () => {
    await world.close().catch(() => undefined);
  });

  function supervisor(
    settings: Partial<SupervisorSettings> = {},
    options: { clock?: () => Date } = {},
    vault: SupervisorVault = world.vault,
  ) {
    return createSupervisor({
      repos: world.repos,
      runner,
      vault,
      adapters: testRegistry(),
      logger: log.logger,
      ...(options.clock === undefined ? {} : { clock: options.clock }),
      settings: {
        workerId: 'worker-test',
        leaseMs: 5_000,
        heartbeatMs: 40,
        loginPollMs: 20,
        pollIntervalMs: 50,
        ...settings,
      },
    });
  }

  const job = async (id: string) => (await world.repos.jobs.getInternal(id))!;

  /** Claims every queued job as a dead worker whose lease has already run out. */
  async function claimAsDeadWorker(): Promise<void> {
    const past = new Date(Date.now() - 60 * 60_000);
    while (await world.repos.jobs.claimNext({ workerId: 'dead-worker', leaseMs: 1, now: past })) {
      // keep claiming
    }
  }

  describe('start-up', () => {
    it('refuses when the sandbox self-check fails', async () => {
      runner.selfCheckError = new Error('bwrap is not installed');
      const error = await supervisor()
        .start()
        .catch((e: unknown) => e);
      expect(error).toBeInstanceOf(SupervisorStartError);
      expect((error as Error).message).toContain('sandbox self-check failed');
    });

    it('refuses when the database does not answer', async () => {
      await world.close();
      const error = await supervisor()
        .start()
        .catch((e: unknown) => e);
      expect(error).toBeInstanceOf(SupervisorStartError);
      expect((error as Error).message).toContain('database did not answer');
    });

    it('recovers expired leases once, then runs queued jobs from its loop', async () => {
      const stale = await activeConnection(world);
      const staleJob = await queueOperation(world, stale.id, { retrySafe: false });
      await claimAsDeadWorker();
      const fresh = await activeConnection(world);
      const freshJob = await queueOperation(world, fresh.id);

      const sup = supervisor();
      await sup.start();
      expect((await job(staleJob)).status).toBe('outcome_unknown');
      await waitFor(async () => (await job(freshJob)).status === 'succeeded');
      await sup.stop();
      await expect(sup.start()).rejects.toBeInstanceOf(SupervisorStartError);
    });
  });

  it('claims only jobs the API authorized with the vault (requireCapability)', async () => {
    const connection = await activeConnection(world);
    const unauthorized = await queueOperation(world, connection.id, { authorize: false });
    const sup = supervisor();
    expect(await sup.tick()).toEqual([]);
    expect((await job(unauthorized)).status).toBe('queued');
    expect(runner.operationCalls).toHaveLength(0);
    // Once authorized it is claimed and runs.
    await world.authorize(unauthorized);
    expect(await sup.tick()).toEqual([unauthorized]);
    await sup.idle();
    expect((await job(unauthorized)).status).toBe('succeeded');
  });

  describe('a stale handler of an earlier attempt (M2)', () => {
    /** The vault refuses the first token request, but only after `release()`. */
    function gatedVault() {
      const gate = deferred<void>();
      const vault: SupervisorVault = {
        isolation: world.vault.isolation,
        check: () => world.vault.check(),
        async call(operation, params) {
          if (operation === 'issueAccessCapability') {
            await gate.promise;
            throw new VaultCallError('denied', 'forbidden');
          }
          return world.vault.call(operation, params);
        },
      };
      return { vault, release: () => gate.resolve() };
    }

    /** Claims attempt 1, lets its lease expire, requeues it and claims attempt 2 as the same worker. */
    async function secondAttempt(settings: Partial<SupervisorSettings> = {}) {
      const connection = await activeConnection(world);
      const jobId = await queueOperation(world, connection.id);
      const { vault, release } = gatedVault();
      // No heartbeat during the test: the stale handler learns nothing about its lease.
      const sup = supervisor({ leaseMs: 60_000, heartbeatMs: 30_000, ...settings }, {}, vault);
      expect(await sup.tick()).toEqual([jobId]);
      await waitFor(async () => (await job(jobId)).status === 'running');
      await world.repos.jobs.recoverExpiredLeases({
        now: new Date(Date.now() + 2 * 60 * 60_000),
        maxAttempts: 3,
        capabilityAware: true,
      });
      expect((await job(jobId)).status).toBe('queued');
      return { jobId, sup, release };
    }

    it('a vault refusal in the stale handler does not end the next attempt', async () => {
      const { jobId, sup, release } = await secondAttempt();
      // Attempt 2, same worker id, claimed by another tick of the same worker (not this supervisor).
      const next = await world.repos.jobs.claimNext({
        workerId: 'worker-test',
        leaseMs: 60_000,
        now: new Date(),
        requireCapability: true,
      });
      expect(next?.attemptCount).toBe(2);
      release();
      await sup.idle();
      const after = await job(jobId);
      expect(after.status).toBe('running');
      expect(after.attemptCount).toBe(2);
      expect(after.error).toBeNull();
      expect((await auditEvents(world)).map((e) => e.eventType)).not.toContain('operation.failed');
    });

    it('extending or completing needs the right attempt', async () => {
      const { jobId, sup, release } = await secondAttempt();
      await world.repos.jobs.claimNext({
        workerId: 'worker-test',
        leaseMs: 60_000,
        now: new Date(),
        requireCapability: true,
      });
      expect(await world.repos.jobs.extendLease(jobId, 'worker-test', 60_000, new Date(), 1)).toBe(
        false,
      );
      expect(await world.repos.jobs.extendLease(jobId, 'worker-test', 60_000, new Date(), 2)).toBe(
        true,
      );
      release();
      await sup.idle();
    });

    it('does not start a second handler for a job id that is still winding down', async () => {
      const { jobId, sup, release } = await secondAttempt();
      expect(await sup.tick()).toEqual([]);
      expect(log.lines.join('')).toContain('claimed again');
      expect(sup.runningJobIds()).toEqual([jobId]);
      release();
      await sup.idle();
      expect(sup.runningJobIds()).toEqual([]);
    });
  });

  it('runs at most `concurrency` jobs at once', async () => {
    const release = deferred<void>();
    let concurrent = 0;
    let peak = 0;
    runner.operation = async (): Promise<OperationJobOutcome> => {
      concurrent += 1;
      peak = Math.max(peak, concurrent);
      await release.promise;
      concurrent -= 1;
      return { status: 'succeeded', data: { items: [] } };
    };
    const ids: string[] = [];
    for (let index = 0; index < 3; index += 1) {
      const connection = await activeConnection(world);
      ids.push(await queueOperation(world, connection.id));
    }
    const sup = supervisor({ concurrency: 2 });
    expect(await sup.tick()).toHaveLength(2);
    expect(await sup.tick()).toHaveLength(0);
    await waitFor(() => runner.operationCalls.length === 2);
    expect(sup.runningJobIds()).toHaveLength(2);
    release.resolve();
    await sup.idle();
    expect(await sup.tick()).toHaveLength(1);
    await sup.idle();
    expect(peak).toBe(2);
    for (const id of ids) expect((await job(id)).status).toBe('succeeded');
  });

  it('aborts a job whose lease was lost and records nothing over recovery', async () => {
    const connection = await activeConnection(world);
    const jobId = await queueOperation(world, connection.id);
    let aborted = false;
    runner.operation = (_spec, signal) =>
      new Promise((resolve) => {
        signal.addEventListener('abort', () => {
          aborted = true;
          resolve({ status: 'failed', error: jobError('cancelled') });
        });
      });
    const sup = supervisor();
    await sup.tick();
    await waitFor(() => runner.operationCalls.length === 1);
    // Another process decided the lease had expired.
    await world.repos.jobs.recoverExpiredLeases({
      now: new Date(Date.now() + 60 * 60_000),
      maxAttempts: 3,
      capabilityAware: true,
    });
    await sup.idle();
    expect(aborted).toBe(true);
    // The vault had issued the token, so recovery ended the job instead of requeueing it (a retry
    // never inherits an issued token); this worker did not overwrite that.
    const after = await job(jobId);
    expect(after.status).toBe('failed');
    expect(after.error?.code).toBe('worker_failure');
    expect((await auditEvents(world)).map((e) => e.eventType)).not.toContain('operation.failed');
    expect(log.lines.join('')).toContain('lease lost');
  });

  it('keeps extending the lease while a job runs', async () => {
    const connection = await activeConnection(world);
    const jobId = await queueOperation(world, connection.id);
    const release = deferred<void>();
    runner.operation = async () => {
      await release.promise;
      return { status: 'succeeded', data: { items: [] } };
    };
    const sup = supervisor({ leaseMs: 300, heartbeatMs: 40 });
    await sup.tick();
    await waitFor(() => runner.operationCalls.length === 1);
    const first = (await job(jobId)).leaseExpiresAt!;
    await new Promise((resolve) => setTimeout(resolve, 500));
    const later = (await job(jobId)).leaseExpiresAt!;
    expect(new Date(later).getTime()).toBeGreaterThan(new Date(first).getTime());
    expect(new Date(later).getTime()).toBeGreaterThan(Date.now());
    release.resolve();
    await sup.idle();
    expect((await job(jobId)).status).toBe('succeeded');
  });

  it('shutdown mid-operation aborts the runner and records the job cancelled', async () => {
    const connection = await activeConnection(world);
    const jobId = await queueOperation(world, connection.id);
    runner.operation = (_spec, signal) =>
      new Promise((resolve) => {
        signal.addEventListener('abort', () =>
          resolve({ status: 'failed', error: jobError('cancelled') }),
        );
      });
    const sup = supervisor();
    await sup.start();
    await waitFor(() => runner.operationCalls.length === 1);
    await sup.stop();
    expect(sup.runningJobIds()).toEqual([]);
    expect((await job(jobId)).status).toBe('cancelled');
    const failed = (await auditEvents(world)).find((e) => e.eventType === 'operation.failed')!;
    expect(failed.metadata).toMatchObject({ jobId, status: 'cancelled', errorCode: 'cancelled' });
    // A stopped supervisor claims nothing.
    const other = await activeConnection(world);
    await queueOperation(world, other.id);
    expect(await sup.tick()).toEqual([]);
  });

  describe('maintenance', () => {
    it('ends expired jobs with an audit event and resets a login connection', async () => {
      const opConnection = await activeConnection(world);
      const unsafeJob = await queueOperation(world, opConnection.id, { retrySafe: false });
      const { connection: loginConn, jobId: loginJob } = await loginConnection(world);
      await claimAsDeadWorker();

      const report = await supervisor().maintenance();
      expect(report).toMatchObject({ recovered: 2, requeued: 0 });

      expect((await job(unsafeJob)).status).toBe('outcome_unknown');
      expect((await job(loginJob)).status).toBe('failed');
      const connection = (await world.repos.connections.get(world.scope, loginConn.id))!;
      expect(connection.status).toBe('authentication_required');
      expect(connection.statusReason).toBe(LOGIN_LEASE_EXPIRED_REASON);

      const events = await auditEvents(world);
      const opEvent = events.find((e) => e.eventType === 'operation.failed')!;
      expect(opEvent.metadata).toMatchObject({
        jobId: unsafeJob,
        status: 'outcome_unknown',
        recovered: true,
      });
      const loginEvent = events.find((e) => e.eventType === 'connection.auth_failed')!;
      expect(loginEvent.metadata).toMatchObject({
        jobId: loginJob,
        status: 'failed',
        errorCode: 'worker_failure',
        connectionReset: true,
      });
    });

    it('requeues a retry-safe operation without an audit event', async () => {
      const connection = await activeConnection(world);
      const jobId = await queueOperation(world, connection.id, { retrySafe: true });
      await claimAsDeadWorker();
      const report = await supervisor().maintenance();
      expect(report).toMatchObject({ recovered: 0, requeued: 1 });
      expect((await job(jobId)).status).toBe('queued');
      expect((await auditEvents(world)).map((e) => e.eventType)).not.toContain('operation.failed');
    });

    it('does not requeue a retry-safe operation whose token was already issued (capabilityAware)', async () => {
      const connection = await activeConnection(world);
      const jobId = await queueOperation(world, connection.id, { retrySafe: true });
      await claimAsDeadWorker();
      // The dead worker got as far as a token: the session may have been handed out.
      const claimed = await job(jobId);
      const issued = await world.service.rpc('supervisor', 'issueAccessCapability', {
        capabilityId: claimed.capabilityRef,
        jobId,
        workerId: 'dead-worker',
        attempt: claimed.attemptCount,
        ttlSeconds: 30,
      });
      expect(issued['ok']).toBe(true);

      const report = await supervisor().maintenance();
      expect(report).toMatchObject({ recovered: 1, requeued: 0 });
      const after = await job(jobId);
      expect(after.status).toBe('failed');
      expect(after.error?.code).toBe('worker_failure');
    });

    it('purges results older than the TTL', async () => {
      const connection = await activeConnection(world);
      const jobId = await queueOperation(world, connection.id);
      const sup = supervisor();
      await sup.tick();
      await sup.idle();
      expect((await job(jobId)).result).not.toBeNull();

      expect((await supervisor({ resultTtlMinutes: 60 }).maintenance()).purgedResults).toBe(0);
      const later = supervisor(
        { resultTtlMinutes: 60 },
        { clock: () => new Date(Date.now() + 61 * 60_000) },
      );
      expect((await later.maintenance()).purgedResults).toBe(1);
      const purged = await job(jobId);
      expect(purged.result).toBeNull();
      expect(purged.resultPurgedAt).not.toBeNull();
    });
  });

  it('validates its settings', () => {
    expect(resolveSupervisorSettings({ workerId: 'w' })).toMatchObject({
      workerId: 'w',
      concurrency: 2,
      leaseMs: 60_000,
      heartbeatMs: 20_000,
      resultTtlMinutes: 60,
    });
    expect(() => resolveSupervisorSettings({ concurrency: 0 })).toThrow(/concurrency/);
    expect(() => resolveSupervisorSettings({ leaseMs: 100, heartbeatMs: 100 })).toThrow(
      /heartbeatMs/,
    );
  });
});
