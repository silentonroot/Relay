import { SESSION_SNAPSHOT_SECRET_TYPE } from '@aab/contracts';
import type { AuditEventType } from '@aab/contracts';
import type { Repositories } from '@aab/database';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { jobError } from '../../src/protocol.js';
import { createSupervisor, OPERATION_REASONS } from '../../src/supervisor/index.js';
import type { OperationJobOutcome } from '../../src/types.js';
import {
  activeConnection,
  APP_ORIGIN,
  auditEvents,
  captureLogger,
  CDN_ORIGIN,
  createWorld,
  dumpTables,
  FakeRunner,
  OTHER_ORIGIN,
  queueOperation,
  registerApplication,
  stateWith,
  testKek,
  testRegistry,
  waitFor,
} from './helpers.js';
import type { World } from './helpers.js';

const COOKIE_CANARY = 'cookie-canary-5b1e2d';
const RESULT_CANARY = 'result-canary-9c4f7a';

describe('operation jobs', () => {
  let world: World;
  let kek: ReturnType<typeof testKek>;
  let runner: FakeRunner;
  let log: ReturnType<typeof captureLogger>;

  beforeEach(async () => {
    world = await createWorld();
    kek = testKek();
    runner = new FakeRunner();
    log = captureLogger();
  });
  afterEach(async () => {
    await world.close();
  });

  function supervisor(repos: Repositories = world.repos, extra: { kek?: typeof kek } = {}) {
    return createSupervisor({
      repos,
      runner,
      kek: extra.kek ?? kek,
      adapters: testRegistry(),
      logger: log.logger,
      settings: { workerId: 'worker-test', leaseMs: 5_000, heartbeatMs: 40, loginPollMs: 20 },
    });
  }

  async function runOnce(repos: Repositories = world.repos, extra: { kek?: typeof kek } = {}) {
    const sup = supervisor(repos, extra);
    const started = await sup.tick();
    await sup.idle();
    return started;
  }

  const eventTypes = async () => (await auditEvents(world)).map((event) => event.eventType);
  const job = async (id: string) => (await world.repos.jobs.getInternal(id))!;
  const connectionOf = async (id: string) => (await world.repos.connections.get(world.scope, id))!;

  it('runs an allowed read operation with the stored snapshot and records the outcome', async () => {
    const connection = await activeConnection(world, kek, { state: stateWith(COOKIE_CANARY) });
    const jobId = await queueOperation(world, connection.id);
    let readAuditedBeforeRun = false;
    runner.operation = async () => {
      readAuditedBeforeRun = (await eventTypes()).includes('vault.secret_read');
      return { status: 'succeeded', data: { items: ['a', 'b'], note: RESULT_CANARY } };
    };

    expect(await runOnce()).toEqual([jobId]);

    expect(readAuditedBeforeRun).toBe(true);
    expect(runner.operationCalls).toHaveLength(1);
    const spec = runner.operationCalls[0]!;
    expect(spec).toMatchObject({
      jobId,
      connectionId: connection.id,
      adapterId: 'test-app',
      adapterVersion: '1.0.0',
      allowedOrigins: [APP_ORIGIN, CDN_ORIGIN],
      operation: 'orders.list',
      arguments: { limit: 5 },
      expectedAccountHint: 'user@example.test',
      timeoutMs: 30_000,
    });
    expect(spec.storageState).toEqual(stateWith(COOKIE_CANARY));

    const finished = await job(jobId);
    expect(finished.status).toBe('succeeded');
    expect(finished.result).toEqual({ items: ['a', 'b'], note: RESULT_CANARY });

    const events = await auditEvents(world);
    const outcome = events.find((event) => event.eventType === 'operation.succeeded')!;
    expect(finished.auditEventId).toBe(outcome.id);
    expect(outcome.actorType).toBe('worker');
    expect(outcome.metadata).toMatchObject({
      jobId,
      operation: 'orders.list',
      status: 'succeeded',
      errorCode: null,
      attempt: 1,
      sandbox: 'unsafe-process',
      resultKeys: ['items', 'note'],
      resultBytes: expect.any(Number),
    });
    const read = events.find((event) => event.eventType === 'vault.secret_read')!;
    expect(read.metadata).toMatchObject({ jobId, snapshotVersion: 1, keyVersion: 1 });

    // Result values reach the job row only; never the audit trail or the log.
    expect(JSON.stringify(events)).not.toContain(RESULT_CANARY);
    expect(log.lines.join('')).not.toContain(RESULT_CANARY);
    // The cookie value is nowhere at rest and never logged.
    expect(await dumpTables(world)).not.toContain(COOKIE_CANARY);
    expect(log.lines.join('')).not.toContain(COOKIE_CANARY);

    const after = await connectionOf(connection.id);
    expect(after.status).toBe('active');
    expect(new Date(after.lastVerifiedAt!).getTime()).toBeGreaterThanOrEqual(
      new Date(connection.lastVerifiedAt!).getTime(),
    );
    const described = await world.repos.vault.describeForConnection(connection.id);
    expect(described[0]?.lastAccessedAt).not.toBeNull();
  });

  const outcomes: {
    name: string;
    outcome: OperationJobOutcome;
    status: string;
    event: AuditEventType;
    errorCode: string | null;
    connectionStatus: string;
    reason: string | null;
    snapshotKept: boolean;
  }[] = [
    {
      name: 'reauth_required',
      outcome: { status: 'reauth_required' },
      status: 'reauth_required',
      event: 'operation.reauth_required',
      errorCode: 'session_expired',
      connectionStatus: 'expired',
      reason: OPERATION_REASONS.reauthRequired,
      snapshotKept: false,
    },
    {
      name: 'identity_mismatch',
      outcome: { status: 'failed', error: jobError('identity_mismatch') },
      status: 'failed',
      event: 'operation.failed',
      errorCode: 'identity_mismatch',
      connectionStatus: 'reconnect_required',
      reason: OPERATION_REASONS.identityMismatch,
      snapshotKept: false,
    },
    {
      name: 'outcome_unknown',
      outcome: { status: 'outcome_unknown' },
      status: 'outcome_unknown',
      event: 'operation.failed',
      errorCode: 'worker_failure',
      connectionStatus: 'active',
      reason: null,
      snapshotKept: true,
    },
    {
      name: 'failed not_found',
      outcome: { status: 'failed', error: jobError('not_found') },
      status: 'failed',
      event: 'operation.failed',
      errorCode: 'not_found',
      connectionStatus: 'active',
      reason: null,
      snapshotKept: true,
    },
    {
      name: 'failed timeout',
      outcome: { status: 'failed', error: jobError('timeout') },
      status: 'failed',
      event: 'operation.failed',
      errorCode: 'timeout',
      connectionStatus: 'active',
      reason: null,
      snapshotKept: true,
    },
    {
      name: 'failed cancelled',
      outcome: { status: 'failed', error: jobError('cancelled') },
      status: 'cancelled',
      event: 'operation.failed',
      errorCode: 'cancelled',
      connectionStatus: 'active',
      reason: null,
      snapshotKept: true,
    },
  ];

  it.each(outcomes)('maps $name to the job status, audit event and connection', async (c) => {
    const connection = await activeConnection(world, kek);
    const jobId = await queueOperation(world, connection.id);
    runner.operation = async () => c.outcome;
    await runOnce();

    const finished = await job(jobId);
    expect(finished.status).toBe(c.status);
    expect(finished.error?.code ?? null).toBe(c.errorCode);
    expect(finished.result).toBeNull();
    const events = await auditEvents(world);
    const outcome = events.find((event) => event.eventType === c.event)!;
    expect(outcome).toBeDefined();
    expect(finished.auditEventId).toBe(outcome.id);
    expect(outcome.metadata).toMatchObject({ status: c.status, errorCode: c.errorCode });

    const after = await connectionOf(connection.id);
    expect(after.status).toBe(c.connectionStatus);
    if (c.reason !== null) expect(after.statusReason).toBe(c.reason);
    const active = await world.repos.vault.getActive(connection.id, SESSION_SNAPSHOT_SECRET_TYPE);
    expect(active !== null).toBe(c.snapshotKept);
    expect(events.some((event) => event.eventType === 'vault.secret_deleted')).toBe(
      !c.snapshotKept,
    );
  });

  it('tolerates the connection being revoked while the job ran', async () => {
    const connection = await activeConnection(world, kek);
    const jobId = await queueOperation(world, connection.id);
    runner.operation = async () => {
      await world.repos.connections.revoke(world.scope, connection.id);
      return { status: 'reauth_required' };
    };
    await runOnce();
    expect((await job(jobId)).status).toBe('reauth_required');
    expect((await connectionOf(connection.id)).status).toBe('revoked');
  });

  describe('authorization changed between enqueue and run (INV-3)', () => {
    async function expectNotRun(jobId: string, status: string) {
      await runOnce();
      expect(runner.operationCalls).toHaveLength(0);
      expect((await job(jobId)).status).toBe(status);
      const types = await eventTypes();
      expect(types).not.toContain('vault.secret_read');
      return types;
    }

    it('grant revoked: denied', async () => {
      const connection = await activeConnection(world, kek);
      const jobId = await queueOperation(world, connection.id);
      const [grant] = await world.repos.grants.listForEvaluation({
        agentId: world.agentId,
        connectionId: connection.id,
        operation: 'orders.list',
      });
      await world.repos.grants.revoke(world.scope, world.agentId, grant!.id);
      const types = await expectNotRun(jobId, 'denied');
      expect(types).toContain('operation.denied');
      const denied = (await auditEvents(world)).find((e) => e.eventType === 'operation.denied')!;
      expect(denied.decision).toBe('deny');
      expect(denied.metadata).toMatchObject({ reasonCode: 'no_matching_grant' });
    });

    it('agent disabled: denied', async () => {
      const connection = await activeConnection(world, kek);
      const jobId = await queueOperation(world, connection.id);
      await world.repos.agents.disable(world.scope, world.agentId);
      await expectNotRun(jobId, 'denied');
      const denied = (await auditEvents(world)).find((e) => e.eventType === 'operation.denied')!;
      expect(denied.metadata).toMatchObject({ reasonCode: 'agent_not_active' });
    });

    it('connection revoked: cancelled', async () => {
      const connection = await activeConnection(world, kek);
      const jobId = await queueOperation(world, connection.id);
      // Revocation without the API's job cancellation, so the job is still queued.
      await world.repos.connections.revoke(world.scope, connection.id);
      await expectNotRun(jobId, 'cancelled');
    });

    it('connection no longer active: denied', async () => {
      const connection = await activeConnection(world, kek);
      const jobId = await queueOperation(world, connection.id);
      await world.repos.connections.transitionStatus(world.scope, connection.id, {
        to: 'expired',
      });
      await expectNotRun(jobId, 'denied');
    });

    it('a write operation is refused in phase 2 even with an allow grant', async () => {
      const connection = await activeConnection(world, kek, { operation: 'orders.cancel' });
      const jobId = await queueOperation(world, connection.id, { operation: 'orders.cancel' });
      await expectNotRun(jobId, 'denied');
      const denied = (await auditEvents(world)).find((e) => e.eventType === 'operation.denied')!;
      expect(denied.metadata).toMatchObject({ reasonCode: 'operation_not_executable' });
    });
  });

  it('re-validates stored arguments', async () => {
    const connection = await activeConnection(world, kek);
    const jobId = await queueOperation(world, connection.id, { arguments: { limit: 1000 } });
    await runOnce();
    expect(runner.operationCalls).toHaveLength(0);
    expect((await job(jobId)).error?.code).toBe('invalid_arguments');
    expect(await eventTypes()).not.toContain('vault.secret_read');
  });

  it('fails adapter_unavailable for an unknown adapter or one without execute', async () => {
    const unknownApp = await registerApplication(world, {
      adapterId: 'unknown-app',
      allowedOrigins: [APP_ORIGIN],
    });
    const manifestApp = await registerApplication(world, {
      adapterId: 'manifest-only',
      allowedOrigins: [APP_ORIGIN],
    });
    const a = await activeConnection(world, kek, { applicationId: unknownApp });
    const b = await activeConnection(world, kek, { applicationId: manifestApp });
    const jobA = await queueOperation(world, a.id);
    const jobB = await queueOperation(world, b.id);
    await runOnce();
    expect(runner.operationCalls).toHaveLength(0);
    expect((await job(jobA)).error?.code).toBe('adapter_unavailable');
    expect((await job(jobB)).error?.code).toBe('adapter_unavailable');
  });

  describe('origin intersection', () => {
    it('keeps the adapter order', async () => {
      await world.close();
      world = await createWorld({ allowedOrigins: [OTHER_ORIGIN, CDN_ORIGIN, APP_ORIGIN] });
      const connection = await activeConnection(world, kek);
      await queueOperation(world, connection.id);
      await runOnce();
      expect(runner.operationCalls[0]!.allowedOrigins).toEqual([APP_ORIGIN, CDN_ORIGIN]);
    });

    it('is the subset the application allows', async () => {
      await world.close();
      world = await createWorld({ allowedOrigins: [CDN_ORIGIN] });
      const connection = await activeConnection(world, kek);
      await queueOperation(world, connection.id);
      await runOnce();
      expect(runner.operationCalls[0]!.allowedOrigins).toEqual([CDN_ORIGIN]);
    });

    it('fails origin_not_allowed when empty', async () => {
      await world.close();
      world = await createWorld({ allowedOrigins: [OTHER_ORIGIN] });
      const connection = await activeConnection(world, kek);
      const jobId = await queueOperation(world, connection.id);
      await runOnce();
      expect(runner.operationCalls).toHaveLength(0);
      expect((await job(jobId)).error?.code).toBe('origin_not_allowed');
      expect(await eventTypes()).not.toContain('vault.secret_read');
    });
  });

  it('without a snapshot: reauth_required and the runner is not called', async () => {
    const connection = await activeConnection(world, kek, { state: null });
    const jobId = await queueOperation(world, connection.id);
    await runOnce();
    expect(runner.operationCalls).toHaveLength(0);
    expect((await job(jobId)).status).toBe('reauth_required');
    const after = await connectionOf(connection.id);
    expect(after.status).toBe('expired');
    expect(after.statusReason).toBe(OPERATION_REASONS.noSnapshot);
  });

  it('a snapshot that cannot be opened fails worker_failure before anything runs', async () => {
    const connection = await activeConnection(world, kek, { state: stateWith(COOKIE_CANARY) });
    const jobId = await queueOperation(world, connection.id);
    await runOnce(world.repos, { kek: testKek() });
    expect(runner.operationCalls).toHaveLength(0);
    expect((await job(jobId)).error?.code).toBe('worker_failure');
    expect(await eventTypes()).not.toContain('vault.secret_read');
    const logged = log.lines.join('');
    expect(logged).toContain('session snapshot could not be opened');
    expect(logged).not.toContain(COOKIE_CANARY);
    // The snapshot is kept: the key may be fixed by an operator.
    expect((await connectionOf(connection.id)).status).toBe('active');
  });

  it('cancellation while running aborts the runner and ends the job cancelled', async () => {
    const connection = await activeConnection(world, kek);
    const jobId = await queueOperation(world, connection.id);
    let seenAbort = false;
    runner.operation = (_spec, signal) =>
      new Promise((resolve) => {
        signal.addEventListener('abort', () => {
          seenAbort = true;
          resolve({ status: 'failed', error: jobError('cancelled') });
        });
      });
    const sup = supervisor();
    await sup.tick();
    await waitFor(() => runner.operationCalls.length === 1);
    await world.repos.jobs.cancelForConnection(connection.id, new Date());
    await sup.idle();
    expect(seenAbort).toBe(true);
    expect((await job(jobId)).status).toBe('cancelled');
  });

  it('after a restart, snapshots are opened unchanged and never cross connections', async () => {
    const a = await activeConnection(world, kek, { state: stateWith('alpha-value') });
    const b = await activeConnection(world, kek, { state: stateWith('beta-value') });
    const expected = new Map([
      [a.id, stateWith('alpha-value')],
      [b.id, stateWith('beta-value')],
    ]);
    runner.operation = async (spec) => {
      expect(spec.storageState).toEqual(expected.get(spec.connectionId));
      return { status: 'succeeded', data: { items: [] } };
    };

    await queueOperation(world, a.id);
    await runOnce();
    // A new supervisor instance: same database, same key, nothing carried in memory.
    await queueOperation(world, b.id);
    await queueOperation(world, a.id);
    const sup = supervisor();
    await sup.tick();
    await sup.idle();
    await sup.tick();
    await sup.idle();

    expect(runner.operationCalls.map((call) => call.connectionId).sort()).toEqual(
      [a.id, a.id, b.id].sort(),
    );
    for (const call of runner.operationCalls) {
      expect(call.storageState).toEqual(expected.get(call.connectionId));
    }
    const statuses = await Promise.all(
      (await world.repos.audit.list(world.scope, { eventType: 'operation.succeeded' })).items.map(
        (event) => event.metadata['status'],
      ),
    );
    expect(statuses).toEqual(['succeeded', 'succeeded', 'succeeded']);
  });

  it('if recording fails the result is not kept and the job is left to lease recovery (INV-10)', async () => {
    const connection = await activeConnection(world, kek);
    const jobId = await queueOperation(world, connection.id, { retrySafe: false });
    runner.operation = async () => ({ status: 'succeeded', data: { items: [RESULT_CANARY] } });
    const failing = (repos: Repositories): Repositories => ({
      ...repos,
      audit: {
        ...repos.audit,
        append: async (input) => {
          if (input.eventType === 'operation.succeeded') throw new Error('audit store down');
          return repos.audit.append(input);
        },
      },
      transaction: (work) => repos.transaction((tx) => work(failing(tx))),
    });
    await runOnce(failing(world.repos));

    const stuck = await job(jobId);
    expect(stuck.status).toBe('running');
    expect(stuck.result).toBeNull();
    expect(await eventTypes()).not.toContain('operation.succeeded');
    expect(log.lines.join('')).toContain('lease recovery will end the job');
    expect(log.lines.join('')).not.toContain('audit store down');

    const later = createSupervisor({
      repos: world.repos,
      runner,
      kek,
      adapters: testRegistry(),
      logger: log.logger,
      clock: () => new Date(Date.now() + 10 * 60_000),
      settings: { workerId: 'worker-recovery' },
    });
    const report = await later.maintenance();
    expect(report.recovered).toBe(1);
    const recovered = await job(jobId);
    expect(recovered.status).toBe('outcome_unknown');
    expect(recovered.result).toBeNull();
    const failed = (await auditEvents(world)).find((e) => e.eventType === 'operation.failed')!;
    expect(failed.metadata).toMatchObject({ jobId, status: 'outcome_unknown', recovered: true });
  });
});
