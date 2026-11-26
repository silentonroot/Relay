import { randomUUID } from 'node:crypto';
import { SESSION_SNAPSHOT_SECRET_TYPE } from '@aab/contracts';
import type { AuditEventType, JsonObject } from '@aab/contracts';
import { hashJobArguments } from '@aab/database';
import type { Repositories } from '@aab/database';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { jobError } from '../../src/protocol.js';
import {
  ARGUMENTS_CHANGED_BY_POLICY,
  ARGUMENTS_HASH_MISMATCH,
  createSupervisor,
  OPERATION_REASONS,
} from '../../src/supervisor/index.js';
import type { OperationJobOutcome, StorageState } from '../../src/types.js';
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
  testRegistry,
  waitFor,
} from './helpers.js';
import type { World } from './helpers.js';

const COOKIE_CANARY = 'cookie-canary-5b1e2d';
const RESULT_CANARY = 'result-canary-9c4f7a';

describe('operation jobs', () => {
  let world: World;
  let runner: FakeRunner;
  let log: ReturnType<typeof captureLogger>;

  beforeEach(async () => {
    world = await createWorld();
    runner = new FakeRunner();
    log = captureLogger();
  });
  afterEach(async () => {
    await world.close();
  });

  function supervisor(repos: Repositories = world.repos) {
    return createSupervisor({
      repos,
      runner,
      vault: world.vault,
      adapters: testRegistry(),
      logger: log.logger,
      settings: { workerId: 'worker-test', leaseMs: 5_000, heartbeatMs: 40, loginPollMs: 20 },
    });
  }

  async function runOnce(repos: Repositories = world.repos) {
    const sup = supervisor(repos);
    const started = await sup.tick();
    await sup.idle();
    return started;
  }

  const eventTypes = async () => (await auditEvents(world)).map((event) => event.eventType);
  const job = async (id: string) => (await world.repos.jobs.getInternal(id))!;
  const connectionOf = async (id: string) => (await world.repos.connections.get(world.scope, id))!;

  it('runs an allowed read operation with the stored snapshot and records the outcome', async () => {
    const connection = await activeConnection(world, { state: stateWith(COOKIE_CANARY) });
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
    // The vault wrote the read (ADR-014 section 10: actor system); the supervisor wrote none.
    const reads = events.filter((event) => event.eventType === 'vault.secret_read');
    expect(reads).toHaveLength(1);
    expect(reads[0]!.actorType).toBe('system');
    expect(reads[0]!.metadata).toMatchObject({ jobId, entryVersion: 1, keyVersion: 1 });

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
    const connection = await activeConnection(world);
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
    const connection = await activeConnection(world);
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
      const connection = await activeConnection(world);
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
      const connection = await activeConnection(world);
      const jobId = await queueOperation(world, connection.id);
      await world.repos.agents.disable(world.scope, world.agentId);
      await expectNotRun(jobId, 'denied');
      const denied = (await auditEvents(world)).find((e) => e.eventType === 'operation.denied')!;
      expect(denied.metadata).toMatchObject({ reasonCode: 'agent_not_active' });
    });

    it('connection revoked: cancelled', async () => {
      const connection = await activeConnection(world);
      const jobId = await queueOperation(world, connection.id);
      // Revocation without the API's job cancellation, so the job is still queued.
      await world.repos.connections.revoke(world.scope, connection.id);
      await expectNotRun(jobId, 'cancelled');
    });

    it('connection no longer active: denied', async () => {
      const connection = await activeConnection(world);
      const jobId = await queueOperation(world, connection.id);
      await world.repos.connections.transitionStatus(world.scope, connection.id, {
        to: 'expired',
      });
      await expectNotRun(jobId, 'denied');
    });

    it('a write is refused in phase 2 even with an allow grant: policy answers approval_required', async () => {
      // The read test at the top of this file is the positive control for this world.
      const connection = await activeConnection(world, { operation: 'orders.cancel' });
      const jobId = await queueOperation(world, connection.id, {
        operation: 'orders.cancel',
        arguments: { orderId: 'order-1', expectedVersion: 1 },
      });
      await expectNotRun(jobId, 'denied');
      const denied = (await auditEvents(world)).find(
        (e) =>
          e.eventType === 'operation.denied' && e.metadata.policyOutcome === 'approval_required',
      )!;
      expect(denied.metadata).toMatchObject({ reasonCode: 'approval_required' });
    });
  });

  it('re-validates stored arguments', async () => {
    const connection = await activeConnection(world);
    const jobId = await queueOperation(world, connection.id, { arguments: { limit: 1000 } });
    await runOnce();
    expect(runner.operationCalls).toHaveLength(0);
    expect((await job(jobId)).error?.code).toBe('invalid_arguments');
    expect(await eventTypes()).not.toContain('vault.secret_read');
  });

  describe('the job row changed after the decision (PE-14, P3-17)', () => {
    /** A direct write to the job row, as a database writer outside the broker would make it. */
    const editRow = (jobId: string, assignments: string) =>
      world.handle.db.execute(`update execution_jobs set ${assignments} where id = '${jobId}'`);

    /** The hash of the row as stored, but with other arguments: what a careless forger writes. */
    const hashWith = async (jobId: string, args: JsonObject) => {
      const row = await job(jobId);
      return hashJobArguments({
        organizationId: row.organizationId,
        agentId: row.agentId!,
        connectionId: row.connectionId,
        operation: row.operation!,
        arguments: args,
        policyDecisionId: row.policyDecisionId,
        timeoutMs: row.timeoutMs,
        retrySafe: row.retrySafe,
      });
    };

    async function expectRefused(jobId: string) {
      await runOnce();
      // The runner is what starts a sandbox; it is never called.
      expect(runner.operationCalls).toHaveLength(0);
      const finished = await job(jobId);
      expect(finished.status).toBe('denied');
      expect(finished.error?.code).toBe('denied');
      expect(finished.result).toBeNull();
      const events = await auditEvents(world);
      const types = events.map((event) => event.eventType);
      expect(types).not.toContain('vault.secret_read');
      const denied = events.filter((event) => event.eventType === 'operation.denied');
      expect(denied).toHaveLength(1);
      expect(denied[0]!.decision).toBe('deny');
      expect(denied[0]!.actorType).toBe('worker');
      expect(denied[0]!.metadata).toMatchObject({
        jobId,
        status: 'denied',
        errorCode: 'denied',
        reasonCode: ARGUMENTS_HASH_MISMATCH,
      });
      expect(finished.auditEventId).toBe(denied[0]!.id);
      const described = await world.repos.vault.describeForConnection(finished.connectionId);
      expect(described[0]?.lastAccessedAt ?? null).toBeNull();
      return denied[0]!;
    }

    it('a job whose arguments differ from the judged hash does not run', async () => {
      const connection = await activeConnection(world);
      const jobId = await queueOperation(world, connection.id, { arguments: { limit: 5 } });
      // Still valid for the adapter and still allowed by the grant: without the hash the
      // worker would run it.
      await editRow(jobId, `arguments = '{"limit": 50}'::jsonb`);
      const denied = await expectRefused(jobId);
      // The audit event carries the reason, never the argument values. The job id (a random
      // UUID) and the wall-clock duration may contain the characters "50" by chance, so they are
      // left out of the substring check; the argument key must not appear anywhere.
      const {
        jobId: _jobId,
        durationMs: _durationMs,
        ...facts
      } = denied.metadata as Record<string, unknown>;
      expect(JSON.stringify(facts)).not.toContain('50');
      expect(JSON.stringify(denied.metadata)).not.toContain('limit');
      expect(log.lines.join('')).toContain('job arguments do not match the judged hash');
    });

    it('an added argument is refused too', async () => {
      const connection = await activeConnection(world);
      const jobId = await queueOperation(world, connection.id, { arguments: {} });
      await editRow(jobId, `arguments = '{"limit": 1}'::jsonb`);
      await expectRefused(jobId);
    });

    it('a job moved to another connection does not run there', async () => {
      const judged = await activeConnection(world);
      const other = await activeConnection(world, { state: stateWith(COOKIE_CANARY) });
      const jobId = await queueOperation(world, judged.id);
      await editRow(jobId, `connection_id = '${other.id}'`);
      await expectRefused(jobId);
      expect(log.lines.join('')).not.toContain(COOKIE_CANARY);
    });

    it('a job switched to another operation does not run', async () => {
      const connection = await activeConnection(world, { operation: 'orders.cancel' });
      const jobId = await queueOperation(world, connection.id, { operation: 'orders.cancel' });
      // Rewritten to a read the grant set would also allow.
      await world.repos.grants.create(world.scope, world.agentId, {
        connectionId: connection.id,
        operation: 'orders.list',
      });
      await editRow(jobId, `operation = 'orders.list'`);
      await expectRefused(jobId);
    });

    it('a hash replaced by the hash of other arguments is refused', async () => {
      const connection = await activeConnection(world);
      const jobId = await queueOperation(world, connection.id, { arguments: { limit: 5 } });
      const otherHash = await hashWith(jobId, { limit: 6 });
      await editRow(jobId, `arguments_hash = '${otherHash}'`);
      await expectRefused(jobId);
    });

    it('an unchanged row still runs, whatever the key order the database stores', async () => {
      const connection = await activeConnection(world);
      const jobId = await queueOperation(world, connection.id, { arguments: { limit: 5 } });
      // Rewriting the same value is not a change.
      await editRow(jobId, `arguments = '{"limit": 5.0}'::jsonb`);
      await runOnce();
      expect(runner.operationCalls).toHaveLength(1);
      expect((await job(jobId)).status).toBe('succeeded');
    });

    it('a job reassigned to another agent does not run', async () => {
      const connection = await activeConnection(world);
      const jobId = await queueOperation(world, connection.id);
      // The other agent holds a grant too, so only the hash stands in the way.
      const other = await world.repos.agents.create(world.scope, {
        name: 'Other',
        clientIdentity: 'agent-2',
      });
      await world.repos.grants.create(world.scope, other.id, {
        connectionId: connection.id,
        operation: 'orders.list',
      });
      await editRow(jobId, `agent_id = '${other.id}'`);
      await expectRefused(jobId);
    });

    it('a job pointed at another policy decision does not run', async () => {
      const connection = await activeConnection(world);
      const jobId = await queueOperation(world, connection.id);
      await editRow(jobId, `policy_decision_id = '${randomUUID()}'`);
      await expectRefused(jobId);
    });

    it('a job whose decision id was removed does not run', async () => {
      const connection = await activeConnection(world);
      const jobId = await queueOperation(world, connection.id);
      await editRow(jobId, `policy_decision_id = null`);
      await expectRefused(jobId);
    });

    it('a job with a longer timeout does not run', async () => {
      const connection = await activeConnection(world);
      const jobId = await queueOperation(world, connection.id);
      await editRow(jobId, `timeout_ms = 3600000`);
      await expectRefused(jobId);
    });

    it('a job whose retry flag was flipped does not run', async () => {
      const connection = await activeConnection(world);
      const jobId = await queueOperation(world, connection.id, { retrySafe: false });
      await editRow(jobId, `retry_safe = true`);
      await expectRefused(jobId);
      const readOnly = await queueOperation(world, connection.id, { retrySafe: true });
      await editRow(readOnly, `retry_safe = false`);
      await runOnce();
      expect(runner.operationCalls).toHaveLength(0);
      expect((await job(readOnly)).status).toBe('denied');
    });

    it('an edit that also recomputes the hash does not run: the vault returns the hash it bound (P3-17)', async () => {
      // The hash is unkeyed and stored beside the arguments, so a writer who knows the layout can
      // replace both and the row stays consistent with itself (step 0 passes). The capability
      // was bound to the hash the API judged, under a MAC, when the job was authorized: the
      // supervisor compares what `readForWorker` returns with the row and runs nothing.
      const connection = await activeConnection(world, { state: stateWith(COOKIE_CANARY) });
      const jobId = await queueOperation(world, connection.id, { arguments: { limit: 5 } });
      const forged = await hashWith(jobId, { limit: 50 });
      await editRow(jobId, `arguments = '{"limit": 50}'::jsonb, arguments_hash = '${forged}'`);
      await runOnce();
      expect(runner.operationCalls).toHaveLength(0);
      const finished = await job(jobId);
      expect(finished.status).toBe('denied');
      expect(finished.error?.code).toBe('denied');
      expect(finished.result).toBeNull();
      const events = await auditEvents(world);
      const denied = events.filter((event) => event.eventType === 'operation.denied');
      expect(denied).toHaveLength(1);
      expect(denied[0]!.decision).toBe('deny');
      expect(denied[0]!.metadata).toMatchObject({ jobId, reasonCode: ARGUMENTS_HASH_MISMATCH });
      expect(JSON.stringify(denied[0]!.metadata)).not.toContain('limit');
      expect(log.lines.join('')).toContain('do not match the hash the vault bound');
      expect(log.lines.join('')).not.toContain(COOKIE_CANARY);
    });
  });

  describe('the runner receives exactly the hashed arguments', () => {
    it('a maxResults grant added after enqueue refuses the job', async () => {
      // The job was judged and stored without the limit.
      const connection = await activeConnection(world);
      const jobId = await queueOperation(world, connection.id, { arguments: {} });
      // The unconstrained grant is replaced by one with a limit.
      const [old] = await world.repos.grants.listForEvaluation({
        agentId: world.agentId,
        connectionId: connection.id,
        operation: 'orders.list',
      });
      await world.repos.grants.revoke(world.scope, world.agentId, old!.id);
      await world.repos.grants.create(world.scope, world.agentId, {
        connectionId: connection.id,
        operation: 'orders.list',
        constraints: { maxResults: 7 },
      });
      await runOnce();
      // Applying the new obligation would make the arguments { limit: 7 }, which the hash does
      // not cover: no sandbox, no snapshot read.
      expect(runner.operationCalls).toHaveLength(0);
      const finished = await job(jobId);
      expect(finished.status).toBe('denied');
      expect(finished.error?.code).toBe('denied');
      const events = await auditEvents(world);
      expect(events.map((event) => event.eventType)).not.toContain('vault.secret_read');
      const denied = events.find((event) => event.eventType === 'operation.denied')!;
      expect(denied.metadata).toMatchObject({ reasonCode: ARGUMENTS_CHANGED_BY_POLICY });
      expect(JSON.stringify(denied.metadata)).not.toContain('limit');
    });

    it('a maxResults grant that adds nothing to the stored arguments does not refuse the job', async () => {
      const connection = await activeConnection(world, {
        grant: false,
      });
      await world.repos.grants.create(world.scope, world.agentId, {
        connectionId: connection.id,
        operation: 'orders.list',
        constraints: { maxResults: 5 },
      });
      const jobId = await queueOperation(world, connection.id, { arguments: { limit: 5 } });
      await runOnce();
      expect(runner.operationCalls).toHaveLength(1);
      expect(runner.operationCalls[0]!.arguments).toEqual({ limit: 5 });
      expect((await job(jobId)).status).toBe('succeeded');
    });

    it('passes the stored arguments to the runner unchanged', async () => {
      const connection = await activeConnection(world);
      await queueOperation(world, connection.id, { arguments: { limit: 3 } });
      await runOnce();
      expect(runner.operationCalls[0]!.arguments).toEqual({ limit: 3 });
    });
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
    const a = await activeConnection(world, { applicationId: unknownApp });
    const b = await activeConnection(world, { applicationId: manifestApp });
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
      const connection = await activeConnection(world);
      await queueOperation(world, connection.id);
      await runOnce();
      expect(runner.operationCalls[0]!.allowedOrigins).toEqual([APP_ORIGIN, CDN_ORIGIN]);
    });

    it('is the subset the application allows', async () => {
      await world.close();
      world = await createWorld({ allowedOrigins: [CDN_ORIGIN] });
      const connection = await activeConnection(world);
      await queueOperation(world, connection.id);
      await runOnce();
      expect(runner.operationCalls[0]!.allowedOrigins).toEqual([CDN_ORIGIN]);
    });

    it('fails origin_not_allowed when empty', async () => {
      await world.close();
      world = await createWorld({ allowedOrigins: [OTHER_ORIGIN] });
      const connection = await activeConnection(world);
      const jobId = await queueOperation(world, connection.id);
      await runOnce();
      expect(runner.operationCalls).toHaveLength(0);
      expect((await job(jobId)).error?.code).toBe('origin_not_allowed');
      expect(await eventTypes()).not.toContain('vault.secret_read');
    });
  });

  it('without a stored session: reauth_required, connection expired, no vault call (M3)', async () => {
    const connection = await activeConnection(world, { state: null });
    const jobId = await queueOperation(world, connection.id);
    await runOnce();
    expect(runner.operationCalls).toHaveLength(0);
    const finished = await job(jobId);
    expect(finished.status).toBe('reauth_required');
    expect(finished.error?.code).toBe('session_expired');
    const after = await connectionOf(connection.id);
    expect(after.status).toBe('expired');
    expect(after.statusReason).toBe(OPERATION_REASONS.noSnapshot);
    const capability = await world.handle.db.execute(
      `select token_hash from vault_access_capabilities where job_id = '${jobId}'`,
    );
    // No token was issued for it (the capability is also revoked with the session).
    expect(JSON.stringify(capability)).not.toMatch(/[0-9a-f]{64}/);
    expect(await eventTypes()).not.toContain('vault.capability_issued');
  });

  it("a session invalidation also revokes the connection's unused capabilities (L5)", async () => {
    const connection = await activeConnection(world);
    const first = await queueOperation(world, connection.id);
    const second = await queueOperation(world, connection.id);
    runner.operation = async () => ({ status: 'reauth_required' });
    const sup = createSupervisor({
      repos: world.repos,
      runner,
      vault: world.vault,
      adapters: testRegistry(),
      logger: log.logger,
      settings: {
        workerId: 'worker-test',
        leaseMs: 5_000,
        heartbeatMs: 40,
        concurrency: 1,
      },
    });
    expect(await sup.tick()).toEqual([first]);
    await sup.idle();
    expect((await job(first)).status).toBe('reauth_required');
    const rows = (await world.handle.db.execute(
      `select revoked_at, revoked_reason from vault_access_capabilities where job_id = '${second}'`,
    )) as unknown as { rows?: Record<string, unknown>[] };
    const row = (rows.rows ?? (rows as unknown as Record<string, unknown>[]))[0]!;
    expect(row['revoked_at']).not.toBeNull();
    expect(row['revoked_reason']).toBe('session_deleted');
  });

  it('a stored session that is not a valid storage state fails worker_failure before anything runs', async () => {
    // Sealed bytes that are JSON but not a storage state.
    const connection = await activeConnection(world, {
      state: { cookies: [{ name: COOKIE_CANARY }], origins: [] } as unknown as StorageState,
    });
    const jobId = await queueOperation(world, connection.id);
    await runOnce();
    expect(runner.operationCalls).toHaveLength(0);
    expect((await job(jobId)).error?.code).toBe('worker_failure');
    const logged = log.lines.join('');
    expect(logged).toContain('not a valid storage state');
    expect(logged).not.toContain(COOKIE_CANARY);
    expect((await connectionOf(connection.id)).status).toBe('active');
  });

  it('cancellation while running aborts the runner and ends the job cancelled', async () => {
    const connection = await activeConnection(world);
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
    const a = await activeConnection(world, { state: stateWith('alpha-value') });
    const b = await activeConnection(world, { state: stateWith('beta-value') });
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
    const connection = await activeConnection(world);
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
      vault: world.vault,
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
