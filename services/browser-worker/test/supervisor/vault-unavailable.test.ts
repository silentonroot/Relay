import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createSupervisor } from '../../src/supervisor/index.js';
import type { SupervisorSettings } from '../../src/supervisor/index.js';
import type { SupervisorVault } from '../../src/vault/gateway.js';
import { startService } from '../../../vault/test/service-helpers.js';
import type { Service } from '../../../vault/test/service-helpers.js';
import {
  activeConnection,
  auditEvents,
  captureLogger,
  cookie,
  createWorld,
  dumpTables,
  fakeLoginHandle,
  FakeRunner,
  loginConnection,
  queueOperation,
  stateWith,
  testRegistry,
  waitFor,
} from './helpers.js';
import type { World } from './helpers.js';

const CANARY = 'vault-down-canary-8e41c9';

/*
 * ADR-014 section 9, P3-11: when the vault cannot be reached the job ends `vault_unavailable`,
 * when it refuses the job ends `vault_denied`, nothing opens or seals a secret locally (the
 * supervisor has no key to do it with; see import-boundary.test.ts), and no job is claimed
 * while the vault is down.
 */
describe('the vault is unreachable or refuses', () => {
  let world: World;
  let runner: FakeRunner;
  let log: ReturnType<typeof captureLogger>;
  let restarted: Service | null = null;

  beforeEach(async () => {
    world = await createWorld();
    runner = new FakeRunner();
    log = captureLogger();
  });
  afterEach(async () => {
    await restarted?.stop().catch(() => undefined);
    restarted = null;
    await world.close();
  });

  function supervisor(
    vault: SupervisorVault = world.vault,
    settings: Partial<SupervisorSettings> = {},
  ) {
    return createSupervisor({
      repos: world.repos,
      runner,
      vault,
      adapters: testRegistry(),
      logger: log.logger,
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

  /** `hello` passes (the vault is up), then the vault goes away before the job's first call. */
  const vanishesAfterCheck = (): SupervisorVault => ({
    isolation: world.vault.isolation,
    call: (operation, params) => world.vault.call(operation, params),
    async check() {
      await world.vault.check();
      await world.service.stop();
    },
  });

  const job = async (id: string) => (await world.repos.jobs.getInternal(id))!;
  const eventTypes = async () => (await auditEvents(world)).map((event) => event.eventType);

  it('a job fails with vault_unavailable and no key is read', async () => {
    const connection = await activeConnection(world, { state: stateWith(CANARY) });
    const jobId = await queueOperation(world, connection.id);
    const sup = supervisor(vanishesAfterCheck());
    expect(await sup.tick()).toEqual([jobId]);
    await sup.idle();

    // The job was claimed (the vault answered `hello`), then ended: no sandbox, no retry.
    const finished = await job(jobId);
    expect(finished.status).toBe('failed');
    expect(finished.error?.code).toBe('vault_unavailable');
    expect(finished.result).toBeNull();
    expect(runner.operationCalls).toHaveLength(0);
    const events = await auditEvents(world);
    const failed = events.find((event) => event.eventType === 'operation.failed')!;
    expect(failed.metadata).toMatchObject({
      jobId,
      status: 'failed',
      errorCode: 'vault_unavailable',
    });
    expect(finished.auditEventId).toBe(failed.id);
    // Nothing was read, by the vault or by anyone else; the session is untouched.
    expect(events.map((event) => event.eventType)).not.toContain('vault.secret_read');
    const described = await world.repos.vault.describeForConnection(connection.id);
    expect(described[0]?.lastAccessedAt ?? null).toBeNull();
    expect((await world.repos.connections.get(world.scope, connection.id))!.status).toBe('active');
    expect(log.lines.join('')).not.toContain(CANARY);
    expect(await dumpTables(world)).not.toContain(CANARY);
  });

  it('a vault that answers but cannot do its work (database down) also fails the job vault_unavailable', async () => {
    const connection = await activeConnection(world);
    const jobId = await queueOperation(world, connection.id);
    world.service.setDatabaseDown(true);
    const sup = supervisor();
    await sup.tick();
    await sup.idle();
    expect((await job(jobId)).error?.code).toBe('vault_unavailable');
    expect(runner.operationCalls).toHaveLength(0);
    world.service.setDatabaseDown(false);
    expect(await eventTypes()).not.toContain('vault.secret_read');
  });

  it('a capability the vault refuses fails the job vault_denied', async () => {
    const connection = await activeConnection(world, { state: stateWith(CANARY) });
    const jobId = await queueOperation(world, connection.id);
    // Revoked after authorization (as a grant revocation would): the vault refuses to issue.
    await world.service.repos.capabilities.revokeForJob({
      jobId,
      reason: 'lease_recovery',
      now: new Date(),
    });
    const sup = supervisor();
    await sup.tick();
    await sup.idle();
    const finished = await job(jobId);
    expect(finished.status).toBe('failed');
    expect(finished.error?.code).toBe('vault_denied');
    expect(runner.operationCalls).toHaveLength(0);
    expect(await eventTypes()).not.toContain('vault.secret_read');
    expect(log.lines.join('')).not.toContain(CANARY);
  });

  it('does not claim a job while the vault is down, and claims it once the vault is back', async () => {
    const connection = await activeConnection(world);
    const jobId = await queueOperation(world, connection.id);
    await world.service.stop();

    const sup = supervisor();
    // The loop runs and ticks; nothing is claimed.
    await sup.start();
    expect(await sup.tick()).toEqual([]);
    await new Promise((resolve) => setTimeout(resolve, 300));
    const waiting = await job(jobId);
    expect(waiting.status).toBe('queued');
    expect(waiting.attemptCount).toBe(0);
    expect(waiting.workerId).toBeNull();
    expect(runner.operationCalls).toHaveLength(0);
    expect(log.lines.join('')).toContain('no job is claimed');

    // The vault comes back on the same sockets, keys and database.
    restarted = await startService({
      reuse: {
        dbHandle: world.service.dbHandle,
        kekDir: world.service.kekDir,
        socketDir: world.service.socketDir,
      },
    });
    await waitFor(async () => (await job(jobId)).status === 'succeeded', 15_000);
    await sup.stop();
    expect(runner.operationCalls).toHaveLength(1);
  });

  it('a login the vault cannot store fails vault_unavailable and stores nothing', async () => {
    const { connection, jobId } = await loginConnection(world);
    runner.login = async () => {
      const handle = fakeLoginHandle(async () => {
        // The vault is reachable for `hello` but cannot work: the completion is not stored.
        world.service.setDatabaseDown(true);
        return {
          status: 'succeeded',
          storageState: { cookies: [cookie('sid', CANARY, 'app.example.test')], origins: [] },
          externalAccountHint: 'user@example.test',
        };
      });
      runner.handles.push(handle);
      return handle;
    };
    const sup = supervisor();
    await sup.tick();
    await waitFor(() => runner.handles.length === 1);
    await world.repos.jobs.requestLoginCompletion(
      { organizationId: world.scope.organizationId, ownerUserId: world.scope.userId },
      jobId,
      new Date(),
    );
    await sup.idle();
    world.service.setDatabaseDown(false);

    const finished = await job(jobId);
    expect(finished.status).toBe('failed');
    expect(finished.error?.code).toBe('vault_unavailable');
    const after = (await world.repos.connections.get(world.scope, connection.id))!;
    expect(after.status).toBe('authentication_required');
    expect(await world.openStored(connection.id)).toBeNull();
    const types = await eventTypes();
    expect(types).toContain('connection.auth_failed');
    expect(types).not.toContain('vault.secret_stored');
    expect(types).not.toContain('connection.auth_completed');
    expect(log.lines.join('')).not.toContain(CANARY);
    expect(await dumpTables(world)).not.toContain(CANARY);
  });

  it('a login the vault refuses fails vault_denied and stores nothing', async () => {
    const { connection, jobId } = await loginConnection(world);
    runner.login = async () => {
      const handle = fakeLoginHandle(async () => {
        await world.service.repos.capabilities.revokeForJob({
          jobId,
          reason: 'lease_recovery',
          now: new Date(),
        });
        return {
          status: 'succeeded',
          storageState: { cookies: [cookie('sid', CANARY, 'app.example.test')], origins: [] },
          externalAccountHint: null,
        };
      });
      runner.handles.push(handle);
      return handle;
    };
    const sup = supervisor();
    await sup.tick();
    await waitFor(() => runner.handles.length === 1);
    await world.repos.jobs.requestLoginCompletion(
      { organizationId: world.scope.organizationId, ownerUserId: world.scope.userId },
      jobId,
      new Date(),
    );
    await sup.idle();

    expect((await job(jobId)).error?.code).toBe('vault_denied');
    expect((await world.repos.connections.get(world.scope, connection.id))!.status).toBe(
      'authentication_required',
    );
    expect(await world.openStored(connection.id)).toBeNull();
    expect(await eventTypes()).not.toContain('vault.secret_stored');
  });
});
