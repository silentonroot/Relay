import { SESSION_SNAPSHOT_SECRET_TYPE } from '@aab/contracts';
import type { JobErrorCode } from '@aab/contracts';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { jobError } from '../../src/protocol.js';
import { LoginStartError } from '../../src/sandbox/index.js';
import { openSnapshot } from '../../src/session-store/index.js';
import { createSupervisor, LOGIN_FAILURE_REASONS } from '../../src/supervisor/index.js';
import type { LoginOutcome, StorageState } from '../../src/types.js';
import {
  activeConnection,
  APP_ORIGIN,
  auditEvents,
  captureLogger,
  CDN_ORIGIN,
  cookie,
  createWorld,
  dumpTables,
  fakeLoginHandle,
  FakeRunner,
  loginConnection,
  OTHER_ORIGIN,
  registerApplication,
  testKek,
  testRegistry,
  waitFor,
} from './helpers.js';
import type { World } from './helpers.js';

const CANARY = 'login-cookie-canary-31d8e0';

const capturedState: StorageState = {
  cookies: [
    cookie('sid', CANARY, '.app.example.test', 2_000_000_000),
    cookie('asset', 'cdn-value', 'cdn.example.test', 1_950_000_000),
    // Third-party: must be dropped, and its earlier expiry must not count.
    cookie('track', 'tracker-value', 'tracker.other.test', 1_800_000_000),
  ],
  origins: [
    { origin: APP_ORIGIN, localStorage: [{ name: 'k', value: 'v' }] },
    { origin: OTHER_ORIGIN, localStorage: [{ name: 'k', value: 'x' }] },
  ],
};

describe('login jobs', () => {
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

  function supervisor() {
    return createSupervisor({
      repos: world.repos,
      runner,
      kek,
      adapters: testRegistry(),
      logger: log.logger,
      settings: { workerId: 'worker-test', leaseMs: 5_000, heartbeatMs: 40, loginPollMs: 20 },
    });
  }

  function loginReturns(outcome: () => Promise<LoginOutcome>) {
    runner.login = async () => {
      const handle = fakeLoginHandle(outcome);
      runner.handles.push(handle);
      return handle;
    };
  }

  const requestCompletion = (jobId: string) =>
    world.repos.jobs.requestLoginCompletion(
      { organizationId: world.scope.organizationId, ownerUserId: world.scope.userId },
      jobId,
      new Date(),
    );

  /** Starts the job, waits for the window, runs `act`, then waits for the job to end. */
  async function runLogin(
    jobId: string,
    act: () => Promise<void> = () => requestCompletion(jobId).then(() => undefined),
  ) {
    const sup = supervisor();
    expect(await sup.tick()).toEqual([jobId]);
    await waitFor(() => runner.handles.length === 1);
    await act();
    await sup.idle();
    return (await world.repos.jobs.getInternal(jobId))!;
  }

  async function expectFailedLogin(
    connectionId: string,
    jobId: string,
    code: JobErrorCode,
    status: 'failed' | 'cancelled' = code === 'cancelled' ? 'cancelled' : 'failed',
  ) {
    const finished = (await world.repos.jobs.getInternal(jobId))!;
    expect(finished.status).toBe(status);
    expect(finished.error?.code).toBe(code);
    const connection = (await world.repos.connections.get(world.scope, connectionId))!;
    expect(connection.status).toBe('authentication_required');
    expect(connection.statusReason).toBe(LOGIN_FAILURE_REASONS[code]);
    const events = await auditEvents(world);
    const failed = events.find((event) => event.eventType === 'connection.auth_failed')!;
    expect(failed.metadata).toMatchObject({ jobId, status, errorCode: code });
    expect(finished.auditEventId).toBe(failed.id);
    expect(events.map((event) => event.eventType)).not.toContain('vault.secret_stored');
    expect(
      await world.repos.vault.getActive(connectionId, SESSION_SNAPSHOT_SECRET_TYPE),
    ).toBeNull();
  }

  it('stores a snapshot filtered to the allowed origins and activates the connection', async () => {
    const { connection, jobId } = await loginConnection(world);
    loginReturns(async () => ({
      status: 'succeeded',
      storageState: structuredClone(capturedState),
      externalAccountHint: '  user@example.test ',
    }));

    const finished = await runLogin(jobId);

    expect(runner.loginCalls[0]).toEqual({
      jobId,
      connectionId: connection.id,
      adapterId: 'test-app',
      adapterVersion: '1.0.0',
      allowedOrigins: [APP_ORIGIN, CDN_ORIGIN],
      timeoutMs: 600_000,
    });
    expect(finished.status).toBe('succeeded');
    expect(runner.handles[0]!.completed).toBe(true);

    const after = (await world.repos.connections.get(world.scope, connection.id))!;
    expect(after.status).toBe('active');
    expect(after.externalAccountHint).toBe('user@example.test');
    expect(after.sessionExpiresAt).toBe(new Date(1_950_000_000_000).toISOString());
    expect(after.lastVerifiedAt).not.toBeNull();
    expect(after.statusReason).toBeNull();

    const opened = await openSnapshot(world.repos, after, kek);
    expect(opened!.storageState.cookies.map((c) => c.name)).toEqual(['sid', 'asset']);
    expect(opened!.storageState.origins.map((o) => o.origin)).toEqual([APP_ORIGIN]);

    const events = await auditEvents(world);
    const types = events.map((event) => event.eventType);
    expect(types).toContain('vault.secret_stored');
    const completed = events.find((event) => event.eventType === 'connection.auth_completed')!;
    expect(finished.auditEventId).toBe(completed.id);
    expect(completed.metadata).toMatchObject({ jobId, accountHintRecorded: true });

    expect(await dumpTables(world)).not.toContain(CANARY);
    expect(await dumpTables(world)).not.toContain('tracker-value');
    expect(log.lines.join('')).not.toContain(CANARY);
  });

  it('refuses a re-login that signs in to a different account', async () => {
    const connection = await activeConnection(world, kek, { hint: 'first@example.test' });
    await world.repos.connections.transitionStatus(world.scope, connection.id, { to: 'expired' });
    await world.repos.connections.transitionStatus(world.scope, connection.id, {
      to: 'authenticating',
    });
    const job = await world.repos.jobs.createLogin({
      organizationId: world.scope.organizationId,
      requestedByUserId: world.scope.userId,
      connectionId: connection.id,
      timeoutMs: 600_000,
    });
    const before = await world.repos.vault.getActive(connection.id, SESSION_SNAPSHOT_SECRET_TYPE);
    loginReturns(async () => ({
      status: 'succeeded',
      storageState: structuredClone(capturedState),
      externalAccountHint: 'second@example.test',
    }));

    await runLogin(job.id);

    const finished = (await world.repos.jobs.getInternal(job.id))!;
    expect(finished.error?.code).toBe('identity_mismatch');
    const after = (await world.repos.connections.get(world.scope, connection.id))!;
    expect(after.status).toBe('authentication_required');
    expect(after.statusReason).toBe(LOGIN_FAILURE_REASONS.identity_mismatch);
    expect(after.externalAccountHint).toBe('first@example.test');
    // Nothing new stored: the earlier version is untouched.
    const stillThere = await world.repos.vault.getActive(
      connection.id,
      SESSION_SNAPSHOT_SECRET_TYPE,
    );
    expect(stillThere?.version).toBe(before?.version);
    expect((await auditEvents(world)).map((e) => e.eventType)).not.toContain('vault.secret_stored');
  });

  it('a re-login to the same account succeeds', async () => {
    const connection = await activeConnection(world, kek, { hint: 'user@example.test' });
    await world.repos.connections.transitionStatus(world.scope, connection.id, { to: 'expired' });
    await world.repos.connections.transitionStatus(world.scope, connection.id, {
      to: 'authenticating',
    });
    const job = await world.repos.jobs.createLogin({
      organizationId: world.scope.organizationId,
      requestedByUserId: world.scope.userId,
      connectionId: connection.id,
      timeoutMs: 600_000,
    });
    loginReturns(async () => ({
      status: 'succeeded',
      storageState: structuredClone(capturedState),
      externalAccountHint: 'user@example.test',
    }));
    expect((await runLogin(job.id)).status).toBe('succeeded');
    const active = await world.repos.vault.getActive(connection.id, SESSION_SNAPSHOT_SECRET_TYPE);
    expect(active?.version).toBe(2);
  });

  it('window closed by the owner', async () => {
    const { connection, jobId } = await loginConnection(world);
    await runLogin(jobId, async () => runner.handles[0]!.closeWindow());
    await expectFailedLogin(connection.id, jobId, 'login_window_closed');
  });

  it('timeout', async () => {
    const created = await world.repos.connections.create(world.scope, {
      applicationId: world.applicationId,
      displayName: 'Short login',
    });
    await world.repos.connections.transitionStatus(world.scope, created.id, {
      to: 'authentication_required',
    });
    await world.repos.connections.transitionStatus(world.scope, created.id, {
      to: 'authenticating',
    });
    const job = await world.repos.jobs.createLogin({
      organizationId: world.scope.organizationId,
      requestedByUserId: world.scope.userId,
      connectionId: created.id,
      timeoutMs: 150,
    });
    await runLogin(job.id, async () => undefined);
    expect(runner.handles[0]!.cancelled).toBe(true);
    await expectFailedLogin(created.id, job.id, 'timeout');
  });

  it('cancelled by revocation: the connection stays revoked', async () => {
    const { connection, jobId } = await loginConnection(world);
    await runLogin(jobId, async () => {
      await world.repos.connections.revoke(world.scope, connection.id);
    });
    expect(runner.handles[0]!.cancelled).toBe(true);
    const finished = (await world.repos.jobs.getInternal(jobId))!;
    expect(finished.status).toBe('cancelled');
    expect((await world.repos.connections.get(world.scope, connection.id))!.status).toBe('revoked');
    const failed = (await auditEvents(world)).find(
      (e) => e.eventType === 'connection.auth_failed',
    )!;
    expect(failed.metadata).toMatchObject({ errorCode: 'cancelled', connectionReset: false });
  });

  it('cancel request on the job', async () => {
    const { connection, jobId } = await loginConnection(world);
    await runLogin(jobId, async () => {
      await world.repos.jobs.cancelForConnection(connection.id, new Date());
    });
    await expectFailedLogin(connection.id, jobId, 'cancelled');
  });

  it('completion requested before sign-in finished (runner reports it)', async () => {
    const { connection, jobId } = await loginConnection(world);
    loginReturns(async () => ({ status: 'failed', error: jobError('login_not_completed') }));
    await runLogin(jobId);
    await expectFailedLogin(connection.id, jobId, 'login_not_completed');
  });

  it('completion with nothing left after filtering', async () => {
    const { connection, jobId } = await loginConnection(world);
    loginReturns(async () => ({
      status: 'succeeded',
      storageState: {
        cookies: [cookie('track', 'x', 'tracker.other.test')],
        origins: [{ origin: OTHER_ORIGIN, localStorage: [] }],
      },
      externalAccountHint: null,
    }));
    await runLogin(jobId);
    await expectFailedLogin(connection.id, jobId, 'login_not_completed');
  });

  it.each([
    ['LoginStartError', new LoginStartError('origin_not_allowed'), 'origin_not_allowed'],
    ['any other error', new Error('display gone'), 'worker_failure'],
  ] as const)('startLogin rejection (%s)', async (_name, error, code) => {
    const { connection, jobId } = await loginConnection(world);
    runner.login = async () => {
      throw error;
    };
    const sup = supervisor();
    await sup.tick();
    await sup.idle();
    await expectFailedLogin(connection.id, jobId, code);
    expect(log.lines.join('')).not.toContain('display gone');
  });

  it('an adapter without a login fails adapter_unavailable before a window opens', async () => {
    const app = await registerApplication(world, {
      adapterId: 'manifest-only',
      allowedOrigins: [APP_ORIGIN],
    });
    const { connection, jobId } = await loginConnection(world, app);
    const sup = supervisor();
    await sup.tick();
    await sup.idle();
    expect(runner.loginCalls).toHaveLength(0);
    await expectFailedLogin(connection.id, jobId, 'adapter_unavailable');
  });

  it('no shared origin fails origin_not_allowed before a window opens', async () => {
    await world.close();
    world = await createWorld({ allowedOrigins: [OTHER_ORIGIN] });
    const { connection, jobId } = await loginConnection(world);
    const sup = supervisor();
    await sup.tick();
    await sup.idle();
    expect(runner.loginCalls).toHaveLength(0);
    await expectFailedLogin(connection.id, jobId, 'origin_not_allowed');
  });

  it('shutdown while the window is open cancels it and resets the connection', async () => {
    const { connection, jobId } = await loginConnection(world);
    const sup = supervisor();
    await sup.tick();
    await waitFor(() => runner.handles.length === 1);
    await sup.stop();
    expect(runner.handles[0]!.cancelled).toBe(true);
    expect(sup.runningJobIds()).toEqual([]);
    await expectFailedLogin(connection.id, jobId, 'cancelled');
  });
});
