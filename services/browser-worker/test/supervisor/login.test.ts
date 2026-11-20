import { SESSION_SNAPSHOT_SECRET_TYPE } from '@aab/contracts';
import type { JobErrorCode } from '@aab/contracts';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { jobError } from '../../src/protocol.js';
import { LoginStartError } from '../../src/sandbox/index.js';
import { createSupervisor, LOGIN_FAILURE_REASONS } from '../../src/supervisor/index.js';
import type { SupervisorSettings } from '../../src/supervisor/index.js';
import type { LoginOutcome, StorageState } from '../../src/types.js';
import type { SupervisorVault } from '../../src/vault/gateway.js';
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
  let runner: FakeRunner;
  let log: ReturnType<typeof captureLogger>;

  beforeEach(async () => {
    world = await createWorld();
    wrapped = null;
    runner = new FakeRunner();
    log = captureLogger();
  });
  afterEach(async () => {
    await world.close();
  });

  function supervisor(
    vault: SupervisorVault = wrapped ?? world.vault,
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
        // The short-window tests below use windows of a few hundred milliseconds.
        minLoginWindowMs: 1,
        ...settings,
      },
    });
  }

  /** Wraps the world's vault so each call's operation and parameters are recorded. */
  let wrapped: SupervisorVault | null = null;
  function recordVaultCalls(): { operation: string; params: Record<string, unknown> }[] {
    const calls: { operation: string; params: Record<string, unknown> }[] = [];
    wrapped = {
      isolation: world.vault.isolation,
      check: () => world.vault.check(),
      call: (operation, params) => {
        calls.push({ operation, params: structuredClone(params) as Record<string, unknown> });
        return world.vault.call(operation, params);
      },
    };
    return calls;
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
    // Derived from the filtered state (the earliest allowed cookie, 1_950_000_000 s) and then
    // capped by the vault at 400 days from now, which is earlier.
    const cap = Date.now() + 400 * 24 * 60 * 60_000;
    expect(new Date(after.sessionExpiresAt!).getTime()).toBeLessThanOrEqual(cap);
    expect(new Date(after.sessionExpiresAt!).getTime()).toBeGreaterThan(cap - 60_000);
    expect(after.lastVerifiedAt).not.toBeNull();
    expect(after.statusReason).toBeNull();

    const stored = JSON.parse((await world.openStored(connection.id))!) as StorageState;
    expect(stored.cookies.map((c) => c.name)).toEqual(['sid', 'asset']);
    expect(stored.origins.map((o) => o.origin)).toEqual([APP_ORIGIN]);

    // The vault wrote both events as `system`; the supervisor wrote no second copy (B3b).
    const events = await auditEvents(world);
    const storedEvents = events.filter((event) => event.eventType === 'vault.secret_stored');
    expect(storedEvents).toHaveLength(1);
    expect(storedEvents[0]!.actorType).toBe('system');
    expect(storedEvents[0]!.metadata).toMatchObject({ jobId, snapshotVersion: 1, originCount: 1 });
    const completedEvents = events.filter(
      (event) => event.eventType === 'connection.auth_completed',
    );
    expect(completedEvents).toHaveLength(1);
    const completed = completedEvents[0]!;
    expect(completed.actorType).toBe('system');
    expect(finished.auditEventId).toBe(completed.id);
    expect(completed.metadata).toMatchObject({ jobId, accountHintRecorded: true });
    expect(events.filter((event) => event.actorType === 'worker')).toEqual([]);

    expect(await dumpTables(world)).not.toContain(CANARY);
    expect(await dumpTables(world)).not.toContain('tracker-value');
    expect(log.lines.join('')).not.toContain(CANARY);
  });

  it('filters to the allowed origins before completeLogin and derives the expiry from what is sent', async () => {
    const { connection, jobId } = await loginConnection(world);
    const soon = Math.floor(Date.now() / 1000) + 3 * 24 * 3600;
    loginReturns(async () => ({
      status: 'succeeded',
      storageState: {
        cookies: [
          cookie('sid', CANARY, 'app.example.test', soon + 86_400),
          cookie('asset', 'cdn-value', 'cdn.example.test', soon),
          // Third-party and earlier: dropped, and its expiry must not count.
          cookie('track', 'tracker-value', 'tracker.other.test', soon - 86_000),
        ],
        origins: [
          { origin: APP_ORIGIN, localStorage: [{ name: 'k', value: 'v' }] },
          { origin: OTHER_ORIGIN, localStorage: [{ name: 'k', value: 'x' }] },
        ],
      },
      externalAccountHint: 'user@example.test',
    }));
    const calls = recordVaultCalls();
    expect((await runLogin(jobId)).status).toBe('succeeded');

    const complete = calls.filter((call) => call.operation === 'completeLogin');
    expect(complete).toHaveLength(1);
    const sent = JSON.parse(
      Buffer.from(complete[0]!.params['plaintext'] as string, 'base64url').toString('utf8'),
    ) as StorageState;
    expect(sent.cookies.map((c) => c.name)).toEqual(['sid', 'asset']);
    expect(sent.origins.map((o) => o.origin)).toEqual([APP_ORIGIN]);
    expect(JSON.stringify(sent)).not.toContain('tracker');
    expect(complete[0]!.params['sessionExpiresAt']).toBe(new Date(soon * 1000).toISOString());
    expect(complete[0]!.params['externalAccountHint']).toBe('user@example.test');
    const after = (await world.repos.connections.get(world.scope, connection.id))!;
    expect(after.sessionExpiresAt).toBe(new Date(soon * 1000).toISOString());
    // The token and the plaintext are not in the log.
    expect(log.lines.join('')).not.toContain(CANARY);
    expect(log.lines.join('')).not.toContain(complete[0]!.params['plaintext'] as string);
  });

  describe('the capability must outlive the sign-in window (M1)', () => {
    it('fails before a window opens when the capability expires too soon', async () => {
      // Authorized for the shortest lifetime (10 s); the default margin is 45 s.
      const { connection, jobId } = await loginConnection(world, world.applicationId, {
        authorize: false,
      });
      await world.authorize(jobId, 10);
      const sup = supervisor(world.vault, { minLoginWindowMs: 5_000 });
      await sup.tick();
      await sup.idle();
      expect(runner.loginCalls).toHaveLength(0);
      await expectFailedLogin(connection.id, jobId, 'timeout');
      // Never `vault_denied` after a capture: nothing was captured.
      expect((await world.repos.jobs.getInternal(jobId))!.error?.code).not.toBe('vault_denied');
    });

    it('shortens the window to what the capability has left, less the margin', async () => {
      const { connection, jobId } = await loginConnection(world, world.applicationId, {
        authorize: false,
      });
      await world.authorize(jobId, 60);
      const sup = supervisor(world.vault, { minLoginWindowMs: 1_000 });
      expect(await sup.tick()).toEqual([jobId]);
      await waitFor(() => runner.handles.length === 1);
      // 60 s capability, 45 s margin: about 15 s, never the job's 600 s.
      const window = runner.loginCalls[0]!.timeoutMs;
      expect(window).toBeLessThanOrEqual(15_000);
      expect(window).toBeGreaterThan(5_000);
      // Completing inside the window still stores the login.
      await requestCompletion(jobId);
      await sup.idle();
      expect((await world.repos.jobs.getInternal(jobId))!.status).toBe('succeeded');
      expect((await world.repos.connections.get(world.scope, connection.id))!.status).toBe(
        'active',
      );
    });
  });

  it('a short-lived cookie does not fail the login or set the session expiry (L6)', async () => {
    const { connection, jobId } = await loginConnection(world);
    const soon = Math.floor(Date.now() / 1000) + 60;
    loginReturns(async () => ({
      status: 'succeeded',
      storageState: {
        cookies: [
          cookie('flash', 'x', 'app.example.test', soon),
          cookie('sid', CANARY, 'app.example.test', -1),
        ],
        origins: [],
      },
      externalAccountHint: null,
    }));
    const calls = recordVaultCalls();
    expect((await runLogin(jobId)).status).toBe('succeeded');
    expect(
      calls.find((c) => c.operation === 'completeLogin')!.params['sessionExpiresAt'],
    ).toBeNull();
    expect(
      (await world.repos.connections.get(world.scope, connection.id))!.sessionExpiresAt,
    ).toBeNull();
  });

  it('refuses a re-login that signs in to a different account', async () => {
    const connection = await activeConnection(world, { hint: 'first@example.test' });
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
    await world.authorize(job.id, 660);
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
    const connection = await activeConnection(world, { hint: 'user@example.test' });
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
    await world.authorize(job.id, 660);
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
    await world.authorize(job.id, 660);
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
    const calls = recordVaultCalls();
    await runLogin(jobId);
    await expectFailedLogin(connection.id, jobId, 'login_not_completed');
    // Failed by the supervisor itself: the vault was never asked (not even for a token).
    expect(calls.filter((call) => call.operation !== 'hello')).toEqual([]);
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
