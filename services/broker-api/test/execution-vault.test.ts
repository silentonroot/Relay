import { ConnectionAuthResponse, OperationJob, Routes } from '@aab/contracts';
import { schema } from '@aab/database';
import { createTestDatabase, sql } from '@aab/database/testing';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createVaultGateway } from '../src/vault/gateway.js';
import type { VaultGateway } from '../src/vault/gateway.js';
import { startFakeVault } from './fake-vault.js';
import type { FakeVault } from './fake-vault.js';
import type { Harness, SignedIn } from './helpers.js';
import { createHarness, expectNoSecretLeaks, login, path, seedOwner } from './helpers.js';
import { executeFor, newWorld, registerApplication, startRealVault } from './vault-world.js';
import type { RealVault } from './vault-world.js';

const owner = { email: 'owner@example.test', password: 'execution vault test password' };
const realClock = () => new Date();
const NO_VAULT_SOCKET = '/nonexistent/aab-vault/api/vault.sock';

interface Rig {
  h: Harness;
  session: SignedIn;
  applicationId: string;
}

async function rig(
  vault: VaultGateway,
  database?: Awaited<ReturnType<typeof createTestDatabase>>,
): Promise<Rig> {
  const h = await createHarness({
    vault,
    clock: realClock,
    ...(database === undefined ? {} : { database }),
  });
  await seedOwner(h, owner);
  const session = await login(h, owner);
  return { h, session, applicationId: await registerApplication(h, session) };
}

const jobRow = async (h: Harness, jobId: string) =>
  (await h.database.db.select().from(schema.executionJobs)).find((row) => row.id === jobId)!;
const eventsOf = async (r: Rig, connectionId: string) =>
  (
    await r.h.repos.audit.list(
      { organizationId: r.session.organizationId, userId: r.session.userId },
      { limit: 200, connectionId },
    )
  ).items;
const startLogin = async (r: Rig, connectionId: string) =>
  r.h.inject({
    method: 'POST',
    url: path(Routes.connectionAuthStart, { id: connectionId }),
    headers: r.session.headers,
  });
const newConnection = async (r: Rig): Promise<string> =>
  (
    await r.h.inject({
      method: 'POST',
      url: path(Routes.connections),
      headers: r.session.headers,
      payload: { applicationId: r.applicationId, displayName: 'Login target' },
    })
  ).json<{ id: string }>().id;

describe('authorizing a job with the real vault (P3-11 happy path)', () => {
  let vault: RealVault;
  let r: Rig;

  beforeAll(async () => {
    const database = await createTestDatabase();
    vault = await startRealVault(database);
    r = await rig(vault.gateway, database);
  }, 60_000);
  afterAll(async () => {
    await expectNoSecretLeaks(r.h);
    await r.h.close();
    await vault.stop();
    await vault.service.dbHandle.close();
  });

  it('an executed job has its capability authorization after the commit', async () => {
    const world = await newWorld(r.h, r.session, r.applicationId);
    const response = await executeFor(r.h, r.session, world);
    expect(response.statusCode, response.body).toBe(202);
    const queued = OperationJob.parse(response.json());
    expect(queued.status).toBe('queued');
    const job = await jobRow(r.h, queued.jobId);
    expect(job.capabilityRef).not.toBeNull();
    const [capability] = (
      await r.h.database.db.select().from(schema.vaultAccessCapabilities)
    ).filter((row) => row.jobId === queued.jobId);
    expect(capability).toMatchObject({
      id: job.capabilityRef,
      purpose: 'read',
      operation: 'orders.list',
      connectionId: world.connectionId,
      agentId: world.agentId,
      tokenHash: null,
      revokedAt: null,
    });
    const types = (await eventsOf(r, world.connectionId)).map((event) => event.eventType);
    expect(types).toContain('vault.capability_authorized');
    expect(types).not.toContain('operation.failed');
  });

  it('a login handoff has its seal authorization after the commit', async () => {
    const connectionId = await newConnection(r);
    const response = await startLogin(r, connectionId);
    expect(response.statusCode, response.body).toBe(200);
    const body = ConnectionAuthResponse.parse(response.json());
    expect(body).toMatchObject({ jobStatus: 'queued', error: null });
    expect(body.connection.status).toBe('authenticating');
    const job = await jobRow(r.h, body.jobId);
    expect(job.capabilityRef).not.toBeNull();
    const [capability] = (
      await r.h.database.db.select().from(schema.vaultAccessCapabilities)
    ).filter((row) => row.jobId === body.jobId);
    expect(capability).toMatchObject({ purpose: 'seal', operation: null, agentId: null });
  });

  it('the sweep leaves an authorized job alone', async () => {
    const world = await newWorld(r.h, r.session, r.applicationId);
    const authorized = OperationJob.parse((await executeFor(r.h, r.session, world)).json());
    expect(await r.h.app.sweepVaultAuthorizations()).toBe(0);
    expect((await jobRow(r.h, authorized.jobId)).status).toBe('queued');
  });
});

describe('a job whose capability cannot be authorized', () => {
  let r: Rig;
  // Seeding an owner hashes a password: that cost belongs in the hook, not in the first test.
  beforeAll(async () => {
    // A socket path that does not exist fails at once; the short timeout is only a backstop.
    r = await rig(
      createVaultGateway({ socketPath: NO_VAULT_SOCKET, isolation: 'shared-uid', timeoutMs: 100 }),
    );
  }, 60_000);
  afterAll(async () => {
    await expectNoSecretLeaks(r.h);
    await r.h.close();
  });

  it('a job whose capability cannot be authorized ends with vault_unavailable', async () => {
    const world = await newWorld(r.h, r.session, r.applicationId);
    const response = await executeFor(r.h, r.session, world);
    // The job is terminal when the request returns: the response carries the outcome.
    expect(response.statusCode, response.body).toBe(200);
    const job = OperationJob.parse(response.json());
    expect(job).toMatchObject({
      status: 'failed',
      error: { code: 'vault_unavailable' },
      result: null,
    });
    const row = await jobRow(r.h, job.jobId);
    expect(row).toMatchObject({
      status: 'failed',
      errorCode: 'vault_unavailable',
      capabilityRef: null,
    });
    expect(
      (await r.h.database.db.select().from(schema.vaultAccessCapabilities)).filter(
        (capability) => capability.jobId === job.jobId,
      ),
    ).toHaveLength(0);
    // Policy was still audited, and the failure is the system's, in the job's chain.
    const events = await eventsOf(r, world.connectionId);
    const failed = events.find((event) => event.eventType === 'operation.failed')!;
    expect(failed).toMatchObject({
      actorType: 'system',
      agentId: world.agentId,
      metadata: { jobId: job.jobId, errorCode: 'vault_unavailable', source: 'authorize' },
    });
    expect(events.map((event) => event.eventType)).toContain('policy.evaluated');
  });

  it('a login handoff ends with vault_unavailable and the connection can sign in again', async () => {
    const connectionId = await newConnection(r);
    const response = await startLogin(r, connectionId);
    expect(response.statusCode, response.body).toBe(200);
    const body = ConnectionAuthResponse.parse(response.json());
    expect(body).toMatchObject({ jobStatus: 'failed', error: { code: 'vault_unavailable' } });
    expect(body.connection.status).toBe('authentication_required');
    const failed = (await eventsOf(r, connectionId)).find(
      (event) => event.eventType === 'connection.auth_failed',
    )!;
    expect(failed).toMatchObject({
      actorType: 'system',
      metadata: { errorCode: 'vault_unavailable', connectionReset: true },
    });
  });
});

describe('a vault that refuses', () => {
  let fake: FakeVault;
  let r: Rig;
  beforeAll(async () => {
    fake = await startFakeVault({ handle: () => ({ error: 'forbidden' }) });
    r = await rig(
      createVaultGateway({ socketPath: fake.socketPath, isolation: 'shared-uid', timeoutMs: 500 }),
    );
  }, 60_000);
  afterAll(async () => {
    await r.h.close();
    await fake.close();
  });

  it('ends the job with vault_denied', async () => {
    const world = await newWorld(r.h, r.session, r.applicationId);
    const job = OperationJob.parse((await executeFor(r.h, r.session, world)).json());
    expect(job).toMatchObject({ status: 'failed', error: { code: 'vault_denied' } });
    expect(fake.requests.map((request) => request.operation)).toEqual([
      'hello',
      'authorizeJobAccess',
    ]);
    expect(
      (await eventsOf(r, world.connectionId)).find(
        (event) => event.eventType === 'operation.failed',
      )?.metadata,
    ).toMatchObject({ errorCode: 'vault_denied' });
  });
});

describe('races and the sweep', () => {
  let vault: RealVault;
  let r: Rig;
  let afterCommitFailure = false;

  beforeAll(async () => {
    const database = await createTestDatabase();
    vault = await startRealVault(database);
    // Authorizes for real, then reports a timeout: the vault committed, the API does not know.
    const flaky: VaultGateway = {
      ...vault.gateway,
      authorizeJobAccess: async (jobId, ttl) => {
        const result = await vault.gateway.authorizeJobAccess(jobId, ttl);
        if (afterCommitFailure) {
          const { VaultCallError } = await import('@aab/vault-client');
          throw new VaultCallError('unavailable', 'timeout');
        }
        return result;
      },
    };
    r = await rig(flaky, database);
  }, 60_000);
  afterAll(async () => {
    await r.h.close();
    await vault.stop();
    await vault.service.dbHandle.close();
  });

  it('does not fail a job that got its capability while the API was told it timed out', async () => {
    afterCommitFailure = true;
    const world = await newWorld(r.h, r.session, r.applicationId);
    const response = await executeFor(r.h, r.session, world);
    afterCommitFailure = false;
    expect(response.statusCode, response.body).toBe(202);
    const job = OperationJob.parse(response.json());
    expect(job.status).toBe('queued');
    expect((await jobRow(r.h, job.jobId)).capabilityRef).not.toBeNull();
    expect((await eventsOf(r, world.connectionId)).map((event) => event.eventType)).not.toContain(
      'operation.failed',
    );
  });

  it('the sweep ends a queued job with no capability older than a minute, and only that one', async () => {
    const old = await newWorld(r.h, r.session, r.applicationId);
    const young = await newWorld(r.h, r.session, r.applicationId);
    const make = async (world: { agentId: string; connectionId: string }) => {
      const created = await r.h.repos.jobs.createOperation({
        organizationId: r.session.organizationId,
        requestedByUserId: r.session.userId,
        agentId: world.agentId,
        connectionId: world.connectionId,
        runId: null,
        operation: 'orders.list',
        arguments: {},
        argumentsHash: 'f'.repeat(64),
        retrySafe: true,
        policyDecisionId: null,
        timeoutMs: 30_000,
      });
      return created.id;
    };
    const oldJob = await make(old);
    const youngJob = await make(young);
    await r.h.database.db.execute(
      sql`update execution_jobs set created_at = now() - interval '5 minutes' where id = ${oldJob}::uuid`,
    );
    expect(await r.h.app.sweepVaultAuthorizations()).toBe(1);
    expect(await jobRow(r.h, oldJob)).toMatchObject({
      status: 'failed',
      errorCode: 'vault_unavailable',
    });
    expect((await jobRow(r.h, youngJob)).status).toBe('queued');
    expect(
      (await eventsOf(r, old.connectionId)).find((event) => event.eventType === 'operation.failed')
        ?.metadata,
    ).toMatchObject({ source: 'sweep', errorCode: 'vault_unavailable' });
    expect(await r.h.app.sweepVaultAuthorizations()).toBe(0);
  });
});
