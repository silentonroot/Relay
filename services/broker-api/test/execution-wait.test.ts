import { randomUUID } from 'node:crypto';
import { ConnectionAuthResponse, OperationJob, Routes } from '@aab/contracts';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { FakeWorker } from './fake-worker.js';
import type { Harness, SignedIn } from './helpers.js';
import { createHarness, expectNoSecretLeaks, login, path, seedOwner } from './helpers.js';

const owner = { email: 'owner@example.test', password: 'wait test password' };

/** A long wait budget, so a worker that finishes mid-request is seen by that request. */
describe('waiting for the worker', () => {
  let h: Harness;
  let session: SignedIn;
  let worker: FakeWorker;
  let applicationId: string;

  const post = (url: string, payload?: object) =>
    h.inject({
      method: 'POST',
      url,
      headers: session.headers,
      ...(payload === undefined ? {} : { payload }),
    });

  async function until<T>(read: () => Promise<T | null>): Promise<T> {
    for (let attempt = 0; attempt < 200; attempt += 1) {
      const value = await read();
      if (value !== null) return value;
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
    throw new Error('timed out waiting for the request to reach the database');
  }

  beforeAll(async () => {
    h = await createHarness({ config: { jobWaitMs: 5_000 } });
    await seedOwner(h, owner);
    session = await login(h, owner);
    worker = new FakeWorker(h.repos);
    applicationId = (
      await post(path(Routes.applicationsRegister), {
        adapterId: 'northstar',
        adapterVersion: '0.1.0',
        name: 'Northstar',
        allowedOrigins: ['https://northstar.example.test'],
        authModes: ['browser_session'],
      })
    ).json<{ id: string }>().id;
  });

  afterAll(async () => {
    await expectNoSecretLeaks(h);
    await h.close();
  });

  it('execute answers 200 with the result when the worker finishes during the wait', async () => {
    const connectionId = (
      await post(path(Routes.connections), { applicationId, displayName: 'Wait connection' })
    ).json<{ id: string }>().id;
    const scope = { organizationId: session.organizationId, userId: session.userId };
    for (const to of ['authentication_required', 'authenticating', 'active'] as const) {
      await h.repos.connections.transitionStatus(scope, connectionId, { to });
    }
    const agentId = (
      await post(path(Routes.agents), { name: 'Wait agent', clientIdentity: 'wait-client' })
    ).json<{ id: string }>().id;
    await post(path(Routes.agentGrants, { id: agentId }), {
      connectionId,
      operation: 'orders.list',
    });

    const pending = post(path(Routes.operationsExecute), {
      agentId,
      connectionId,
      operation: 'orders.list',
      arguments: {},
      idempotencyKey: `key-${randomUUID()}`,
    });
    const job = await until(() => worker.claim());
    await worker.finish(job, 'succeeded', { result: { orders: [] } });
    const response = await pending;
    expect(response.statusCode, response.body).toBe(200);
    expect(OperationJob.parse(response.json())).toMatchObject({
      jobId: job.id,
      status: 'succeeded',
      result: { orders: [] },
    });
  });

  it('auth/complete answers 200 with the connection and the job error when the login fails', async () => {
    const connectionId = (
      await post(path(Routes.connections), { applicationId, displayName: 'Login connection' })
    ).json<{ id: string }>().id;
    const started = ConnectionAuthResponse.parse(
      (await post(path(Routes.connectionAuthStart, { id: connectionId }))).json(),
    );

    const pending = post(path(Routes.connectionAuthComplete, { id: connectionId }));
    // The worker acts once the owner has said the sign-in is done.
    await until(async () => {
      const job = await h.repos.jobs.getInternal(started.jobId);
      return job === null || job.completionRequestedAt === null ? null : job;
    });
    const job = (await worker.claim())!;
    await worker.completeLogin(job, 'failed', 'The sign-in window was closed.');

    const response = await pending;
    expect(response.statusCode, response.body).toBe(200);
    const body = ConnectionAuthResponse.parse(response.json());
    expect(body.connection).toMatchObject({
      status: 'authentication_required',
      statusReason: 'The sign-in window was closed.',
    });
    expect(body).toMatchObject({
      jobId: started.jobId,
      jobStatus: 'failed',
      error: { code: 'login_not_completed' },
    });
  });

  it('auth/complete answers 200 with an active connection when the login succeeds', async () => {
    const connectionId = (
      await post(path(Routes.connections), { applicationId, displayName: 'Login ok connection' })
    ).json<{ id: string }>().id;
    const started = ConnectionAuthResponse.parse(
      (await post(path(Routes.connectionAuthStart, { id: connectionId }))).json(),
    );
    const pending = post(path(Routes.connectionAuthComplete, { id: connectionId }));
    await until(async () => {
      const job = await h.repos.jobs.getInternal(started.jobId);
      return job === null || job.completionRequestedAt === null ? null : job;
    });
    await worker.completeLogin((await worker.claim())!, 'active');

    const response = await pending;
    expect(response.statusCode, response.body).toBe(200);
    const body = ConnectionAuthResponse.parse(response.json());
    expect(body.connection).toMatchObject({
      status: 'active',
      externalAccountHint: 'n***@example.test',
    });
    expect(body.connection.sessionExpiresAt).not.toBeNull();
    expect(body).toMatchObject({ jobStatus: 'succeeded', error: null });
  });
});
