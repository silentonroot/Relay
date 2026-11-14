import { randomUUID } from 'node:crypto';
import { ConnectionAuthResponse, OperationJob, Routes } from '@aab/contracts';
import type { AuditEvent, ConnectionStatus } from '@aab/contracts';
import { schema } from '@aab/database';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { FakeWorker } from './fake-worker.js';
import type { Harness, SignedIn } from './helpers.js';
import {
  createHarness,
  expectError,
  expectNoSecretLeaks,
  login,
  path,
  seedOwner,
  seedTenant,
} from './helpers.js';

const owner = { email: 'owner@example.test', password: 'execution test password' };
const other = { email: 'other@example.test', password: 'other owner test password' };
/** Planted in arguments; it must never reach an audit row, a log line or an error body. */
const CANARY = 'NS-424242-canary';

interface World {
  agentId: string;
  connectionId: string;
}

describe('operation execution and login handoff', () => {
  let h: Harness;
  let session: SignedIn;
  let otherSession: SignedIn;
  let worker: FakeWorker;
  let applicationId: string;
  let counter = 0;

  const scope = () => ({ organizationId: session.organizationId, userId: session.userId });
  const post = (url: string, payload?: object, as: SignedIn = session) =>
    h.inject({
      method: 'POST',
      url,
      headers: as.headers,
      ...(payload === undefined ? {} : { payload }),
    });
  const get = (url: string, as: SignedIn = session) =>
    h.inject({ method: 'GET', url, headers: { cookie: as.cookie } });

  async function newWorld(
    options: {
      status?: ConnectionStatus | 'created';
      grant?: false | { effect?: 'allow' | 'deny'; constraints?: object; expiresAt?: string };
      operation?: string;
      as?: SignedIn;
      appId?: string;
    } = {},
  ): Promise<World> {
    counter += 1;
    const as = options.as ?? session;
    const asScope = { organizationId: as.organizationId, userId: as.userId };
    const connection = await post(
      path(Routes.connections),
      {
        applicationId: options.appId ?? (as === session ? applicationId : await otherApp()),
        displayName: `Connection ${counter}`,
      },
      as,
    );
    expect(connection.statusCode, connection.body).toBe(201);
    const connectionId = connection.json<{ id: string }>().id;
    const agent = await post(
      path(Routes.agents),
      { name: `Agent ${counter}`, clientIdentity: `client-${counter}` },
      as,
    );
    const agentId = agent.json<{ id: string }>().id;

    const status = options.status ?? 'active';
    const route: ConnectionStatus[] = ['authentication_required', 'authenticating', 'active'];
    if (status === 'expired') route.push('expired');
    if (status !== 'created') {
      for (const step of route) {
        await h.repos.connections.transitionStatus(asScope, connectionId, { to: step });
      }
    }
    if (options.grant !== false) {
      const grant = await post(
        path(Routes.agentGrants, { id: agentId }),
        {
          connectionId,
          operation: options.operation ?? 'orders.list',
          ...options.grant,
        },
        as,
      );
      expect(grant.statusCode, grant.body).toBe(201);
    }
    return { agentId, connectionId };
  }

  const execute = (world: World, overrides: Record<string, unknown> = {}, as: SignedIn = session) =>
    post(
      path(Routes.operationsExecute),
      {
        agentId: world.agentId,
        connectionId: world.connectionId,
        operation: 'orders.list',
        arguments: {},
        idempotencyKey: `key-${randomUUID()}`,
        ...overrides,
      },
      as,
    );

  const jobRows = async (connectionId: string) =>
    (await h.database.db.select().from(schema.executionJobs)).filter(
      (row) => row.connectionId === connectionId,
    );

  async function events(connectionId?: string): Promise<AuditEvent[]> {
    const page = await h.repos.audit.list(scope(), {
      limit: 200,
      ...(connectionId === undefined ? {} : { connectionId }),
    });
    return page.items;
  }

  beforeAll(async () => {
    h = await createHarness();
    await seedOwner(h, owner);
    await seedTenant(h, other, 'Other Org');
    session = await login(h, owner);
    otherSession = await login(h, other);
    worker = new FakeWorker(h.repos);
    const application = await post(path(Routes.applicationsRegister), {
      adapterId: 'northstar',
      adapterVersion: '0.1.0',
      name: 'Northstar',
      allowedOrigins: ['https://northstar.example.test'],
      authModes: ['browser_session'],
    });
    applicationId = application.json<{ id: string }>().id;
  });

  // The fake worker claims the oldest queued job, so no test may leave one for the next.
  afterEach(async () => {
    const queued = (await h.database.db.select().from(schema.executionJobs)).filter(
      (row) => row.status === 'queued',
    );
    for (const connectionId of new Set(queued.map((row) => row.connectionId))) {
      await h.repos.jobs.cancelForConnection(connectionId, new Date());
    }
  });

  afterAll(async () => {
    await expectNoSecretLeaks(h);
    await h.close();
  });

  /* ---------------------------------------------------------------- policy */

  describe('POST /operations/execute: policy', () => {
    it('denies an ungranted read with no job row and a deny audit event (exit criterion)', async () => {
      const world = await newWorld({ grant: false });
      const response = await execute(world);
      expectError(response, 403, 'denied');
      expect(await jobRows(world.connectionId)).toHaveLength(0);
      const decisions = (await events(world.connectionId)).filter(
        (event) => event.eventType === 'policy.evaluated',
      );
      expect(decisions).toHaveLength(1);
      expect(decisions[0]).toMatchObject({
        decision: 'deny',
        agentId: world.agentId,
        metadata: { operation: 'orders.list', reasonCode: 'no_matching_grant', outcome: 'deny' },
      });
    });

    it('creates a job for a granted read: 202 without a worker, 200 with the result after it', async () => {
      const world = await newWorld();
      const runId = randomUUID();
      const key = `key-${randomUUID()}`;
      const first = await execute(world, { arguments: { limit: 5 }, runId, idempotencyKey: key });
      expect(first.statusCode, first.body).toBe(202);
      const queued = OperationJob.parse(first.json());
      expect(queued).toMatchObject({
        status: 'queued',
        operation: 'orders.list',
        agentId: world.agentId,
        connectionId: world.connectionId,
        runId,
        result: null,
        error: null,
        finishedAt: null,
      });

      const [row] = await jobRows(world.connectionId);
      expect(row).toMatchObject({
        id: queued.jobId,
        kind: 'operation',
        requestedByUserId: session.userId,
        retrySafe: true,
        timeoutMs: 15_000,
        arguments: { limit: 5 },
        runId,
      });
      const decision = (await events(world.connectionId)).find(
        (event) => event.eventType === 'policy.evaluated',
      )!;
      expect(decision).toMatchObject({
        decision: 'allow',
        runId,
        metadata: { operation: 'orders.list', reasonCode: 'allowed', argumentKeys: ['limit'] },
      });
      expect(row!.policyDecisionId).toBe(decision.id);
      expect(queued.auditEventId).toBe(decision.id);

      const finished = await worker.finishNext('succeeded', { result: { orders: [] } });
      const replay = await execute(world, { arguments: { limit: 5 }, runId, idempotencyKey: key });
      expect(replay.statusCode, replay.body).toBe(200);
      const done = OperationJob.parse(replay.json());
      expect(done).toMatchObject({
        jobId: queued.jobId,
        status: 'succeeded',
        result: { orders: [] },
      });
      expect(done.auditEventId).toBe(finished.auditEventId);
      expect(done.auditEventId).not.toBe(decision.id);
      expect(done.finishedAt).not.toBeNull();

      const fetched = await get(path(Routes.operation, { jobId: queued.jobId }));
      expect(fetched.statusCode).toBe(200);
      expect(OperationJob.parse(fetched.json())).toEqual(done);
      expect(await jobRows(world.connectionId)).toHaveLength(1);
    });

    it('reports each terminal status in the job', async () => {
      for (const status of ['failed', 'denied', 'reauth_required', 'outcome_unknown'] as const) {
        const world = await newWorld();
        const created = OperationJob.parse((await execute(world)).json());
        await worker.finishNext(status, {
          error: { code: 'worker_failure', message: 'Something went wrong.' },
        });
        const fetched = OperationJob.parse(
          (await get(path(Routes.operation, { jobId: created.jobId }))).json(),
        );
        expect(fetched).toMatchObject({
          status,
          result: null,
          error: { code: 'worker_failure' },
        });
      }
    });

    it('lets a deny grant beat an allow grant', async () => {
      const world = await newWorld();
      await post(path(Routes.agentGrants, { id: world.agentId }), {
        connectionId: world.connectionId,
        operation: 'orders.list',
        effect: 'deny',
      });
      expectError(await execute(world), 403, 'denied');
      expect(await jobRows(world.connectionId)).toHaveLength(0);
      const decision = (await events(world.connectionId)).find(
        (event) => event.eventType === 'policy.evaluated',
      );
      expect(decision?.metadata).toMatchObject({ reasonCode: 'explicit_deny' });
      expect(decision?.metadata.matchedGrantIds).toHaveLength(1);
    });

    it('denies with an expired or a revoked grant', async () => {
      const world = await newWorld({ grant: false });
      const expiring = await post(path(Routes.agentGrants, { id: world.agentId }), {
        connectionId: world.connectionId,
        operation: 'orders.list',
        expiresAt: new Date(h.clock.now().getTime() + 60_000).toISOString(),
      });
      expect(expiring.statusCode).toBe(201);
      h.clock.advance(120_000);
      expectError(await execute(world), 403, 'denied');

      const revocable = await newWorld();
      const grants = (await get(path(Routes.agentGrants, { id: revocable.agentId }))).json<{
        items: { id: string }[];
      }>().items;
      const revoked = await h.inject({
        method: 'DELETE',
        url: path(Routes.agentGrant, { id: revocable.agentId, grantId: grants[0]!.id }),
        headers: session.headers,
      });
      expect(revoked.statusCode).toBe(200);
      expectError(await execute(revocable), 403, 'denied');
      expect(await jobRows(revocable.connectionId)).toHaveLength(0);
    });

    it('denies a disabled agent and a revoked connection', async () => {
      const disabled = await newWorld();
      await post(path(Routes.agentDisable, { id: disabled.agentId }));
      expectError(await execute(disabled), 403, 'denied');

      const revoked = await newWorld();
      await post(path(Routes.connectionRevoke, { id: revoked.connectionId }), {});
      expectError(await execute(revoked), 403, 'denied');
      expect(await jobRows(disabled.connectionId)).toHaveLength(0);
      expect(await jobRows(revoked.connectionId)).toHaveLength(0);
    });

    it("answers 404 for another owner's agent or connection, and audits nothing about it", async () => {
      const mine = await newWorld();
      const theirs = await newWorld({ as: otherSession });
      const before = (await h.repos.audit.list(scope(), { limit: 200 })).items.length;
      const otherBefore = (
        await h.repos.audit.list(
          { organizationId: otherSession.organizationId, userId: otherSession.userId },
          { limit: 200 },
        )
      ).items.length;

      const attempts = [
        execute({ agentId: theirs.agentId, connectionId: mine.connectionId }),
        execute({ agentId: mine.agentId, connectionId: theirs.connectionId }),
        execute({ agentId: randomUUID(), connectionId: mine.connectionId }),
        execute({ agentId: mine.agentId, connectionId: randomUUID() }),
      ];
      const bodies = [];
      for (const attempt of attempts) {
        const response = await attempt;
        expectError(response, 404, 'not_found');
        bodies.push(response.json<{ error: { message: string } }>().error.message);
      }
      expect(new Set(bodies).size).toBe(1);
      expect((await h.repos.audit.list(scope(), { limit: 200 })).items).toHaveLength(before);
      expect(
        (
          await h.repos.audit.list(
            { organizationId: otherSession.organizationId, userId: otherSession.userId },
            { limit: 200 },
          )
        ).items,
      ).toHaveLength(otherBefore);
    });

    it('denies an operation the adapter does not declare as operation_unknown', async () => {
      const world = await newWorld();
      expectError(await execute(world, { operation: 'orders.delete' }), 403, 'denied');
      const decision = (await events(world.connectionId)).find(
        (event) => event.eventType === 'policy.evaluated',
      );
      expect(decision?.metadata).toMatchObject({ reasonCode: 'operation_unknown' });
      expect(await jobRows(world.connectionId)).toHaveLength(0);
    });

    it('rejects invalid arguments with field paths only', async () => {
      const world = await newWorld();
      const response = await execute(world, { arguments: { status: CANARY, limit: 1000 } });
      const body = expectError(response, 400, 'validation_failed');
      expect(body.error.details?.map((detail) => detail.path).sort()).toEqual([
        'arguments.limit',
        'arguments.status',
      ]);
      expect(response.body).not.toContain(CANARY);
      expect(response.body).not.toContain('1000');
      expect(await jobRows(world.connectionId)).toHaveLength(0);
    });

    it('rejects unknown argument keys and does not echo their names', async () => {
      const world = await newWorld();
      const response = await execute(world, { arguments: { [`extra${CANARY}`]: 1 } });
      expectError(response, 400, 'validation_failed');
      expect(response.body).not.toContain(CANARY);
    });

    it('rejects __proto__ in arguments', async () => {
      const world = await newWorld();
      const response = await h.inject({
        method: 'POST',
        url: path(Routes.operationsExecute),
        headers: { ...session.headers, 'content-type': 'application/json' },
        payload: `{"agentId":"${world.agentId}","connectionId":"${world.connectionId}","operation":"orders.list","idempotencyKey":"key-proto-1","arguments":{"__proto__":{"limit":1}}}`,
      });
      expectError(response, 400, 'validation_failed');
      expect(await jobRows(world.connectionId)).toHaveLength(0);
    });

    it('applies obligations: a maxResults constraint supplies the limit in the stored job', async () => {
      const world = await newWorld({ grant: { constraints: { maxResults: 7 } } });
      const response = await execute(world, { arguments: {} });
      expect(response.statusCode, response.body).toBe(202);
      const [row] = await jobRows(world.connectionId);
      expect(row!.arguments).toEqual({ limit: 7 });

      // A limit above the cap does not satisfy the grant at all.
      expectError(await execute(world, { arguments: { limit: 50 } }), 403, 'denied');
      expect(await jobRows(world.connectionId)).toHaveLength(1);
    });
  });

  describe('POST /operations/execute: connection state', () => {
    it('answers 409 reauth_required for an expired connection with a grant', async () => {
      const world = await newWorld({ status: 'expired' });
      expectError(await execute(world), 409, 'reauth_required');
      expect(await jobRows(world.connectionId)).toHaveLength(0);
      const decision = (await events(world.connectionId)).find(
        (event) => event.eventType === 'policy.evaluated',
      );
      expect(decision).toMatchObject({ decision: 'deny' });
      expect(decision?.metadata).toMatchObject({ reasonCode: 'connection_not_active' });
    });

    it('answers 403 denied (not 409) for an expired connection without a grant', async () => {
      const world = await newWorld({ status: 'expired', grant: false });
      const response = await execute(world);
      expectError(response, 403, 'denied');
      expect(response.body).not.toMatch(/expired|connection_not_active/);
    });

    it('answers 409 reauth_required for a connection that is waiting for a login', async () => {
      const world = await newWorld({ status: 'created' });
      expectError(await execute(world), 409, 'reauth_required');
    });
  });

  /* ---------------------------------------------------------------- idempotency */

  describe('idempotency', () => {
    it('returns the same job for the same key and body, and creates no second row', async () => {
      const world = await newWorld();
      const body = { arguments: { limit: 3 }, idempotencyKey: 'idem-key-same-1' };
      const first = OperationJob.parse((await execute(world, body)).json());
      const second = OperationJob.parse((await execute(world, body)).json());
      expect(second.jobId).toBe(first.jobId);
      expect(await jobRows(world.connectionId)).toHaveLength(1);
      const decisions = (await events(world.connectionId)).filter(
        (event) => event.eventType === 'policy.evaluated',
      );
      expect(decisions).toHaveLength(1);
    });

    it('answers 409 for the same key with a different body', async () => {
      const world = await newWorld();
      const key = 'idem-key-diff-1';
      expect((await execute(world, { idempotencyKey: key })).statusCode).toBe(202);
      expectError(
        await execute(world, { idempotencyKey: key, arguments: { limit: 2 } }),
        409,
        'conflict',
      );
      expectError(
        await execute(world, { idempotencyKey: key, runId: randomUUID() }),
        409,
        'conflict',
      );
      expect(await jobRows(world.connectionId)).toHaveLength(1);
    });

    it('creates one job for two concurrent identical requests', async () => {
      const world = await newWorld();
      const body = { arguments: { limit: 4 }, idempotencyKey: 'idem-key-race-1' };
      const [a, b] = await Promise.all([execute(world, body), execute(world, body)]);
      expect(a.statusCode, a.body).toBe(202);
      expect(b.statusCode, b.body).toBe(202);
      expect(OperationJob.parse(a.json()).jobId).toBe(OperationJob.parse(b.json()).jobId);
      expect(await jobRows(world.connectionId)).toHaveLength(1);
      // The loser's policy event rolled back with its job.
      const decisions = (await events(world.connectionId)).filter(
        (event) => event.eventType === 'policy.evaluated',
      );
      expect(decisions).toHaveLength(1);
    });
  });

  /* ---------------------------------------------------------------- audit and logs */

  it('never puts argument values in audit metadata, responses or logs', async () => {
    const world = await newWorld({ operation: 'orders.get' });
    h.forbiddenInLogs.add(CANARY);
    h.forbiddenInResponses.add(CANARY);
    const response = await execute(world, {
      operation: 'orders.get',
      arguments: { orderId: 'NS-424242' },
    });
    // The planted value is the argument itself (NS-424242 plus a suffix is not valid input).
    expect(response.statusCode, response.body).toBe(202);
    const invalid = await execute(world, {
      operation: 'orders.get',
      arguments: { orderId: CANARY },
    });
    expectError(invalid, 400, 'validation_failed');
    const denied = await execute(
      { ...world, agentId: (await newWorld({ grant: false })).agentId },
      { operation: 'orders.get', arguments: { orderId: CANARY } },
    );
    expect([400, 403]).toContain(denied.statusCode);

    const all = [...(await h.repos.audit.list(scope(), { limit: 500 })).items].map((event) =>
      JSON.stringify(event),
    );
    expect(all.length).toBeGreaterThan(0);
    for (const row of all) {
      expect(row).not.toContain(CANARY);
      expect(row).not.toContain('NS-424242');
    }
    expect(h.logs.join('')).not.toContain('NS-424242');
  });

  /* ---------------------------------------------------------------- GET /operations/:jobId */

  describe('GET /operations/:jobId', () => {
    it('is 404 for a login job, another owner, and a missing job', async () => {
      const world = await newWorld({ status: 'created', grant: false });
      const started = ConnectionAuthResponse.parse(
        (await post(path(Routes.connectionAuthStart, { id: world.connectionId }))).json(),
      );
      expectError(await get(path(Routes.operation, { jobId: started.jobId })), 404, 'not_found');

      const opWorld = await newWorld();
      const job = OperationJob.parse((await execute(opWorld)).json());
      expectError(
        await get(path(Routes.operation, { jobId: job.jobId }), otherSession),
        404,
        'not_found',
      );
      expectError(await get(path(Routes.operation, { jobId: randomUUID() })), 404, 'not_found');
    });
  });

  /* ---------------------------------------------------------------- login handoff */

  describe('connection login handoff', () => {
    it('starts, completes with the worker, and returns the active connection', async () => {
      const world = await newWorld({ status: 'created', grant: false });
      const start = await post(path(Routes.connectionAuthStart, { id: world.connectionId }));
      expect(start.statusCode, start.body).toBe(200);
      const started = ConnectionAuthResponse.parse(start.json());
      expect(started).toMatchObject({
        connection: { id: world.connectionId, status: 'authenticating' },
        jobStatus: 'queued',
        error: null,
      });

      const [row] = await jobRows(world.connectionId);
      expect(row).toMatchObject({ id: started.jobId, kind: 'login', timeoutMs: 600_000 });
      const history = await h.repos.connections.listStatusEvents(scope(), world.connectionId);
      expect(history!.map((entry) => entry.toStatus)).toEqual([
        'created',
        'authentication_required',
        'authenticating',
      ]);
      const audit = (await events(world.connectionId)).find(
        (event) => event.eventType === 'connection.auth_started',
      );
      expect(audit?.metadata).toMatchObject({
        connectionId: world.connectionId,
        jobId: started.jobId,
        adapterId: 'northstar',
      });

      // The worker has not finished: 202 with the connection still authenticating.
      const pending = await post(path(Routes.connectionAuthComplete, { id: world.connectionId }));
      expect(pending.statusCode, pending.body).toBe(202);
      const pendingBody = ConnectionAuthResponse.parse(pending.json());
      expect(pendingBody.connection.status).toBe('authenticating');
      expect(pendingBody.jobId).toBe(started.jobId);

      const job = await worker.claim();
      expect(job?.completionRequestedAt).not.toBeNull();
      await worker.completeLogin(job!, 'active');
      const done = await post(path(Routes.connectionAuthComplete, { id: world.connectionId }));
      // The handoff is over, so there is no active login job any more.
      expectError(done, 409, 'conflict');
      const connection = (await get(path(Routes.connection, { id: world.connectionId }))).json<{
        status: string;
        externalAccountHint: string;
        sessionExpiresAt: string;
      }>();
      expect(connection.status).toBe('active');
      expect(connection.externalAccountHint).toBe('n***@example.test');
      expect(connection.sessionExpiresAt).not.toBeNull();
    });

    it('moves an authentication_required connection to authenticating', async () => {
      const world = await newWorld({ status: 'created', grant: false });
      await h.repos.connections.transitionStatus(scope(), world.connectionId, {
        to: 'authentication_required',
      });
      const start = await post(path(Routes.connectionAuthStart, { id: world.connectionId }));
      expect(start.statusCode, start.body).toBe(200);
      const history = await h.repos.connections.listStatusEvents(scope(), world.connectionId);
      expect(history!.map((entry) => entry.toStatus)).toEqual([
        'created',
        'authentication_required',
        'authenticating',
      ]);
    });

    it('answers 409 to a second start and to complete without a start', async () => {
      const world = await newWorld({ status: 'created', grant: false });
      const url = path(Routes.connectionAuthStart, { id: world.connectionId });
      expect((await post(url)).statusCode).toBe(200);
      expectError(await post(url), 409, 'conflict');
      expect(
        (await jobRows(world.connectionId)).filter((row) => row.kind === 'login'),
      ).toHaveLength(1);

      const idle = await newWorld({ grant: false });
      expectError(
        await post(path(Routes.connectionAuthComplete, { id: idle.connectionId })),
        409,
        'conflict',
      );
    });

    it('answers 409 for a revoked connection, 409 for an adapter without a login path, 404 for another owner', async () => {
      const revoked = await newWorld({ grant: false });
      await post(path(Routes.connectionRevoke, { id: revoked.connectionId }), {});
      expectError(
        await post(path(Routes.connectionAuthStart, { id: revoked.connectionId })),
        409,
        'conflict',
      );

      // An application whose adapter this API does not know cannot be signed in to.
      const unknownApp = await post(path(Routes.applicationsRegister), {
        adapterId: 'ledgerly',
        adapterVersion: '1.0.0',
        name: 'Ledgerly',
        allowedOrigins: ['https://ledgerly.example.test'],
        authModes: ['browser_session'],
      });
      const unknown = await newWorld({
        status: 'created',
        grant: false,
        appId: unknownApp.json<{ id: string }>().id,
      });
      const response = await post(path(Routes.connectionAuthStart, { id: unknown.connectionId }));
      expectError(response, 409, 'conflict');
      expect(await jobRows(unknown.connectionId)).toHaveLength(0);

      const theirs = await newWorld({
        as: otherSession,
        grant: false,
        status: 'created',
        appId: await otherApp(),
      });
      expectError(
        await post(path(Routes.connectionAuthStart, { id: theirs.connectionId })),
        404,
        'not_found',
      );
      expectError(
        await post(path(Routes.connectionAuthComplete, { id: theirs.connectionId })),
        404,
        'not_found',
      );
    });
  });

  /* ---------------------------------------------------------------- revocation and grants */

  describe('revocation', () => {
    it('deletes ciphertext, cancels queued jobs and audits the deletion', async () => {
      const world = await newWorld();
      const queued = OperationJob.parse((await execute(world)).json());
      const ensured = await h.repos.vault.ensureSecret({
        connectionId: world.connectionId,
        secretType: 'session_snapshot',
        now: new Date(),
      });
      await h.repos.vault.putVersion({
        secretId: ensured.secretId,
        version: ensured.nextVersion,
        sealed: {
          algorithm: 'test',
          ciphertext: Buffer.from('fake sealed bytes'),
          nonce: Buffer.alloc(12, 1),
          authTag: Buffer.alloc(16, 2),
          wrappedDek: Buffer.alloc(48, 3),
          kekVersion: 1,
          aadVersion: 1,
        },
        now: new Date(),
      });
      const versionsFor = async () =>
        (await h.database.db.select().from(schema.vaultSecretVersions)).filter(
          (row) => row.secretId === ensured.secretId,
        );
      expect(await versionsFor()).toHaveLength(1);

      const revoke = await post(path(Routes.connectionRevoke, { id: world.connectionId }), {});
      expect(revoke.statusCode, revoke.body).toBe(200);
      expect(await versionsFor()).toHaveLength(0);

      const fetched = OperationJob.parse(
        (await get(path(Routes.operation, { jobId: queued.jobId }))).json(),
      );
      expect(fetched).toMatchObject({ status: 'cancelled', error: { code: 'cancelled' } });

      const deleted = (await events(world.connectionId)).find(
        (event) => event.eventType === 'vault.secret_deleted',
      );
      expect(deleted?.metadata).toMatchObject({
        connectionId: world.connectionId,
        vaultEntryIds: [ensured.secretId],
        versionsDeleted: 1,
      });
      expect(JSON.stringify(deleted)).not.toContain('fake sealed bytes');
    });

    it('writes no vault event when there was nothing to delete', async () => {
      const world = await newWorld();
      await post(path(Routes.connectionRevoke, { id: world.connectionId }), {});
      expect(
        (await events(world.connectionId)).filter(
          (event) => event.eventType === 'vault.secret_deleted',
        ),
      ).toHaveLength(0);
    });
  });

  describe('grant creation', () => {
    it('rejects an operation the adapter does not declare, allow or deny', async () => {
      const world = await newWorld({ grant: false });
      for (const effect of ['allow', 'deny'] as const) {
        const response = await post(path(Routes.agentGrants, { id: world.agentId }), {
          connectionId: world.connectionId,
          operation: 'orders.explode',
          effect,
        });
        const body = expectError(response, 400, 'validation_failed');
        expect(body.error.details?.[0]?.path).toBe('operation');
      }
      const grants = (await get(path(Routes.agentGrants, { id: world.agentId }))).json<{
        items: unknown[];
      }>();
      expect(grants.items).toHaveLength(0);
    });

    it('still answers 404 for a foreign agent or connection before checking the operation', async () => {
      const mine = await newWorld({ grant: false });
      const theirs = await newWorld({ as: otherSession, grant: false, appId: await otherApp() });
      expectError(
        await post(path(Routes.agentGrants, { id: mine.agentId }), {
          connectionId: theirs.connectionId,
          operation: 'orders.explode',
        }),
        404,
        'not_found',
      );
    });
  });

  /* ---------------------------------------------------------------- guards */

  describe('guards', () => {
    const targets = () => [
      { url: path(Routes.operationsExecute), payload: {} as object | undefined },
      { url: path(Routes.connectionAuthStart, { id: randomUUID() }), payload: undefined },
      { url: path(Routes.connectionAuthComplete, { id: randomUUID() }), payload: undefined },
      { url: path(Routes.connectionRevoke, { id: randomUUID() }), payload: undefined },
    ];

    it('requires a session (401) and a CSRF token (403) on every new mutation', async () => {
      for (const { url, payload } of targets()) {
        expectError(
          await h.inject({ method: 'POST', url, ...(payload === undefined ? {} : { payload }) }),
          401,
          'unauthenticated',
        );
        expectError(
          await h.inject({
            method: 'POST',
            url,
            headers: { cookie: session.cookie },
            ...(payload === undefined ? {} : { payload }),
          }),
          403,
          'csrf_failed',
        );
      }
      expectError(
        await h.inject({ method: 'GET', url: path(Routes.operation, { jobId: randomUUID() }) }),
        401,
        'unauthenticated',
      );
    });

    it('accepts auth/start and auth/complete without a body or content type', async () => {
      const world = await newWorld({ status: 'created', grant: false });
      const start = await h.inject({
        method: 'POST',
        url: path(Routes.connectionAuthStart, { id: world.connectionId }),
        headers: session.headers,
      });
      expect(start.statusCode, start.body).toBe(200);
      const complete = await h.inject({
        method: 'POST',
        url: path(Routes.connectionAuthComplete, { id: world.connectionId }),
        headers: session.headers,
      });
      expect(complete.statusCode, complete.body).toBe(202);
    });

    it('lists the new routes in the OpenAPI document', async () => {
      const document = (await get('/v1/openapi.json')).json<{ paths: Record<string, unknown> }>();
      expect(Object.keys(document.paths)).toEqual(
        expect.arrayContaining([
          '/v1/operations/execute',
          '/v1/operations/{jobId}',
          '/v1/connections/{id}/auth/start',
          '/v1/connections/{id}/auth/complete',
        ]),
      );
    });
  });

  /** An application in the other organization, created on first use. */
  let otherAppId: string | undefined;
  async function otherApp(): Promise<string> {
    if (otherAppId === undefined) {
      const response = await post(
        path(Routes.applicationsRegister),
        {
          adapterId: 'northstar',
          adapterVersion: '0.1.0',
          name: 'Northstar',
          allowedOrigins: ['https://northstar.example.test'],
          authModes: ['browser_session'],
        },
        otherSession,
      );
      otherAppId = response.json<{ id: string }>().id;
    }
    return otherAppId;
  }
});
