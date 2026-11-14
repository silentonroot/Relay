import type { JsonObject } from '@aab/contracts';
import { sql } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { rowsOf } from '../src/client.js';
import {
  ConflictError,
  createRepositories,
  InvalidTransitionError,
  NotFoundError,
  ValidationError,
} from '../src/index.js';
import type { DatabaseHandle, Repositories } from '../src/index.js';
import { openTestDb, seedConnectionAndAgent, seedTenant, UNKNOWN_ID } from './helpers.js';
import type { Tenant } from './helpers.js';

let handle: DatabaseHandle;
let repositories: Repositories;
let tenant: Tenant;
let other: Tenant;
let teammate: Tenant;

const T0 = new Date('2030-01-01T00:00:00.000Z');
const at = (ms: number) => new Date(T0.getTime() + ms);

beforeAll(async () => {
  handle = await openTestDb();
  repositories = createRepositories(handle.db);
  tenant = await seedTenant(repositories, 'exec');
  other = await seedTenant(repositories, 'exec-other');
  // A second member of the first organization.
  const user = await repositories.users.create({
    email: 'exec-teammate@synthetic.test',
    passwordHash: 'scrypt$synthetic$not-a-real-hash',
  });
  await repositories.organizations.addMember({
    organizationId: tenant.organization.id,
    userId: user.id,
    role: 'member',
  });
  teammate = {
    organization: tenant.organization,
    user,
    scope: { organizationId: tenant.organization.id, userId: user.id },
  };
});

afterAll(async () => {
  await handle.close();
});

/** claimNext is global, so every test starts with no live jobs from earlier tests. */
beforeEach(async () => {
  await handle.db.execute(
    sql`update execution_jobs set status = 'cancelled' where status in ('queued', 'running')`,
  );
});

async function fixture() {
  return seedConnectionAndAgent(repositories, tenant);
}

function operationInput(
  f: Awaited<ReturnType<typeof fixture>>,
  overrides: Partial<Parameters<Repositories['jobs']['createOperation']>[0]> = {},
) {
  return {
    organizationId: tenant.organization.id,
    requestedByUserId: tenant.user.id,
    agentId: f.agent.id,
    connectionId: f.connection.id,
    runId: null,
    operation: 'orders.list',
    arguments: { limit: 5 },
    retrySafe: true,
    policyDecisionId: null,
    timeoutMs: 30_000,
    ...overrides,
  };
}

describe('jobs.createOperation and createLogin', () => {
  it('queue an operation job and a login job with the right shape', async () => {
    const f = await fixture();
    const op = await repositories.jobs.createOperation(operationInput(f));
    expect(op).toMatchObject({
      kind: 'operation',
      status: 'queued',
      agentId: f.agent.id,
      operation: 'orders.list',
      arguments: { limit: 5 },
      retrySafe: true,
      attemptCount: 0,
      workerId: null,
      result: null,
      error: null,
    });

    const login = await repositories.jobs.createLogin({
      organizationId: tenant.organization.id,
      requestedByUserId: tenant.user.id,
      connectionId: f.connection.id,
      timeoutMs: 600_000,
    });
    expect(login).toMatchObject({
      kind: 'login',
      status: 'queued',
      agentId: null,
      operation: null,
      arguments: null,
    });
  });

  it('refuse an agent or connection from another organization as not found', async () => {
    const f = await fixture();
    const foreign = await seedConnectionAndAgent(repositories, other);
    await expect(
      repositories.jobs.createOperation(operationInput(f, { agentId: foreign.agent.id })),
    ).rejects.toBeInstanceOf(NotFoundError);
    await expect(
      repositories.jobs.createOperation(operationInput(f, { connectionId: foreign.connection.id })),
    ).rejects.toBeInstanceOf(NotFoundError);
    await expect(
      repositories.jobs.createLogin({
        organizationId: tenant.organization.id,
        requestedByUserId: teammate.user.id,
        connectionId: f.connection.id,
        timeoutMs: 1000,
      }),
    ).rejects.toBeInstanceOf(NotFoundError);
  });

  it('reject malformed input', async () => {
    const f = await fixture();
    await expect(
      repositories.jobs.createOperation(operationInput(f, { timeoutMs: 0 })),
    ).rejects.toBeInstanceOf(ValidationError);
    await expect(
      repositories.jobs.createOperation(
        operationInput(f, { arguments: [] as unknown as Record<string, never> }),
      ),
    ).rejects.toBeInstanceOf(ValidationError);
  });

  it('allow only one non-terminal login job per connection', async () => {
    const f = await fixture();
    const input = {
      organizationId: tenant.organization.id,
      requestedByUserId: tenant.user.id,
      connectionId: f.connection.id,
      timeoutMs: 600_000,
    };
    const first = await repositories.jobs.createLogin(input);
    await expect(repositories.jobs.createLogin(input)).rejects.toBeInstanceOf(ConflictError);
    expect((await repositories.jobs.findActiveLogin(f.connection.id))?.id).toBe(first.id);

    // A running login is still active.
    await repositories.jobs.claimNext({ workerId: 'w1', leaseMs: 1000, now: T0 });
    await expect(repositories.jobs.createLogin(input)).rejects.toBeInstanceOf(ConflictError);

    await repositories.jobs.complete(first.id, 'w1', {
      status: 'failed',
      error: { code: 'login_not_completed', message: 'x' },
      now: at(10),
    });
    expect(await repositories.jobs.findActiveLogin(f.connection.id)).toBeNull();
    const second = await repositories.jobs.createLogin(input);
    expect(second.id).not.toBe(first.id);

    // Operation jobs are not limited.
    await repositories.jobs.createOperation(operationInput(f));
    await repositories.jobs.createOperation(operationInput(f));
  });
});

describe('database constraints on execution_jobs', () => {
  it('reject kind/field mismatches, bad enums and non-object payloads', async () => {
    const f = await fixture();
    const org = tenant.organization.id;
    const usr = tenant.user.id;
    const base = sql`insert into execution_jobs (organization_id, requested_by_user_id, kind, agent_id, connection_id, operation, arguments, timeout_ms, status, error_code) values`;
    const row = (
      kind: string,
      agent: string | null,
      operation: string | null,
      args: string | null,
      status = 'queued',
      errorCode: string | null = null,
    ) =>
      sql`${base} (${org}, ${usr}, ${kind}, ${agent}, ${f.connection.id}, ${operation}, ${args}::jsonb, 1000, ${status}, ${errorCode})`;

    const invalid = [
      row('operation', null, 'orders.list', '{}'),
      row('operation', f.agent.id, null, '{}'),
      row('operation', f.agent.id, 'orders.list', null),
      row('login', f.agent.id, null, null),
      row('login', null, 'orders.list', null),
      row('login', null, null, '{}'),
      row('sync', null, null, null),
      row('operation', f.agent.id, 'orders.list', '[]'),
      row('operation', f.agent.id, 'orders.list', '{}', 'paused'),
      row('operation', f.agent.id, 'orders.list', '{}', 'failed', 'boom'),
    ];
    for (const statement of invalid) {
      await expect(handle.db.execute(statement)).rejects.toThrow();
    }
    // The same statements with valid values go through.
    await handle.db.execute(row('operation', f.agent.id, 'orders.list', '{}', 'failed', 'timeout'));
    await handle.db.execute(row('login', null, null, null));
  });

  it('reject bad idempotency hashes, versions and secret statuses', async () => {
    const f = await fixture();
    const job = await repositories.jobs.createOperation(operationInput(f));
    await expect(
      handle.db.execute(
        sql`insert into operation_requests (agent_id, idempotency_key, request_hash, job_id) values (${f.agent.id}, 'k-1', 'nothex', ${job.id})`,
      ),
    ).rejects.toThrow();
    await expect(
      handle.db.execute(
        sql`insert into vault_secrets (connection_id, secret_type, status) values (${f.connection.id}, 'session_snapshot', 'weird')`,
      ),
    ).rejects.toThrow();
  });
});

describe('jobs.getForOwner and getInternal', () => {
  it('return the job to its requester only', async () => {
    const f = await fixture();
    const job = await repositories.jobs.createOperation(operationInput(f));
    const owner = { organizationId: tenant.organization.id, ownerUserId: tenant.user.id };
    expect((await repositories.jobs.getForOwner(owner, job.id)).id).toBe(job.id);

    const notFound = [
      repositories.jobs.getForOwner(
        { organizationId: tenant.organization.id, ownerUserId: teammate.user.id },
        job.id,
      ),
      repositories.jobs.getForOwner(
        { organizationId: other.organization.id, ownerUserId: tenant.user.id },
        job.id,
      ),
      repositories.jobs.getForOwner(
        { organizationId: other.organization.id, ownerUserId: other.user.id },
        job.id,
      ),
      repositories.jobs.getForOwner(owner, UNKNOWN_ID),
      repositories.jobs.getForOwner(owner, 'not-a-uuid'),
    ];
    const errors = await Promise.all(notFound.map((p) => p.catch((error: unknown) => error)));
    for (const error of errors) {
      expect(error).toBeInstanceOf(NotFoundError);
      // Indistinguishable from a missing job.
      expect((error as Error).message).toBe('job not found');
    }
  });

  it('getInternal is unscoped and null when missing', async () => {
    const f = await fixture();
    const job = await repositories.jobs.createOperation(operationInput(f));
    expect((await repositories.jobs.getInternal(job.id))?.id).toBe(job.id);
    expect(await repositories.jobs.getInternal(UNKNOWN_ID)).toBeNull();
    expect(await repositories.jobs.getInternal('nope')).toBeNull();
  });
});

describe('jobs.claimNext', () => {
  it('claims the oldest queued job and sets the lease fields', async () => {
    const f = await fixture();
    const first = await repositories.jobs.createOperation(operationInput(f));
    const g = await fixture();
    await repositories.jobs.createOperation(operationInput(g));

    const claimed = await repositories.jobs.claimNext({ workerId: 'w1', leaseMs: 5000, now: T0 });
    expect(claimed).toMatchObject({
      id: first.id,
      status: 'running',
      attemptCount: 1,
      workerId: 'w1',
      leaseExpiresAt: at(5000).toISOString(),
      startedAt: T0.toISOString(),
    });
  });

  it('returns null when nothing is queued', async () => {
    expect(
      await repositories.jobs.claimNext({ workerId: 'w1', leaseMs: 5000, now: T0 }),
    ).toBeNull();
  });

  it('never runs two jobs of one connection, and moves on to other connections', async () => {
    const f = await fixture();
    const g = await fixture();
    const a1 = await repositories.jobs.createOperation(operationInput(f));
    const a2 = await repositories.jobs.createOperation(operationInput(f));
    const b1 = await repositories.jobs.createOperation(operationInput(g));

    const one = await repositories.jobs.claimNext({ workerId: 'w1', leaseMs: 5000, now: T0 });
    const two = await repositories.jobs.claimNext({ workerId: 'w2', leaseMs: 5000, now: T0 });
    const three = await repositories.jobs.claimNext({ workerId: 'w3', leaseMs: 5000, now: T0 });
    expect(one?.id).toBe(a1.id);
    expect(two?.id).toBe(b1.id);
    expect(three).toBeNull();

    await repositories.jobs.complete(a1.id, 'w1', { status: 'succeeded', result: {}, now: at(1) });
    const four = await repositories.jobs.claimNext({ workerId: 'w3', leaseMs: 5000, now: at(2) });
    expect(four?.id).toBe(a2.id);
  });

  it('keeps started_at and counts the attempt when a job is claimed again', async () => {
    const f = await fixture();
    const job = await repositories.jobs.createOperation(operationInput(f));
    await repositories.jobs.claimNext({ workerId: 'w1', leaseMs: 1000, now: T0 });
    await repositories.jobs.recoverExpiredLeases({ now: at(2000), maxAttempts: 3 });
    const again = await repositories.jobs.claimNext({
      workerId: 'w2',
      leaseMs: 1000,
      now: at(3000),
    });
    expect(again).toMatchObject({
      id: job.id,
      attemptCount: 2,
      workerId: 'w2',
      startedAt: T0.toISOString(),
    });
  });
});

describe('jobs.extendLease', () => {
  it('extends only for the worker that holds a running job', async () => {
    const f = await fixture();
    const job = await repositories.jobs.createOperation(operationInput(f));
    expect(await repositories.jobs.extendLease(job.id, 'w1', 1000, T0)).toBe(false);
    await repositories.jobs.claimNext({ workerId: 'w1', leaseMs: 1000, now: T0 });
    expect(await repositories.jobs.extendLease(job.id, 'w2', 9000, at(500))).toBe(false);
    expect(await repositories.jobs.extendLease(job.id, 'w1', 9000, at(500))).toBe(true);
    expect((await repositories.jobs.getInternal(job.id))?.leaseExpiresAt).toBe(
      at(9500).toISOString(),
    );
    await repositories.jobs.complete(job.id, 'w1', { status: 'succeeded', now: at(600) });
    expect(await repositories.jobs.extendLease(job.id, 'w1', 9000, at(700))).toBe(false);
    expect(await repositories.jobs.extendLease(UNKNOWN_ID, 'w1', 9000, at(700))).toBe(false);
  });
});

describe('jobs.complete', () => {
  it('stores the result of a succeeded job and clears nothing else', async () => {
    const f = await fixture();
    const job = await repositories.jobs.createOperation(operationInput(f));
    await repositories.jobs.claimNext({ workerId: 'w1', leaseMs: 1000, now: T0 });
    const done = await repositories.jobs.complete(job.id, 'w1', {
      status: 'succeeded',
      result: { orders: [1, 2] },
      auditEventId: UNKNOWN_ID,
      now: at(100),
    });
    expect(done).toMatchObject({
      status: 'succeeded',
      result: { orders: [1, 2] },
      error: null,
      auditEventId: UNKNOWN_ID,
      finishedAt: at(100).toISOString(),
    });
  });

  it('stores the error but never a result for other terminal statuses', async () => {
    const f = await fixture();
    const job = await repositories.jobs.createOperation(operationInput(f));
    await repositories.jobs.claimNext({ workerId: 'w1', leaseMs: 1000, now: T0 });
    const done = await repositories.jobs.complete(job.id, 'w1', {
      status: 'reauth_required',
      result: { leaked: true },
      error: { code: 'session_expired', message: 'y'.repeat(500) },
      now: at(100),
    });
    expect(done.status).toBe('reauth_required');
    expect(done.result).toBeNull();
    expect(done.error?.code).toBe('session_expired');
    expect(done.error?.message).toHaveLength(300);
  });

  it('rejects a wrong worker, a non-running job and a non-terminal status', async () => {
    const f = await fixture();
    const job = await repositories.jobs.createOperation(operationInput(f));
    const outcome = { status: 'succeeded' as const, now: at(100) };

    // Still queued.
    await expect(repositories.jobs.complete(job.id, 'w1', outcome)).rejects.toBeInstanceOf(
      ConflictError,
    );
    await repositories.jobs.claimNext({ workerId: 'w1', leaseMs: 1000, now: T0 });
    await expect(repositories.jobs.complete(job.id, 'w2', outcome)).rejects.toBeInstanceOf(
      ConflictError,
    );
    await expect(
      repositories.jobs.complete(job.id, 'w1', { status: 'running', now: at(100) }),
    ).rejects.toBeInstanceOf(ValidationError);
    await repositories.jobs.complete(job.id, 'w1', outcome);
    // Already terminal: a second completion changes nothing.
    await expect(
      repositories.jobs.complete(job.id, 'w1', { status: 'failed', now: at(200) }),
    ).rejects.toBeInstanceOf(ConflictError);
    expect((await repositories.jobs.getInternal(job.id))?.status).toBe('succeeded');
    await expect(repositories.jobs.complete(UNKNOWN_ID, 'w1', outcome)).rejects.toBeInstanceOf(
      ConflictError,
    );
  });

  it('rejects a worker whose lease was recovered by someone else', async () => {
    const f = await fixture();
    const job = await repositories.jobs.createOperation(operationInput(f, { retrySafe: false }));
    await repositories.jobs.claimNext({ workerId: 'w1', leaseMs: 1000, now: T0 });
    await repositories.jobs.recoverExpiredLeases({ now: at(5000), maxAttempts: 3 });
    await expect(
      repositories.jobs.complete(job.id, 'w1', { status: 'succeeded', now: at(6000) }),
    ).rejects.toBeInstanceOf(ConflictError);
  });
});

describe('jobs.requestLoginCompletion', () => {
  const loginFor = (f: Awaited<ReturnType<typeof fixture>>) =>
    repositories.jobs.createLogin({
      organizationId: tenant.organization.id,
      requestedByUserId: tenant.user.id,
      connectionId: f.connection.id,
      timeoutMs: 600_000,
    });
  const owner = () => ({ organizationId: tenant.organization.id, ownerUserId: tenant.user.id });

  it('sets completion_requested_at for the owner and keeps the first time', async () => {
    const f = await fixture();
    const login = await loginFor(f);
    const first = await repositories.jobs.requestLoginCompletion(owner(), login.id, at(10));
    expect(first.completionRequestedAt).toBe(at(10).toISOString());
    const second = await repositories.jobs.requestLoginCompletion(owner(), login.id, at(20));
    expect(second.completionRequestedAt).toBe(at(10).toISOString());
  });

  it('is NotFound for another owner, an operation job and a finished job', async () => {
    const f = await fixture();
    const login = await loginFor(f);
    await expect(
      repositories.jobs.requestLoginCompletion(
        { organizationId: tenant.organization.id, ownerUserId: teammate.user.id },
        login.id,
        at(10),
      ),
    ).rejects.toBeInstanceOf(NotFoundError);
    await expect(
      repositories.jobs.requestLoginCompletion(
        { organizationId: other.organization.id, ownerUserId: other.user.id },
        login.id,
        at(10),
      ),
    ).rejects.toBeInstanceOf(NotFoundError);
    expect((await repositories.jobs.getInternal(login.id))?.completionRequestedAt).toBeNull();

    const op = await repositories.jobs.createOperation(operationInput(f));
    await expect(
      repositories.jobs.requestLoginCompletion(owner(), op.id, at(10)),
    ).rejects.toBeInstanceOf(NotFoundError);

    await repositories.jobs.cancelForConnection(f.connection.id, at(30));
    await expect(
      repositories.jobs.requestLoginCompletion(owner(), login.id, at(40)),
    ).rejects.toBeInstanceOf(NotFoundError);
  });
});

describe('jobs.cancelForConnection', () => {
  it('cancels queued jobs, flags running ones and leaves other connections alone', async () => {
    const f = await fixture();
    const g = await fixture();
    const running = await repositories.jobs.createOperation(operationInput(f));
    const queued = await repositories.jobs.createOperation(operationInput(f));
    const unrelated = await repositories.jobs.createOperation(operationInput(g));
    const claimed = await repositories.jobs.claimNext({ workerId: 'w1', leaseMs: 1000, now: T0 });
    expect(claimed?.id).toBe(running.id);

    const touched = await repositories.jobs.cancelForConnection(f.connection.id, at(50));
    expect(touched.map((job) => job.id).sort()).toEqual([running.id, queued.id].sort());

    expect(await repositories.jobs.getInternal(queued.id)).toMatchObject({
      status: 'cancelled',
      error: { code: 'cancelled' },
      finishedAt: at(50).toISOString(),
    });
    expect(await repositories.jobs.getInternal(running.id)).toMatchObject({
      status: 'running',
      cancelRequestedAt: at(50).toISOString(),
      finishedAt: null,
    });
    expect((await repositories.jobs.getInternal(unrelated.id))?.status).toBe('queued');
    expect(await repositories.jobs.cancelForConnection(UNKNOWN_ID, at(60))).toEqual([]);
  });
});

describe('jobs.recoverExpiredLeases', () => {
  async function runningJob(kind: 'safe' | 'unsafe' | 'login', leaseMs: number, workerId = 'w1') {
    const f = await fixture();
    const job =
      kind === 'login'
        ? await repositories.jobs.createLogin({
            organizationId: tenant.organization.id,
            requestedByUserId: tenant.user.id,
            connectionId: f.connection.id,
            timeoutMs: 1000,
          })
        : await repositories.jobs.createOperation(
            operationInput(f, { retrySafe: kind === 'safe' }),
          );
    return { f, job, claimed: await repositories.jobs.claimNext({ workerId, leaseMs, now: T0 }) };
  }

  it('requeues a retry-safe operation, marks an unsafe one outcome_unknown, fails a login', async () => {
    const safe = await runningJob('safe', 1000);
    expect(safe.claimed?.id).toBe(safe.job.id);
    const unsafe = await runningJob('unsafe', 1000, 'w2');
    const login = await runningJob('login', 1000, 'w3');
    const alive = await runningJob('safe', 60_000, 'w4');

    const changed = await repositories.jobs.recoverExpiredLeases({ now: at(5000), maxAttempts: 3 });
    expect(changed.map((job) => job.id).sort()).toEqual(
      [safe.job.id, unsafe.job.id, login.job.id].sort(),
    );

    expect(await repositories.jobs.getInternal(safe.job.id)).toMatchObject({
      status: 'queued',
      workerId: null,
      leaseExpiresAt: null,
      finishedAt: null,
      attemptCount: 1,
    });
    expect(await repositories.jobs.getInternal(unsafe.job.id)).toMatchObject({
      status: 'outcome_unknown',
      error: { code: 'worker_failure' },
      finishedAt: at(5000).toISOString(),
    });
    expect(await repositories.jobs.getInternal(login.job.id)).toMatchObject({
      status: 'failed',
      error: { code: 'worker_failure' },
      finishedAt: at(5000).toISOString(),
    });
    expect((await repositories.jobs.getInternal(alive.job.id))?.status).toBe('running');
  });

  it('fails a retry-safe operation once its attempts are used up', async () => {
    const { job } = await runningJob('safe', 1000);
    const changed = await repositories.jobs.recoverExpiredLeases({ now: at(5000), maxAttempts: 1 });
    expect(changed).toHaveLength(1);
    expect(await repositories.jobs.getInternal(job.id)).toMatchObject({
      status: 'failed',
      error: { code: 'worker_failure' },
    });
  });

  it('does nothing when no lease has expired', async () => {
    await runningJob('safe', 60_000);
    expect(await repositories.jobs.recoverExpiredLeases({ now: at(1000), maxAttempts: 3 })).toEqual(
      [],
    );
  });
});

describe('jobs.purgeResults', () => {
  it('nulls old results of terminal jobs and records when', async () => {
    const oldJob = await finishedJob({ finishedAt: at(-1000), result: { secret: 'synthetic' } });
    const newJob = await finishedJob({ finishedAt: at(10_000), result: { keep: true } });
    const failedJob = await finishedJob({ finishedAt: at(-1000), status: 'failed' });

    const purged = await repositories.jobs.purgeResults(at(-500), at(6000));
    expect(purged).toBe(1);
    expect(await repositories.jobs.getInternal(oldJob)).toMatchObject({
      result: null,
      resultPurgedAt: at(6000).toISOString(),
    });
    expect((await repositories.jobs.getInternal(newJob))?.result).toEqual({ keep: true });
    expect((await repositories.jobs.getInternal(failedJob))?.resultPurgedAt).toBeNull();
    // Nothing left to purge.
    expect(await repositories.jobs.purgeResults(at(-500), at(7000))).toBe(0);
  });

  async function finishedJob(options: {
    finishedAt: Date;
    result?: JsonObject;
    status?: 'succeeded' | 'failed';
  }): Promise<string> {
    const f = await fixture();
    const job = await repositories.jobs.createOperation(operationInput(f));
    await repositories.jobs.claimNext({ workerId: 'w1', leaseMs: 1000, now: T0 });
    await repositories.jobs.complete(job.id, 'w1', {
      status: options.status ?? 'succeeded',
      result: options.result ?? null,
      now: options.finishedAt,
    });
    return job.id;
  }
});

describe('operationRequests', () => {
  const hash = (char: string) => char.repeat(64);

  it('finds a stored request and rejects a duplicate idempotency key', async () => {
    const f = await fixture();
    const job = await repositories.jobs.createOperation(operationInput(f));
    expect(await repositories.operationRequests.find(f.agent.id, 'key-0001')).toBeNull();

    const created = await repositories.operationRequests.create({
      agentId: f.agent.id,
      idempotencyKey: 'key-0001',
      requestHash: hash('a'),
      jobId: job.id,
    });
    expect(await repositories.operationRequests.find(f.agent.id, 'key-0001')).toEqual(created);
    expect(created).toMatchObject({ requestHash: hash('a'), jobId: job.id });

    const second = await repositories.jobs.createOperation(operationInput(f));
    await expect(
      repositories.operationRequests.create({
        agentId: f.agent.id,
        idempotencyKey: 'key-0001',
        requestHash: hash('b'),
        jobId: second.id,
      }),
    ).rejects.toBeInstanceOf(ConflictError);

    // The key is scoped per agent.
    const peer = await repositories.agents.create(tenant.scope, {
      name: 'peer',
      clientIdentity: 'peer-agent',
    });
    await repositories.operationRequests.create({
      agentId: peer.id,
      idempotencyKey: 'key-0001',
      requestHash: hash('b'),
      jobId: second.id,
    });
  });

  it('rejects a malformed hash', async () => {
    const f = await fixture();
    const job = await repositories.jobs.createOperation(operationInput(f));
    await expect(
      repositories.operationRequests.create({
        agentId: f.agent.id,
        idempotencyKey: 'key-0002',
        requestHash: 'short',
        jobId: job.id,
      }),
    ).rejects.toBeInstanceOf(ValidationError);
  });
});

describe('connection and agent additions for the worker', () => {
  it('getForExecution returns the connection with its application, unscoped', async () => {
    const f = await fixture();
    const result = await repositories.connections.getForExecution(f.connection.id);
    expect(result?.connection.id).toBe(f.connection.id);
    expect(result?.connection.sessionExpiresAt).toBeNull();
    expect(result?.application.id).toBe(f.application.id);
    expect(await repositories.connections.getForExecution(UNKNOWN_ID)).toBeNull();
    expect(await repositories.connections.getForExecution('nope')).toBeNull();
  });

  it('recordSession stores the hint and expiry and shows them on the connection', async () => {
    const f = await fixture();
    const updated = await repositories.connections.recordSession(f.connection.id, {
      externalAccountHint: '  ada@synthetic.test ',
      sessionExpiresAt: at(86_400_000),
      lastVerifiedAt: at(1000),
    });
    expect(updated).toMatchObject({
      externalAccountHint: 'ada@synthetic.test',
      sessionExpiresAt: at(86_400_000).toISOString(),
      lastVerifiedAt: at(1000).toISOString(),
    });
    const read = await repositories.connections.get(tenant.scope, f.connection.id);
    expect(read?.sessionExpiresAt).toBe(at(86_400_000).toISOString());

    const cleared = await repositories.connections.recordSession(f.connection.id, {
      externalAccountHint: null,
      sessionExpiresAt: null,
      lastVerifiedAt: at(2000),
    });
    expect(cleared).toMatchObject({ externalAccountHint: null, sessionExpiresAt: null });
    await expect(
      repositories.connections.recordSession(UNKNOWN_ID, {
        externalAccountHint: null,
        sessionExpiresAt: null,
        lastVerifiedAt: at(2000),
      }),
    ).rejects.toBeInstanceOf(NotFoundError);
  });

  it('transitionStatusInternal follows the transition table and records a worker event', async () => {
    const f = await fixture();
    await expect(
      repositories.connections.transitionStatusInternal(f.connection.id, { to: 'active' }),
    ).rejects.toBeInstanceOf(InvalidTransitionError);

    await repositories.connections.transitionStatusInternal(f.connection.id, {
      to: 'authentication_required',
    });
    await repositories.connections.transitionStatusInternal(f.connection.id, {
      to: 'authenticating',
    });
    const active = await repositories.connections.transitionStatusInternal(f.connection.id, {
      to: 'active',
      reason: 'login verified',
    });
    expect(active).toMatchObject({ status: 'active', statusReason: 'login verified' });
    expect(active.lastVerifiedAt).not.toBeNull();

    const events = await repositories.connections.listStatusEvents(tenant.scope, f.connection.id);
    expect(events?.map((event) => [event.toStatus, event.actorType, event.actorId])).toEqual([
      ['created', 'user', tenant.user.id],
      ['authentication_required', 'worker', null],
      ['authenticating', 'worker', null],
      ['active', 'worker', null],
    ]);
    await expect(
      repositories.connections.transitionStatusInternal(UNKNOWN_ID, { to: 'revoked' }),
    ).rejects.toBeInstanceOf(NotFoundError);
  });

  it('agents.getInternal finds an agent without a scope', async () => {
    const f = await fixture();
    expect((await repositories.agents.getInternal(f.agent.id))?.id).toBe(f.agent.id);
    expect(await repositories.agents.getInternal(UNKNOWN_ID)).toBeNull();
    expect(await repositories.agents.getInternal('nope')).toBeNull();
  });
});

describe('sanity', () => {
  it('leaves no job in a state that violates the one-running-per-connection rule', async () => {
    const rows = rowsOf(
      await handle.db.execute(
        sql`select connection_id from execution_jobs where status = 'running' group by connection_id having count(*) > 1`,
      ),
    );
    expect(rows).toEqual([]);
  });
});
