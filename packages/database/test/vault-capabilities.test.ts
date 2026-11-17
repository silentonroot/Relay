import { randomUUID } from 'node:crypto';
import { sql } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { rowsOf } from '../src/client.js';
import {
  ConflictError,
  createRepositories,
  MAX_CLOCK_SKEW_SECONDS,
  NotFoundError,
  ValidationError,
} from '../src/index.js';
import type { DatabaseHandle, Repositories } from '../src/index.js';
import {
  addOperationJob,
  at,
  AUTH_MAC,
  authorize,
  auditTypes,
  capabilityRow,
  consumeInput,
  issue,
  jobRow,
  markRunning,
  newToken,
  resetClock,
  secretRow,
  seedLogin,
  seedOperation,
  setConnectionStatus,
  SECRET_TYPE,
  T0,
  TOKEN_MAC,
  TOKEN_TTL,
} from './capability-fixtures.js';
import type { CapabilityFixture, Issued } from './capability-fixtures.js';
import { fakeSealed, openTestDb, seedTenant, UNKNOWN_ID } from './helpers.js';
import type { Tenant } from './helpers.js';

let handle: DatabaseHandle;
let repositories: Repositories;
let tenant: Tenant;
let other: Tenant;
let teammate: Tenant;

beforeAll(async () => {
  handle = await openTestDb();
  repositories = createRepositories(handle.db);
  tenant = await seedTenant(repositories, 'caps');
  other = await seedTenant(repositories, 'caps-other');
  const user = await repositories.users.create({
    email: 'caps-teammate@synthetic.test',
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

// The statements compare `now` with the database clock (see capability-fixtures.ts).
beforeEach(resetClock);

const op = () => seedOperation(handle.db, repositories, tenant);
const login = () => seedLogin(handle.db, repositories, tenant);

type Mutation = (f: Issued) => Promise<void>;

/**
 * Consume overrides that mention a time are thunks: `at()` reads the clock of the test that
 * runs the case, not the clock of the moment the case table was built.
 */
type Overrides = Record<string, unknown> | (() => Record<string, unknown>);
const resolve = (overrides: Overrides | undefined): Record<string, unknown> =>
  typeof overrides === 'function' ? overrides() : (overrides ?? {});

/** The message of a database error, which Drizzle wraps in a generic "Failed query" error. */
function databaseMessage(error: unknown): string {
  const parts: string[] = [];
  for (let current = error; current instanceof Error; current = current.cause) {
    parts.push(current.message);
  }
  return parts.join(' | ');
}

async function refusedBy(statement: Promise<unknown>, pattern: RegExp): Promise<void> {
  let thrown: unknown;
  try {
    await statement;
  } catch (error) {
    thrown = error;
  }
  expect(thrown, 'expected the statement to be refused').toBeDefined();
  expect(databaseMessage(thrown)).toMatch(pattern);
}

async function sql1(statement: ReturnType<typeof sql>) {
  await handle.db.execute(statement);
}

/** Authorization-stage inputs, for tests that call `insertAuthorization` directly. */
function authInput(f: CapabilityFixture, overrides: Record<string, unknown> = {}) {
  return {
    capabilityId: randomUUID(),
    jobId: f.jobId,
    secretId: f.secretId,
    purpose: f.purpose,
    organizationId: f.tenant.organization.id,
    agentId: f.purpose === 'read' ? f.agentId : null,
    connectionId: f.connectionId,
    operation: f.operation,
    argumentsHash: f.argumentsHash,
    now: T0,
    ttlSeconds: 600,
    authorizationMac: AUTH_MAC,
    macKekVersion: 1,
    ...overrides,
  };
}

describe('capabilities.insertAuthorization (stage 1)', () => {
  it('creates the capability, sets capability_ref and appends vault.capability_authorized', async () => {
    const f = await op();
    const { capabilityId } = await authorize(repositories, f);
    const row = await capabilityRow(handle.db, capabilityId);
    expect(row).toMatchObject({
      purpose: 'read',
      operation: 'orders.list',
      token_hash: null,
      used_at: null,
      revoked_at: null,
    });
    expect(String(row.job_id)).toBe(f.jobId);
    expect(String(row.secret_id)).toBe(f.secretId);
    expect(
      new Date(String(row.expires_at)).getTime() - new Date(String(row.issued_at)).getTime(),
    ).toBe(600_000);
    expect(String((await jobRow(handle.db, f.jobId)).capability_ref)).toBe(capabilityId);
    expect((await auditTypes(handle.db, tenant.organization.id)).at(-1)).toBe(
      'vault.capability_authorized',
    );
    const [event] = rowsOf(
      await handle.db.execute(
        sql`select metadata from audit_events where organization_id = ${tenant.organization.id}::uuid and event_type = 'vault.capability_authorized' order by sequence desc limit 1`,
      ),
    );
    expect(JSON.stringify(event!.metadata)).not.toMatch(/mac|hash|token/i);
  });

  it('authorizes a login job as a seal capability with no agent, operation or arguments hash', async () => {
    const f = await login();
    const { capabilityId } = await authorize(repositories, f);
    expect(await capabilityRow(handle.db, capabilityId)).toMatchObject({
      purpose: 'seal',
      agent_id: null,
      operation: null,
      arguments_hash: null,
    });
  });

  it('refuses every lifetime that is not a safe integer within 10 to 3,600 seconds (P3-7)', async () => {
    const f = await op();
    const bad: unknown[] = [
      0,
      -1,
      9,
      3601,
      1.5,
      Number.NaN,
      Number.POSITIVE_INFINITY,
      Number.NEGATIVE_INFINITY,
      2 ** 53,
      '600',
      null,
      undefined,
    ];
    for (const ttlSeconds of bad) {
      await expect(
        repositories.capabilities.insertAuthorization(authInput(f, { ttlSeconds })),
      ).rejects.toBeInstanceOf(ValidationError);
    }
    // Missing altogether.
    const { ttlSeconds: _omitted, ...withoutTtl } = authInput(f);
    await expect(
      repositories.capabilities.insertAuthorization(withoutTtl as never),
    ).rejects.toBeInstanceOf(ValidationError);
    expect((await jobRow(handle.db, f.jobId)).capability_ref).toBeNull();
    expect(
      rowsOf(
        await handle.db.execute(
          sql`select 1 from vault_access_capabilities where job_id = ${f.jobId}::uuid`,
        ),
      ),
    ).toHaveLength(0);
    // The bounds themselves are accepted.
    await repositories.capabilities.insertAuthorization(authInput(f, { ttlSeconds: 10 }));
    const g = await op();
    await repositories.capabilities.insertAuthorization(authInput(g, { ttlSeconds: 3600 }));
  });

  it('refuses an invalid clock value', async () => {
    const f = await op();
    await expect(
      repositories.capabilities.insertAuthorization(authInput(f, { now: new Date(Number.NaN) })),
    ).rejects.toBeInstanceOf(ValidationError);
    await expect(
      repositories.capabilities.insertAuthorization(authInput(f, { now: '2030-01-01' })),
    ).rejects.toBeInstanceOf(ValidationError);
  });

  it('refuses malformed ids, hashes and purposes before touching the database', async () => {
    const f = await op();
    const cases: Record<string, unknown>[] = [
      { capabilityId: 'nope' },
      { jobId: 'nope' },
      { secretId: 'nope' },
      { connectionId: 'nope' },
      { authorizationMac: 'short' },
      { authorizationMac: 'A'.repeat(64) },
      { macKekVersion: 0 },
      { macKekVersion: 1.5 },
      { purpose: 'write' },
      { argumentsHash: 'xyz' },
      { purpose: 'seal' }, // a read binding presented as a seal
      { agentId: null }, // a read without an agent
      { operation: null },
    ];
    for (const overrides of cases) {
      await expect(
        repositories.capabilities.insertAuthorization(authInput(f, overrides)),
      ).rejects.toBeInstanceOf(ValidationError);
    }
  });

  const refusals: [string, (f: CapabilityFixture) => Promise<Record<string, unknown>>][] = [
    [
      'a job that is not queued',
      async (f) => {
        await markRunning(handle.db, f.jobId);
        return {};
      },
    ],
    [
      'a job with a cancellation requested',
      async (f) => {
        await sql1(
          sql`update execution_jobs set cancel_requested_at = now() where id = ${f.jobId}::uuid`,
        );
        return {};
      },
    ],
    [
      'a connection that is not active',
      async (f) => {
        await setConnectionStatus(handle.db, f.connectionId, 'reconnect_required');
        return {};
      },
    ],
    [
      'a revoked secret',
      async (f) => {
        await sql1(
          sql`update vault_secrets set status = 'revoked', active_version_id = null where id = ${f.secretId}::uuid`,
        );
        return {};
      },
    ],
    [
      'a binding with another organization',
      async () => ({ organizationId: other.organization.id }),
    ],
    ['a binding with another connection', async () => ({ connectionId: randomUUID() })],
    ['a binding with another agent', async () => ({ agentId: randomUUID() })],
    ['a binding with another operation', async () => ({ operation: 'orders.get' })],
    ['a binding with another arguments hash', async () => ({ argumentsHash: 'c'.repeat(64) })],
    [
      'a secret of another connection',
      async () => {
        const g = await op();
        return { secretId: g.secretId };
      },
    ],
    [
      'a policy decision that is not an allow',
      async (f) => {
        // audit_events is append-only: build a job whose decision event is a deny instead.
        const deny = await repositories.audit.append({
          organizationId: tenant.organization.id,
          actorType: 'system',
          agentId: f.agentId,
          connectionId: f.connectionId,
          eventType: 'policy.evaluated',
          decision: 'deny',
          metadata: { operation: f.operation },
          timestamp: T0,
        });
        await sql1(
          sql`update execution_jobs set policy_decision_id = ${deny.id}::uuid where id = ${f.jobId}::uuid`,
        );
        return {};
      },
    ],
    [
      'a policy decision for another operation',
      async (f) => {
        const wrong = await repositories.audit.append({
          organizationId: tenant.organization.id,
          actorType: 'system',
          agentId: f.agentId,
          connectionId: f.connectionId,
          eventType: 'policy.evaluated',
          decision: 'allow',
          metadata: { operation: 'orders.get' },
          timestamp: T0,
        });
        await sql1(
          sql`update execution_jobs set policy_decision_id = ${wrong.id}::uuid where id = ${f.jobId}::uuid`,
        );
        return {};
      },
    ],
    [
      'a job with no policy decision',
      async (f) => {
        await sql1(
          sql`update execution_jobs set policy_decision_id = null where id = ${f.jobId}::uuid`,
        );
        return {};
      },
    ],
    // Review M1: authorization follows the grant and the agent the decision rested on.
    [
      'a matched grant that was revoked after the decision',
      async (f) => {
        await repositories.grants.revoke(tenant.scope, f.agentId, f.grantId!, at(500));
        return {};
      },
    ],
    [
      'a matched grant that was revoked while another allow grant is still in force',
      async (f) => {
        await repositories.grants.create(tenant.scope, f.agentId, {
          connectionId: f.connectionId,
          operation: f.operation!,
          effect: 'allow',
        });
        await sql1(sql`update agent_grants set revoked_at = now() where id = ${f.grantId!}::uuid`);
        return {};
      },
    ],
    [
      'a matched grant that has expired',
      async (f) => {
        await sql1(
          sql`update agent_grants set expires_at = ${at(-1000).toISOString()}::timestamptz where id = ${f.grantId!}::uuid`,
        );
        return {};
      },
    ],
    [
      'a disabled agent',
      async (f) => {
        await repositories.agents.disable(tenant.scope, f.agentId);
        return {};
      },
    ],
    [
      'a deny grant created after the decision',
      async (f) => {
        await repositories.grants.create(tenant.scope, f.agentId, {
          connectionId: f.connectionId,
          operation: f.operation!,
          effect: 'deny',
        });
        return {};
      },
    ],
    [
      'a decision that names no grant',
      async (f) => {
        const bare = await repositories.audit.append({
          organizationId: tenant.organization.id,
          actorType: 'system',
          agentId: f.agentId,
          connectionId: f.connectionId,
          eventType: 'policy.evaluated',
          decision: 'allow',
          metadata: { operation: f.operation, outcome: 'allow' },
          timestamp: T0,
        });
        await sql1(
          sql`update execution_jobs set policy_decision_id = ${bare.id}::uuid where id = ${f.jobId}::uuid`,
        );
        return {};
      },
    ],
    [
      'a decision that names the grant of another operation',
      async (f) => {
        const other = await repositories.grants.create(tenant.scope, f.agentId, {
          connectionId: f.connectionId,
          operation: 'orders.get',
          effect: 'allow',
        });
        const wrong = await repositories.audit.append({
          organizationId: tenant.organization.id,
          actorType: 'system',
          agentId: f.agentId,
          connectionId: f.connectionId,
          eventType: 'policy.evaluated',
          decision: 'allow',
          metadata: { operation: f.operation, outcome: 'allow', matchedGrantIds: [other.id] },
          timestamp: T0,
        });
        await sql1(
          sql`update execution_jobs set policy_decision_id = ${wrong.id}::uuid where id = ${f.jobId}::uuid`,
        );
        return {};
      },
    ],
    [
      'a policy decision written more than an hour before the job',
      async (f) => {
        const old = await repositories.audit.append({
          organizationId: tenant.organization.id,
          actorType: 'system',
          agentId: f.agentId,
          connectionId: f.connectionId,
          eventType: 'policy.evaluated',
          decision: 'allow',
          metadata: { operation: f.operation, outcome: 'allow', matchedGrantIds: [f.grantId] },
          timestamp: at(-2 * 3600 * 1000),
        });
        await sql1(
          sql`update execution_jobs set policy_decision_id = ${old.id}::uuid where id = ${f.jobId}::uuid`,
        );
        return {};
      },
    ],
    [
      'a policy decision written more than an hour after the job',
      async (f) => {
        const later = await repositories.audit.append({
          organizationId: tenant.organization.id,
          actorType: 'system',
          agentId: f.agentId,
          connectionId: f.connectionId,
          eventType: 'policy.evaluated',
          decision: 'allow',
          metadata: { operation: f.operation, outcome: 'allow', matchedGrantIds: [f.grantId] },
          timestamp: at(2 * 3600 * 1000),
        });
        await sql1(
          sql`update execution_jobs set policy_decision_id = ${later.id}::uuid where id = ${f.jobId}::uuid`,
        );
        return {};
      },
    ],
    // Review M2: the database clock is authoritative over the caller's `now`.
    ['a caller clock 10 s ahead of the database', async () => ({ now: at(10_000) })],
    ['a caller clock 10 s behind the database', async () => ({ now: at(-10_000) })],
  ];
  for (const [name, arrange] of refusals) {
    it(`refuses ${name} and leaves nothing behind`, async () => {
      const f = await op();
      const overrides = await arrange(f);
      await expect(
        repositories.capabilities.insertAuthorization(authInput(f, overrides)),
      ).rejects.toBeInstanceOf(ConflictError);
      expect((await jobRow(handle.db, f.jobId)).capability_ref).toBeNull();
      expect(
        rowsOf(
          await handle.db.execute(
            sql`select 1 from vault_access_capabilities where job_id = ${f.jobId}::uuid`,
          ),
        ),
      ).toHaveLength(0);
    });
  }

  it('refuses a login capability for an active connection and an operation capability for a login job', async () => {
    const l = await login();
    await setConnectionStatus(handle.db, l.connectionId, 'active');
    await expect(
      repositories.capabilities.insertAuthorization(authInput(l)),
    ).rejects.toBeInstanceOf(ConflictError);
    const l2 = await login();
    await expect(
      repositories.capabilities.insertAuthorization(
        authInput(l2, {
          purpose: 'read',
          agentId: l2.agentId,
          operation: 'orders.list',
          argumentsHash: 'd'.repeat(64),
        }),
      ),
    ).rejects.toBeInstanceOf(ConflictError);
  });

  it('refuses a second authorization for the same job', async () => {
    const f = await op();
    const first = await authorize(repositories, f);
    await expect(authorize(repositories, f)).rejects.toBeInstanceOf(ConflictError);
    expect(String((await jobRow(handle.db, f.jobId)).capability_ref)).toBe(first.capabilityId);
    expect(
      rowsOf(
        await handle.db.execute(
          sql`select 1 from vault_access_capabilities where job_id = ${f.jobId}::uuid`,
        ),
      ),
    ).toHaveLength(1);
  });

  it('rolls back the capability and the job link when its audit event cannot be written', async () => {
    const f = await op();
    await expect(
      repositories.capabilities.insertAuthorization(
        authInput(f, { actor: { type: 'user', id: 'not-a-uuid' } }),
      ),
    ).rejects.toBeInstanceOf(ValidationError);
    expect((await jobRow(handle.db, f.jobId)).capability_ref).toBeNull();
    expect(
      rowsOf(
        await handle.db.execute(
          sql`select 1 from vault_access_capabilities where job_id = ${f.jobId}::uuid`,
        ),
      ),
    ).toHaveLength(0);
  });
});

describe('database checks of vault_access_capabilities', () => {
  const insertRow = (f: CapabilityFixture, columns: string, values: ReturnType<typeof sql>) =>
    handle.db.execute(
      sql`insert into vault_access_capabilities (organization_id, job_id, agent_id, connection_id, secret_id, purpose, operation, arguments_hash, authorization_mac, mac_kek_version, issued_at, expires_at ${sql.raw(columns)})
          values (${f.tenant.organization.id}::uuid, ${f.jobId}::uuid, ${f.agentId}::uuid, ${f.connectionId}::uuid, ${f.secretId}::uuid, 'read', ${f.operation}, ${f.argumentsHash}, ${AUTH_MAC}, 1, ${values})`,
    );
  const window = (issued: string, expires: string) =>
    sql`${issued}::timestamptz, ${expires}::timestamptz`;

  it('refuses a capability row whose expiry exceeds the upper bound', async () => {
    const f = await op();
    await expect(
      insertRow(f, '', window('2030-01-01T00:00:00Z', '2030-01-01T01:00:01Z')),
    ).rejects.toThrow();
    await expect(
      insertRow(f, '', window('2030-01-01T00:00:00Z', '2030-01-01T00:00:00Z')),
    ).rejects.toThrow();
    await expect(
      insertRow(f, '', window('2030-01-01T00:00:00Z', '2029-12-31T00:00:00Z')),
    ).rejects.toThrow();
    // Exactly one hour is the largest accepted window.
    await insertRow(f, '', window('2030-01-01T00:00:00Z', '2030-01-01T01:00:00Z'));
  });

  it('refuses token lifetimes above 120 seconds or past the authorization, and half-written tokens', async () => {
    const f = await op();
    const base = (extra: string) =>
      handle.db.execute(
        sql`insert into vault_access_capabilities (organization_id, job_id, agent_id, connection_id, secret_id, purpose, operation, arguments_hash, authorization_mac, mac_kek_version, issued_at, expires_at, worker_id, attempt, secret_version, token_hash, token_issued_at, token_expires_at)
            values (${f.tenant.organization.id}::uuid, ${f.jobId}::uuid, ${f.agentId}::uuid, ${f.connectionId}::uuid, ${f.secretId}::uuid, 'read', ${f.operation}, ${f.argumentsHash}, ${AUTH_MAC}, 1, '2030-01-01T00:00:00Z', '2030-01-01T00:10:00Z', 'w', 1, 1, ${newToken().hash}, ${sql.raw(extra)})`,
      );
    await expect(base(`'2030-01-01T00:00:00Z', '2030-01-01T00:02:01Z'`)).rejects.toThrow();
    await expect(base(`'2030-01-01T00:09:30Z', '2030-01-01T00:10:30Z'`)).rejects.toThrow();
    await expect(base(`'2030-01-01T00:00:00Z', '2030-01-01T00:00:00Z'`)).rejects.toThrow();
    await base(`'2030-01-01T00:00:00Z', '2030-01-01T00:02:00Z'`);
    // A token hash without its times, worker and attempt.
    const g = await op();
    await expect(
      insertRow(
        g,
        ', token_hash',
        sql`'2030-01-01T00:00:00Z'::timestamptz, '2030-01-01T00:10:00Z'::timestamptz, ${newToken().hash}`,
      ),
    ).rejects.toThrow();
  });

  it('refuses used_at without a token, half-recorded revocation, bad hex and bad purposes', async () => {
    const f = await op();
    await expect(
      insertRow(
        f,
        ', used_at',
        sql`'2030-01-01T00:00:00Z'::timestamptz, '2030-01-01T00:10:00Z'::timestamptz, now()`,
      ),
    ).rejects.toThrow();
    await expect(
      insertRow(
        f,
        ', revoked_at',
        sql`'2030-01-01T00:00:00Z'::timestamptz, '2030-01-01T00:10:00Z'::timestamptz, now()`,
      ),
    ).rejects.toThrow();
    await expect(
      insertRow(
        f,
        ', revoked_at, revoked_reason',
        sql`'2030-01-01T00:00:00Z'::timestamptz, '2030-01-01T00:10:00Z'::timestamptz, now(), 'because'`,
      ),
    ).rejects.toThrow();
    await expect(
      handle.db.execute(
        sql`insert into vault_access_capabilities (organization_id, job_id, agent_id, connection_id, secret_id, purpose, operation, arguments_hash, authorization_mac, mac_kek_version, issued_at, expires_at)
            values (${f.tenant.organization.id}::uuid, ${f.jobId}::uuid, ${f.agentId}::uuid, ${f.connectionId}::uuid, ${f.secretId}::uuid, 'read', ${f.operation}, ${f.argumentsHash}, 'not hex', 1, '2030-01-01T00:00:00Z', '2030-01-01T00:10:00Z')`,
      ),
    ).rejects.toThrow();
    await expect(
      handle.db.execute(
        sql`insert into vault_access_capabilities (organization_id, job_id, agent_id, connection_id, secret_id, purpose, operation, arguments_hash, authorization_mac, mac_kek_version, issued_at, expires_at)
            values (${f.tenant.organization.id}::uuid, ${f.jobId}::uuid, ${f.agentId}::uuid, ${f.connectionId}::uuid, ${f.secretId}::uuid, 'write', ${f.operation}, ${f.argumentsHash}, ${AUTH_MAC}, 1, '2030-01-01T00:00:00Z', '2030-01-01T00:10:00Z')`,
      ),
    ).rejects.toThrow();
    // A login capability may not carry an operation.
    const l = await login();
    await expect(
      handle.db.execute(
        sql`insert into vault_access_capabilities (organization_id, job_id, connection_id, secret_id, purpose, operation, authorization_mac, mac_kek_version, issued_at, expires_at)
            values (${l.tenant.organization.id}::uuid, ${l.jobId}::uuid, ${l.connectionId}::uuid, ${l.secretId}::uuid, 'seal', 'orders.list', ${AUTH_MAC}, 1, '2030-01-01T00:00:00Z', '2030-01-01T00:10:00Z')`,
      ),
    ).rejects.toThrow();
  });

  it('allows one unused, unrevoked capability per job (partial unique index)', async () => {
    const f = await op();
    await insertRow(f, '', window('2030-01-01T00:00:00Z', '2030-01-01T00:10:00Z'));
    await expect(
      insertRow(f, '', window('2030-01-01T00:00:00Z', '2030-01-01T00:10:00Z')),
    ).rejects.toThrow();
    await sql1(
      sql`update vault_access_capabilities set revoked_at = now(), revoked_reason = 'owner_requested' where job_id = ${f.jobId}::uuid`,
    );
    await insertRow(f, '', window('2030-01-01T00:00:00Z', '2030-01-01T00:10:00Z'));
  });

  it('keeps token hashes unique', async () => {
    const a = await op();
    const b = await op();
    const same = newToken().hash;
    const withToken = (f: CapabilityFixture) =>
      handle.db.execute(
        sql`insert into vault_access_capabilities (organization_id, job_id, agent_id, connection_id, secret_id, purpose, operation, arguments_hash, authorization_mac, mac_kek_version, issued_at, expires_at, worker_id, attempt, secret_version, token_hash, token_issued_at, token_expires_at)
            values (${f.tenant.organization.id}::uuid, ${f.jobId}::uuid, ${f.agentId}::uuid, ${f.connectionId}::uuid, ${f.secretId}::uuid, 'read', ${f.operation}, ${f.argumentsHash}, ${AUTH_MAC}, 1, '2030-01-01T00:00:00Z', '2030-01-01T00:10:00Z', 'w', 1, 1, ${same}, '2030-01-01T00:00:00Z', '2030-01-01T00:00:30Z')`,
      );
    await withToken(a);
    await expect(withToken(b)).rejects.toThrow();
  });
});

describe('capabilities.issueToken (stage 2)', () => {
  const issueInput = (f: CapabilityFixture & { capabilityId: string }, overrides = {}) => ({
    capabilityId: f.capabilityId,
    jobId: f.jobId,
    workerId: 'worker-1',
    attempt: 1,
    tokenHash: newToken().hash,
    tokenTtlSeconds: TOKEN_TTL,
    now: at(1000),
    authorizationMac: AUTH_MAC,
    computeTokenMac: () => TOKEN_MAC,
    ...overrides,
  });

  it('binds the worker, the attempt and the active secret version and stores the token MAC', async () => {
    const f = await op();
    const issued = await issue(handle.db, repositories, f);
    expect(issued.record).toMatchObject({
      workerId: 'worker-1',
      attempt: 1,
      secretVersion: 1,
      tokenMac: TOKEN_MAC,
      tokenHash: issued.tokenHash,
      usedAt: null,
    });
    expect(issued.record.tokenIssuedAt).toBe(at(1000).toISOString());
    expect(issued.record.tokenExpiresAt).toBe(at(1000 + TOKEN_TTL * 1000).toISOString());
    const row = await capabilityRow(handle.db, issued.capabilityId);
    expect(row.token_mac).toBe(TOKEN_MAC);
    expect((await auditTypes(handle.db, tenant.organization.id)).at(-1)).toBe(
      'vault.capability_issued',
    );
    // The raw token is nowhere in the database.
    const dump = JSON.stringify(
      rowsOf(await handle.db.execute(sql`select * from vault_access_capabilities`)),
    );
    const audit = JSON.stringify(
      rowsOf(await handle.db.execute(sql`select metadata from audit_events`)),
    );
    expect(dump).not.toContain(issued.token);
    expect(audit).not.toContain(issued.token);
    expect(audit).not.toContain(issued.tokenHash);
    expect(audit).not.toContain(TOKEN_MAC);
  });

  it('never lets the token outlive the authorization', async () => {
    const f = await op();
    const authorized = await authorize(repositories, f, { ttlSeconds: 10 });
    await markRunning(handle.db, f.jobId);
    const issued = await repositories.capabilities.issueToken(
      issueInput(authorized, { now: at(4000), tokenTtlSeconds: 120 }),
    );
    expect(issued!.tokenExpiresAt).toBe(at(10_000).toISOString());
  });

  it('binds version 0 for a login with no stored session and the current version otherwise', async () => {
    const l = await login();
    const first = await issue(handle.db, repositories, l);
    expect(first.record.secretVersion).toBe(0);
    expect(first.record.purpose).toBe('seal');

    const l2 = await login();
    await repositories.vault.putVersion({
      secretId: l2.secretId,
      version: 1,
      sealed: fakeSealed('login'),
      now: T0,
    });
    const second = await issue(handle.db, repositories, l2);
    expect(second.record.secretVersion).toBe(1);
  });

  it('refuses every lifetime that is not a safe integer within 1 to 120 seconds (P3-7)', async () => {
    const f = await op();
    const authorized = await authorize(repositories, f);
    await markRunning(handle.db, f.jobId);
    const bad: unknown[] = [
      0,
      -1,
      121,
      0.5,
      Number.NaN,
      Infinity,
      -Infinity,
      2 ** 53,
      '30',
      null,
      undefined,
    ];
    for (const tokenTtlSeconds of bad) {
      await expect(
        repositories.capabilities.issueToken(issueInput(authorized, { tokenTtlSeconds })),
      ).rejects.toBeInstanceOf(ValidationError);
    }
    const { tokenTtlSeconds: _omitted, ...without } = issueInput(authorized);
    await expect(repositories.capabilities.issueToken(without as never)).rejects.toBeInstanceOf(
      ValidationError,
    );
    expect((await capabilityRow(handle.db, authorized.capabilityId)).token_hash).toBeNull();
    // 1 and 120 are accepted.
    expect(
      await repositories.capabilities.issueToken(issueInput(authorized, { tokenTtlSeconds: 120 })),
    ).not.toBeNull();
  });

  const refusals: [
    string,
    (f: Awaited<ReturnType<typeof authorize>>) => Promise<Record<string, unknown>>,
  ][] = [
    ['a job that is still queued', async () => ({})],
    ['another worker', async () => ({ workerId: 'worker-2' })],
    ['another attempt', async () => ({ attempt: 2 })],
    ['a MAC other than the verified one', async () => ({ authorizationMac: 'f'.repeat(64) })],
    ['another job id', async () => ({ jobId: randomUUID() })],
    ['an expired authorization', async () => ({ now: at(601_000) })],
    [
      'a cancellation request',
      async (f) => {
        await sql1(
          sql`update execution_jobs set cancel_requested_at = now() where id = ${f.jobId}::uuid`,
        );
        return {};
      },
    ],
    [
      'a revoked capability',
      async (f) => {
        await sql1(
          sql`update vault_access_capabilities set revoked_at = now(), revoked_reason = 'owner_requested' where id = ${f.capabilityId}::uuid`,
        );
        return {};
      },
    ],
    [
      'a connection that is no longer active',
      async (f) => {
        await setConnectionStatus(handle.db, f.connectionId, 'expired');
        return {};
      },
    ],
    [
      'a revoked secret',
      async (f) => {
        await sql1(
          sql`update vault_secrets set status = 'revoked', active_version_id = null where id = ${f.secretId}::uuid`,
        );
        return {};
      },
    ],
    [
      'a secret with no active version',
      async (f) => {
        await sql1(
          sql`update vault_secrets set status = 'deleted', active_version_id = null where id = ${f.secretId}::uuid`,
        );
        return {};
      },
    ],
  ];
  for (const [name, arrange] of refusals) {
    it(`refuses ${name} and changes nothing`, async () => {
      const f = await op();
      const authorized = await authorize(repositories, f);
      if (name !== 'a job that is still queued') await markRunning(handle.db, f.jobId);
      const overrides = await arrange(authorized);
      const before = await capabilityRow(handle.db, authorized.capabilityId);
      const events = (await auditTypes(handle.db, tenant.organization.id)).length;
      const result = await repositories.capabilities.issueToken(issueInput(authorized, overrides));
      expect(result).toBeNull();
      expect(await capabilityRow(handle.db, authorized.capabilityId)).toEqual(before);
      expect((await auditTypes(handle.db, tenant.organization.id)).length).toBe(events);
    });
  }

  it('issues one token only: a second issue for the same capability changes nothing', async () => {
    const f = await op();
    const issued = await issue(handle.db, repositories, f);
    const before = await capabilityRow(handle.db, issued.capabilityId);
    expect(
      await repositories.capabilities.issueToken(issueInput(issued, { now: at(1500) })),
    ).toBeNull();
    expect(await capabilityRow(handle.db, issued.capabilityId)).toEqual(before);
  });

  it('rolls everything back when the token MAC cannot be computed or its audit event fails', async () => {
    const f = await op();
    const authorized = await authorize(repositories, f);
    await markRunning(handle.db, f.jobId);
    await expect(
      repositories.capabilities.issueToken(
        issueInput(authorized, {
          computeTokenMac: () => {
            throw new Error('mac failed');
          },
        }),
      ),
    ).rejects.toThrow('mac failed');
    await expect(
      repositories.capabilities.issueToken(
        issueInput(authorized, { actor: { type: 'user', id: 'not-a-uuid' } }),
      ),
    ).rejects.toBeInstanceOf(ValidationError);
    await expect(
      repositories.capabilities.issueToken(
        issueInput(authorized, { computeTokenMac: () => 'bad' }),
      ),
    ).rejects.toBeInstanceOf(ValidationError);
    expect((await capabilityRow(handle.db, authorized.capabilityId)).token_hash).toBeNull();
    expect((await capabilityRow(handle.db, authorized.capabilityId)).token_mac).toBeNull();
  });

  it('getAuthorization returns the stored row for the vault and null for unknown ids', async () => {
    const f = await op();
    const authorized = await authorize(repositories, f);
    const record = await repositories.capabilities.getAuthorization(authorized.capabilityId);
    expect(record).toMatchObject({
      id: authorized.capabilityId,
      authorizationMac: AUTH_MAC,
      macKekVersion: 1,
      tokenHash: null,
    });
    expect(await repositories.capabilities.getAuthorization(UNKNOWN_ID)).toBeNull();
    expect(await repositories.capabilities.getAuthorization('nope')).toBeNull();
  });
});

describe('capabilities.consumeRead (stage 3, operation job)', () => {
  it('consumes once, returns the bound row and sets used_at', async () => {
    const f = await op();
    const issued = await issue(handle.db, repositories, f);
    const consumed = await repositories.capabilities.consumeRead(consumeInput(issued));
    expect(consumed).toMatchObject({
      id: issued.capabilityId,
      secretId: f.secretId,
      secretVersion: 1,
      workerId: 'worker-1',
      attempt: 1,
      usedAt: at(2000).toISOString(),
      tokenMac: TOKEN_MAC,
      authorizationMac: AUTH_MAC,
    });
    expect((await capabilityRow(handle.db, issued.capabilityId)).used_at).not.toBeNull();
    expect(await repositories.capabilities.consumeRead(consumeInput(issued))).toBeNull();
  });

  /**
   * Each case breaks exactly one condition of the statement. Afterwards the consume must return
   * null, the capability row must be byte-for-byte what it was, and describeForRejection must
   * name the reason.
   */
  const negatives: [string, string, Mutation, Overrides?][] = [
    [
      'expired token',
      'expired',
      async () => undefined,
      () => ({ now: at(1000 + TOKEN_TTL * 1000) }), // token_expires_at is not "after" itself
    ],
    [
      'revoked capability',
      'revoked',
      async (f) => {
        await repositories.capabilities.revokeForAgentConnection({
          agentId: f.agentId,
          connectionId: f.connectionId,
          reason: 'grant_revoked',
          now: at(1500),
        });
        // revokeForAgentConnection leaves an issued-but-unused capability revoked.
      },
    ],
    [
      'already used capability',
      'used',
      async (f) => {
        expect(await repositories.capabilities.consumeRead(consumeInput(f))).not.toBeNull();
      },
    ],
    ['wrong token hash', 'unknown_token', async () => undefined, { tokenHash: newToken().hash }],
    [
      'wrong job',
      'binding_mismatch',
      async () => undefined,
      { jobId: '00000000-0000-4000-8000-000000000001' },
    ],
    [
      'wrong connection',
      'binding_mismatch',
      async () => undefined,
      { connectionId: '00000000-0000-4000-8000-000000000002' },
    ],
    ['wrong operation', 'binding_mismatch', async () => undefined, { operation: 'orders.get' }],
    [
      'job bound to another worker',
      'binding_mismatch',
      async (f) => {
        await sql1(
          sql`update execution_jobs set worker_id = 'worker-2' where id = ${f.jobId}::uuid`,
        );
      },
    ],
    [
      'job on another attempt',
      'binding_mismatch',
      async (f) => {
        await sql1(sql`update execution_jobs set attempt_count = 2 where id = ${f.jobId}::uuid`);
      },
    ],
    [
      'job whose capability_ref points elsewhere',
      'binding_mismatch',
      async (f) => {
        await sql1(
          sql`update execution_jobs set capability_ref = null where id = ${f.jobId}::uuid`,
        );
      },
    ],
    [
      'job no longer running',
      'job_not_running',
      async (f) => {
        await sql1(sql`update execution_jobs set status = 'succeeded' where id = ${f.jobId}::uuid`);
      },
    ],
    [
      'job with a cancellation requested',
      'job_not_running',
      async (f) => {
        await sql1(
          sql`update execution_jobs set cancel_requested_at = now() where id = ${f.jobId}::uuid`,
        );
      },
    ],
    [
      'connection revoked',
      'connection_not_active',
      async (f) => {
        await setConnectionStatus(handle.db, f.connectionId, 'revoked');
      },
    ],
    [
      'connection degraded',
      'connection_not_active',
      async (f) => {
        await setConnectionStatus(handle.db, f.connectionId, 'degraded');
      },
    ],
    [
      'secret revoked',
      'secret_not_active',
      async (f) => {
        await sql1(
          sql`update vault_secrets set status = 'revoked', active_version_id = null where id = ${f.secretId}::uuid`,
        );
      },
    ],
    [
      'secret deleted',
      'secret_not_active',
      async (f) => {
        await sql1(
          sql`update vault_secrets set status = 'deleted', active_version_id = null where id = ${f.secretId}::uuid`,
        );
      },
    ],
    [
      'secret version replaced after issue',
      'secret_not_active',
      async (f) => {
        await repositories.vault.putVersion({
          secretId: f.secretId,
          version: 2,
          sealed: fakeSealed('v2'),
          now: at(1500),
        });
      },
    ],
    [
      'token MAC missing',
      'integrity',
      async (f) => {
        await sql1(
          sql`update vault_access_capabilities set token_mac = null where id = ${f.capabilityId}::uuid`,
        );
      },
    ],
  ];
  for (const [name, reason, arrange, overrides] of negatives) {
    it(`refuses ${name}, changes nothing and is labelled ${reason}`, async () => {
      const f = await op();
      const issued = await issue(handle.db, repositories, f);
      await arrange(issued);
      const before = await capabilityRow(handle.db, issued.capabilityId);
      const jobBefore = await jobRow(handle.db, f.jobId);
      const input = consumeInput(issued, resolve(overrides));
      expect(await repositories.capabilities.consumeRead(input)).toBeNull();
      expect(await capabilityRow(handle.db, issued.capabilityId)).toEqual(before);
      expect(await jobRow(handle.db, f.jobId)).toEqual(jobBefore);
      const rejection = await repositories.capabilities.describeForRejection({
        ...input,
        purpose: 'read',
      });
      expect(rejection.reason).toBe(reason);
    });
  }

  it('refuses a capability that never received a token and labels it unknown_token', async () => {
    const f = await op();
    const authorized = await authorize(repositories, f);
    await markRunning(handle.db, f.jobId);
    const { hash } = newToken();
    const input = {
      tokenHash: hash,
      jobId: f.jobId,
      connectionId: f.connectionId,
      operation: f.operation,
      now: at(2000),
    };
    const before = await capabilityRow(handle.db, authorized.capabilityId);
    expect(await repositories.capabilities.consumeRead(input)).toBeNull();
    expect(await capabilityRow(handle.db, authorized.capabilityId)).toEqual(before);
    expect(
      (await repositories.capabilities.describeForRejection({ ...input, purpose: 'read' })).reason,
    ).toBe('unknown_token');
  });

  it('refuses a seal token presented as a read (wrong purpose) and the reverse', async () => {
    const l = await login();
    const sealIssued = await issue(handle.db, repositories, l);
    const input = consumeInput(sealIssued, { operation: 'orders.list' });
    const before = await capabilityRow(handle.db, sealIssued.capabilityId);
    expect(await repositories.capabilities.consumeRead(input)).toBeNull();
    expect(
      await repositories.capabilities.consumeSeal(
        consumeInput(sealIssued, { operation: 'orders.list' }),
      ),
    ).toBeNull();
    expect(await capabilityRow(handle.db, sealIssued.capabilityId)).toEqual(before);
    expect(
      (await repositories.capabilities.describeForRejection({ ...input, purpose: 'read' })).reason,
    ).toBe('binding_mismatch');

    const f = await op();
    const readIssued = await issue(handle.db, repositories, f);
    const readBefore = await capabilityRow(handle.db, readIssued.capabilityId);
    const asSeal = consumeInput(readIssued, { operation: null });
    expect(await repositories.capabilities.consumeSeal(asSeal)).toBeNull();
    expect(await capabilityRow(handle.db, readIssued.capabilityId)).toEqual(readBefore);
    expect(
      (await repositories.capabilities.describeForRejection({ ...asSeal, purpose: 'seal' })).reason,
    ).toBe('binding_mismatch');
  });

  it('refuses malformed input without a database round trip that could change anything', async () => {
    const f = await op();
    const issued = await issue(handle.db, repositories, f);
    const before = await capabilityRow(handle.db, issued.capabilityId);
    for (const overrides of [
      { tokenHash: 'nope' },
      { tokenHash: issued.token }, // the raw token is not a hash
      { jobId: 'nope' },
      { connectionId: 'nope' },
      { operation: null },
    ]) {
      expect(
        await repositories.capabilities.consumeRead(consumeInput(issued, overrides)),
      ).toBeNull();
    }
    await expect(
      repositories.capabilities.consumeRead(consumeInput(issued, { now: new Date(Number.NaN) })),
    ).rejects.toBeInstanceOf(ValidationError);
    expect(await capabilityRow(handle.db, issued.capabilityId)).toEqual(before);
  });

  it('commits with its audit event or not at all (P3-13)', async () => {
    const f = await op();
    const issued = await issue(handle.db, repositories, f);
    await expect(
      repositories.transaction(async (tx) => {
        expect(await tx.capabilities.consumeRead(consumeInput(issued))).not.toBeNull();
        // The vault's next step: the event that describes the read. It fails here.
        await tx.audit.append({
          organizationId: tenant.organization.id,
          actorType: 'system',
          actorId: 'not-a-uuid',
          eventType: 'vault.secret_read',
        });
      }),
    ).rejects.toBeInstanceOf(ValidationError);
    expect((await capabilityRow(handle.db, issued.capabilityId)).used_at).toBeNull();
    // Still redeemable afterwards: the failed transaction left no trace.
    expect(await repositories.capabilities.consumeRead(consumeInput(issued))).not.toBeNull();
  });
});

describe('capabilities.consumeSeal (stage 3, login job)', () => {
  it('consumes once for an authenticating connection with no stored session', async () => {
    const l = await login();
    const issued = await issue(handle.db, repositories, l);
    const input = consumeInput(issued, { operation: null });
    const consumed = await repositories.capabilities.consumeSeal(input);
    expect(consumed).toMatchObject({
      purpose: 'seal',
      secretVersion: 0,
      usedAt: at(2000).toISOString(),
    });
    expect(await repositories.capabilities.consumeSeal(input)).toBeNull();
    expect(
      (await repositories.capabilities.describeForRejection({ ...input, purpose: 'seal' })).reason,
    ).toBe('used');
  });

  const negatives: [string, string, Mutation, Overrides?][] = [
    [
      'connection no longer authenticating',
      'connection_not_active',
      async (f) => {
        await setConnectionStatus(handle.db, f.connectionId, 'active');
      },
    ],
    [
      'connection revoked',
      'connection_not_active',
      async (f) => {
        await setConnectionStatus(handle.db, f.connectionId, 'revoked');
      },
    ],
    [
      'secret revoked',
      'secret_not_active',
      async (f) => {
        await sql1(
          sql`update vault_secrets set status = 'revoked', active_version_id = null where id = ${f.secretId}::uuid`,
        );
      },
    ],
    [
      'active version moved after issue',
      'secret_not_active',
      async (f) => {
        await repositories.vault.putVersion({
          secretId: f.secretId,
          version: 1,
          sealed: fakeSealed('moved'),
          now: at(1500),
        });
      },
    ],
    [
      'expired token',
      'expired',
      async () => undefined,
      () => ({ now: at(1000 + TOKEN_TTL * 1000 + 1) }),
    ],
    [
      'revoked capability',
      'revoked',
      async (f) => {
        await repositories.capabilities.revokeForConnection({
          connectionId: f.connectionId,
          reason: 'owner_requested',
          now: at(1500),
        });
      },
    ],
    [
      'wrong job',
      'binding_mismatch',
      async () => undefined,
      { jobId: '00000000-0000-4000-8000-000000000003' },
    ],
    [
      'wrong connection',
      'binding_mismatch',
      async () => undefined,
      { connectionId: '00000000-0000-4000-8000-000000000004' },
    ],
    [
      'job on another worker',
      'binding_mismatch',
      async (f) => {
        await sql1(
          sql`update execution_jobs set worker_id = 'worker-9' where id = ${f.jobId}::uuid`,
        );
      },
    ],
    ['wrong token hash', 'unknown_token', async () => undefined, { tokenHash: newToken().hash }],
  ];
  for (const [name, reason, arrange, overrides] of negatives) {
    it(`refuses ${name}, changes nothing and is labelled ${reason}`, async () => {
      const l = await login();
      const issued = await issue(handle.db, repositories, l);
      await arrange(issued);
      const before = await capabilityRow(handle.db, issued.capabilityId);
      const input = consumeInput(issued, { operation: null, ...resolve(overrides) });
      expect(await repositories.capabilities.consumeSeal(input)).toBeNull();
      expect(await capabilityRow(handle.db, issued.capabilityId)).toEqual(before);
      expect(
        (await repositories.capabilities.describeForRejection({ ...input, purpose: 'seal' }))
          .reason,
      ).toBe(reason);
    });
  }
});

describe('capabilities.describeForRejection and recordRejection', () => {
  it('attributes an unknown token to the presented job only when that job exists', async () => {
    const f = await op();
    const known = await repositories.capabilities.describeForRejection({
      tokenHash: newToken().hash,
      jobId: f.jobId,
      connectionId: f.connectionId,
      operation: 'orders.list',
      now: at(0),
      purpose: 'read',
    });
    expect(known).toEqual({
      reason: 'unknown_token',
      organizationId: tenant.organization.id,
      capabilityId: null,
      jobId: f.jobId,
      connectionId: f.connectionId,
      purpose: 'read',
    });
    // A presented connection that is not the job's is not echoed into the event.
    const mismatch = await repositories.capabilities.describeForRejection({
      tokenHash: newToken().hash,
      jobId: f.jobId,
      connectionId: UNKNOWN_ID,
      operation: 'orders.list',
      now: at(0),
      purpose: 'read',
    });
    expect(mismatch.connectionId).toBeNull();

    const unresolved = await repositories.capabilities.describeForRejection({
      tokenHash: 'garbage',
      jobId: UNKNOWN_ID,
      connectionId: UNKNOWN_ID,
      operation: null,
      now: at(0),
      purpose: 'seal',
    });
    expect(unresolved).toEqual({
      reason: 'unknown_token',
      organizationId: null,
      capabilityId: null,
      jobId: null,
      connectionId: null,
      purpose: 'seal',
    });
    expect(
      await repositories.capabilities.recordRejection(unresolved, {
        role: 'supervisor',
        now: at(0),
      }),
    ).toBeNull();
  });

  it('answers with the capability own ids, not the presented ones, when the token resolves', async () => {
    const f = await op();
    const issued = await issue(handle.db, repositories, f);
    const rejection = await repositories.capabilities.describeForRejection({
      ...consumeInput(issued),
      jobId: UNKNOWN_ID,
      purpose: 'read',
    });
    expect(rejection).toEqual({
      reason: 'binding_mismatch',
      organizationId: tenant.organization.id,
      capabilityId: issued.capabilityId,
      jobId: f.jobId,
      connectionId: f.connectionId,
      purpose: 'read',
    });
  });

  it('writes vault.capability_rejected with the reason and no token, hash or MAC (P3-12)', async () => {
    const f = await op();
    const issued = await issue(handle.db, repositories, f);
    await repositories.capabilities.consumeRead(consumeInput(issued));
    const input = consumeInput(issued);
    const rejection = await repositories.capabilities.describeForRejection({
      ...input,
      purpose: 'read',
    });
    const eventId = await repositories.capabilities.recordRejection(rejection, {
      role: 'supervisor',
      now: at(3000),
    });
    expect(eventId).not.toBeNull();
    const [event] = rowsOf(
      await handle.db.execute(
        sql`select event_type, decision, actor_type, metadata, connection_id from audit_events where id = ${eventId}::uuid`,
      ),
    );
    expect(event).toMatchObject({
      event_type: 'vault.capability_rejected',
      decision: 'deny',
      actor_type: 'system',
    });
    expect(event!.metadata).toEqual({
      reason: 'used',
      purpose: 'read',
      role: 'supervisor',
      capabilityId: issued.capabilityId,
      jobId: f.jobId,
    });
    const text = JSON.stringify(event);
    for (const secret of [issued.token, issued.tokenHash, TOKEN_MAC, AUTH_MAC]) {
      expect(text).not.toContain(secret);
    }
  });
});

describe('revocation (P3-8, P3-18)', () => {
  it('connections.revoke revokes unused capabilities in the same transaction, with an event', async () => {
    const f = await op();
    const issued = await issue(handle.db, repositories, f);
    const g = await op();
    // Same connection: a second capability needs another job on the connection.
    const second = await addOperationJob(repositories, f);
    const used = await authorize(repositories, second);
    await sql1(
      sql`update vault_access_capabilities set token_hash = ${newToken().hash}, token_issued_at = ${at(1000).toISOString()}::timestamptz, token_expires_at = ${at(5000).toISOString()}::timestamptz, worker_id = 'w', attempt = 1, secret_version = 1, token_mac = ${TOKEN_MAC}, used_at = ${at(2000).toISOString()}::timestamptz where id = ${used.capabilityId}::uuid`,
    );
    const unrelated = await authorize(repositories, g);

    await repositories.connections.revoke(tenant.scope, f.connectionId, {});
    expect((await capabilityRow(handle.db, issued.capabilityId)).revoked_reason).toBe(
      'connection_revoked',
    );
    // A used capability is not rewritten; another connection's capability is untouched.
    expect((await capabilityRow(handle.db, used.capabilityId)).revoked_at).toBeNull();
    expect((await capabilityRow(handle.db, unrelated.capabilityId)).revoked_at).toBeNull();
    const events = await auditTypes(handle.db, tenant.organization.id);
    expect(
      events.filter((type) => type === 'vault.capability_revoked').length,
    ).toBeGreaterThanOrEqual(1);
  });

  it('a failed connection revocation leaves its capabilities alone', async () => {
    const f = await op();
    const issued = await issue(handle.db, repositories, f);
    await expect(
      repositories.transaction(async (tx) => {
        await tx.connections.revoke(tenant.scope, f.connectionId, {});
        throw new Error('abort');
      }),
    ).rejects.toThrow('abort');
    expect((await capabilityRow(handle.db, issued.capabilityId)).revoked_at).toBeNull();
    expect((await repositories.connections.get(tenant.scope, f.connectionId))!.status).toBe(
      'active',
    );
  });

  it('grants.revoke revokes the agent capabilities for that connection only', async () => {
    const f = await op();
    const g = await op();
    const issued = await issue(handle.db, repositories, f);
    const elsewhere = await authorize(repositories, g);
    const grant = await repositories.grants.create(tenant.scope, f.agentId, {
      connectionId: f.connectionId,
      operation: 'orders.list',
      effect: 'allow',
      constraints: {},
      approvalMode: 'none',
    });
    await repositories.grants.revoke(tenant.scope, f.agentId, grant.id, at(1500));
    expect(await capabilityRow(handle.db, issued.capabilityId)).toMatchObject({
      revoked_reason: 'grant_revoked',
    });
    expect((await capabilityRow(handle.db, elsewhere.capabilityId)).revoked_at).toBeNull();
    // Revoking the same grant again changes nothing (and writes no second event).
    const count = (await auditTypes(handle.db, tenant.organization.id)).filter(
      (type) => type === 'vault.capability_revoked',
    ).length;
    await repositories.grants.revoke(tenant.scope, f.agentId, grant.id, at(1600));
    expect(
      (await auditTypes(handle.db, tenant.organization.id)).filter(
        (type) => type === 'vault.capability_revoked',
      ).length,
    ).toBe(count);
  });

  it('agents.disable revokes the agent capabilities on every connection', async () => {
    const f = await op();
    const issued = await issue(handle.db, repositories, f);
    await repositories.agents.disable(tenant.scope, f.agentId);
    expect(await capabilityRow(handle.db, issued.capabilityId)).toMatchObject({
      revoked_reason: 'agent_disabled',
    });
    // The consume now refuses it, with the reason `revoked`.
    expect(await repositories.capabilities.consumeRead(consumeInput(issued))).toBeNull();
    expect(
      (
        await repositories.capabilities.describeForRejection({
          ...consumeInput(issued),
          purpose: 'read',
        })
      ).reason,
    ).toBe('revoked');
  });

  it('revokeForConnection and revokeForAgentConnection ignore malformed ids and write no event for nothing', async () => {
    const before = (await auditTypes(handle.db, tenant.organization.id)).length;
    expect(
      await repositories.capabilities.revokeForConnection({
        connectionId: 'nope',
        reason: 'owner_requested',
        now: T0,
      }),
    ).toEqual({ revoked: 0, capabilityIds: [] });
    expect(
      await repositories.capabilities.revokeForAgentConnection({
        agentId: UNKNOWN_ID,
        connectionId: null,
        reason: 'agent_disabled',
        now: T0,
      }),
    ).toEqual({ revoked: 0, capabilityIds: [] });
    expect((await auditTypes(handle.db, tenant.organization.id)).length).toBe(before);
  });

  it('rolls back the revocation when its audit event cannot be written', async () => {
    const f = await op();
    const issued = await issue(handle.db, repositories, f);
    await expect(
      repositories.capabilities.revokeForConnection({
        connectionId: f.connectionId,
        reason: 'owner_requested',
        now: T0,
        actor: { type: 'user', id: 'not-a-uuid' },
      }),
    ).rejects.toBeInstanceOf(ValidationError);
    expect((await capabilityRow(handle.db, issued.capabilityId)).revoked_at).toBeNull();
  });

  it('deleteForConnection makes the secrets of a revoked connection terminal and others deleted', async () => {
    const f = await op();
    await repositories.connections.revoke(tenant.scope, f.connectionId, {});
    expect(await repositories.vault.deleteForConnection(f.connectionId, at(100))).toBe(1);
    expect((await secretRow(handle.db, f.secretId)).status).toBe('revoked');
    expect((await secretRow(handle.db, f.secretId)).active_version_id).toBeNull();
    // Idempotent and terminal: a second call neither errors nor changes the status.
    expect(await repositories.vault.deleteForConnection(f.connectionId, at(200))).toBe(0);
    expect((await secretRow(handle.db, f.secretId)).status).toBe('revoked');

    const g = await op();
    await repositories.vault.deleteForConnection(g.connectionId, at(100));
    expect((await secretRow(handle.db, g.secretId)).status).toBe('deleted');
  });
});

describe('the revoked secret trigger and putVersion (P3-8)', () => {
  async function revokedSecret() {
    const f = await op();
    // What revocation does: the ciphertext goes, then the secret becomes terminal.
    await sql1(sql`delete from vault_secret_versions where secret_id = ${f.secretId}::uuid`);
    await sql1(
      sql`update vault_secrets set status = 'revoked', active_version_id = null where id = ${f.secretId}::uuid`,
    );
    return f;
  }

  it('the trigger refuses to move a secret out of revoked, whatever the new status', async () => {
    for (const status of ['pending', 'active', 'deleted']) {
      const f = await revokedSecret();
      await refusedBy(
        handle.db.execute(
          sql`update vault_secrets set status = ${status} where id = ${f.secretId}::uuid`,
        ),
        /revoked secret can never change status/,
      );
      expect((await secretRow(handle.db, f.secretId)).status).toBe('revoked');
    }
  });

  it('refuses to give a revoked secret an active version, and to insert a version for it', async () => {
    const f = await op();
    const versionId = String(
      rowsOf(
        await handle.db.execute(
          sql`select id from vault_secret_versions where secret_id = ${f.secretId}::uuid`,
        ),
      )[0]!.id,
    );
    // Revoking while the pointer is still set is refused: a revoked secret has no active version.
    await refusedBy(
      handle.db.execute(
        sql`update vault_secrets set status = 'revoked' where id = ${f.secretId}::uuid`,
      ),
      /no active version/,
    );
    await sql1(
      sql`update vault_secrets set status = 'revoked', active_version_id = null where id = ${f.secretId}::uuid`,
    );
    await refusedBy(
      handle.db.execute(
        sql`update vault_secrets set active_version_id = ${versionId}::uuid where id = ${f.secretId}::uuid`,
      ),
      /no active version/,
    );
    await refusedBy(
      handle.db.execute(
        sql`insert into vault_secret_versions (secret_id, version, algorithm, ciphertext, nonce, auth_tag, wrapped_dek, kek_version, aad_version)
            values (${f.secretId}::uuid, 9, 'x', '\\x00', '\\x00', '\\x00', '\\x00', 1, 1)`,
      ),
      /revoked secret/,
    );
  });

  it('allows a revoked secret to be revoked again (idempotent revocation)', async () => {
    const f = await revokedSecret();
    await sql1(
      sql`update vault_secrets set status = 'revoked', active_version_id = null, updated_at = now() where id = ${f.secretId}::uuid`,
    );
    expect((await secretRow(handle.db, f.secretId)).status).toBe('revoked');
  });

  it('putVersion refuses a revoked secret and stores nothing', async () => {
    const f = await revokedSecret();
    await expect(
      repositories.vault.putVersion({
        secretId: f.secretId,
        version: 5,
        sealed: fakeSealed('late'),
        now: at(10),
      }),
    ).rejects.toBeInstanceOf(ConflictError);
    expect(
      rowsOf(
        await handle.db.execute(
          sql`select 1 from vault_secret_versions where secret_id = ${f.secretId}::uuid`,
        ),
      ),
    ).toHaveLength(0);
    expect((await secretRow(handle.db, f.secretId)).status).toBe('revoked');
  });
});

describe('active-pointer compare-and-set (P3-9)', () => {
  async function versions(secretId: string): Promise<number[]> {
    return rowsOf(
      await handle.db.execute(
        sql`select version from vault_secret_versions where secret_id = ${secretId}::uuid order by version`,
      ),
    ).map((row) => Number(row.version));
  }

  it('moves the pointer only from the expected version and stores nothing otherwise', async () => {
    const f = await op(); // version 1 is active
    await expect(
      repositories.vault.putVersion({
        secretId: f.secretId,
        version: 2,
        sealed: fakeSealed('x'),
        now: at(10),
        expectedActiveVersion: 0,
      }),
    ).rejects.toBeInstanceOf(ConflictError);
    await expect(
      repositories.vault.putVersion({
        secretId: f.secretId,
        version: 2,
        sealed: fakeSealed('x'),
        now: at(10),
        expectedActiveVersion: 2,
      }),
    ).rejects.toBeInstanceOf(ConflictError);
    expect(await versions(f.secretId)).toEqual([1]);
    expect(Number((await secretRow(handle.db, f.secretId)).last_version)).toBe(1);

    await repositories.vault.putVersion({
      secretId: f.secretId,
      version: 2,
      sealed: fakeSealed('y'),
      now: at(20),
      expectedActiveVersion: 1,
    });
    expect(await versions(f.secretId)).toEqual([2]);
    // The version the login was bound to is gone: replaying the same expectation is refused.
    await expect(
      repositories.vault.putVersion({
        secretId: f.secretId,
        version: 3,
        sealed: fakeSealed('z'),
        now: at(30),
        expectedActiveVersion: 1,
      }),
    ).rejects.toBeInstanceOf(ConflictError);
    expect(await versions(f.secretId)).toEqual([2]);
  });

  it('expects 0 for a secret that has no version yet, and rejects non-integers', async () => {
    const l = await login();
    await expect(
      repositories.vault.putVersion({
        secretId: l.secretId,
        version: 1,
        sealed: fakeSealed('a'),
        now: at(10),
        expectedActiveVersion: 1,
      }),
    ).rejects.toBeInstanceOf(ConflictError);
    for (const expectedActiveVersion of [-1, 0.5, Number.NaN, Infinity]) {
      await expect(
        repositories.vault.putVersion({
          secretId: l.secretId,
          version: 1,
          sealed: fakeSealed('a'),
          now: at(10),
          expectedActiveVersion,
        }),
      ).rejects.toBeInstanceOf(ValidationError);
    }
    await repositories.vault.putVersion({
      secretId: l.secretId,
      version: 1,
      sealed: fakeSealed('a'),
      now: at(10),
      expectedActiveVersion: 0,
    });
    expect(await versions(l.secretId)).toEqual([1]);
  });

  it('getVersion returns the exact bound version and nothing else', async () => {
    const f = await op();
    expect((await repositories.vault.getVersion(f.secretId, 1))?.version).toBe(1);
    expect(await repositories.vault.getVersion(f.secretId, 2)).toBeNull();
    expect(await repositories.vault.getVersion('nope', 1)).toBeNull();
    await sql1(sql`update vault_secrets set status = 'deleted' where id = ${f.secretId}::uuid`);
    expect(await repositories.vault.getVersion(f.secretId, 1)).toBeNull();
  });
});

describe('rewrap compare-and-set (P3-9)', () => {
  async function version(f: CapabilityFixture) {
    return rowsOf(
      await handle.db.execute(
        sql`select * from vault_secret_versions where secret_id = ${f.secretId}::uuid`,
      ),
    )[0]!;
  }
  const rewrapInput = (row: Record<string, unknown>, overrides = {}) => ({
    versionId: String(row.id),
    fromKekVersion: Number(row.kek_version),
    expectedWrappedDek: Buffer.from(row.wrapped_dek as Uint8Array),
    toKekVersion: 2,
    newWrappedDek: Buffer.from('rewrapped-under-kek-2'),
    now: at(500),
    ...overrides,
  });

  it('changes exactly wrapped_dek and kek_version and appends vault.secret_rewrapped', async () => {
    const f = await op();
    const before = await version(f);
    expect(await repositories.vault.rewrapVersion(rewrapInput(before))).toBe(true);
    const after = await version(f);
    const { wrapped_dek: oldDek, kek_version: oldKek, ...restBefore } = before;
    const { wrapped_dek: newDek, kek_version: newKek, ...restAfter } = after;
    expect(restAfter).toEqual(restBefore);
    expect(Buffer.from(newDek as Uint8Array).toString()).toBe('rewrapped-under-kek-2');
    expect(Number(newKek)).toBe(2);
    expect(Buffer.from(oldDek as Uint8Array).toString()).not.toBe('rewrapped-under-kek-2');
    expect(Number(oldKek)).toBe(1);
    const [event] = rowsOf(
      await handle.db.execute(
        sql`select metadata from audit_events where organization_id = ${tenant.organization.id}::uuid and event_type = 'vault.secret_rewrapped' order by sequence desc limit 1`,
      ),
    );
    expect(event!.metadata).toEqual({
      connectionId: f.connectionId,
      vaultEntryId: f.secretId,
      entryVersion: 1,
      keyVersionFrom: 1,
      keyVersionTo: 2,
    });
    expect(JSON.stringify(event)).not.toContain('rewrapped-under-kek-2');
    // Running it again is a skip: the kek version no longer matches.
    expect(await repositories.vault.rewrapVersion(rewrapInput(before))).toBe(false);
  });

  it('refuses when wrapped_dek changed, when kek_version changed, or when the version is gone', async () => {
    const f = await op();
    const row = await version(f);
    expect(
      await repositories.vault.rewrapVersion(
        rewrapInput(row, { expectedWrappedDek: Buffer.from('something else') }),
      ),
    ).toBe(false);
    expect(await repositories.vault.rewrapVersion(rewrapInput(row, { fromKekVersion: 5 }))).toBe(
      false,
    );
    expect(await version(f)).toEqual(row);

    // The version is replaced while the rewrap was in flight.
    await repositories.vault.putVersion({
      secretId: f.secretId,
      version: 2,
      sealed: fakeSealed('replaced'),
      now: at(10),
    });
    expect(await repositories.vault.rewrapVersion(rewrapInput(row))).toBe(false);
    const replacement = await version(f);
    expect(Number(replacement.version)).toBe(2);
    expect(Number(replacement.kek_version)).toBe(1);
    expect(
      await repositories.vault.rewrapVersion(rewrapInput(row, { versionId: UNKNOWN_ID })),
    ).toBe(false);
  });

  it('skips a version whose secret or connection was revoked', async () => {
    const f = await op();
    const row = await version(f);
    await repositories.connections.revoke(tenant.scope, f.connectionId, {});
    expect(await repositories.vault.rewrapVersion(rewrapInput(row))).toBe(false);
    expect(await version(f)).toEqual(row);

    const g = await op();
    const gRow = await version(g);
    await sql1(sql`update vault_secrets set status = 'deleted' where id = ${g.secretId}::uuid`);
    // A deleted secret is not revoked: rewrapping its leftover row is allowed, a revoked one is not.
    await sql1(sql`update vault_secrets set status = 'active' where id = ${g.secretId}::uuid`);
    expect(await repositories.vault.rewrapVersion(rewrapInput(gRow))).toBe(true);
  });

  it('rejects malformed input before touching the database', async () => {
    const f = await op();
    const row = await version(f);
    for (const overrides of [
      { versionId: 'nope' },
      { fromKekVersion: 0 },
      { toKekVersion: 1 }, // same as from
      { toKekVersion: 0 },
      { toKekVersion: 1.5 },
      { newWrappedDek: Buffer.alloc(0) },
      { expectedWrappedDek: 'text' },
    ]) {
      await expect(
        repositories.vault.rewrapVersion(rewrapInput(row, overrides as never)),
      ).rejects.toBeInstanceOf(ValidationError);
    }
    expect(await version(f)).toEqual(row);
  });

  it('rolls the rewrap back when its audit event cannot be written', async () => {
    const f = await op();
    const row = await version(f);
    await expect(
      repositories.transaction(async (tx) => {
        expect(await tx.vault.rewrapVersion(rewrapInput(row))).toBe(true);
        throw new Error('abort');
      }),
    ).rejects.toThrow('abort');
    expect(await version(f)).toEqual(row);
  });

  it('listForRewrap pages candidates below the target KEK and countByKekVersion counts versions', async () => {
    const f = await op();
    const g = await op();
    const row = await version(f);
    await repositories.vault.rewrapVersion(rewrapInput(row));
    const candidates = await repositories.vault.listForRewrap({ belowKekVersion: 2, limit: 500 });
    expect(candidates.some((candidate) => candidate.secretId === f.secretId)).toBe(false);
    const mine = candidates.find((candidate) => candidate.secretId === g.secretId)!;
    expect(mine).toMatchObject({
      connectionId: g.connectionId,
      organizationId: tenant.organization.id,
      ownerUserId: tenant.user.id,
      secretType: SECRET_TYPE,
      version: 1,
      kekVersion: 1,
      aadVersion: 1,
    });
    expect(Buffer.isBuffer(mine.wrappedDek)).toBe(true);
    expect(Object.keys(mine)).not.toContain('ciphertext');

    // Keyset paging.
    const first = await repositories.vault.listForRewrap({ belowKekVersion: 2, limit: 1 });
    const second = await repositories.vault.listForRewrap({
      belowKekVersion: 2,
      limit: 1,
      afterVersionId: first[0]!.versionId,
    });
    expect(second[0]?.versionId).not.toBe(first[0]!.versionId);

    const counts = await repositories.vault.countByKekVersion();
    expect(counts.find((entry) => entry.kekVersion === 2)!.versions).toBeGreaterThanOrEqual(1);
    expect(counts.find((entry) => entry.kekVersion === 1)!.versions).toBeGreaterThanOrEqual(1);

    // Revoked secrets are not candidates.
    await repositories.connections.revoke(tenant.scope, g.connectionId, {});
    await repositories.vault.deleteForConnection(g.connectionId, at(1));
    expect(
      (await repositories.vault.listForRewrap({ belowKekVersion: 2, limit: 500 })).some(
        (candidate) => candidate.secretId === g.secretId,
      ),
    ).toBe(false);

    for (const bad of [
      { belowKekVersion: 1, limit: 10 },
      { belowKekVersion: 2, limit: 0 },
      { belowKekVersion: 2, limit: 501 },
      { belowKekVersion: 2, limit: 1, afterVersionId: 'nope' },
    ]) {
      await expect(repositories.vault.listForRewrap(bad)).rejects.toBeInstanceOf(ValidationError);
    }
  });
});

describe('Phase 3 claim and lease recovery variants (default behaviour unchanged)', () => {
  beforeEach(async () => {
    await sql1(
      sql`update execution_jobs set status = 'cancelled' where status in ('queued', 'running')`,
    );
  });

  it('claimNext without the option still claims a job that has no capability', async () => {
    const f = await op();
    const claimed = await repositories.jobs.claimNext({ workerId: 'w', leaseMs: 1000, now: at(0) });
    expect(claimed?.id).toBe(f.jobId);
    expect(claimed?.capabilityRef).toBeNull();
  });

  it('claimNext with requireCapability skips jobs without one and claims the authorized job', async () => {
    const bare = await op();
    expect(
      await repositories.jobs.claimNext({
        workerId: 'w',
        leaseMs: 1000,
        now: at(0),
        requireCapability: true,
      }),
    ).toBeNull();
    const f = await op();
    const authorized = await authorize(repositories, f);
    const claimed = await repositories.jobs.claimNext({
      workerId: 'w',
      leaseMs: 1000,
      now: at(0),
      requireCapability: true,
    });
    expect(claimed?.id).toBe(f.jobId);
    expect(claimed?.capabilityRef).toBe(authorized.capabilityId);
    expect(String((await jobRow(handle.db, bare.jobId)).status)).toBe('queued');
  });

  it('recoverExpiredLeases without the option still requeues a retry-safe read whose token was issued', async () => {
    const f = await op();
    const issued = await issue(handle.db, repositories, f);
    await sql1(
      sql`update execution_jobs set lease_expires_at = ${at(10).toISOString()}::timestamptz where id = ${f.jobId}::uuid`,
    );
    const [job] = await repositories.jobs.recoverExpiredLeases({ now: at(100), maxAttempts: 3 });
    expect(job).toMatchObject({ id: f.jobId, status: 'queued' });
    expect((await capabilityRow(handle.db, issued.capabilityId)).revoked_at).toBeNull();
  });

  it('capability-aware recovery requeues a retry-safe read whose capability never got a token', async () => {
    const f = await op();
    const authorized = await authorize(repositories, f);
    await markRunning(handle.db, f.jobId);
    await sql1(
      sql`update execution_jobs set lease_expires_at = ${at(10).toISOString()}::timestamptz where id = ${f.jobId}::uuid`,
    );
    const [job] = await repositories.jobs.recoverExpiredLeases({
      now: at(100),
      maxAttempts: 3,
      capabilityAware: true,
    });
    expect(job).toMatchObject({ id: f.jobId, status: 'queued' });
    expect((await capabilityRow(handle.db, authorized.capabilityId)).revoked_at).toBeNull();
  });

  it('capability-aware recovery fails a read whose token was issued and revokes the capability', async () => {
    const f = await op();
    const issued = await issue(handle.db, repositories, f);
    await sql1(
      sql`update execution_jobs set lease_expires_at = ${at(10).toISOString()}::timestamptz where id = ${f.jobId}::uuid`,
    );
    const [job] = await repositories.jobs.recoverExpiredLeases({
      now: at(100),
      maxAttempts: 3,
      capabilityAware: true,
    });
    expect(job).toMatchObject({ id: f.jobId, status: 'failed', error: { code: 'worker_failure' } });
    expect(await capabilityRow(handle.db, issued.capabilityId)).toMatchObject({
      revoked_reason: 'lease_recovery',
    });
    expect(
      (await auditTypes(handle.db, tenant.organization.id)).filter(
        (type) => type === 'vault.capability_revoked',
      ).length,
    ).toBeGreaterThanOrEqual(1);
  });

  it('capability-aware recovery keeps outcome_unknown for an operation that is not retry-safe and fails a login', async () => {
    const f = await op();
    await sql1(sql`update execution_jobs set retry_safe = false where id = ${f.jobId}::uuid`);
    const issued = await issue(handle.db, repositories, f);
    const l = await login();
    const loginIssued = await issue(handle.db, repositories, l);
    await sql1(
      sql`update execution_jobs set lease_expires_at = ${at(10).toISOString()}::timestamptz where id in (${f.jobId}::uuid, ${l.jobId}::uuid)`,
    );
    const changed = await repositories.jobs.recoverExpiredLeases({
      now: at(100),
      maxAttempts: 3,
      capabilityAware: true,
    });
    const byId = new Map(changed.map((job) => [job.id, job]));
    expect(byId.get(f.jobId)?.status).toBe('outcome_unknown');
    expect(byId.get(l.jobId)?.status).toBe('failed');
    for (const capabilityId of [issued.capabilityId, loginIssued.capabilityId]) {
      expect((await capabilityRow(handle.db, capabilityId)).revoked_reason).toBe('lease_recovery');
    }
  });
});

describe('purge', () => {
  it('deletes capabilities of finished jobs seven days after expiry and clears the job link', async () => {
    const f = await op();
    const g = await op();
    const h = await op();
    const old = await authorize(repositories, f, { now: T0 });
    const recent = await authorize(repositories, g, { now: T0 });
    const live = await authorize(repositories, h, { now: T0 });
    await sql1(
      sql`update execution_jobs set status = 'succeeded' where id in (${f.jobId}::uuid, ${g.jobId}::uuid)`,
    );
    // Both finished-job capabilities expire at T0 + 600 s. Other tests in this file leave
    // finished jobs with capabilities of the same age, so the test checks its own rows.
    const expiry = at(600_000).getTime();
    const exists = async (id: string) =>
      rowsOf(
        await handle.db.execute(
          sql`select id from vault_access_capabilities where id = ${id}::uuid`,
        ),
      ).length === 1;
    // Exactly seven days after expiry is not yet "more than seven days".
    await repositories.capabilities.purge(new Date(expiry + 7 * 86_400_000));
    expect(await exists(old.capabilityId)).toBe(true);
    expect(await exists(recent.capabilityId)).toBe(true);
    expect(
      await repositories.capabilities.purge(new Date(expiry + 7 * 86_400_000 + 1)),
    ).toBeGreaterThanOrEqual(2);
    expect(await exists(old.capabilityId)).toBe(false);
    expect(await exists(recent.capabilityId)).toBe(false);
    expect((await jobRow(handle.db, f.jobId)).capability_ref).toBeNull();
    expect((await jobRow(handle.db, g.jobId)).capability_ref).toBeNull();
    // `live` expired as well, but its job is still queued: it stays.
    expect(await capabilityRow(handle.db, live.capabilityId)).toBeDefined();
    expect(String((await jobRow(handle.db, h.jobId)).capability_ref)).toBe(live.capabilityId);
    await expect(repositories.capabilities.purge(new Date(Number.NaN))).rejects.toBeInstanceOf(
      ValidationError,
    );
  });
});

describe('scoped dashboard reads (ADR-010)', () => {
  it('vault.describeForOwner returns metadata for the owner and NotFound for everyone else', async () => {
    const f = await op();
    const [description] = await repositories.vault.describeForOwner(tenant.scope, f.connectionId);
    expect(description).toMatchObject({
      id: f.secretId,
      secretType: SECRET_TYPE,
      status: 'active',
      activeVersion: 1,
      kekVersion: 1,
    });
    expect(JSON.stringify(description)).not.toMatch(/ciphertext|wrapped|nonce|tag/i);
    for (const scope of [
      teammate.scope, // same organization, not the owner
      other.scope, // another organization
      { organizationId: other.organization.id, userId: tenant.user.id }, // owner id, wrong organization
      { organizationId: tenant.organization.id, userId: other.user.id },
      { organizationId: 'nope', userId: 'nope' },
    ]) {
      await expect(
        repositories.vault.describeForOwner(scope, f.connectionId),
      ).rejects.toBeInstanceOf(NotFoundError);
    }
    await expect(
      repositories.vault.describeForOwner(tenant.scope, UNKNOWN_ID),
    ).rejects.toBeInstanceOf(NotFoundError);
    await expect(repositories.vault.describeForOwner(tenant.scope, 'nope')).rejects.toBeInstanceOf(
      NotFoundError,
    );
  });

  it('capabilities.summarizeForConnection counts for the owner and NotFound for everyone else', async () => {
    const f = await op();
    const issued = await issue(handle.db, repositories, f);
    await repositories.capabilities.consumeRead(consumeInput(issued));
    await repositories.capabilities.recordRejection(
      await repositories.capabilities.describeForRejection({
        ...consumeInput(issued),
        purpose: 'read',
      }),
      { role: 'supervisor', now: at(3000) },
    );
    await repositories.capabilities.recordRejection(
      await repositories.capabilities.describeForRejection({
        ...consumeInput(issued, { tokenHash: newToken().hash }),
        purpose: 'read',
      }),
      { role: 'supervisor', now: at(3100) },
    );
    expect(
      await repositories.capabilities.summarizeForConnection(
        tenant.scope,
        f.connectionId,
        at(-1000),
      ),
    ).toEqual({
      authorized: 1,
      issued: 1,
      used: 1,
      revoked: 0,
      rejectedByReason: { used: 1, unknown_token: 1 },
    });
    // A later window excludes them.
    expect(
      (
        await repositories.capabilities.summarizeForConnection(
          tenant.scope,
          f.connectionId,
          at(10_000_000),
        )
      ).authorized,
    ).toBe(0);
    for (const scope of [
      teammate.scope,
      other.scope,
      { organizationId: other.organization.id, userId: tenant.user.id },
      { organizationId: 'nope', userId: 'nope' },
    ]) {
      await expect(
        repositories.capabilities.summarizeForConnection(scope, f.connectionId, at(-1000)),
      ).rejects.toBeInstanceOf(NotFoundError);
    }
    await expect(
      repositories.capabilities.summarizeForConnection(tenant.scope, UNKNOWN_ID, at(0)),
    ).rejects.toBeInstanceOf(NotFoundError);
  });
});

describe('authorization follows the grant and the agent (review M1)', () => {
  it('leaves queued jobs of a revoked grant queued, and refuses to authorize them', async () => {
    const f = await op();
    await repositories.grants.revoke(tenant.scope, f.agentId, f.grantId!, at(500));
    // grants.revoke does not cancel queued jobs: the authorization is what refuses them, and
    // the vault turns the refusal into a failed job (vault_denied).
    expect(String((await jobRow(handle.db, f.jobId)).status)).toBe('queued');
    await expect(authorize(repositories, f)).rejects.toBeInstanceOf(ConflictError);
  });

  it('refuses a job queued before the grant was revoked even though a capability for the revoked grant never existed', async () => {
    const f = await op();
    const sibling = await addOperationJob(repositories, f);
    const authorized = await authorize(repositories, f);
    await repositories.grants.revoke(tenant.scope, f.agentId, f.grantId!, at(500));
    // The authorized one lost its capability; the one still waiting for authorization is refused.
    expect((await capabilityRow(handle.db, authorized.capabilityId)).revoked_reason).toBe(
      'grant_revoked',
    );
    await expect(authorize(repositories, sibling)).rejects.toBeInstanceOf(ConflictError);
  });

  it('refuses after the agent is disabled and revokes the capabilities it already had', async () => {
    const f = await op();
    const g = await addOperationJob(repositories, f);
    const authorized = await authorize(repositories, f);
    await repositories.agents.disable(tenant.scope, f.agentId);
    expect((await capabilityRow(handle.db, authorized.capabilityId)).revoked_reason).toBe(
      'agent_disabled',
    );
    await expect(authorize(repositories, g)).rejects.toBeInstanceOf(ConflictError);
    expect((await jobRow(handle.db, g.jobId)).capability_ref).toBeNull();
  });

  it('ignores a deny grant that was revoked or has expired, and authorizes', async () => {
    const f = await op();
    const revokedDeny = await repositories.grants.create(tenant.scope, f.agentId, {
      connectionId: f.connectionId,
      operation: f.operation!,
      effect: 'deny',
    });
    await repositories.grants.revoke(tenant.scope, f.agentId, revokedDeny.id, at(500));
    const expiredDeny = await repositories.grants.create(tenant.scope, f.agentId, {
      connectionId: f.connectionId,
      operation: f.operation!,
      effect: 'deny',
    });
    await sql1(
      sql`update agent_grants set expires_at = ${at(-1000).toISOString()}::timestamptz where id = ${expiredDeny.id}::uuid`,
    );
    await authorize(repositories, f);
  });

  it('authorizes while the grant is unrevoked and not yet expired', async () => {
    const f = await op();
    await sql1(
      sql`update agent_grants set expires_at = ${at(60_000).toISOString()}::timestamptz where id = ${f.grantId!}::uuid`,
    );
    await authorize(repositories, f);
  });

  it('lets a policy decision authorize at most one job (review L1)', async () => {
    const f = await op();
    await expect(
      repositories.jobs.createOperation({
        organizationId: tenant.organization.id,
        requestedByUserId: tenant.user.id,
        agentId: f.agentId,
        connectionId: f.connectionId,
        runId: null,
        operation: f.operation!,
        arguments: { limit: 5 },
        argumentsHash: f.argumentsHash!,
        retrySafe: true,
        policyDecisionId: f.policyEventId,
        timeoutMs: 30_000,
      }),
    ).rejects.toBeInstanceOf(ConflictError);
    // Several jobs with no decision (login jobs, Phase 2 rows) are fine: the index is partial.
    const l1 = await login();
    const l2 = await login();
    expect([l1.policyEventId, l2.policyEventId]).toEqual([null, null]);
  });
});

describe('the database clock is authoritative (review M2)', () => {
  const skewMs = (MAX_CLOCK_SKEW_SECONDS - 1) * 1000;

  it('accepts an authorization and a token whose clock is inside the skew limit, in both directions', async () => {
    const f = await op();
    const g = await op();
    const ahead = await authorize(repositories, f, { now: at(skewMs) });
    const behind = await authorize(repositories, g, { now: at(-skewMs) });
    await markRunning(handle.db, f.jobId);
    await markRunning(handle.db, g.jobId);
    for (const [fixture, authorized, now] of [
      [f, ahead, at(skewMs)],
      [g, behind, at(-skewMs)],
    ] as const) {
      expect(
        await repositories.capabilities.issueToken({
          capabilityId: authorized.capabilityId,
          jobId: fixture.jobId,
          workerId: 'worker-1',
          attempt: 1,
          tokenHash: newToken().hash,
          tokenTtlSeconds: TOKEN_TTL,
          now,
          authorizationMac: AUTH_MAC,
          computeTokenMac: () => TOKEN_MAC,
        }),
      ).not.toBeNull();
    }
  });

  for (const [label, offset] of [
    ['ahead of', 10_000],
    ['behind', -10_000],
  ] as const) {
    it(`refuses a token issue whose clock is 10 s ${label} the database, and changes nothing`, async () => {
      const f = await op();
      const authorized = await authorize(repositories, f);
      await markRunning(handle.db, f.jobId);
      const before = await capabilityRow(handle.db, authorized.capabilityId);
      const result = await repositories.capabilities.issueToken({
        capabilityId: authorized.capabilityId,
        jobId: f.jobId,
        workerId: 'worker-1',
        attempt: 1,
        tokenHash: newToken().hash,
        tokenTtlSeconds: TOKEN_TTL,
        now: at(offset),
        authorizationMac: AUTH_MAC,
        computeTokenMac: () => TOKEN_MAC,
      });
      expect(result).toBeNull();
      expect(await capabilityRow(handle.db, authorized.capabilityId)).toEqual(before);
    });
  }

  const TWO_HOURS = 2 * 3600 * 1000;

  /** Moves the capability window into the past, as if real time had passed. */
  async function age(capabilityId: string, columns: 'token' | 'all') {
    await sql1(
      columns === 'all'
        ? sql`update vault_access_capabilities set issued_at = issued_at - interval '2 hours', expires_at = expires_at - interval '2 hours', token_issued_at = token_issued_at - interval '2 hours', token_expires_at = token_expires_at - interval '2 hours' where id = ${capabilityId}::uuid`
        : sql`update vault_access_capabilities set token_issued_at = token_issued_at - interval '2 hours', token_expires_at = token_expires_at - interval '2 hours' where id = ${capabilityId}::uuid`,
    );
  }

  it('refuses a read whose token expired by the database clock when the caller passes an earlier time', async () => {
    const f = await op();
    const issued = await issue(handle.db, repositories, f);
    await age(issued.capabilityId, 'token');
    const before = await capabilityRow(handle.db, issued.capabilityId);
    // The caller's clock is two hours behind: by its own time the token is still inside its
    // window (T0 + 1 s .. T0 + 31 s, two hours earlier), by the database's it expired.
    const input = consumeInput(issued, { now: at(2000 - TWO_HOURS) });
    expect(await repositories.capabilities.consumeRead(input)).toBeNull();
    expect(await capabilityRow(handle.db, issued.capabilityId)).toEqual(before);
    expect(
      (await repositories.capabilities.describeForRejection({ ...input, purpose: 'read' })).reason,
    ).toBe('expired');
  });

  it('refuses a seal whose authorization expired by the database clock when the caller passes an earlier time', async () => {
    const l = await login();
    const issued = await issue(handle.db, repositories, l);
    await age(issued.capabilityId, 'all');
    const before = await capabilityRow(handle.db, issued.capabilityId);
    const input = consumeInput(issued, { operation: null, now: at(2000 - TWO_HOURS) });
    expect(await repositories.capabilities.consumeSeal(input)).toBeNull();
    expect(await capabilityRow(handle.db, issued.capabilityId)).toEqual(before);
  });

  it('still consumes inside the window, and there is no grace interval on expiry', async () => {
    const f = await op();
    const issued = await issue(handle.db, repositories, f);
    expect(await repositories.capabilities.consumeRead(consumeInput(issued))).not.toBeNull();
    // token_expires_at is T0 + 31 s: a clock at that instant is already too late.
    const g = await op();
    const late = await issue(handle.db, repositories, g);
    expect(
      await repositories.capabilities.consumeRead(
        consumeInput(late, { now: at(1000 + TOKEN_TTL * 1000) }),
      ),
    ).toBeNull();
  });
});

describe("consume runs in the caller's transaction (review M2)", () => {
  it('opens no transaction or savepoint of its own inside one', async () => {
    const f = await op();
    const l = await login();
    const issued = await issue(handle.db, repositories, f);
    const loginIssued = await issue(handle.db, repositories, l);
    await handle.db.transaction(async (tx) => {
      const nested = vi.spyOn(tx, 'transaction');
      const repos = createRepositories(tx);
      expect(await repos.capabilities.consumeRead(consumeInput(issued))).not.toBeNull();
      expect(
        await repos.capabilities.consumeSeal(consumeInput(loginIssued, { operation: null })),
      ).not.toBeNull();
      expect(nested).not.toHaveBeenCalled();
    });
    // Outside a transaction it still works (it opens its own).
    const g = await op();
    const again = await issue(handle.db, repositories, g);
    expect(await repositories.capabilities.consumeRead(consumeInput(again))).not.toBeNull();
  });

  it("rolls the consume back with the caller (the lock and the use are the caller's)", async () => {
    const f = await op();
    const issued = await issue(handle.db, repositories, f);
    await expect(
      repositories.transaction(async (tx) => {
        expect(await tx.capabilities.consumeRead(consumeInput(issued))).not.toBeNull();
        throw new Error('abort');
      }),
    ).rejects.toThrow('abort');
    expect((await capabilityRow(handle.db, issued.capabilityId)).used_at).toBeNull();
    expect(await repositories.capabilities.consumeRead(consumeInput(issued))).not.toBeNull();
  });
});

describe("consume binds the connection to the capability's organization (review nit)", () => {
  it("refuses when the connection row no longer belongs to the capability's organization", async () => {
    const f = await op();
    const issued = await issue(handle.db, repositories, f);
    await sql1(
      sql`update connections set organization_id = ${other.organization.id}::uuid where id = ${f.connectionId}::uuid`,
    );
    const before = await capabilityRow(handle.db, issued.capabilityId);
    expect(await repositories.capabilities.consumeRead(consumeInput(issued))).toBeNull();
    expect(await capabilityRow(handle.db, issued.capabilityId)).toEqual(before);

    const l = await login();
    const sealIssued = await issue(handle.db, repositories, l);
    await sql1(
      sql`update connections set organization_id = ${other.organization.id}::uuid where id = ${l.connectionId}::uuid`,
    );
    expect(
      await repositories.capabilities.consumeSeal(consumeInput(sealIssued, { operation: null })),
    ).toBeNull();
  });
});

describe('a revoked connection gets no secret rows (review nit)', () => {
  it('ensureSecret and putVersion refuse once the connection is revoked, before any cleanup ran', async () => {
    const f = await op();
    await setConnectionStatus(handle.db, f.connectionId, 'revoked');
    await expect(
      repositories.vault.ensureSecret({
        connectionId: f.connectionId,
        secretType: 'other_type',
        now: T0,
      }),
    ).rejects.toBeInstanceOf(ConflictError);
    await expect(
      repositories.vault.ensureSecret({
        connectionId: f.connectionId,
        secretType: SECRET_TYPE,
        now: T0,
      }),
    ).rejects.toBeInstanceOf(ConflictError);
    await expect(
      repositories.vault.putVersion({
        secretId: f.secretId,
        version: 2,
        sealed: fakeSealed('late'),
        now: T0,
      }),
    ).rejects.toBeInstanceOf(ConflictError);
    expect(
      rowsOf(
        await handle.db.execute(
          sql`select 1 from vault_secrets where connection_id = ${f.connectionId}::uuid`,
        ),
      ),
    ).toHaveLength(1);
    expect(
      rowsOf(
        await handle.db.execute(
          sql`select 1 from vault_secret_versions where secret_id = ${f.secretId}::uuid and version = 2`,
        ),
      ),
    ).toHaveLength(0);
  });

  it('refuses an unknown connection with NotFoundError', async () => {
    await expect(
      repositories.vault.ensureSecret({
        connectionId: UNKNOWN_ID,
        secretType: SECRET_TYPE,
        now: T0,
      }),
    ).rejects.toBeInstanceOf(NotFoundError);
  });
});
