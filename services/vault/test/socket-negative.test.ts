import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { sealSecret } from '@aab/crypto';
import { exchange } from './helpers.js';
import { rowsOf } from '../../../packages/database/src/client.js';
import {
  auditEvents,
  capabilityRowOf,
  CANARY,
  completeParams,
  errorCode,
  execSql,
  isPlainForbidden,
  ok,
  openStored,
  prepare,
  readParams,
  rejectedReasons,
  SECRET_TYPE,
  seedLoginJob,
  seedSealedOperation,
  seedTenant,
  sleep,
  sql,
  startService,
  storageStateJson,
} from './service-helpers.js';
import type { SealedOperation, Service, Tenant } from './service-helpers.js';

/*
 * B6a: the exit-criteria negative cases, each one sent over the vault's real Unix sockets to the
 * real operations (PGlite). Every case must be refused with the right reason (or error) and change
 * nothing: no plaintext in the answer, and the secret, its versions, the connection, the job and the
 * capability row are byte-for-byte what they were, with no event other than the rejection itself.
 * The cases that already go through the sockets elsewhere are listed in the coverage map in
 * docs/phase-3.md (B6a); this file adds what was missing.
 */

let service: Service;
beforeAll(async () => {
  service = await startService();
});
afterAll(async () => {
  await service.cleanup();
});

const NOT_A_REJECTION = ['vault.capability_rejected', 'vault.request_refused'];

/** Everything a refused request must leave alone, as text. */
async function snapshot(tenant: Tenant, op: SealedOperation, capabilityId?: string) {
  const one = async (table: string, column: string, id: string): Promise<string[]> =>
    rowsOf(
      await service.db.execute(
        sql.raw(
          `select row_to_json(t)::text as j from ${table} as t where ${column} = '${id}'::uuid`,
        ),
      ),
    ).map((row) => String(row['j']));
  const events = (await auditEvents(service, tenant.organization.id)).filter(
    (event) => !NOT_A_REJECTION.includes(String(event['event_type'])),
  );
  return JSON.stringify({
    secret: await one('vault_secrets', 'id', op.secretId),
    versions: await one('vault_secret_versions', 'secret_id', op.secretId),
    connection: await one('connections', 'id', op.connectionId),
    job: await one('execution_jobs', 'id', op.jobId),
    capability:
      capabilityId === undefined
        ? null
        : await one('vault_access_capabilities', 'id', capabilityId),
    events: events.map((event) => [event['event_type'], event['decision']]),
  });
}

async function readCase(label: string) {
  const tenant = await seedTenant(service.repos, label);
  const op = await seedSealedOperation(service, tenant);
  const prepared = await prepare(service, op);
  return { tenant, op, prepared, org: tenant.organization.id };
}

async function loginCase(label: string) {
  const tenant = await seedTenant(service.repos, label);
  const login = await seedLoginJob(service, tenant);
  const prepared = await prepare(service, login);
  return { tenant, login: login as SealedOperation, prepared, org: tenant.organization.id };
}

const hex = (value: Buffer): string => value.toString('hex');

describe('wrong AAD: a version sealed for another owner record fails to open (P3-10, VS-15)', () => {
  // The vault rebuilds the AAD from the connection row and the capability binding. A version whose
  // bytes are genuine (sealed with the real KEK by the @aab/crypto helper) but bound to another
  // organization, owner, connection, secret, type or version number must not open.
  const wrongField: Array<[string, (aad: Record<string, unknown>) => Record<string, unknown>]> = [
    ['organization', (aad) => ({ ...aad, organizationId: randomUUID() })],
    ['owner', (aad) => ({ ...aad, userId: randomUUID() })],
    ['connection', (aad) => ({ ...aad, connectionId: randomUUID() })],
    ['secret', (aad) => ({ ...aad, secretId: randomUUID() })],
    ['type', (aad) => ({ ...aad, secretType: 'browser_session' })],
    ['version number', (aad) => ({ ...aad, secretVersion: 2 })],
  ];

  it.each(wrongField)(
    'a version sealed for another %s is refused as integrity, returns nothing and changes nothing',
    async (_name, alter) => {
      const f = await readCase('aad');
      const goodAad = {
        organizationId: f.tenant.organization.id,
        userId: f.tenant.user.id,
        connectionId: f.op.connectionId,
        secretId: f.op.secretId,
        secretType: SECRET_TYPE,
        secretVersion: 1,
      };
      const sealed = await sealSecret({
        plaintext: Buffer.from(CANARY, 'utf8'),
        aad: alter(goodAad) as typeof goodAad,
        kek: service.vault.keys.kekProvider,
      });
      // Positive control: the same sealing with the right AAD is what the seed holds, so the only
      // difference below is the one altered field.
      await execSql(
        service,
        sql`update vault_secret_versions
            set ciphertext = decode(${hex(sealed.ciphertext)}, 'hex'), nonce = decode(${hex(sealed.nonce)}, 'hex'),
                auth_tag = decode(${hex(sealed.authTag)}, 'hex'), wrapped_dek = decode(${hex(sealed.wrappedDek)}, 'hex')
            where secret_id = ${f.op.secretId}::uuid and version = 1`,
      );
      const before = await snapshot(f.tenant, f.op);
      const response = await service.rpc('supervisor', 'readForWorker', readParams(f.prepared));
      expect(isPlainForbidden(response)).toBe(true);
      expect(JSON.stringify(response)).not.toContain(CANARY);
      expect(await rejectedReasons(service, f.org)).toEqual(['integrity']);
      expect(await auditEvents(service, f.org, 'vault.secret_read')).toHaveLength(0);
      // The consume is spent with its rejection (ADR-014 section 6): that is the only change, and
      // it is the capability row's own `used_at`.
      expect(await snapshot(f.tenant, f.op)).toBe(before);
      expect((await capabilityRowOf(service, f.prepared.capabilityId))['used_at']).not.toBeNull();
    },
  );

  it('positive control: the same sealing with the right AAD opens through the socket', async () => {
    const f = await readCase('aad-control');
    const sealed = await sealSecret({
      plaintext: Buffer.from('REPLACED-OK', 'utf8'),
      aad: {
        organizationId: f.tenant.organization.id,
        userId: f.tenant.user.id,
        connectionId: f.op.connectionId,
        secretId: f.op.secretId,
        secretType: SECRET_TYPE,
        secretVersion: 1,
      },
      kek: service.vault.keys.kekProvider,
    });
    await execSql(
      service,
      sql`update vault_secret_versions
          set ciphertext = decode(${hex(sealed.ciphertext)}, 'hex'), nonce = decode(${hex(sealed.nonce)}, 'hex'),
              auth_tag = decode(${hex(sealed.authTag)}, 'hex'), wrapped_dek = decode(${hex(sealed.wrappedDek)}, 'hex')
          where secret_id = ${f.op.secretId}::uuid and version = 1`,
    );
    const read = ok(await service.rpc('supervisor', 'readForWorker', readParams(f.prepared)));
    expect(Buffer.from(read['plaintext'] as string, 'base64url').toString('utf8')).toBe(
      'REPLACED-OK',
    );
  });
});

describe('refusals that consume nothing: the capability row and every other row are untouched', () => {
  it('a login (seal) token presented to readForWorker is refused as binding_mismatch (wrong purpose, the other way round)', async () => {
    const f = await loginCase('neg-purpose-rev');
    const before = await snapshot(f.tenant, f.login, f.prepared.capabilityId);
    const response = await service.rpc('supervisor', 'readForWorker', {
      token: f.prepared.token,
      jobId: f.login.jobId,
      connectionId: f.login.connectionId,
      operation: 'orders.list',
    });
    expect(isPlainForbidden(response)).toBe(true);
    expect(await rejectedReasons(service, f.org)).toEqual(['binding_mismatch']);
    expect(await snapshot(f.tenant, f.login, f.prepared.capabilityId)).toBe(before);
    // The login still completes with the same token: the refused read consumed nothing.
    ok(
      await service.rpc(
        'supervisor',
        'completeLogin',
        completeParams(f.prepared, storageStateJson('still-works')),
      ),
    );
  });

  it('a revoked capability (revocation of the connection) is refused as revoked, for a read', async () => {
    const f = await readCase('neg-revoked-cap');
    await service.repos.capabilities.revokeForConnection({
      connectionId: f.op.connectionId,
      reason: 'owner_requested',
      now: new Date(),
    });
    const before = await snapshot(f.tenant, f.op, f.prepared.capabilityId);
    const response = await service.rpc('supervisor', 'readForWorker', readParams(f.prepared));
    expect(isPlainForbidden(response)).toBe(true);
    expect(JSON.stringify(response)).not.toContain(CANARY);
    expect(await rejectedReasons(service, f.org)).toEqual(['revoked']);
    expect(await snapshot(f.tenant, f.op, f.prepared.capabilityId)).toBe(before);
  });

  it('a revoked capability is refused as revoked, for a login completion; nothing is stored', async () => {
    const f = await loginCase('neg-revoked-login');
    await service.repos.capabilities.revokeForConnection({
      connectionId: f.login.connectionId,
      reason: 'owner_requested',
      now: new Date(),
    });
    const before = await snapshot(f.tenant, f.login, f.prepared.capabilityId);
    const response = await service.rpc(
      'supervisor',
      'completeLogin',
      completeParams(f.prepared, storageStateJson('x')),
    );
    expect(isPlainForbidden(response)).toBe(true);
    expect(await rejectedReasons(service, f.org)).toEqual(['revoked']);
    expect(await snapshot(f.tenant, f.login, f.prepared.capabilityId)).toBe(before);
    expect(await openStored(service, f.tenant, f.login.connectionId)).toBeNull();
  });

  it('a revoked authorization yields no token: issue is refused as revoked and sets nothing', async () => {
    const tenant = await seedTenant(service.repos, 'neg-revoked-auth');
    const op = await seedSealedOperation(service, tenant);
    const authorized = ok(
      await service.rpc('api', 'authorizeJobAccess', { jobId: op.jobId, ttlSeconds: 600 }),
    );
    const capabilityId = authorized['capabilityId'] as string;
    await service.repos.capabilities.revokeForConnection({
      connectionId: op.connectionId,
      reason: 'owner_requested',
      now: new Date(),
    });
    await execSql(
      service,
      sql`update execution_jobs set status = 'running', worker_id = 'worker-1', attempt_count = 1 where id = ${op.jobId}::uuid`,
    );
    const before = await snapshot(tenant, op, capabilityId);
    const response = await service.rpc('supervisor', 'issueAccessCapability', {
      capabilityId,
      jobId: op.jobId,
      workerId: 'worker-1',
      attempt: 1,
      ttlSeconds: 30,
    });
    expect(isPlainForbidden(response)).toBe(true);
    expect(JSON.stringify(response)).not.toMatch(/token/i);
    expect(await rejectedReasons(service, tenant.organization.id)).toEqual(['revoked']);
    expect(await snapshot(tenant, op, capabilityId)).toBe(before);
    expect((await capabilityRowOf(service, capabilityId))['token_hash']).toBeNull();
  });

  it('a revoked secret (status revoked, capability not yet marked) is refused as secret_not_active', async () => {
    const f = await readCase('neg-revoked-secret');
    await execSql(
      service,
      sql`update vault_secrets set status = 'revoked', active_version_id = null where id = ${f.op.secretId}::uuid`,
    );
    await execSql(
      service,
      sql`delete from vault_secret_versions where secret_id = ${f.op.secretId}::uuid`,
    );
    const before = await snapshot(f.tenant, f.op, f.prepared.capabilityId);
    const response = await service.rpc('supervisor', 'readForWorker', readParams(f.prepared));
    expect(isPlainForbidden(response)).toBe(true);
    expect(JSON.stringify(response)).not.toContain(CANARY);
    expect(await rejectedReasons(service, f.org)).toEqual(['secret_not_active']);
    expect(await snapshot(f.tenant, f.op, f.prepared.capabilityId)).toBe(before);
  });

  it('after the real revocation transaction (connection revoked, versions deleted) the token is refused and nothing returns', async () => {
    const f = await readCase('neg-revoked-real');
    // The same calls, in the same order, as the connection-revoke route (see revocation-race.test.ts).
    const now = new Date();
    await service.repos.connections.revoke(f.tenant.scope, f.op.connectionId, {});
    await service.repos.jobs.cancelForConnection(f.op.connectionId, now);
    await service.repos.vault.deleteForConnection(f.op.connectionId, now);
    await service.repos.capabilities.revokeForConnection({
      connectionId: f.op.connectionId,
      reason: 'connection_revoked',
      now,
    });
    const response = await service.rpc('supervisor', 'readForWorker', readParams(f.prepared));
    expect(isPlainForbidden(response)).toBe(true);
    expect(JSON.stringify(response)).not.toContain(CANARY);
    expect(await rejectedReasons(service, f.org)).toEqual(['revoked']);
    const versions = rowsOf(
      await service.db.execute(
        sql`select count(*)::int as n from vault_secret_versions where secret_id = ${f.op.secretId}::uuid`,
      ),
    )[0]!;
    expect(versions['n']).toBe(0);
    expect(await auditEvents(service, f.org, 'vault.secret_read')).toHaveLength(0);
  });

  it('a used token is refused as used on a login completion too, and the stored session stays the first one', async () => {
    const f = await loginCase('neg-used-login');
    ok(
      await service.rpc(
        'supervisor',
        'completeLogin',
        completeParams(f.prepared, storageStateJson('first-session')),
      ),
    );
    const before = await snapshot(f.tenant, f.login, f.prepared.capabilityId);
    const again = await service.rpc(
      'supervisor',
      'completeLogin',
      completeParams(f.prepared, storageStateJson('second-session')),
    );
    expect(isPlainForbidden(again)).toBe(true);
    expect(await rejectedReasons(service, f.org)).toEqual(['used']);
    expect(await snapshot(f.tenant, f.login, f.prepared.capabilityId)).toBe(before);
    expect(await openStored(service, f.tenant, f.login.connectionId)).toBe(
      storageStateJson('first-session'),
    );
  });

  it('an unknown token on a login completion is refused as unknown_token and nothing is stored', async () => {
    const f = await loginCase('neg-unknown-login');
    const before = await snapshot(f.tenant, f.login, f.prepared.capabilityId);
    const response = await service.rpc(
      'supervisor',
      'completeLogin',
      completeParams(f.prepared, storageStateJson('x'), { token: 'U'.repeat(43) }),
    );
    expect(isPlainForbidden(response)).toBe(true);
    expect(await rejectedReasons(service, f.org)).toEqual(['unknown_token']);
    expect(await snapshot(f.tenant, f.login, f.prepared.capabilityId)).toBe(before);
  });

  it('a login token for another connection or job is refused as binding_mismatch; the real one still completes', async () => {
    const f = await loginCase('neg-bind-login');
    const other = await loginCase('neg-bind-login-other');
    const before = await snapshot(f.tenant, f.login, f.prepared.capabilityId);
    for (const override of [
      { connectionId: other.login.connectionId },
      { jobId: other.login.jobId },
    ]) {
      const response = await service.rpc(
        'supervisor',
        'completeLogin',
        completeParams(f.prepared, storageStateJson('x'), override),
      );
      expect(isPlainForbidden(response)).toBe(true);
    }
    expect(await rejectedReasons(service, f.org)).toEqual(['binding_mismatch', 'binding_mismatch']);
    expect(await snapshot(f.tenant, f.login, f.prepared.capabilityId)).toBe(before);
    ok(
      await service.rpc(
        'supervisor',
        'completeLogin',
        completeParams(f.prepared, storageStateJson('real')),
      ),
    );
  });

  it('a login token under another worker or attempt is refused as binding_mismatch and stores nothing', async () => {
    const worker = await loginCase('neg-worker-login');
    await execSql(
      service,
      sql`update execution_jobs set worker_id = 'worker-2' where id = ${worker.login.jobId}::uuid`,
    );
    const attempt = await loginCase('neg-attempt-login');
    await execSql(
      service,
      sql`update execution_jobs set attempt_count = 2 where id = ${attempt.login.jobId}::uuid`,
    );
    for (const f of [worker, attempt]) {
      const before = await snapshot(f.tenant, f.login, f.prepared.capabilityId);
      const response = await service.rpc(
        'supervisor',
        'completeLogin',
        completeParams(f.prepared, storageStateJson('x')),
      );
      expect(isPlainForbidden(response)).toBe(true);
      expect(await rejectedReasons(service, f.org)).toEqual(['binding_mismatch']);
      expect(await snapshot(f.tenant, f.login, f.prepared.capabilityId)).toBe(before);
      expect(await openStored(service, f.tenant, f.login.connectionId)).toBeNull();
    }
  });

  it('a read token presented after its authorization window closed (rows edited to the past, to exercise the SQL checks) is refused as expired', async () => {
    const f = await readCase('neg-expired-auth');
    // Close the window by the database's own clock. The consume judges `now()` in SQL; the vault
    // has no request field that can move it (VS-21).
    await execSql(
      service,
      sql`update vault_access_capabilities
          set issued_at = now() - interval '20 minutes', expires_at = now() - interval '1 second',
              token_issued_at = now() - interval '10 minutes', token_expires_at = now() - interval '9 minutes'
          where id = ${f.prepared.capabilityId}::uuid`,
    );
    const before = await snapshot(f.tenant, f.op, f.prepared.capabilityId);
    const response = await service.rpc('supervisor', 'readForWorker', readParams(f.prepared));
    expect(isPlainForbidden(response)).toBe(true);
    expect(JSON.stringify(response)).not.toContain(CANARY);
    expect(await rejectedReasons(service, f.org)).toEqual(['expired']);
    expect(await snapshot(f.tenant, f.op, f.prepared.capabilityId)).toBe(before);
  });

  it('an expired login token (rows edited to the past, to exercise the SQL checks) is refused as expired and nothing is stored', async () => {
    const f = await loginCase('neg-expired-login');
    await execSql(
      service,
      sql`update vault_access_capabilities
          set issued_at = now() - interval '20 minutes', expires_at = now() - interval '1 second',
              token_issued_at = now() - interval '10 minutes', token_expires_at = now() - interval '9 minutes'
          where id = ${f.prepared.capabilityId}::uuid`,
    );
    const before = await snapshot(f.tenant, f.login, f.prepared.capabilityId);
    const response = await service.rpc(
      'supervisor',
      'completeLogin',
      completeParams(f.prepared, storageStateJson('x')),
    );
    expect(isPlainForbidden(response)).toBe(true);
    expect(await rejectedReasons(service, f.org)).toEqual(['expired']);
    expect(await snapshot(f.tenant, f.login, f.prepared.capabilityId)).toBe(before);
  });

  it('a read token whose real 1 s TTL has run out (waited, database clock) is refused as expired', async () => {
    const tenant = await seedTenant(service.repos, 'neg-ttl-read');
    const op = await seedSealedOperation(service, tenant);
    // The shortest token the vault issues: no row edit, so the MACs stay valid and only the clock moves.
    const prepared = await prepare(service, op, { tokenTtl: 1 });
    await sleep(2_000);
    const before = await snapshot(tenant, op, prepared.capabilityId);
    const response = await service.rpc('supervisor', 'readForWorker', readParams(prepared));
    expect(isPlainForbidden(response)).toBe(true);
    expect(JSON.stringify(response)).not.toContain(CANARY);
    expect(await rejectedReasons(service, tenant.organization.id)).toEqual(['expired']);
    expect(await snapshot(tenant, op, prepared.capabilityId)).toBe(before);
  });

  it('a login token whose real 1 s TTL has run out (waited, database clock) is refused as expired and nothing is stored', async () => {
    const tenant = await seedTenant(service.repos, 'neg-ttl-login');
    const login = await seedLoginJob(service, tenant);
    const prepared = await prepare(service, login, { tokenTtl: 1 });
    await sleep(2_000);
    const before = await snapshot(tenant, login as SealedOperation, prepared.capabilityId);
    const response = await service.rpc(
      'supervisor',
      'completeLogin',
      completeParams(prepared, storageStateJson('x')),
    );
    expect(isPlainForbidden(response)).toBe(true);
    expect(await rejectedReasons(service, tenant.organization.id)).toEqual(['expired']);
    expect(await snapshot(tenant, login as SealedOperation, prepared.capabilityId)).toBe(before);
    expect(await openStored(service, tenant, login.connectionId)).toBeNull();
  });

  it('an authorization that really expired (10 s, database clock) before issue yields no token', async () => {
    const tenant = await seedTenant(service.repos, 'neg-expired-issue');
    const op = await seedSealedOperation(service, tenant);
    // The shortest authorization the vault accepts is 10 s: no row edit, so the MACs stay valid and
    // the only thing that changes between authorize and issue is the database's clock.
    const authorized = ok(
      await service.rpc('api', 'authorizeJobAccess', { jobId: op.jobId, ttlSeconds: 10 }),
    );
    const capabilityId = authorized['capabilityId'] as string;
    await execSql(
      service,
      sql`update execution_jobs set status = 'running', worker_id = 'worker-1', attempt_count = 1 where id = ${op.jobId}::uuid`,
    );
    await sleep(10_500);
    const before = await snapshot(tenant, op, capabilityId);
    const response = await service.rpc('supervisor', 'issueAccessCapability', {
      capabilityId,
      jobId: op.jobId,
      workerId: 'worker-1',
      attempt: 1,
      ttlSeconds: 30,
    });
    expect(isPlainForbidden(response)).toBe(true);
    expect(await rejectedReasons(service, tenant.organization.id)).toEqual(['expired']);
    expect(await snapshot(tenant, op, capabilityId)).toBe(before);
    expect((await capabilityRowOf(service, capabilityId))['token_hash']).toBeNull();
  }, 60_000);

  it('a wrong-shaped token is refused as malformed before any database work, and consumes nothing', async () => {
    const f = await readCase('neg-shape');
    const before = await snapshot(f.tenant, f.op, f.prepared.capabilityId);
    const counters = () => service.rpc('admin', 'status', {});
    const status = ok(await counters())['counters'] as Record<string, number>;
    for (const token of [
      '',
      'short',
      f.prepared.token.slice(1),
      `${f.prepared.token}A`,
      'é'.repeat(43),
    ]) {
      const response = await service.rpc(
        'supervisor',
        'readForWorker',
        readParams(f.prepared, { token }),
      );
      expect(errorCode(response)).toBe('malformed');
    }
    expect(await rejectedReasons(service, f.org)).toEqual([]);
    expect(await snapshot(f.tenant, f.op, f.prepared.capabilityId)).toBe(before);
    expect(
      (ok(await counters())['counters'] as Record<string, number>)['rejectedUnattributed'],
    ).toBe(status['rejectedUnattributed']);
    // The real token still redeems.
    ok(await service.rpc('supervisor', 'readForWorker', readParams(f.prepared)));
  });
});

describe('lifetimes and authority at the api socket (VS-6, VS-20, P3-7)', () => {
  it('every missing, fractional, unsafe or out-of-range lifetime is malformed, creates no capability and no token', async () => {
    const tenant = await seedTenant(service.repos, 'neg-ttl');
    const op = await seedSealedOperation(service, tenant);
    const before = await snapshot(tenant, op);
    const line = (body: string) =>
      `{"id":"ttl","operation":"authorizeJobAccess","params":{"jobId":"${op.jobId}"${body}}}\n`;
    const raw = [
      '', // missing
      ',"ttlSeconds":null',
      ',"ttlSeconds":"600"',
      ',"ttlSeconds":0',
      ',"ttlSeconds":-1',
      ',"ttlSeconds":9',
      ',"ttlSeconds":3601',
      ',"ttlSeconds":1.5',
      ',"ttlSeconds":1e9',
      ',"ttlSeconds":1e999', // Infinity once parsed
      ',"ttlSeconds":9007199254740993', // beyond the safe integers
      ',"ttlSeconds":[600]',
    ];
    for (const body of raw) {
      const answer = JSON.parse((await exchange(service.vault.sockets.api, line(body))) ?? 'null');
      expect(answer, body).toEqual({ id: 'ttl', ok: false, error: { code: 'malformed' } });
    }
    expect((await service.repos.jobs.getInternal(op.jobId))?.capabilityRef).toBeNull();
    expect(await snapshot(tenant, op)).toBe(before);
    expect(
      await auditEvents(service, tenant.organization.id, 'vault.capability_authorized'),
    ).toHaveLength(0);

    // The token lifetime: the authorization is real, the lifetimes are not.
    const authorized = ok(
      await service.rpc('api', 'authorizeJobAccess', { jobId: op.jobId, ttlSeconds: 600 }),
    );
    await execSql(
      service,
      sql`update execution_jobs set status = 'running', worker_id = 'worker-1', attempt_count = 1 where id = ${op.jobId}::uuid`,
    );
    for (const ttlSeconds of [undefined, null, 0, -1, 121, 1.5, 1e9, '30']) {
      const response = await service.rpc('supervisor', 'issueAccessCapability', {
        capabilityId: authorized['capabilityId'],
        jobId: op.jobId,
        workerId: 'worker-1',
        attempt: 1,
        ...(ttlSeconds === undefined ? {} : { ttlSeconds }),
      });
      expect(errorCode(response), String(ttlSeconds)).toBe('malformed');
    }
    expect(
      (await capabilityRowOf(service, authorized['capabilityId'] as string))['token_hash'],
    ).toBeNull();
    expect(await rejectedReasons(service, tenant.organization.id)).toEqual([]);
  });

  it('a job whose grant was revoked, or whose agent was disabled, after it was queued is not authorized', async () => {
    const revoked = await seedTenant(service.repos, 'neg-grant');
    const opA = await seedSealedOperation(service, revoked);
    await service.repos.grants.revoke(revoked.scope, opA.agentId, opA.grantId!);
    const disabled = await seedTenant(service.repos, 'neg-agent');
    const opB = await seedSealedOperation(service, disabled);
    await service.repos.agents.disable(disabled.scope, opB.agentId);
    for (const [tenant, op] of [
      [revoked, opA],
      [disabled, opB],
    ] as const) {
      const before = await snapshot(tenant, op);
      const response = await service.rpc('api', 'authorizeJobAccess', {
        jobId: op.jobId,
        ttlSeconds: 600,
      });
      expect(errorCode(response)).toBe('conflict');
      expect((await service.repos.jobs.getInternal(op.jobId))?.capabilityRef).toBeNull();
      expect(
        await auditEvents(service, tenant.organization.id, 'vault.capability_authorized'),
      ).toHaveLength(0);
      expect(await snapshot(tenant, op)).toBe(before);
    }
  });
});
