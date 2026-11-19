import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { rowsOf } from '../../../packages/database/src/client.js';
import {
  auditEvents,
  capabilityRowOf,
  completeParams,
  CANARY,
  errorCode,
  execSql,
  isPlainForbidden,
  ok,
  openStored,
  prepare,
  putSealed,
  rejectedReasons,
  seedLoginJob,
  seedTenant,
  sql,
  startService,
  storageStateJson,
} from './service-helpers.js';
import type { Service } from './service-helpers.js';

let service: Service;
beforeAll(async () => {
  service = await startService();
});
afterAll(async () => {
  await service.cleanup();
});

async function state(connectionId: string, jobId: string) {
  return rowsOf(
    await service.db.execute(
      sql`select k.status as connection_status, k.external_account_hint, k.last_verified_at, j.status as job_status, j.audit_event_id
          from connections k, execution_jobs j where k.id = ${connectionId}::uuid and j.id = ${jobId}::uuid`,
    ),
  )[0]!;
}

describe('completeLogin', () => {
  it('seals under the active KEK, activates the connection, records the session, audits and completes the job', async () => {
    const tenant = await seedTenant(service.repos, 'login-happy');
    const login = await seedLoginJob(service, tenant);
    const prepared = await prepare(service, login);
    expect(prepared.secretVersion).toBe(0);
    const stored = storageStateJson();
    const result = ok(
      await service.rpc(
        'supervisor',
        'completeLogin',
        completeParams(prepared, stored, {
          externalAccountHint: '  alice@example.test  ',
          sessionExpiresAt: '2030-01-01T00:00:00.000Z',
        }),
      ),
    );
    expect(result).toEqual({ secretId: login.secretId, secretVersion: 1, kekVersion: 1 });
    expect(await openStored(service, tenant, login.connectionId)).toBe(stored);
    expect(await state(login.connectionId, login.jobId)).toMatchObject({
      connection_status: 'active',
      external_account_hint: 'alice@example.test',
      job_status: 'succeeded',
    });
    expect((await state(login.connectionId, login.jobId))['audit_event_id']).not.toBeNull();
    const types = (await auditEvents(service, tenant.organization.id)).map((e) => e['event_type']);
    expect(
      types.filter((t) => String(t).startsWith('vault.') || String(t).startsWith('connection.')),
    ).toEqual(
      expect.arrayContaining([
        'vault.capability_authorized',
        'vault.capability_issued',
        'vault.secret_stored',
        'connection.auth_completed',
      ]),
    );
    expect((await capabilityRowOf(service, prepared.capabilityId))['used_at']).not.toBeNull();
    const status = rowsOf(
      await service.db.execute(
        sql`select to_status from connection_status_events where connection_id = ${login.connectionId}::uuid order by created_at desc limit 1`,
      ),
    )[0];
    expect(status).toMatchObject({ to_status: 'active' });
    // The token cannot complete a second login.
    const again = await service.rpc(
      'supervisor',
      'completeLogin',
      completeParams(prepared, stored),
    );
    expect(isPlainForbidden(again)).toBe(true);
    expect(await rejectedReasons(service, tenant.organization.id)).toEqual(['used']);
  });

  it('a replacement login stores the next version and deletes the previous one', async () => {
    const tenant = await seedTenant(service.repos, 'login-replace');
    const first = await seedLoginJob(service, tenant);
    const p1 = await prepare(service, first);
    ok(
      await service.rpc('supervisor', 'completeLogin', completeParams(p1, storageStateJson('one'))),
    );
    // Sign in again: the connection goes back to authenticating and a new login job runs.
    await execSql(
      service,
      sql`update connections set status = 'authenticating' where id = ${first.connectionId}::uuid`,
    );
    const job = await service.repos.jobs.createLogin({
      organizationId: tenant.organization.id,
      requestedByUserId: tenant.user.id,
      connectionId: first.connectionId,
      timeoutMs: 600_000,
    });
    const second = { ...first, jobId: job.id };
    const p2 = await prepare(service, second);
    expect(p2.secretVersion).toBe(1);
    const result = ok(
      await service.rpc('supervisor', 'completeLogin', completeParams(p2, storageStateJson('two'))),
    );
    expect(result['secretVersion']).toBe(2);
    expect(await openStored(service, tenant, first.connectionId)).toBe(storageStateJson('two'));
    const versions = rowsOf(
      await service.db.execute(
        sql`select version from vault_secret_versions where secret_id = ${first.secretId}::uuid`,
      ),
    );
    expect(versions).toEqual([{ version: 2 }]);
  });

  it('a replacement whose expected version changed stores nothing (P3-9)', async () => {
    const tenant = await seedTenant(service.repos, 'login-moved');
    const login = await seedLoginJob(service, tenant);
    const prepared = await prepare(service, login); // bound version 0: "no session yet"
    // Meanwhile another writer stored version 1: the pointer moved away from the bound 0.
    await putSealed(service, tenant, login.connectionId, login.secretId, 1, 'someone else');
    const response = await service.rpc(
      'supervisor',
      'completeLogin',
      completeParams(prepared, storageStateJson('late')),
    );
    expect(isPlainForbidden(response)).toBe(true);
    expect(await openStored(service, tenant, login.connectionId)).toBe('someone else');
    expect(await rejectedReasons(service, tenant.organization.id)).toEqual(['secret_not_active']);
    expect((await state(login.connectionId, login.jobId))['job_status']).toBe('running');
  });

  it('a different account than the one the connection was verified for is refused and nothing is stored', async () => {
    const tenant = await seedTenant(service.repos, 'login-identity');
    const first = await seedLoginJob(service, tenant);
    const p1 = await prepare(service, first);
    ok(
      await service.rpc(
        'supervisor',
        'completeLogin',
        completeParams(p1, storageStateJson('one'), { externalAccountHint: 'alice' }),
      ),
    );
    await execSql(
      service,
      sql`update connections set status = 'authenticating' where id = ${first.connectionId}::uuid`,
    );
    const job = await service.repos.jobs.createLogin({
      organizationId: tenant.organization.id,
      requestedByUserId: tenant.user.id,
      connectionId: first.connectionId,
      timeoutMs: 600_000,
    });
    const p2 = await prepare(service, { ...first, jobId: job.id });
    const response = await service.rpc(
      'supervisor',
      'completeLogin',
      completeParams(p2, storageStateJson('mallory'), { externalAccountHint: 'mallory' }),
    );
    expect(errorCode(response)).toBe('conflict');
    expect(await openStored(service, tenant, first.connectionId)).toBe(storageStateJson('one'));
    // Rolled back whole: the capability is unused and the job is still running for the supervisor to fail.
    expect((await capabilityRowOf(service, p2.capabilityId))['used_at']).toBeNull();
    expect((await state(first.connectionId, job.id))['job_status']).toBe('running');
  });

  it('a revocation that commits first makes the completion store nothing', async () => {
    const tenant = await seedTenant(service.repos, 'login-revoked');
    const login = await seedLoginJob(service, tenant);
    const prepared = await prepare(service, login);
    await service.repos.connections.revoke(tenant.scope, login.connectionId);
    const response = await service.rpc(
      'supervisor',
      'completeLogin',
      completeParams(prepared, storageStateJson('after-revoke')),
    );
    expect(isPlainForbidden(response)).toBe(true);
    expect(JSON.stringify(response)).not.toContain(CANARY);
    expect(await openStored(service, tenant, login.connectionId)).toBeNull();
    const versions = rowsOf(
      await service.db.execute(
        sql`select count(*)::int as n from vault_secret_versions where secret_id = ${login.secretId}::uuid`,
      ),
    )[0]!;
    expect(versions['n']).toBe(0);
  });

  it('rejects storage state larger than the cap at the protocol layer', async () => {
    const tenant = await seedTenant(service.repos, 'login-big');
    const login = await seedLoginJob(service, tenant);
    const prepared = await prepare(service, login);
    const response = await service.rpc('supervisor', 'completeLogin', {
      ...completeParams(prepared, 'x'),
      plaintext: 'A'.repeat(2_796_204),
    });
    expect(errorCode(response)).toBe('malformed');
  });
});
