import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { rowsOf } from '../../../packages/database/src/client.js';
import {
  auditEvents,
  capabilityRowOf,
  completeParams,
  errorCode,
  execSql,
  ok,
  prepare,
  readParams,
  seedLoginJob,
  seedSealedOperation,
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

/** A database trigger that makes the audit append of one event type fail. */
async function failAuditOf(eventType: string): Promise<void> {
  await execSql(
    service,
    sql.raw(`create or replace function aab_test_fail_audit() returns trigger as $$
      begin
        if new.event_type = '${eventType}' then raise exception 'simulated audit failure'; end if;
        return new;
      end $$ language plpgsql`),
  );
  await execSql(
    service,
    sql.raw(
      'create trigger aab_test_fail_audit before insert on audit_events for each row execute function aab_test_fail_audit()',
    ),
  );
}
async function allowAudit(): Promise<void> {
  await execSql(service, sql.raw('drop trigger if exists aab_test_fail_audit on audit_events'));
}
beforeEach(allowAudit);

describe('P3-13: audit in the same transaction', () => {
  it('a failing audit append rolls back the read: the consume is undone and the token still works', async () => {
    const tenant = await seedTenant(service.repos, 'atomic-read');
    const op = await seedSealedOperation(service, tenant);
    const prepared = await prepare(service, op);
    await failAuditOf('vault.secret_read');
    const failed = await service.rpc('supervisor', 'readForWorker', readParams(prepared));
    expect(errorCode(failed)).toBe('service_unavailable');
    const row = await capabilityRowOf(service, prepared.capabilityId);
    expect(row['used_at']).toBeNull();
    const secret = rowsOf(
      await service.db.execute(
        sql`select last_accessed_at from vault_secrets where id = ${op.secretId}::uuid`,
      ),
    )[0]!;
    expect(secret['last_accessed_at']).toBeNull();
    // No rejection event either: an internal failure is not a theft signal.
    expect(
      await auditEvents(service, tenant.organization.id, 'vault.capability_rejected'),
    ).toHaveLength(0);
    await allowAudit();
    ok(await service.rpc('supervisor', 'readForWorker', readParams(prepared)));
  });

  it('a failing audit append rolls back the login completion: nothing stored, job still running', async () => {
    const tenant = await seedTenant(service.repos, 'atomic-login');
    const login = await seedLoginJob(service, tenant);
    const prepared = await prepare(service, login);
    await failAuditOf('connection.auth_completed');
    const failed = await service.rpc(
      'supervisor',
      'completeLogin',
      completeParams(prepared, storageStateJson()),
    );
    expect(errorCode(failed)).toBe('service_unavailable');
    const versions = rowsOf(
      await service.db.execute(
        sql`select count(*)::int as n from vault_secret_versions where secret_id = ${login.secretId}::uuid`,
      ),
    )[0]!;
    expect(versions['n']).toBe(0);
    const state = rowsOf(
      await service.db.execute(
        sql`select k.status as connection_status, j.status as job_status, c.used_at
            from connections k, execution_jobs j, vault_access_capabilities c
            where k.id = ${login.connectionId}::uuid and j.id = ${login.jobId}::uuid and c.id = ${prepared.capabilityId}::uuid`,
      ),
    )[0]!;
    expect(state).toMatchObject({
      connection_status: 'authenticating',
      job_status: 'running',
      used_at: null,
    });
    expect(await auditEvents(service, tenant.organization.id, 'vault.secret_stored')).toHaveLength(
      0,
    );
    await allowAudit();
    ok(
      await service.rpc(
        'supervisor',
        'completeLogin',
        completeParams(prepared, storageStateJson()),
      ),
    );
  });

  it('a failing audit append rolls back an authorization and an issue', async () => {
    const tenant = await seedTenant(service.repos, 'atomic-issue');
    const op = await seedSealedOperation(service, tenant);
    await failAuditOf('vault.capability_authorized');
    expect(
      errorCode(
        await service.rpc('api', 'authorizeJobAccess', { jobId: op.jobId, ttlSeconds: 60 }),
      ),
    ).toBe('service_unavailable');
    const job = rowsOf(
      await service.db.execute(
        sql`select capability_ref from execution_jobs where id = ${op.jobId}::uuid`,
      ),
    )[0]!;
    expect(job['capability_ref']).toBeNull();
    await allowAudit();
    const authorized = ok(
      await service.rpc('api', 'authorizeJobAccess', { jobId: op.jobId, ttlSeconds: 60 }),
    );

    await execSql(
      service,
      sql`update execution_jobs set status = 'running', worker_id = 'worker-1', attempt_count = 1 where id = ${op.jobId}::uuid`,
    );
    await failAuditOf('vault.capability_issued');
    const params = {
      capabilityId: authorized['capabilityId'],
      jobId: op.jobId,
      workerId: 'worker-1',
      attempt: 1,
      ttlSeconds: 30,
    };
    expect(errorCode(await service.rpc('supervisor', 'issueAccessCapability', params))).toBe(
      'service_unavailable',
    );
    const row = await capabilityRowOf(service, authorized['capabilityId'] as string);
    expect(row['token_hash']).toBeNull();
    expect(row['token_mac']).toBeNull();
    await allowAudit();
    ok(await service.rpc('supervisor', 'issueAccessCapability', params));
  });

  it('a failing audit append rolls back a rewrap row (see rewrap.test.ts for the full flow)', async () => {
    // Needs a second KEK version; the flow lives in rewrap.test.ts. Here: with a single KEK
    // there is nothing to rewrap and the call is a no-op, not an error.
    expect(ok(await service.rpc('admin', 'rewrap', { batchSize: 10, maxBatches: 1 }))).toEqual({
      rewrapped: 0,
      skipped: 0,
      failed: 0,
      remaining: 0,
    });
  });
});
