import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  capabilityRowOf,
  CANARY,
  completeParams,
  execSql,
  isPlainForbidden,
  ok,
  prepare,
  putSealed,
  readParams,
  rejectedReasons,
  seedSealedOperation,
  seedTenant,
  sql,
  startService,
} from './service-helpers.js';
import type { Service } from './service-helpers.js';

let service: Service;
beforeAll(async () => {
  service = await startService();
});
afterAll(async () => {
  await service.cleanup();
});

async function fresh(label: string) {
  const tenant = await seedTenant(service.repos, label);
  const op = await seedSealedOperation(service, tenant);
  const prepared = await prepare(service, op);
  return { tenant, op, prepared };
}

/** Refused, no plaintext, the reason audited, and the capability still unused (nothing consumed). */
async function expectRefused(
  response: Record<string, unknown>,
  tenantOrg: string,
  prepared: Awaited<ReturnType<typeof prepare>>,
  reason: string,
) {
  expect(isPlainForbidden(response)).toBe(true);
  expect(JSON.stringify(response)).not.toContain(CANARY);
  expect(await rejectedReasons(service, tenantOrg)).toEqual([reason]);
  expect((await capabilityRowOf(service, prepared.capabilityId))['used_at']).toBeNull();
}

describe('P3-5: a capability opens only what it is bound to', () => {
  it('rejects a capability presented for another job', async () => {
    const { tenant, prepared } = await fresh('b-job');
    const otherTenant = await seedTenant(service.repos, 'b-job-other');
    const other = await seedSealedOperation(service, otherTenant);
    const response = await service.rpc(
      'supervisor',
      'readForWorker',
      readParams(prepared, { jobId: other.jobId }),
    );
    await expectRefused(response, tenant.organization.id, prepared, 'binding_mismatch');
  });

  it('rejects a capability presented for another connection', async () => {
    const { tenant, prepared } = await fresh('b-conn');
    const otherTenant = await seedTenant(service.repos, 'b-conn-other');
    const other = await seedSealedOperation(service, otherTenant);
    const response = await service.rpc(
      'supervisor',
      'readForWorker',
      readParams(prepared, { connectionId: other.connectionId }),
    );
    await expectRefused(response, tenant.organization.id, prepared, 'binding_mismatch');
  });

  it('rejects a capability presented for another operation', async () => {
    const { tenant, prepared } = await fresh('b-op');
    const response = await service.rpc(
      'supervisor',
      'readForWorker',
      readParams(prepared, { operation: 'orders.delete' }),
    );
    await expectRefused(response, tenant.organization.id, prepared, 'binding_mismatch');
  });

  it('rejects a read capability presented as a login completion (wrong purpose)', async () => {
    const { tenant, prepared } = await fresh('b-purpose');
    const response = await service.rpc(
      'supervisor',
      'completeLogin',
      completeParams(prepared, 'x'),
    );
    await expectRefused(response, tenant.organization.id, prepared, 'binding_mismatch');
  });

  it('rejects a capability whose bound version is no longer the active one', async () => {
    const { tenant, op, prepared } = await fresh('b-version');
    // A newer version replaced the one the capability was bound to.
    await putSealed(service, tenant, op.connectionId, op.secretId, 2, 'a newer session');
    const response = await service.rpc('supervisor', 'readForWorker', readParams(prepared));
    await expectRefused(response, tenant.organization.id, prepared, 'secret_not_active');
  });

  it('rejects a capability when the job runs under another worker or attempt', async () => {
    const worker = await fresh('b-worker');
    await execSql(
      service,
      sql`update execution_jobs set worker_id = 'worker-2' where id = ${worker.op.jobId}::uuid`,
    );
    await expectRefused(
      await service.rpc('supervisor', 'readForWorker', readParams(worker.prepared)),
      worker.tenant.organization.id,
      worker.prepared,
      'binding_mismatch',
    );

    const attempt = await fresh('b-attempt');
    await execSql(
      service,
      sql`update execution_jobs set attempt_count = 2 where id = ${attempt.op.jobId}::uuid`,
    );
    await expectRefused(
      await service.rpc('supervisor', 'readForWorker', readParams(attempt.prepared)),
      attempt.tenant.organization.id,
      attempt.prepared,
      'binding_mismatch',
    );
  });

  it('issue is refused for another worker or attempt than the one running the job', async () => {
    const tenant = await seedTenant(service.repos, 'b-issue');
    const op = await seedSealedOperation(service, tenant);
    const authorized = ok(
      await service.rpc('api', 'authorizeJobAccess', { jobId: op.jobId, ttlSeconds: 600 }),
    );
    await execSql(
      service,
      sql`update execution_jobs set status = 'running', worker_id = 'worker-1', attempt_count = 1 where id = ${op.jobId}::uuid`,
    );
    for (const override of [{ workerId: 'worker-2' }, { attempt: 2 }]) {
      const response = await service.rpc('supervisor', 'issueAccessCapability', {
        capabilityId: authorized['capabilityId'],
        jobId: op.jobId,
        workerId: 'worker-1',
        attempt: 1,
        ttlSeconds: 30,
        ...override,
      });
      expect(isPlainForbidden(response)).toBe(true);
    }
    expect(await rejectedReasons(service, tenant.organization.id)).toEqual([
      'binding_mismatch',
      'binding_mismatch',
    ]);
    // No token was produced by the refused issues.
    expect(
      (await capabilityRowOf(service, authorized['capabilityId'] as string))['token_hash'],
    ).toBeNull();
  });
});
