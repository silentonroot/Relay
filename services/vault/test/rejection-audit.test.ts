import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  auditEvents,
  capabilityRowOf,
  CANARY,
  errorCode,
  execSql,
  isPlainForbidden,
  ok,
  prepare,
  readParams,
  rejectedReasons,
  seedSealedOperation,
  seedTenant,
  sleep,
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

async function fresh(label: string, tokenTtl?: number) {
  const tenant = await seedTenant(service.repos, label);
  const op = await seedSealedOperation(service, tenant);
  const prepared = await prepare(service, op, tokenTtl === undefined ? {} : { tokenTtl });
  return { tenant, op, prepared, org: tenant.organization.id };
}

describe('P3-12: theft signals are distinct from ordinary failures', () => {
  const cases: Array<[string, (f: Awaited<ReturnType<typeof fresh>>) => Promise<void>]> = [
    [
      'revoked',
      async (f) => {
        await service.repos.capabilities.revokeForConnection({
          connectionId: f.op.connectionId,
          reason: 'owner_requested',
          now: new Date(),
        });
      },
    ],
    [
      'job_not_running',
      async (f) => {
        await execSql(
          service,
          sql`update execution_jobs set cancel_requested_at = now() where id = ${f.op.jobId}::uuid`,
        );
      },
    ],
    [
      'connection_not_active',
      async (f) => {
        await execSql(
          service,
          sql`update connections set status = 'authentication_required' where id = ${f.op.connectionId}::uuid`,
        );
      },
    ],
    [
      'secret_not_active',
      async (f) => {
        await execSql(
          service,
          sql`update vault_secrets set status = 'deleted' where id = ${f.op.secretId}::uuid`,
        );
      },
    ],
  ];

  it.each(cases)(
    'each rejected presentation writes vault.capability_rejected with its reason: %s',
    async (reason, mutate) => {
      const f = await fresh(`rej-${reason}`);
      await mutate(f);
      const response = await service.rpc('supervisor', 'readForWorker', readParams(f.prepared));
      expect(isPlainForbidden(response)).toBe(true);
      expect(JSON.stringify(response)).not.toContain(CANARY);
      expect(await rejectedReasons(service, f.org)).toEqual([reason]);
      expect(await auditEvents(service, f.org, 'vault.secret_read')).toHaveLength(0);
      const [event] = await auditEvents(service, f.org, 'vault.capability_rejected');
      expect(event).toMatchObject({ actor_type: 'system', decision: 'deny' });
      // Metadata holds ids, the role and the reason; never a token, a hash or a MAC.
      const text = JSON.stringify(event);
      expect(text).not.toContain(f.prepared.token);
      expect(text).not.toMatch(/[0-9a-f]{64}/);
    },
  );

  it('an expired token is refused as expired', async () => {
    const f = await fresh('rej-expired', 1);
    await sleep(1300);
    const response = await service.rpc('supervisor', 'readForWorker', readParams(f.prepared));
    expect(isPlainForbidden(response)).toBe(true);
    expect(await rejectedReasons(service, f.org)).toEqual(['expired']);
  });

  it('an internal failure (database down) is service_unavailable and writes no rejection event', async () => {
    const f = await fresh('rej-internal');
    const before = ok(await service.rpc('admin', 'status', {}))['counters'] as Record<
      string,
      number
    >;
    service.setDatabaseDown(true);
    let responses: Array<Record<string, unknown>>;
    try {
      responses = [
        await service.rpc('api', 'authorizeJobAccess', { jobId: f.op.jobId, ttlSeconds: 60 }),
        await service.rpc('supervisor', 'issueAccessCapability', {
          capabilityId: f.prepared.capabilityId,
          jobId: f.op.jobId,
          workerId: 'worker-1',
          attempt: 1,
          ttlSeconds: 30,
        }),
        await service.rpc('supervisor', 'readForWorker', readParams(f.prepared)),
        await service.rpc('supervisor', 'completeLogin', {
          ...readParams(f.prepared),
          operation: undefined,
          plaintext: 'eA',
          externalAccountHint: null,
          sessionExpiresAt: null,
        }),
        await service.rpc('admin', 'status', {}),
        await service.rpc('admin', 'rewrap', { batchSize: 10, maxBatches: 1 }),
        await service.rpc('admin', 'kekRetirementCheck', { kekVersion: 1 }),
      ];
    } finally {
      service.setDatabaseDown(false);
    }
    for (const response of responses) expect(errorCode(response)).toBe('service_unavailable');
    expect(await rejectedReasons(service, f.org)).toEqual([]);
    expect(service.log.text()).toContain('vault request failed');
    const after = ok(await service.rpc('admin', 'status', {}))['counters'] as Record<
      string,
      number
    >;
    expect(after['internalFailures']).toBeGreaterThan(before['internalFailures']!);
    // The capability was neither consumed nor refused: it still redeems once the database is back.
    expect((await capabilityRowOf(service, f.prepared.capabilityId))['used_at']).toBeNull();
    ok(await service.rpc('supervisor', 'readForWorker', readParams(f.prepared)));
  });

  it('a vault whose key for the capability is missing is a refusal (key_unavailable), not an internal failure', async () => {
    // Covered with real key files in keys.test.ts; here the MAC key of a row's KEK version is
    // simply not loaded: a row claiming KEK version 9.
    const f = await fresh('rej-mac-version');
    await execSql(
      service,
      sql`update vault_access_capabilities set mac_kek_version = 9 where id = ${f.prepared.capabilityId}::uuid`,
    );
    const response = await service.rpc('supervisor', 'readForWorker', readParams(f.prepared));
    expect(isPlainForbidden(response)).toBe(true);
    expect(await rejectedReasons(service, f.org)).toEqual(['key_unavailable']);
  });
});
