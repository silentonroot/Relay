import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  auditEvents,
  errorCode,
  ok,
  seedSealedOperation,
  seedTenant,
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

describe('P3-2: a request refused for its role is audited as vault.request_refused', () => {
  it('appends the event to the chain of the job the request named, with role, operation and request id only', async () => {
    const tenant = await seedTenant(service.repos, 'refused');
    const op = await seedSealedOperation(service, tenant);
    const response = await service.rpc('api', 'issueAccessCapability', {
      capabilityId: '99999999-9999-4999-8999-999999999999',
      jobId: op.jobId,
      workerId: 'worker-1',
      attempt: 1,
      ttlSeconds: 30,
    });
    expect(errorCode(response)).toBe('forbidden');
    const events = await auditEvents(service, tenant.organization.id, 'vault.request_refused');
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({ actor_type: 'system', decision: 'deny' });
    expect(events[0]!['metadata']).toEqual({
      role: 'api',
      operation: 'issueAccessCapability',
      requestId: response['id'],
      jobId: op.jobId,
    });
  });

  it('logs and counts a refusal that resolves to no organization, and writes nothing to any chain', async () => {
    const before = ok(await service.rpc('admin', 'status', {}))['counters'] as Record<
      string,
      number
    >;
    expect(errorCode(await service.rpc('api', 'rewrap', { batchSize: 1, maxBatches: 1 }))).toBe(
      'forbidden',
    );
    expect(
      errorCode(
        await service.rpc('supervisor', 'authorizeJobAccess', {
          jobId: '99999999-9999-4999-8999-999999999999',
          ttlSeconds: 60,
        }),
      ),
    ).toBe('forbidden');
    const after = ok(await service.rpc('admin', 'status', {}))['counters'] as Record<
      string,
      number
    >;
    expect(after['refusedUnattributed']).toBe(before['refusedUnattributed']! + 2);
    expect(service.log.text()).toContain('vault.request_refused');
  });

  it('a refused request never changes state, even with a valid job id', async () => {
    const tenant = await seedTenant(service.repos, 'refused-nochange');
    const op = await seedSealedOperation(service, tenant);
    // The supervisor may not authorize: the job gets no capability.
    expect(
      errorCode(
        await service.rpc('supervisor', 'authorizeJobAccess', { jobId: op.jobId, ttlSeconds: 60 }),
      ),
    ).toBe('forbidden');
    const job = await service.repos.jobs.getInternal(op.jobId);
    expect(job?.capabilityRef).toBeNull();
    expect(
      await auditEvents(service, tenant.organization.id, 'vault.capability_authorized'),
    ).toHaveLength(0);
  });
});
