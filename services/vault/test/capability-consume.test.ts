import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  auditEvents,
  CANARY,
  isPlainForbidden,
  ok,
  prepare,
  readParams,
  rejectedReasons,
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

describe('P3-4: check and consume are one atomic step', () => {
  it('redeems a capability exactly once under 20 concurrent redemptions', async () => {
    const tenant = await seedTenant(service.repos, 'race');
    const op = await seedSealedOperation(service, tenant);
    const prepared = await prepare(service, op);
    const responses = await Promise.all(
      Array.from({ length: 20 }, () =>
        service.rpc('supervisor', 'readForWorker', readParams(prepared)),
      ),
    );
    const winners = responses.filter((response) => response['ok'] === true);
    expect(winners).toHaveLength(1);
    expect(
      Buffer.from((winners[0]!['result'] as { plaintext: string }).plaintext, 'base64url').toString(
        'utf8',
      ),
    ).toBe(op.plaintext);
    const losers = responses.filter((response) => response['ok'] !== true);
    expect(losers).toHaveLength(19);
    for (const loser of losers) {
      expect(isPlainForbidden(loser)).toBe(true);
      expect(JSON.stringify(loser)).not.toContain(CANARY);
    }
    // One read event; every loser audited as a used token.
    expect(await auditEvents(service, tenant.organization.id, 'vault.secret_read')).toHaveLength(1);
    expect(await rejectedReasons(service, tenant.organization.id)).toEqual(Array(19).fill('used'));
  });

  it('a used capability is refused and audited as used, with no plaintext', async () => {
    const tenant = await seedTenant(service.repos, 'used');
    const op = await seedSealedOperation(service, tenant);
    const prepared = await prepare(service, op);
    ok(await service.rpc('supervisor', 'readForWorker', readParams(prepared)));
    const again = await service.rpc('supervisor', 'readForWorker', readParams(prepared));
    expect(isPlainForbidden(again)).toBe(true);
    expect(JSON.stringify(again)).not.toContain(CANARY);
    expect(await rejectedReasons(service, tenant.organization.id)).toEqual(['used']);
  });

  it('a second issue for one capability is refused (one token per authorization)', async () => {
    const tenant = await seedTenant(service.repos, 'twice-issue');
    const op = await seedSealedOperation(service, tenant);
    const prepared = await prepare(service, op);
    const second = await service.rpc('supervisor', 'issueAccessCapability', {
      capabilityId: prepared.capabilityId,
      jobId: op.jobId,
      workerId: prepared.workerId,
      attempt: 1,
      ttlSeconds: 30,
    });
    expect(isPlainForbidden(second)).toBe(true);
    expect(await rejectedReasons(service, tenant.organization.id)).toEqual(['used']);
    // The first token still works: the refused second issue changed nothing.
    ok(await service.rpc('supervisor', 'readForWorker', readParams(prepared)));
  });
});
