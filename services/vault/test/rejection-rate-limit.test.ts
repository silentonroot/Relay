import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  auditEvents,
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
import { REJECTIONS_PER_WINDOW } from '../src/operations.js';

let service: Service;
beforeAll(async () => {
  service = await startService();
});
afterAll(async () => {
  await service.cleanup();
});

const counter = async (name: string) =>
  (ok(await service.rpc('admin', 'status', {}))['counters'] as Record<string, number>)[name]!;

describe('vault.capability_rejected is rate limited per organization (fix 5)', () => {
  it('appends at most 60 per organization per minute, logs and counts the rest, and still refuses', async () => {
    expect(REJECTIONS_PER_WINDOW).toBe(60);
    const loud = await seedTenant(service.repos, 'rej-loud');
    const quiet = await seedTenant(service.repos, 'rej-quiet');
    const loudOp = await seedSealedOperation(service, loud);
    const quietOp = await seedSealedOperation(service, quiet);
    const loudPrepared = await prepare(service, loudOp);
    const quietPrepared = await prepare(service, quietOp);
    ok(await service.rpc('supervisor', 'readForWorker', readParams(loudPrepared)));
    const before = await counter('rejectedRateLimited');

    // The spent token, presented 65 times: every one is refused, only 60 reach the chain.
    for (let i = 0; i < 65; i += 1) {
      const response = await service.rpc('supervisor', 'readForWorker', readParams(loudPrepared));
      expect(isPlainForbidden(response)).toBe(true);
    }
    expect(await rejectedReasons(service, loud.organization.id)).toEqual(Array(60).fill('used'));
    expect(await counter('rejectedRateLimited')).toBe(before + 5);
    expect(service.log.text()).toContain('over its rejection rate limit');

    // Another organization is not starved by the loud one.
    ok(await service.rpc('supervisor', 'readForWorker', readParams(quietPrepared)));
    const again = await service.rpc('supervisor', 'readForWorker', readParams(quietPrepared));
    expect(isPlainForbidden(again)).toBe(true);
    expect(await rejectedReasons(service, quiet.organization.id)).toEqual(['used']);
    expect(await auditEvents(service, loud.organization.id, 'vault.secret_read')).toHaveLength(1);
  }, 60_000);
});
