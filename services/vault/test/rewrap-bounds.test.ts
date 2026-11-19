import { afterAll, describe, expect, it } from 'vitest';
import { REWRAP_MAX_BATCH, REWRAP_MAX_ROWS_PER_CALL } from '../src/operations.js';
import {
  addKek,
  ok,
  openStored,
  seedSealedOperation,
  seedTenant,
  startService,
} from './service-helpers.js';
import type { SealedOperation, Tenant } from './service-helpers.js';

const cleanups: Array<() => Promise<void>> = [];
afterAll(async () => {
  for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
});

/** `count` sealed sessions under KEK v1, then a restart with KEK v1 and v2 loaded. */
async function rotated(count: number, operations?: Parameters<typeof startService>[0]) {
  const first = await startService();
  cleanups.push(() => first.cleanup());
  const sealed: Array<{ tenant: Tenant; op: SealedOperation }> = [];
  for (let i = 0; i < count; i += 1) {
    const tenant = await seedTenant(first.repos, `rwb-${i}`);
    sealed.push({ tenant, op: await seedSealedOperation(first, tenant, `session-${i}`) });
  }
  await first.stop();
  await addKek(first.kekDir, 2);
  const second = await startService({ reuse: first, ...operations });
  cleanups.push(() => second.cleanup());
  return { first, second, sealed };
}

describe('rewrap batch sizes', () => {
  it('a batch size above the 500-row listing cap still walks every batch (fix 4)', async () => {
    expect(REWRAP_MAX_BATCH).toBe(500);
    const { second, sealed } = await rotated(520, {
      // Lift the per-call bound so only the batch comparison is under test.
      operations: { rewrapMaxRowsPerCall: 10_000 },
    });
    const result = ok(await second.rpc('admin', 'rewrap', { batchSize: 1_000, maxBatches: 10 }));
    // Comparing the 500-row page against the requested 1,000 stopped after the first page.
    expect(result).toEqual({ rewrapped: 520, skipped: 0, failed: 0, remaining: 0 });
    for (const { tenant, op } of [sealed[0]!, sealed[519]!]) {
      expect(await openStored(second, tenant, op.connectionId)).toBe(op.plaintext);
    }
  }, 120_000);
});

describe('rewrap does a bounded amount of work per call (fix 3)', () => {
  it('has a default bound of 500 rows per call', () => {
    expect(REWRAP_MAX_ROWS_PER_CALL).toBe(500);
  });

  it('stops after the bound and reports what remains; the next call continues', async () => {
    const { second } = await rotated(5, { operations: { rewrapMaxRowsPerCall: 2 } });
    const params = { batchSize: 100, maxBatches: 100 };
    expect(ok(await second.rpc('admin', 'rewrap', params))).toEqual({
      rewrapped: 2,
      skipped: 0,
      failed: 0,
      remaining: 3,
    });
    expect(ok(await second.rpc('admin', 'rewrap', params))).toEqual({
      rewrapped: 2,
      skipped: 0,
      failed: 0,
      remaining: 1,
    });
    expect(ok(await second.rpc('admin', 'rewrap', params))).toEqual({
      rewrapped: 1,
      skipped: 0,
      failed: 0,
      remaining: 0,
    });
  });
});
