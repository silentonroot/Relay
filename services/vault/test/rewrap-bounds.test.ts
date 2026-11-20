import { afterAll, describe, expect, it } from 'vitest';
import { REWRAP_MAX_BATCH, REWRAP_MAX_ROWS_PER_CALL } from '../src/operations.js';
import {
  addKek,
  errorCode,
  ok,
  openStored,
  seedSealedOperation,
  seedTenant,
  seedUnwrappableRowsFirst,
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
    // A call that stopped at its bound names where it stopped (the cursor); the rewrapped rows
    // have left the list, so calling again without it also continues.
    const first = ok(await second.rpc('admin', 'rewrap', params));
    expect(first).toMatchObject({ rewrapped: 2, skipped: 0, failed: 0, remaining: 3 });
    expect(first['nextAfterId']).toEqual(expect.stringMatching(/^[0-9a-f-]{36}$/));
    expect(ok(await second.rpc('admin', 'rewrap', params))).toMatchObject({
      rewrapped: 2,
      skipped: 0,
      failed: 0,
      remaining: 1,
    });
    // The last call reached the end of the list: no cursor.
    expect(ok(await second.rpc('admin', 'rewrap', params))).toEqual({
      rewrapped: 1,
      skipped: 0,
      failed: 0,
      remaining: 0,
    });
  });
});

describe('rewrap cursor across calls (B4)', () => {
  it('a call that starts after nextAfterId never examines the rows before it', async () => {
    const { second } = await rotated(520, { operations: { rewrapMaxRowsPerCall: 500 } });
    await seedUnwrappableRowsFirst(second, 600);
    const params = { batchSize: 100, maxBatches: 100 };
    // 500 unwrappable rows come first: the call spends its whole bound on them.
    const one = ok(await second.rpc('admin', 'rewrap', params));
    expect(one).toMatchObject({ rewrapped: 0, failed: 500 });
    expect(one['nextAfterId']).toBe('00000000-0000-4000-8000-000000000500');
    // Without the cursor the next call would examine the same 500 rows again; with it, the
    // remaining 100 failing rows and then the good ones.
    const two = ok(await second.rpc('admin', 'rewrap', { ...params, afterId: one['nextAfterId'] }));
    expect(two).toMatchObject({ rewrapped: 400, failed: 100 });
    expect(two['nextAfterId']).toBeDefined();
    const three = ok(
      await second.rpc('admin', 'rewrap', { ...params, afterId: two['nextAfterId'] }),
    );
    expect(three).toMatchObject({ rewrapped: 120, failed: 0, remaining: 600 });
    expect(three['nextAfterId']).toBeUndefined();
  }, 180_000);

  it('rejects a cursor that is not a uuid, and unknown fields', async () => {
    const { second } = await rotated(1);
    for (const afterId of ['x', 5, null]) {
      expect(
        errorCode(await second.rpc('admin', 'rewrap', { batchSize: 1, maxBatches: 1, afterId })),
      ).toBe('malformed');
    }
    expect(
      errorCode(await second.rpc('admin', 'rewrap', { batchSize: 1, maxBatches: 1, cursor: 'x' })),
    ).toBe('malformed');
  });
});
