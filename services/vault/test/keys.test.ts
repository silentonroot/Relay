import { readdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import {
  addKek,
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

const cleanups: Array<() => Promise<void>> = [];
afterAll(async () => {
  for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
});

describe('P3-20: only the vault touches key files; a missing KEK version fails reads, not the vault', () => {
  it('a missing KEK version is reported and its versions are refused', async () => {
    const first = await startService();
    cleanups.push(() => first.cleanup());
    const tenant = await seedTenant(first.repos, 'key-missing');
    const old = await seedSealedOperation(first, tenant); // sealed under KEK v1
    await first.stop();
    // The owner adds v2 and (wrongly, early) removes v1 by hand: the vault never does either.
    await addKek(first.kekDir, 2);
    await rm(join(first.kekDir, 'kek-v1.key'));

    const second = await startService({ reuse: first });
    cleanups.push(() => second.cleanup());
    const status = ok(await second.rpc('admin', 'status', {}));
    expect(status).toMatchObject({
      kekVersions: [2],
      currentKekVersion: 2,
      versionsByKek: { '1': 1 },
      missingKekVersions: [1],
    });
    // A fresh capability (MAC under KEK v2) for a version still wrapped under the missing v1.
    const prepared = await prepare(second, old);
    const response = await second.rpc('supervisor', 'readForWorker', readParams(prepared));
    expect(isPlainForbidden(response)).toBe(true);
    expect(JSON.stringify(response)).not.toContain(CANARY);
    expect(await rejectedReasons(second, tenant.organization.id)).toEqual(['key_unavailable']);
    expect(await auditEvents(second, tenant.organization.id, 'vault.secret_read')).toHaveLength(0);

    // The vault still works for everything else: a session sealed under v2 reads fine.
    const other = await seedTenant(second.repos, 'key-present');
    const fresh = await seedSealedOperation(second, other);
    const prepared2 = await prepare(second, fresh);
    expect(
      ok(await second.rpc('supervisor', 'readForWorker', readParams(prepared2))),
    ).toMatchObject({
      kekVersion: 2,
    });
    // Rewrap cannot move a version whose KEK is missing: counted as failed, not an abort.
    expect(ok(await second.rpc('admin', 'rewrap', { batchSize: 10, maxBatches: 1 }))).toEqual({
      rewrapped: 0,
      skipped: 0,
      failed: 1,
      remaining: 1,
    });
    expect(ok(await second.rpc('admin', 'kekRetirementCheck', { kekVersion: 1 }))).toEqual({
      referencingVersions: 1,
      safeToRemove: false,
    });
    expect(await readdir(first.kekDir)).toEqual(['kek-v2.key']);
  });

  it('kekRetirementCheck reports safe only when nothing references the version', async () => {
    const service = await startService({ kekVersions: [1, 2] });
    cleanups.push(() => service.cleanup());
    const tenant = await seedTenant(service.repos, 'retire');
    await seedSealedOperation(service, tenant); // wrapped under the current KEK, v2
    expect(ok(await service.rpc('admin', 'kekRetirementCheck', { kekVersion: 1 }))).toEqual({
      referencingVersions: 0,
      safeToRemove: true,
    });
    expect(ok(await service.rpc('admin', 'kekRetirementCheck', { kekVersion: 2 }))).toEqual({
      referencingVersions: 1,
      safeToRemove: false,
    });
    expect(ok(await service.rpc('admin', 'kekRetirementCheck', { kekVersion: 7 }))).toEqual({
      referencingVersions: 0,
      safeToRemove: true,
    });
    // Nothing the vault did removed or changed a key file.
    expect((await readdir(service.kekDir)).sort()).toEqual(['kek-v1.key', 'kek-v2.key']);
  });
});
