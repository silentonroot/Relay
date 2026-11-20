import { chmod, mkdir, readdir, realpath, rename, rm, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { VaultKeys } from '../src/keys.js';
import { makeKekDir, removeDir } from './helpers.js';
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

describe('the key directory must not sit under a directory others can rename (B2 residual)', () => {
  async function loadUnder(parentMode: number): Promise<unknown> {
    const dir = await makeKekDir([1]);
    const parent = dirname(dir);
    cleanups.push(() => removeDir(parent));
    await chmod(parent, parentMode);
    return VaultKeys.load(dir).then(
      () => 'loaded',
      (error: unknown) => error,
    );
  }

  it('refuses a parent writable by group or by other, and loads under a private one', async () => {
    expect(await loadUnder(0o700)).toBe('loaded');
    expect(await loadUnder(0o755)).toBe('loaded');
    for (const mode of [0o775, 0o777, 0o757, 0o770]) {
      const error = await loadUnder(mode);
      expect(error).toBeInstanceOf(Error);
      expect((error as Error).message).toContain('writable by group or other');
    }
  });

  it('accepts a sticky directory only when root owns it (the socket directory rule)', async () => {
    // A sticky parent owned by the vault's own user is refused: it is not root's /tmp. A
    // root-owned sticky directory is accepted; every test key directory lives under /tmp.
    const error = await loadUnder(0o1777);
    expect(error).toBeInstanceOf(Error);
    expect((error as Error).message).toContain('not a sticky directory owned by root');
    expect(tmpdir()).toBe((await realpath(tmpdir())).toString());
    expect(await loadUnder(0o700)).toBe('loaded');
  });

  it('refuses a key directory reached through a symbolic link, even a safe target in an unsafe directory', async () => {
    const safe = await makeKekDir([1]);
    cleanups.push(() => removeDir(dirname(safe)));
    const outer = dirname(await makeKekDir([]));
    cleanups.push(() => removeDir(outer));
    await chmod(outer, 0o777);
    const link = join(outer, 'link');
    await symlink(safe, link);
    const error = await VaultKeys.load(link).catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(Error);
    expect((error as Error).message).toContain('symbolic link');
  });

  it('checks every ancestor, not only the parent', async () => {
    const dir = await makeKekDir([1]);
    const parent = dirname(dir);
    cleanups.push(() => removeDir(parent));
    // The key directory sits two levels down; the unsafe directory is the outer one.
    const nested = join(parent, 'inner');
    await mkdir(nested, { mode: 0o700 });
    await rename(dir, join(nested, 'keys'));
    await chmod(parent, 0o777);
    const error = await VaultKeys.load(join(nested, 'keys')).catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(Error);
    expect((error as Error).message).toContain(parent);
  });
});
