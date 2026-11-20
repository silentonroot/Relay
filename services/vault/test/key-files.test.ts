import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmod, lstat, readdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import {
  addKek,
  completeParams,
  ok,
  prepare,
  readParams,
  seedLoginJob,
  seedSealedOperation,
  seedTenant,
  startService,
  storageStateJson,
} from './service-helpers.js';

/*
 * P3-20: no vault operation, including rewrap and the admin command, deletes, renames or
 * modifies a key file. The directory is hashed before and after: names, contents, modes,
 * inode numbers and change times, and the directory's own times.
 */

const VAULT_DIR = join(import.meta.dirname, '..');
const cleanups: Array<() => Promise<void>> = [];
afterAll(async () => {
  for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
});

async function snapshot(directory: string): Promise<string> {
  const lines: string[] = [];
  const own = await lstat(directory);
  lines.push(`dir mode=${own.mode} ino=${own.ino} mtime=${own.mtimeMs} ctime=${own.ctimeMs}`);
  for (const name of (await readdir(directory)).sort()) {
    const path = join(directory, name);
    const stat = await lstat(path);
    const digest = createHash('sha256')
      .update(await readFile(path))
      .digest('hex');
    lines.push(
      `${name} mode=${stat.mode} ino=${stat.ino} size=${stat.size} mtime=${stat.mtimeMs} ctime=${stat.ctimeMs} sha256=${digest}`,
    );
  }
  return lines.join('\n');
}

function cli(args: string[], env: Record<string, string>) {
  return new Promise<number | null>((resolve) => {
    const child = spawn(
      process.execPath,
      ['--import', 'tsx', 'src/scripts/vault-cli.ts', ...args],
      { cwd: VAULT_DIR, env: { PATH: process.env['PATH'] ?? '', ...env }, stdio: 'ignore' },
    );
    child.once('exit', (code) => resolve(code));
  });
}

describe('P3-20: key files are never changed by the vault or its admin command', () => {
  it('start, read, login, refusal, status, rewrap, retirement check and stop leave the key directory as it was', async () => {
    const first = await startService();
    cleanups.push(() => first.cleanup());
    const tenant = await seedTenant(first.repos, 'keyfiles');
    await seedSealedOperation(first, tenant);
    const login = await seedLoginJob(first, await seedTenant(first.repos, 'keyfiles-login'));
    await first.stop();
    await addKek(first.kekDir, 2);
    const before = await snapshot(first.kekDir);
    expect(before.split('\n')).toHaveLength(3);

    // A new vault with KEK v1 and v2: the start itself must not touch the files either.
    const second = await startService({ reuse: first });
    cleanups.push(() => second.cleanup());
    const op = await seedSealedOperation(second, await seedTenant(second.repos, 'keyfiles-2'));
    const prepared = await prepare(second, op);
    ok(await second.rpc('supervisor', 'readForWorker', readParams(prepared)));
    const refused = await second.rpc(
      'supervisor',
      'readForWorker',
      readParams(prepared, { token: 'A'.repeat(43) }),
    );
    expect(refused['ok']).toBe(false);
    const prepared2 = await prepare(second, login);
    ok(
      await second.rpc(
        'supervisor',
        'completeLogin',
        completeParams(prepared2, storageStateJson('keyfiles')),
      ),
    );
    ok(await second.rpc('admin', 'status', {}));
    ok(await second.rpc('admin', 'rewrap', { batchSize: 1, maxBatches: 5 }));
    ok(await second.rpc('admin', 'kekRetirementCheck', { kekVersion: 1 }));
    const env = { AAB_VAULT_SOCKET_DIR: second.socketDir };
    expect(await cli(['status'], env)).toBe(0);
    expect(await cli(['rewrap'], env)).toBe(0);
    expect(await cli(['kek-retirement-check', '1'], env)).toBe(0);
    expect(await cli(['kek-retirement-check', '2'], env)).toBe(0);
    await second.stop();
    expect(await snapshot(first.kekDir)).toBe(before);
  }, 120_000);

  it('a vault that misses a KEK still changes nothing: refused reads and failed rewraps leave the files alone', async () => {
    const first = await startService();
    cleanups.push(() => first.cleanup());
    const old = await seedSealedOperation(first, await seedTenant(first.repos, 'keyfiles-miss'));
    await first.stop();
    await addKek(first.kekDir, 2);
    await rm(join(first.kekDir, 'kek-v1.key')); // the owner's mistake, not the vault's
    const before = await snapshot(first.kekDir);

    const second = await startService({ reuse: first });
    cleanups.push(() => second.cleanup());
    const prepared = await prepare(second, old);
    expect((await second.rpc('supervisor', 'readForWorker', readParams(prepared)))['ok']).toBe(
      false,
    );
    expect(ok(await second.rpc('admin', 'rewrap', { batchSize: 10, maxBatches: 1 }))).toMatchObject(
      { failed: 1, rewrapped: 0 },
    );
    const env = { AAB_VAULT_SOCKET_DIR: second.socketDir };
    expect(await cli(['rewrap'], env)).toBe(3);
    await second.stop();
    expect(await snapshot(first.kekDir)).toBe(before);
    expect(await readdir(first.kekDir)).toEqual(['kek-v2.key']);
  }, 120_000);

  it('the snapshot notices a rename, a rewrite and a mode change (the check can fail)', async () => {
    const service = await startService({ kekVersions: [1, 2] });
    cleanups.push(() => service.cleanup());
    const base = await snapshot(service.kekDir);
    await chmod(join(service.kekDir, 'kek-v1.key'), 0o400);
    expect(await snapshot(service.kekDir)).not.toBe(base);
    await chmod(join(service.kekDir, 'kek-v1.key'), 0o600);
    await rename(join(service.kekDir, 'kek-v2.key'), join(service.kekDir, 'kek-v2.key.bak'));
    expect(await snapshot(service.kekDir)).not.toBe(base);
    await rename(join(service.kekDir, 'kek-v2.key.bak'), join(service.kekDir, 'kek-v2.key'));
    const original = await readFile(join(service.kekDir, 'kek-v2.key'));
    await writeFile(join(service.kekDir, 'kek-v2.key'), original);
    expect(await snapshot(service.kekDir)).not.toBe(base);
  });
});
