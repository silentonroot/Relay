import { spawn } from 'node:child_process';
import { chmod, readdir, rm, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { makeKekDir, removeDir } from './helpers.js';
import {
  addKek,
  seedSealedOperation,
  seedTenant,
  seedUnwrappableRowsFirst,
  startService,
} from './service-helpers.js';

const VAULT_DIR = join(import.meta.dirname, '..');
const cleanups: Array<() => Promise<void>> = [];
afterAll(async () => {
  for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
});

function run(script: string, args: string[], env: Record<string, string> = {}) {
  return new Promise<{ code: number | null; stdout: string; stderr: string }>((resolve) => {
    const child = spawn(process.execPath, ['--import', 'tsx', script, ...args], {
      cwd: VAULT_DIR,
      env: { PATH: process.env['PATH'] ?? '', ...env },
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk: Buffer) => (stdout += chunk.toString()));
    child.stderr.on('data', (chunk: Buffer) => (stderr += chunk.toString()));
    child.once('exit', (code) => resolve({ code, stdout, stderr }));
  });
}

describe('init-kek (moved from the worker)', () => {
  it('creates v1, refuses to add or overwrite without --next, and --next adds the next version', async () => {
    const dir = join(await makeKekDir([]), '..', 'fresh-keys');
    cleanups.push(() => removeDir(join(dir, '..')));
    const script = 'src/scripts/init-kek.ts';
    const first = await run(script, [dir]);
    expect(first).toMatchObject({ code: 0, stdout: `${join(dir, 'kek-v1.key')}\n`, stderr: '' });
    expect((await stat(dir)).mode & 0o777).toBe(0o700);
    expect((await stat(join(dir, 'kek-v1.key'))).mode & 0o777).toBe(0o600);

    const again = await run(script, [dir]);
    expect(again.code).toBe(1);
    expect(again.stderr).toContain('refusing to overwrite');

    const next = await run(script, ['--next', dir]);
    expect(next).toMatchObject({ code: 0, stdout: `${join(dir, 'kek-v2.key')}\n` });
    expect((await readdir(dir)).sort()).toEqual(['kek-v1.key', 'kek-v2.key']);
    expect((await stat(join(dir, 'kek-v2.key'))).mode & 0o777).toBe(0o600);
  });

  it('refuses --next, and creates no file, under a parent that others can rename (the vault would refuse it)', async () => {
    const dir = await makeKekDir([1]);
    const parent = join(dir, '..');
    cleanups.push(() => removeDir(parent));
    await chmod(parent, 0o777);
    const next = await run('src/scripts/init-kek.ts', ['--next', dir]);
    expect(next.code).toBe(1);
    expect(next.stderr).toContain('writable by group or other');
    expect(await readdir(dir)).toEqual(['kek-v1.key']);
    // A directory that does not exist yet is checked through its nearest existing ancestor.
    const fresh = await run('src/scripts/init-kek.ts', [join(parent, 'new', 'keys')]);
    expect(fresh.code).toBe(1);
    await expect(stat(join(parent, 'new'))).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('refuses --next on an empty directory and a relative path', async () => {
    const parent = join(await makeKekDir([]), '..');
    cleanups.push(() => removeDir(parent));
    expect((await run('src/scripts/init-kek.ts', ['--next', join(parent, 'none')])).code).toBe(1);
    expect((await run('src/scripts/init-kek.ts', ['relative'])).code).toBe(2);
    expect((await run('src/scripts/init-kek.ts', ['--bogus', join(parent, 'x')])).code).toBe(2);
  });
});

describe('the vault admin command', () => {
  it('status, rewrap and kek-retirement-check talk to the admin socket only', async () => {
    const first = await startService();
    cleanups.push(() => first.cleanup());
    const tenant = await seedTenant(first.repos, 'cli');
    await seedSealedOperation(first, tenant);
    await first.stop();
    await addKek(first.kekDir, 2);
    const second = await startService({ reuse: first });
    cleanups.push(() => second.cleanup());
    const env = { AAB_VAULT_SOCKET_DIR: second.socketDir };
    const cli = 'src/scripts/vault-cli.ts';

    const status = await run(cli, ['status'], env);
    expect(status.code).toBe(0);
    expect(JSON.parse(status.stdout)).toMatchObject({
      kekVersions: [1, 2],
      currentKekVersion: 2,
      versionsByKek: { '1': 1 },
      missingKekVersions: [],
    });
    expect(JSON.parse((await run(cli, ['kek-retirement-check', '1'], env)).stdout)).toEqual({
      referencingVersions: 1,
      safeToRemove: false,
    });
    const rewrap = await run(cli, ['rewrap', '--batch-size', '10'], env);
    expect(rewrap.code).toBe(0);
    expect(JSON.parse(rewrap.stdout)).toEqual({
      rewrapped: 1,
      skipped: 0,
      failed: 0,
      remaining: 0,
    });
    expect(JSON.parse((await run(cli, ['kek-retirement-check', '1'], env)).stdout)).toEqual({
      referencingVersions: 0,
      safeToRemove: true,
    });

    expect((await run(cli, ['bogus'], env)).code).toBe(2);
    expect((await run(cli, ['rewrap', '--batch-size', 'x'], env)).code).toBe(2);
    expect((await run(cli, ['status'], {})).code).toBe(2);
    const unreachable = await run(cli, ['status'], {
      AAB_VAULT_SOCKET_DIR: '/nonexistent-aab-dir',
    });
    expect(unreachable.code).toBe(1);
    expect(unreachable.stderr).toContain('unreachable');
  });
});

describe('the vault admin command, rewrap across calls (B2 review fix 3)', () => {
  it('keeps calling while rows remain, so a per-call bound does not leave work behind', async () => {
    const first = await startService();
    cleanups.push(() => first.cleanup());
    for (let i = 0; i < 5; i += 1) {
      await seedSealedOperation(first, await seedTenant(first.repos, `cli-multi-${i}`));
    }
    await first.stop();
    await addKek(first.kekDir, 2);
    // At most two rows per call: five rows take three calls.
    const second = await startService({ reuse: first, operations: { rewrapMaxRowsPerCall: 2 } });
    cleanups.push(() => second.cleanup());
    const env = { AAB_VAULT_SOCKET_DIR: second.socketDir };
    const rewrap = await run('src/scripts/vault-cli.ts', ['rewrap', '--batch-size', '10'], env);
    expect(rewrap.code).toBe(0);
    expect(JSON.parse(rewrap.stdout)).toEqual({
      rewrapped: 5,
      skipped: 0,
      failed: 0,
      remaining: 0,
    });
  });
});

describe('the vault admin command, rows that cannot be rewrapped (B4)', () => {
  it('rewraps every good row behind 600 failing ones, then exits 3', async () => {
    const first = await startService();
    cleanups.push(() => first.cleanup());
    for (let i = 0; i < 3; i += 1) {
      await seedSealedOperation(first, await seedTenant(first.repos, `cli-cursor-${i}`));
    }
    // 600 rows that sort before the real ones and never unwrap: more than one call's bound.
    await seedUnwrappableRowsFirst(first, 600);
    await first.stop();
    await addKek(first.kekDir, 2);
    const second = await startService({ reuse: first });
    cleanups.push(() => second.cleanup());
    const env = { AAB_VAULT_SOCKET_DIR: second.socketDir };
    const rewrap = await run('src/scripts/vault-cli.ts', ['rewrap', '--batch-size', '100'], env);
    expect(rewrap.code).toBe(3);
    expect(JSON.parse(rewrap.stdout)).toEqual({
      rewrapped: 3,
      skipped: 0,
      failed: 600,
      remaining: 600,
    });
    const status = await run('src/scripts/vault-cli.ts', ['status'], env);
    expect(JSON.parse(status.stdout)).toMatchObject({ versionsByKek: { '1': 600, '2': 3 } });
  }, 120_000);
});

describe('the documented command line keeps the exit code (B4 review M1)', () => {
  /** Runs exactly what docs/operations.md tells the operator to type, from the repository root. */
  function documented(args: string[], env: Record<string, string>) {
    return new Promise<{ code: number | null; stdout: string }>((resolve) => {
      const child = spawn(
        'corepack',
        ['pnpm', '--silent', '--dir', 'services/vault', 'run', 'vault', ...args],
        {
          cwd: join(VAULT_DIR, '..', '..'),
          env: { PATH: process.env['PATH'] ?? '', HOME: process.env['HOME'] ?? '', ...env },
        },
      );
      let stdout = '';
      child.stdout.on('data', (chunk: Buffer) => (stdout += chunk.toString()));
      child.once('exit', (code) => resolve({ code, stdout }));
    });
  }

  it('exits 3 for a missing KEK, 2 for bad usage and 1 for an unreachable vault', async () => {
    const first = await startService();
    cleanups.push(() => first.cleanup());
    await seedSealedOperation(first, await seedTenant(first.repos, 'cli-doc'));
    await first.stop();
    await addKek(first.kekDir, 2);
    await rm(join(first.kekDir, 'kek-v1.key')); // the owner's mistake: the old key is gone
    const second = await startService({ reuse: first });
    cleanups.push(() => second.cleanup());
    const env = { AAB_VAULT_SOCKET_DIR: second.socketDir };

    const rewrap = await documented(['rewrap', '--batch-size', '10'], env);
    expect(rewrap.code).toBe(3);
    expect(JSON.parse(rewrap.stdout)).toEqual({
      rewrapped: 0,
      skipped: 0,
      failed: 1,
      remaining: 1,
    });
    expect((await documented(['bogus'], env)).code).toBe(2);
    expect((await documented(['status'], { AAB_VAULT_SOCKET_DIR: '/nonexistent-aab' })).code).toBe(
      1,
    );
  }, 120_000);
});
