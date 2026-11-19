import { lstat } from 'node:fs/promises';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { createDatabase } from '@aab/database';
import { createLogger } from '../src/logging.js';
import { startVault, VaultStartError } from '../src/vault.js';
import { makeKekDir, makeSocketDir, removeDir, testConfig } from './helpers.js';
import { startService } from './service-helpers.js';

const cleanups: Array<() => Promise<void>> = [];
afterEach(async () => {
  for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
});

describe('the vault needs its database to start (fail closed)', () => {
  it('refuses to start, with nothing listening, when DATABASE_URL cannot be reached', async () => {
    const socketDir = await makeSocketDir();
    const kekDir = await makeKekDir();
    cleanups.push(async () => {
      await removeDir(socketDir);
      await removeDir(join(kekDir, '..'));
    });
    const config = testConfig(socketDir, kekDir, {
      databaseUrl: 'postgres://aab:hunter2-secret@127.0.0.1:1/aab',
    });
    const error = await startVault(config, { logger: createLogger('silent') }).catch(
      (caught: unknown) => caught,
    );
    expect(error).toBeInstanceOf(VaultStartError);
    expect((error as Error).message).toContain('DATABASE_URL');
    expect((error as Error).message).not.toContain('hunter2');
    for (const role of ['api', 'supervisor', 'admin']) {
      await expect(lstat(join(socketDir, role, 'vault.sock'))).rejects.toMatchObject({
        code: 'ENOENT',
      });
    }
  });

  it('refuses to start when the vault tables cannot be read through the injected database', async () => {
    const socketDir = await makeSocketDir();
    const kekDir = await makeKekDir();
    cleanups.push(async () => {
      await removeDir(socketDir);
      await removeDir(join(kekDir, '..'));
    });
    const unmigrated = createDatabase({ connectionString: 'postgres://x@127.0.0.1:1/none' });
    cleanups.push(() => unmigrated.close().catch(() => undefined));
    const error = await startVault(testConfig(socketDir, kekDir), {
      logger: createLogger('silent'),
      database: unmigrated,
    }).catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(VaultStartError);
  });

  it('serves every operation of ADR-014 section 4 once the database is there, and stops cleanly', async () => {
    const service = await startService();
    cleanups.push(() => service.cleanup());
    for (const role of ['api', 'supervisor', 'admin'] as const) {
      const hello = await service.rpc(role, 'hello', { protocolVersion: 1 });
      expect(hello).toMatchObject({ ok: true, result: { role } });
    }
    await service.stop();
    for (const role of ['api', 'supervisor', 'admin']) {
      await expect(lstat(join(service.socketDir, role, 'vault.sock'))).rejects.toMatchObject({
        code: 'ENOENT',
      });
    }
  });
});
