import { chmod, lstat, mkdir } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { VAULT_ROLES } from '@aab/contracts';
import { createLogger } from '../src/logging.js';
import { DEFAULT_HANDLERS } from '../src/handlers.js';
import { startVault } from '../src/vault.js';
import { call, LogCapture, makeKekDir, makeSocketDir, removeDir, testConfig } from './helpers.js';

/*
 * Real group ownership needs groups this user belongs to (a non-root process may chown to its
 * own supplementary groups). Skipped where fewer than three exist besides the primary group;
 * the pure checks in startup.test.ts cover the same rules without the groups.
 */
const primary = process.getegid?.() ?? -1;
const groups = [...new Set(process.getgroups?.() ?? [])].filter((gid) => gid !== primary);
const GIDS = groups.slice(0, 3);
const enough = GIDS.length === 3 && process.platform === 'linux';

const cleanups: Array<() => Promise<void>> = [];
afterEach(async () => {
  for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
});

async function setup() {
  const socketDir = await makeSocketDir();
  const kekDir = await makeKekDir();
  cleanups.push(async () => {
    await removeDir(socketDir);
    await removeDir(dirname(kekDir));
  });
  const config = testConfig(socketDir, kekDir, {
    isolation: 'separate-uid',
    roleGroups: {
      api: String(GIDS[0]),
      supervisor: String(GIDS[1]),
      admin: String(GIDS[2]),
    },
  });
  return { socketDir, kekDir, config };
}

describe.skipIf(!enough)('separate-uid isolation with real groups (P3-3)', () => {
  it('creates 0750 role directories and 0660 sockets owned by each role group, with no shared-uid warning', async () => {
    const { config, socketDir } = await setup();
    const log = new LogCapture();
    const vault = await startVault(config, {
      handlers: DEFAULT_HANDLERS,
      logger: createLogger('debug', log),
    });
    cleanups.push(() => vault.stop());
    const expectedGid = { api: GIDS[0], supervisor: GIDS[1], admin: GIDS[2] } as const;
    for (const role of VAULT_ROLES) {
      const dir = await lstat(join(socketDir, role));
      expect(dir.mode & 0o7777 & ~0o2000).toBe(0o750);
      expect(dir.gid).toBe(expectedGid[role]);
      const socket = await lstat(vault.sockets[role]);
      expect(socket.mode & 0o777).toBe(0o660);
      expect(socket.gid).toBe(expectedGid[role]);
      const reply = await call(vault.sockets[role], {
        id: 'h',
        operation: 'hello',
        params: { protocolVersion: 1 },
      });
      expect(reply).toMatchObject({ ok: true, result: { isolation: 'separate-uid', role } });
    }
    expect(log.records().some((record) => record['isolation'] === 'shared-uid')).toBe(false);
  });

  it('refuses a role directory with the wrong group, group write access or other access', async () => {
    for (const [mode, gid, expected] of [
      [0o750, GIDS[1], "role's group"],
      [0o770, GIDS[0], 'never write'],
      [0o755, GIDS[0], 'other'],
    ] as const) {
      const { config, socketDir } = await setup();
      const directory = join(socketDir, 'api');
      await mkdir(directory, { mode: 0o700 });
      const { chown } = await import('node:fs/promises');
      await chown(directory, process.geteuid?.() ?? 0, gid ?? 0);
      await chmod(directory, mode);
      await expect(
        startVault(config, { handlers: DEFAULT_HANDLERS, logger: createLogger('silent') }),
      ).rejects.toThrow(expected);
    }
  });

  it('refuses a socket directory that a group can write to', async () => {
    const { config, socketDir } = await setup();
    await chmod(socketDir, 0o770);
    await expect(
      startVault(config, { handlers: DEFAULT_HANDLERS, logger: createLogger('silent') }),
    ).rejects.toThrow('socket directory');
  });
});
