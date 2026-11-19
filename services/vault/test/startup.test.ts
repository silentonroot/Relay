import { spawn } from 'node:child_process';
import { chmod, lstat, mkdir, readFile, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { VAULT_ROLES } from '@aab/contracts';
import { ConfigError } from '../src/config.js';
import {
  ancestorProblem,
  directoryProblem,
  socketProblem,
  SocketSafetyError,
} from '../src/socket-safety.js';
import { DEFAULT_HANDLERS } from '../src/handlers.js';
import { startVault } from '../src/vault.js';
import type { RunningVault } from '../src/vault.js';
import {
  call,
  LogCapture,
  makeKekDir,
  makeSocketDir,
  removeDir,
  startTestVault,
  testConfig,
} from './helpers.js';
import type { Harness } from './helpers.js';
import { createLogger } from '../src/logging.js';
import type { Stats } from 'node:fs';

const cleanups: Array<() => Promise<void>> = [];
afterEach(async () => {
  for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
});

async function dirs(): Promise<{ socketDir: string; kekDir: string }> {
  const socketDir = await makeSocketDir();
  const kekDir = await makeKekDir();
  cleanups.push(async () => {
    await removeDir(socketDir);
    await removeDir(dirname(kekDir));
  });
  return { socketDir, kekDir };
}

/** Starts expecting a refusal; returns the message and checks nothing is left listening. */
async function refused(
  socketDir: string,
  kekDir: string,
  overrides: Parameters<typeof testConfig>[2] = {},
  safety: Parameters<typeof startVault>[1] = {},
): Promise<string> {
  let vault: RunningVault | undefined;
  try {
    vault = await startVault(testConfig(socketDir, kekDir, overrides), {
      handlers: DEFAULT_HANDLERS,
      logger: createLogger('silent'),
      ...safety,
    });
  } catch (error) {
    return (error as Error).message;
  }
  await vault.stop();
  throw new Error('expected the vault to refuse to start');
}

function fakeStat(partial: {
  mode: number;
  uid?: number;
  gid?: number;
  kind: 'dir' | 'socket' | 'link' | 'file';
}): Stats {
  return {
    mode: partial.mode,
    uid: partial.uid ?? 1000,
    gid: partial.gid ?? 2000,
    isDirectory: () => partial.kind === 'dir',
    isSocket: () => partial.kind === 'socket',
    isSymbolicLink: () => partial.kind === 'link',
    isFile: () => partial.kind === 'file',
  } as unknown as Stats;
}

describe('refuses to start on unsafe socket permissions (P3-3)', () => {
  it('on a platform other than Linux', async () => {
    const { socketDir, kekDir } = await dirs();
    for (const platform of ['darwin', 'win32', 'freebsd'] as const) {
      const message = await refused(socketDir, kekDir, {}, { safety: { platform } });
      expect(message).toContain('Linux only');
      expect(await readdir(socketDir)).toEqual([]);
    }
  });

  it.each([0o705, 0o701, 0o704, 0o707, 0o755])(
    'when a role directory is accessible to other (mode %o)',
    async (mode) => {
      const { socketDir, kekDir } = await dirs();
      const role = join(socketDir, 'supervisor');
      await mkdir(role, { mode: 0o700 });
      await chmod(role, mode);
      const message = await refused(socketDir, kekDir);
      expect(message).toContain('role directory');
      expect(message).toContain(role);
    },
  );

  it('when a shared-uid role directory is open to its group', async () => {
    const { socketDir, kekDir } = await dirs();
    const role = join(socketDir, 'api');
    await mkdir(role, { mode: 0o700 });
    await chmod(role, 0o750);
    expect(await refused(socketDir, kekDir)).toContain('must be mode 0700');
  });

  it('when the base directory is open to group or other in shared-uid isolation', async () => {
    const { socketDir, kekDir } = await dirs();
    await chmod(socketDir, 0o750);
    expect(await refused(socketDir, kekDir)).toContain('socket directory');
  });

  it('when the base directory is writable by group or other, or readable by other', async () => {
    const { socketDir, kekDir } = await dirs();
    const group = {
      AAB_VAULT_ISOLATION: 'separate-uid' as const,
    };
    void group;
    for (const mode of [0o770, 0o707, 0o755]) {
      await chmod(socketDir, mode);
      const message = await refused(
        socketDir,
        kekDir,
        {
          isolation: 'separate-uid',
          roleGroups: { api: '1', supervisor: '2', admin: '3' },
        },
        { safety: { resolveGroup: (spec) => Promise.resolve(Number(spec)) } },
      );
      expect(message).toContain('socket directory');
    }
  });

  it('when a role directory is a symbolic link', async () => {
    const { socketDir, kekDir } = await dirs();
    const elsewhere = join(socketDir, 'elsewhere');
    await mkdir(elsewhere, { mode: 0o700 });
    await symlink(elsewhere, join(socketDir, 'admin'));
    expect(await refused(socketDir, kekDir)).toContain('is a symbolic link');
  });

  it('when the socket directory itself, or a parent of it, is a symbolic link', async () => {
    const { socketDir, kekDir } = await dirs();
    const real = join(socketDir, 'real');
    await mkdir(real, { mode: 0o700 });
    const link = join(socketDir, 'link');
    await symlink(real, link);
    expect(await refused(link, kekDir)).toContain('symbolic link');
    // A real directory reached through a linked parent.
    await mkdir(join(real, 'inner'), { mode: 0o700 });
    expect(await refused(join(link, 'inner'), kekDir)).toContain('symbolic link');
  });

  it('when the socket path is a symbolic link, a regular file or a directory', async () => {
    const { socketDir, kekDir } = await dirs();
    const role = join(socketDir, 'api');
    await mkdir(role, { mode: 0o700 });
    const target = join(socketDir, 'target');
    await writeFile(target, 'precious');
    await symlink(target, join(role, 'vault.sock'));
    expect(await refused(socketDir, kekDir)).toContain('not a socket owned by the vault');
    expect(await readFile(target, 'utf8')).toBe('precious');

    await rm(join(role, 'vault.sock'));
    await writeFile(join(role, 'vault.sock'), 'a regular file');
    expect(await refused(socketDir, kekDir)).toContain('not a socket owned by the vault');
    expect(await readFile(join(role, 'vault.sock'), 'utf8')).toBe('a regular file');

    await rm(join(role, 'vault.sock'));
    await mkdir(join(role, 'vault.sock'));
    expect(await refused(socketDir, kekDir)).toContain('not a socket owned by the vault');
  });

  it('when two roles resolve to the same group (shared role directories)', async () => {
    const { socketDir, kekDir } = await dirs();
    const message = await refused(
      socketDir,
      kekDir,
      { isolation: 'separate-uid', roleGroups: { api: 'a', supervisor: 'b', admin: 'c' } },
      { safety: { resolveGroup: () => Promise.resolve(4242) } },
    );
    expect(message).toContain('same group');
  });

  it("when a role group is the vault's own primary group", async () => {
    const { socketDir, kekDir } = await dirs();
    const message = await refused(
      socketDir,
      kekDir,
      { isolation: 'separate-uid', roleGroups: { api: 'a', supervisor: 'b', admin: 'c' } },
      {
        safety: {
          gid: 1000,
          resolveGroup: (spec) => Promise.resolve({ a: 1000, b: 2, c: 3 }[spec] ?? 9),
        },
      },
    );
    expect(message).toContain('primary group');
  });

  it('when the socket directory is inside the repository', async () => {
    const { socketDir, kekDir } = await dirs();
    const message = await refused(
      socketDir,
      kekDir,
      {},
      { safety: { repositoryRoot: dirname(socketDir) } },
    );
    expect(message).toContain('inside the repository');
  });

  it('when the socket directory is under the real repository root by default', async () => {
    const { kekDir } = await dirs();
    const inRepo = join(import.meta.dirname, '..', '..', '..', 'node_modules', '.aab-v-test');
    await mkdir(inRepo, { recursive: true, mode: 0o700 });
    cleanups.push(() => removeDir(inRepo));
    expect(await refused(inRepo, kekDir)).toContain('inside the repository');
  });

  it('when the socket directory does not exist, is too long, or overlaps the key directory', async () => {
    const { socketDir, kekDir } = await dirs();
    expect(await refused(join(socketDir, 'missing'), kekDir)).toContain('does not exist');
    const long = join(socketDir, 'x'.repeat(90));
    await mkdir(long, { mode: 0o700 });
    expect(await refused(long, kekDir)).toContain('too long');
    expect(await refused(socketDir, join(socketDir, 'keys'))).toContain('contain one another');
  });

  it('when another vault is already listening on a socket', async () => {
    const harness = await startTestVault();
    cleanups.push(() => harness.cleanup());
    const kekDir = await makeKekDir();
    cleanups.push(() => removeDir(dirname(kekDir)));
    const message = await refused(harness.socketDir, kekDir);
    expect(message).toContain('another process is listening');
    // The running vault is untouched.
    const reply = await call(harness.vault.sockets.api, {
      id: 'x',
      operation: 'hello',
      params: { protocolVersion: 1 },
    });
    expect(reply['ok']).toBe(true);
  });

  it('when the vault would run as root', async () => {
    const { socketDir, kekDir } = await dirs();
    expect(await refused(socketDir, kekDir, {}, { safety: { uid: 0 } })).toContain(
      'not run as root',
    );
  });

  it('does not accept an invalid configuration object either (startup path, not only the loader)', async () => {
    const { socketDir, kekDir } = await dirs();
    await expect(
      startVault(testConfig(socketDir, kekDir, { isolation: 'separate-uid', roleGroups: {} }), {
        handlers: DEFAULT_HANDLERS,
        logger: createLogger('silent'),
      }),
    ).rejects.toBeInstanceOf(SocketSafetyError);
    expect(ConfigError).toBeDefined();
  });
});

describe('pure directory and socket checks', () => {
  const dir = { isolation: 'separate-uid' as const, uid: 1000, gid: 2000, kind: 'role' as const };
  it('accepts exactly 0750 and 2750 with the right owner and group', () => {
    expect(directoryProblem(fakeStat({ mode: 0o40750, kind: 'dir' }), dir)).toBeNull();
    expect(directoryProblem(fakeStat({ mode: 0o42750, kind: 'dir' }), dir)).toBeNull();
  });
  it.each([
    [{ mode: 0o40755, kind: 'dir' as const }, 'other'],
    [{ mode: 0o40770, kind: 'dir' as const }, 'never write'],
    [{ mode: 0o40700, kind: 'dir' as const }, 'must be mode 0750'],
    [{ mode: 0o40751, kind: 'dir' as const }, 'other'],
    [{ mode: 0o40750, kind: 'dir' as const, uid: 0 }, "vault's user"],
    [{ mode: 0o40750, kind: 'dir' as const, gid: 3000 }, "role's group"],
    [{ mode: 0o120750, kind: 'link' as const }, 'symbolic link'],
    [{ mode: 0o100750, kind: 'file' as const }, 'not a directory'],
  ])('refuses %j', (stat, expected) => {
    expect(directoryProblem(fakeStat(stat), dir)).toContain(expected);
  });

  it('checks a socket: type, owner, mode, group', () => {
    const expected = { isolation: 'separate-uid' as const, uid: 1000, gid: 2000 };
    expect(socketProblem(fakeStat({ mode: 0o140660, kind: 'socket' }), expected)).toBeNull();
    expect(socketProblem(fakeStat({ mode: 0o140666, kind: 'socket' }), expected)).toContain('mode');
    expect(socketProblem(fakeStat({ mode: 0o140664, kind: 'socket' }), expected)).toContain('mode');
    expect(socketProblem(fakeStat({ mode: 0o140660, kind: 'socket', gid: 1 }), expected)).toContain(
      'group',
    );
    expect(socketProblem(fakeStat({ mode: 0o140660, kind: 'socket', uid: 5 }), expected)).toContain(
      'owned',
    );
    expect(socketProblem(fakeStat({ mode: 0o100660, kind: 'file' }), expected)).toContain('socket');
    expect(
      socketProblem(fakeStat({ mode: 0o140600, kind: 'socket' }), {
        ...expected,
        isolation: 'shared-uid',
      }),
    ).toBeNull();
  });
});

describe('listeners and sockets', () => {
  let harness: Harness;
  afterEach(async () => {
    await harness?.cleanup();
  });

  it('creates one directory and one socket per role, modes 0700 and 0600 in shared-uid', async () => {
    harness = await startTestVault();
    const seen = new Set<string>();
    for (const role of VAULT_ROLES) {
      const directory = join(harness.socketDir, role);
      const socket = join(directory, 'vault.sock');
      expect(harness.vault.sockets[role]).toBe(socket);
      const dirStat = await lstat(directory);
      expect(dirStat.mode & 0o7777).toBe(0o700);
      const socketStat = await lstat(socket);
      expect(socketStat.isSocket()).toBe(true);
      expect(socketStat.mode & 0o777).toBe(0o600);
      expect(socketStat.uid).toBe(process.geteuid?.());
      seen.add(`${dirStat.dev}:${dirStat.ino}`);
    }
    expect(seen.size).toBe(3);
  });

  it('opens no TCP listener and listens only on filesystem paths', async () => {
    const listening = async () => {
      const entries: string[] = [];
      for (const file of ['/proc/net/tcp', '/proc/net/tcp6']) {
        const text = await readFile(file, 'utf8').catch(() => '');
        for (const row of text.split('\n').slice(1)) {
          const columns = row.trim().split(/\s+/);
          if (columns[3] === '0A') entries.push(`${file} ${columns[1]} ${columns[9]}`);
        }
      }
      return entries.sort();
    };
    const before = await listening();
    harness = await startTestVault();
    expect(await listening()).toEqual(before);
    for (const role of VAULT_ROLES) {
      const address = harness.vault.servers[role].server.address();
      expect(typeof address).toBe('string');
      expect(address).toBe(harness.vault.sockets[role]);
    }
  });

  it('stop() closes the sockets and removes them, and a restart works', async () => {
    harness = await startTestVault();
    const sockets = Object.values(harness.vault.sockets);
    await harness.vault.stop();
    for (const socket of sockets) {
      await expect(lstat(socket)).rejects.toMatchObject({ code: 'ENOENT' });
    }
    const again = await startVault(testConfig(harness.socketDir, harness.kekDir), {
      handlers: DEFAULT_HANDLERS,
      logger: createLogger('silent'),
    });
    expect(Object.keys(again.sockets)).toHaveLength(3);
    await again.stop();
  });

  it('removes a stale socket it owns (left by a killed process) and then listens', async () => {
    const { socketDir, kekDir } = await dirs();
    const role = join(socketDir, 'admin');
    await mkdir(role, { mode: 0o700 });
    const stale = join(role, 'vault.sock');
    const child = spawn(process.execPath, [
      '-e',
      `require('node:net').createServer().listen(${JSON.stringify(stale)},()=>process.stdout.write('ready'))`,
    ]);
    await new Promise<void>((resolve) => child.stdout.once('data', () => resolve()));
    child.kill('SIGKILL');
    await new Promise((resolve) => child.once('exit', resolve));
    expect((await lstat(stale)).isSocket()).toBe(true);

    const vault = await startVault(testConfig(socketDir, kekDir), {
      handlers: DEFAULT_HANDLERS,
      logger: createLogger('silent'),
    });
    cleanups.push(() => vault.stop());
    const reply = await call(vault.sockets.admin, {
      id: 'x',
      operation: 'hello',
      params: { protocolVersion: 1 },
    });
    expect(reply['ok']).toBe(true);
  });

  it('warns once at start in shared-uid isolation and reports it in hello', async () => {
    harness = await startTestVault();
    for (const role of VAULT_ROLES) {
      await call(harness.vault.sockets[role], {
        id: 'h',
        operation: 'hello',
        params: { protocolVersion: 1 },
      });
    }
    const warnings = harness.log.records().filter((record) => record['level'] === 40);
    const shared = warnings.filter((record) => record['isolation'] === 'shared-uid');
    expect(shared).toHaveLength(1);
    expect(String(shared[0]?.['msg'])).toContain('shared-uid isolation');
  });
});

describe('key directory', () => {
  it('refuses to start without a KEK, with an unsafe directory, or with a missing one', async () => {
    const { socketDir, kekDir } = await dirs();
    expect(await refused(socketDir, join(kekDir, 'missing'))).toContain('KEK directory');

    const empty = join(dirname(kekDir), 'empty');
    await mkdir(empty, { mode: 0o700 });
    expect(await refused(socketDir, empty)).toContain('no KEK files');

    await chmod(kekDir, 0o750);
    expect(await refused(socketDir, kekDir)).toContain('must not be accessible by group or other');
    await chmod(kekDir, 0o700);
    const [first] = (await readdir(kekDir)).filter((name) => name.endsWith('.key'));
    await chmod(join(kekDir, first ?? ''), 0o644);
    expect(await refused(socketDir, kekDir)).toContain('must not be accessible by group or other');
  });

  it('derives MAC keys per KEK version in memory and does not print them', async () => {
    const socketDir = await makeSocketDir();
    const kekDir = await makeKekDir([1, 2]);
    const log = new LogCapture();
    const vault = await startVault(testConfig(socketDir, kekDir), {
      handlers: DEFAULT_HANDLERS,
      logger: createLogger('debug', log),
    });
    cleanups.push(async () => {
      await vault.stop();
      await removeDir(socketDir);
      await removeDir(dirname(kekDir));
    });
    expect(vault.keys.kekVersions).toEqual([1, 2]);
    expect(vault.keys.currentKekVersion).toBe(2);
    const first = vault.keys.macKey(1);
    const second = vault.keys.macKey(2);
    expect(first).toBeDefined();
    expect(second).toBeDefined();
    expect(first?.export().equals(second?.export() ?? Buffer.alloc(0))).toBe(false);
    expect(vault.keys.macKey(3)).toBeUndefined();
    const current = vault.keys.currentMacKey();
    expect(current.kekVersion).toBe(2);
    const keyText = first?.export().toString('hex') ?? 'missing';
    expect(JSON.stringify(vault.keys)).not.toContain(keyText);
    expect(String(JSON.stringify(vault.keys))).toContain('kekVersions');
    expect(log.text()).not.toContain(keyText);
  });
});

describe('ancestors of the socket directory (B2 review fix 6)', () => {
  it('refuses to start when a parent directory is writable by group or other', async () => {
    for (const mode of [0o770, 0o707, 0o777]) {
      const { socketDir, kekDir } = await dirs();
      // The parent can be renamed through by its group/others: the vault must not trust what is below.
      const child = join(socketDir, 'sockets');
      await mkdir(child, { mode: 0o700 });
      await chmod(socketDir, mode);
      const message = await refused(child, kekDir);
      expect(message, mode.toString(8)).toContain('ancestor of the socket directory');
      expect(message).toContain(socketDir);
    }
  });

  it('starts when the parents are private (the same layout with 0750 and 0700)', async () => {
    for (const mode of [0o700, 0o750, 0o755]) {
      const { socketDir, kekDir } = await dirs();
      const child = join(socketDir, 'sockets');
      await mkdir(child, { mode: 0o700 });
      await chmod(socketDir, mode);
      const vault = await startVault(testConfig(child, kekDir), {
        handlers: DEFAULT_HANDLERS,
        logger: createLogger('silent'),
      });
      await vault.stop();
    }
  });

  it('judges a directory by owner, write bits and the sticky bit', () => {
    const dir = (mode: number, uid: number) =>
      fakeStat({ mode: 0o040000 | mode, uid, kind: 'dir' });
    const VAULT = 1000;
    expect(ancestorProblem(dir(0o755, 0), VAULT)).toBeNull(); // /run
    expect(ancestorProblem(dir(0o700, VAULT), VAULT)).toBeNull(); // /run/user/1000
    expect(ancestorProblem(dir(0o1777, 0), VAULT)).toBeNull(); // /tmp
    expect(ancestorProblem(dir(0o775, 0), VAULT)).toContain('writable by group or other');
    expect(ancestorProblem(dir(0o777, 0), VAULT)).toContain('writable by group or other');
    expect(ancestorProblem(dir(0o757, VAULT), VAULT)).toContain('writable by group or other');
    // Sticky only protects a directory root owns; anyone else's sticky directory is renameable by its owner.
    expect(ancestorProblem(dir(0o1777, VAULT), VAULT)).toContain('writable by group or other');
    expect(ancestorProblem(dir(0o755, 1234), VAULT)).toContain('neither root nor');
    expect(ancestorProblem(fakeStat({ mode: 0o120777, kind: 'link' }), VAULT)).toContain(
      'symbolic link',
    );
    expect(ancestorProblem(fakeStat({ mode: 0o100644, uid: 0, kind: 'file' }), VAULT)).toContain(
      'not a directory',
    );
  });
});
