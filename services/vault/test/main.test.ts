import { spawn } from 'node:child_process';
import { lstat } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { createDatabase, migrate } from '@aab/database';
import { sql } from '@aab/database/testing';
import { afterEach, describe, expect, it } from 'vitest';
import { call, makeKekDir, makeSocketDir, removeDir } from './helpers.js';

const cleanups: Array<() => Promise<void>> = [];
afterEach(async () => {
  for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
});

/**
 * Creates a throwaway, fully migrated database on the server of `serverUrl` and returns its URL
 * with a function that drops it again.
 */
async function createMigratedDatabase(
  serverUrl: string,
): Promise<{ url: string; drop: () => Promise<void> }> {
  const name = `aab_vault_main_${randomBytes(6).toString('hex')}`;
  const runAdmin = async (statement: string): Promise<void> => {
    const admin = createDatabase({ connectionString: serverUrl, maxConnections: 1 });
    try {
      await admin.db.execute(sql.raw(statement));
    } finally {
      await admin.close();
    }
  };
  await runAdmin(`create database ${name}`);
  const drop = () => runAdmin(`drop database if exists ${name} with (force)`);
  try {
    const target = new URL(serverUrl);
    target.pathname = `/${name}`;
    const handle = createDatabase({ connectionString: target.toString(), maxConnections: 1 });
    try {
      await migrate(handle.db);
    } finally {
      await handle.close();
    }
    return { url: target.toString(), drop };
  } catch (error) {
    await drop();
    throw error;
  }
}

function run(env: Record<string, string>) {
  const child = spawn(process.execPath, ['--import', 'tsx', 'src/main.ts'], {
    cwd: join(import.meta.dirname, '..'),
    // An empty environment apart from the settings (ADR-014 section 3).
    env: { PATH: process.env['PATH'] ?? '', ...env },
  });
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', (chunk: Buffer) => (stdout += chunk.toString()));
  child.stderr.on('data', (chunk: Buffer) => (stderr += chunk.toString()));
  const exited = new Promise<number | null>((resolve) =>
    child.once('exit', (code) => resolve(code)),
  );
  return { child, exited, out: () => stdout, err: () => stderr };
}

describe('entry point', () => {
  it('refuses an invalid configuration with a non-zero exit and no value in the message', async () => {
    const proc = run({
      DATABASE_URL: 'postgres://aab:hunter2-secret@localhost/aab',
      AAB_KEK_DIR: 'not-absolute-secret',
      AAB_VAULT_SOCKET_DIR: '/run/aab-vault',
      AAB_VAULT_ISOLATION: 'shared-uid',
    });
    expect(await proc.exited).toBe(1);
    expect(proc.err()).toContain('AAB_KEK_DIR');
    for (const leaked of ['hunter2', 'not-absolute-secret']) {
      expect(proc.err() + proc.out()).not.toContain(leaked);
    }
  });

  // The vault now connects to its database before it listens (B2b), so the process-level start
  // needs a reachable PostgreSQL: set AAB_TEST_DATABASE_URL (a server where the role may create
  // databases); the test creates and migrates its own throwaway database there and drops it. The in-process equivalents (hello on every socket, shutdown removing
  // the sockets) run against PGlite in service-boundary.test.ts and startup.test.ts.
  const liveDatabase = process.env['AAB_TEST_DATABASE_URL'] ?? '';
  it.skipIf(liveDatabase === '')(
    'starts, answers hello on every socket, and on SIGTERM closes and removes the sockets',
    async () => {
      const database = await createMigratedDatabase(liveDatabase);
      cleanups.push(database.drop);
      const socketDir = await makeSocketDir();
      const kekDir = await makeKekDir();
      cleanups.push(async () => {
        await removeDir(socketDir);
        await removeDir(dirname(kekDir));
      });
      const proc = run({
        DATABASE_URL: database.url,
        AAB_KEK_DIR: kekDir,
        AAB_VAULT_SOCKET_DIR: socketDir,
        AAB_VAULT_ISOLATION: 'shared-uid',
      });
      cleanups.push(async () => {
        proc.child.kill('SIGKILL');
        await proc.exited;
      });
      for (let i = 0; i < 100 && !proc.out().includes('"msg":"vault listening"'); i += 1) {
        await new Promise((resolve) => setTimeout(resolve, 100));
        if (proc.child.exitCode !== null) throw new Error(`vault exited early: ${proc.err()}`);
      }
      const socket = join(socketDir, 'api', 'vault.sock');
      const reply = await call(socket, {
        id: 'm',
        operation: 'hello',
        params: { protocolVersion: 1 },
      });
      expect(reply).toMatchObject({ ok: true, result: { role: 'api', isolation: 'shared-uid' } });
      // The umask is 0117 and the mode is set explicitly: no access for group or other.
      expect((await lstat(socket)).mode & 0o777).toBe(0o600);
      expect(proc.out()).toContain('shared-uid isolation');

      proc.child.kill('SIGTERM');
      expect(await proc.exited).toBe(0);
      for (const role of ['api', 'supervisor', 'admin']) {
        await expect(lstat(join(socketDir, role, 'vault.sock'))).rejects.toMatchObject({
          code: 'ENOENT',
        });
      }
    },
  );

  it('refuses to start, listening on nothing, when the database cannot be reached (fail closed)', async () => {
    const socketDir = await makeSocketDir();
    const kekDir = await makeKekDir();
    cleanups.push(async () => {
      await removeDir(socketDir);
      await removeDir(dirname(kekDir));
    });
    const proc = run({
      // Port 1 on loopback: nothing listens there; the password must never be printed.
      DATABASE_URL: 'postgres://aab:hunter2-secret@127.0.0.1:1/aab',
      AAB_KEK_DIR: kekDir,
      AAB_VAULT_SOCKET_DIR: socketDir,
      AAB_VAULT_ISOLATION: 'shared-uid',
    });
    expect(await proc.exited).toBe(1);
    expect(proc.err()).toContain('database');
    expect(proc.err() + proc.out()).not.toContain('hunter2');
    for (const role of ['api', 'supervisor', 'admin']) {
      await expect(lstat(join(socketDir, role, 'vault.sock'))).rejects.toMatchObject({
        code: 'ENOENT',
      });
    }
  });
});
