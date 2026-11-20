import { execFile } from 'node:child_process';
import { mkdir, mkdtemp, rm } from 'node:fs/promises';
import net from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createSupervisor, SupervisorStartError } from '../../src/supervisor/index.js';
import { createSupervisorVault } from '../../src/vault/gateway.js';
import { startFakeVault } from '../../../broker-api/test/fake-vault.js';
import type { FakeVault, FakeVaultOptions } from '../../../broker-api/test/fake-vault.js';
import { captureLogger, createWorld, FakeRunner, testRegistry } from './helpers.js';
import type { World } from './helpers.js';

const run = promisify(execFile);
const WORKER_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const TSX = path.resolve(WORKER_DIR, '..', '..', 'node_modules', '.bin', 'tsx');

/*
 * P3-1 and ADR-014 section 3: the supervisor asks the vault `hello` before it claims anything
 * and refuses to start when the vault is not what it may use. A stand-in vault answers `hello`
 * as configured; the real one is used by the other supervisor tests.
 */
describe('supervisor start-up against the vault', () => {
  let world: World;
  let fake: FakeVault | null = null;
  let readableDir: string;

  beforeEach(async () => {
    world = await createWorld();
    readableDir = await mkdtemp(path.join(tmpdir(), 'aab-readable-keydir-'));
  });
  afterEach(async () => {
    await fake?.close();
    fake = null;
    await rm(readableDir, { recursive: true, force: true });
    await world.close();
  });

  async function startWith(
    hello: NonNullable<FakeVaultOptions['hello']>,
    isolation: 'separate-uid' | 'shared-uid',
  ): Promise<unknown> {
    fake = await startFakeVault({ hello });
    const runner = new FakeRunner();
    const supervisor = createSupervisor({
      repos: world.repos,
      runner,
      vault: createSupervisorVault({
        socketPath: fake.socketPath,
        isolation,
        timeoutMs: 2_000,
      }),
      adapters: testRegistry(),
      logger: captureLogger().logger,
      settings: { workerId: 'worker-test', pollIntervalMs: 50 },
    });
    try {
      await supervisor.start();
      await supervisor.stop();
      return null;
    } catch (error) {
      return error;
    }
  }

  it("refuses to start when the vault's key directory is readable", async () => {
    // The vault says where its keys are; in separate-uid mode this user must not be able to open it.
    const error = await startWith(
      { role: 'supervisor', isolation: 'separate-uid', keyDirectory: readableDir },
      'separate-uid',
    );
    expect(error).toBeInstanceOf(SupervisorStartError);
    expect((error as Error).message).toContain("the vault's key directory");
    expect((error as Error).message).toContain(readableDir);
  });

  it('starts when the key directory cannot be opened (separate-uid)', async () => {
    const error = await startWith(
      {
        role: 'supervisor',
        isolation: 'separate-uid',
        keyDirectory: path.join(readableDir, 'not-there'),
      },
      'separate-uid',
    );
    expect(error).toBeNull();
  });

  it('does not probe the key directory in shared-uid mode', async () => {
    const error = await startWith(
      { role: 'supervisor', isolation: 'shared-uid', keyDirectory: readableDir },
      'shared-uid',
    );
    expect(error).toBeNull();
  });

  it('refuses a vault that answers as another role', async () => {
    for (const role of ['api', 'admin']) {
      const error = await startWith(
        { role, isolation: 'shared-uid', keyDirectory: '/nonexistent/aab-keys' },
        'shared-uid',
      );
      expect(error).toBeInstanceOf(SupervisorStartError);
      expect((error as Error).message).toContain('AAB_VAULT_SOCKET');
      expect((error as Error).message).toContain('supervisor');
      await fake?.close();
      fake = null;
    }
  });

  it('refuses a vault whose isolation mode differs from the configured one', async () => {
    const error = await startWith(
      { role: 'supervisor', isolation: 'separate-uid', keyDirectory: '/nonexistent/aab-keys' },
      'shared-uid',
    );
    expect(error).toBeInstanceOf(SupervisorStartError);
    expect((error as Error).message).toContain('AAB_VAULT_ISOLATION');
  });

  it('refuses to start when a sibling role socket accepts a connection (separate-uid, L1)', async () => {
    // <root>/supervisor/vault.sock is ours; <root>/admin/vault.sock must be out of reach.
    const root = await mkdtemp(path.join(process.env['XDG_RUNTIME_DIR'] ?? tmpdir(), 'aab-roles-'));
    await mkdir(path.join(root, 'supervisor'));
    await mkdir(path.join(root, 'admin'));
    const server = net.createServer((socket) => socket.end());
    await new Promise<void>((resolve) =>
      server.listen(path.join(root, 'admin', 'vault.sock'), resolve),
    );
    const client = {
      call: async () => ({
        protocolVersion: 1,
        serviceVersion: '0.0.0',
        isolation: 'separate-uid',
        role: 'supervisor',
        keyDirectory: '/nonexistent/aab-keys',
        currentKekVersion: 1,
      }),
    } as never;
    try {
      const supervisor = createSupervisor({
        repos: world.repos,
        runner: new FakeRunner(),
        vault: createSupervisorVault({
          socketPath: path.join(root, 'supervisor', 'vault.sock'),
          isolation: 'separate-uid',
          client,
        }),
        adapters: testRegistry(),
        logger: captureLogger().logger,
        settings: { workerId: 'worker-test' },
      });
      const error = await supervisor.start().catch((e: unknown) => e);
      expect(error).toBeInstanceOf(SupervisorStartError);
      expect((error as Error).message).toContain('admin-role socket');
      // With nothing listening there, it starts.
      server.close();
      await rm(path.join(root, 'admin', 'vault.sock'), { force: true });
      await supervisor.start();
      await supervisor.stop();
    } finally {
      server.close();
      await rm(root, { recursive: true, force: true });
    }
  });

  it('starts degraded when the vault does not answer, and claims nothing', async () => {
    const socketPath = path.join(readableDir, 'nobody-listens.sock');
    const runner = new FakeRunner();
    const supervisor = createSupervisor({
      repos: world.repos,
      runner,
      vault: createSupervisorVault({ socketPath, isolation: 'shared-uid', timeoutMs: 500 }),
      adapters: testRegistry(),
      logger: captureLogger().logger,
      settings: { workerId: 'worker-test', pollIntervalMs: 50 },
    });
    await supervisor.start();
    expect(await supervisor.tick()).toEqual([]);
    await supervisor.stop();
  });

  it('refuses to start as a process when AAB_KEK_DIR is set, before opening anything', async () => {
    const result = await run(TSX, ['src/main.ts'], {
      cwd: WORKER_DIR,
      env: {
        PATH: process.env['PATH'] ?? '',
        DATABASE_URL: 'postgres://aab:synthetic-db-password@127.0.0.1:1/aab',
        AAB_VAULT_SOCKET: '/nonexistent/supervisor/vault.sock',
        AAB_KEK_DIR: '/nonexistent/aab-keys',
      },
      timeout: 60_000,
    }).catch((error: { code: number; stdout: string; stderr: string }) => error);
    expect((result as { code?: number }).code).toBe(1);
    expect(result.stderr).toContain('AAB_KEK_DIR');
    expect(result.stderr).toContain('must not be set');
    expect(result.stderr).not.toContain('synthetic-db-password');
  }, 90_000);
});
