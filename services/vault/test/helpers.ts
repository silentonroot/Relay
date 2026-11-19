import { chmod, mkdir, mkdtemp, rm } from 'node:fs/promises';
import { connect } from 'node:net';
import type { Socket } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Writable } from 'node:stream';
import { generateLocalKek } from '@aab/crypto';
import type { VaultRole } from '@aab/contracts';
import { loadVaultConfig } from '../src/config.js';
import type { VaultConfig } from '../src/config.js';
import { DEFAULT_HANDLERS } from '../src/handlers.js';
import { createLogger } from '../src/logging.js';
import { startVault } from '../src/vault.js';
import type { RunningVault, StartVaultOptions } from '../src/vault.js';

/** Unix socket paths are limited to ~100 bytes: socket directories live under the runtime dir. */
export async function makeSocketDir(): Promise<string> {
  const runtime = process.env['XDG_RUNTIME_DIR'];
  if (runtime === undefined || runtime === '') {
    throw new Error('XDG_RUNTIME_DIR is required: socket paths must stay short');
  }
  const dir = await mkdtemp(join(runtime, 'aab-v-'));
  await chmod(dir, 0o700);
  return dir;
}

export async function makeKekDir(versions: number[] = [1]): Promise<string> {
  const dir = join(await mkdtemp(join(tmpdir(), 'aab-kek-')), 'keys');
  await mkdir(dir, { mode: 0o700 });
  await chmod(dir, 0o700);
  for (const version of versions) await generateLocalKek(dir, version);
  return dir;
}

export async function removeDir(path: string): Promise<void> {
  await rm(path, { recursive: true, force: true });
}

/** A valid shared-uid configuration; individual tests override what they exercise. */
export function testConfig(
  socketDir: string,
  kekDir: string,
  overrides: Partial<VaultConfig> = {},
): VaultConfig {
  return {
    ...loadVaultConfig({
      DATABASE_URL: 'postgres://user:pw@localhost:5432/aab',
      AAB_KEK_DIR: kekDir,
      AAB_VAULT_SOCKET_DIR: socketDir,
      AAB_VAULT_ISOLATION: 'shared-uid',
      AAB_LOG_LEVEL: 'silent',
    }),
    ...overrides,
  };
}

export class LogCapture extends Writable {
  readonly lines: string[] = [];
  override _write(chunk: Buffer, _encoding: string, callback: () => void): void {
    this.lines.push(
      ...chunk
        .toString('utf8')
        .split('\n')
        .filter((line) => line !== ''),
    );
    callback();
  }
  text(): string {
    return this.lines.join('\n');
  }
  records(): Array<Record<string, unknown>> {
    return this.lines.map((line) => JSON.parse(line) as Record<string, unknown>);
  }
}

export interface Harness {
  vault: RunningVault;
  socketDir: string;
  kekDir: string;
  log: LogCapture;
  cleanup(): Promise<void>;
}

export async function startTestVault(
  overrides: Partial<VaultConfig> = {},
  options: StartVaultOptions = {},
): Promise<Harness> {
  const socketDir = await makeSocketDir();
  const kekDir = await makeKekDir();
  const log = new LogCapture();
  const config = testConfig(socketDir, kekDir, overrides);
  const logger = createLogger('debug', log);
  let vault: RunningVault;
  try {
    // Protocol-level tests run the listeners with the stub handlers (no database); the real
    // operations are started with `startOperationsVault` (test/service-helpers.ts).
    vault = await startVault(config, { logger, handlers: DEFAULT_HANDLERS, ...options });
  } catch (error) {
    await removeDir(socketDir);
    await removeDir(join(kekDir, '..'));
    throw error;
  }
  return {
    vault,
    socketDir,
    kekDir,
    log,
    async cleanup() {
      await vault.stop();
      await removeDir(socketDir);
      await removeDir(join(kekDir, '..'));
    },
  };
}

/** Sends raw bytes, then resolves with the first response line (or null if the peer closes). */
export function exchange(path: string, bytes: string | Buffer): Promise<string | null> {
  return new Promise((resolve, reject) => {
    const socket = connect(path);
    let data = '';
    socket.on('connect', () => socket.write(bytes));
    socket.on('data', (chunk) => {
      data += chunk.toString('utf8');
      const end = data.indexOf('\n');
      if (end !== -1) {
        resolve(data.slice(0, end));
        socket.destroy();
      }
    });
    socket.on('close', () => resolve(data === '' ? null : data));
    socket.on('error', (error) => {
      if (
        (error as NodeJS.ErrnoException).code === 'EPIPE' ||
        (error as NodeJS.ErrnoException).code === 'ECONNRESET'
      ) {
        resolve(data === '' ? null : data);
      } else {
        reject(error);
      }
    });
  });
}

export async function call(
  path: string,
  request: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const line = await exchange(path, `${JSON.stringify(request)}\n`);
  if (line === null) throw new Error('connection closed without a response');
  return JSON.parse(line) as Record<string, unknown>;
}

export function socketOf(harness: Harness, role: VaultRole): string {
  return harness.vault.sockets[role];
}

export function openSocket(path: string): Promise<Socket> {
  return new Promise((resolve, reject) => {
    const socket = connect(path);
    socket.once('connect', () => resolve(socket));
    socket.once('error', reject);
  });
}

export function waitClosed(socket: Socket, ms = 5_000): Promise<boolean> {
  return new Promise((resolve) => {
    if (socket.destroyed) return resolve(true);
    const timer = setTimeout(() => resolve(false), ms);
    socket.once('close', () => {
      clearTimeout(timer);
      resolve(true);
    });
  });
}
