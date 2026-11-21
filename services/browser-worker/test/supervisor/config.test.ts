import { execFile } from 'node:child_process';
import { mkdtemp, readdir, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import {
  DEFAULT_TOKEN_TTL_SECONDS,
  TOKEN_TTL_MAX_SECONDS,
  TOKEN_TTL_MIN_SECONDS,
} from '@aab/contracts';
import { describe, expect, it } from 'vitest';
import { ConfigError, loadWorkerConfig } from '../../src/config.js';
import { createLogger } from '../../src/logging.js';

const run = promisify(execFile);
const here = path.dirname(fileURLToPath(import.meta.url));
const WORKER_DIR = path.resolve(here, '..', '..');
const TSX = path.resolve(WORKER_DIR, '..', '..', 'node_modules', '.bin', 'tsx');

const minimal = {
  DATABASE_URL: 'postgres://aab:synthetic-db-password@127.0.0.1:5432/aab',
  AAB_VAULT_SOCKET: '/run/aab/vault/supervisor/vault.sock',
};

function configError(env: Record<string, string | undefined>): ConfigError {
  try {
    loadWorkerConfig(env);
  } catch (error) {
    if (error instanceof ConfigError) return error;
    throw error;
  }
  throw new Error('expected a ConfigError');
}

describe('worker configuration', () => {
  it('refuses unsafe-process unless the vault isolation is shared-uid (L2)', () => {
    const error = configError({ ...minimal, AAB_WORKER_SANDBOX: 'unsafe-process' });
    expect(error.message).toContain('unsafe-process');
    expect(error.message).toContain('shared-uid');
    expect(
      configError({
        ...minimal,
        AAB_WORKER_SANDBOX: 'unsafe-process',
        AAB_VAULT_ISOLATION: 'separate-uid',
      }).message,
    ).toContain('unsafe-process');
    expect(
      loadWorkerConfig({
        ...minimal,
        AAB_WORKER_SANDBOX: 'unsafe-process',
        AAB_VAULT_ISOLATION: 'shared-uid',
      }).sandbox,
    ).toBe('unsafe-process');
    // The real sandboxes work with either mode.
    for (const sandbox of ['bubblewrap', 'docker']) {
      expect(loadWorkerConfig({ ...minimal, AAB_WORKER_SANDBOX: sandbox }).sandbox).toBe(sandbox);
    }
  });

  it('applies defaults', () => {
    expect(loadWorkerConfig(minimal)).toEqual({
      databaseUrl: minimal.DATABASE_URL,
      vaultSocket: '/run/aab/vault/supervisor/vault.sock',
      vaultIsolation: 'separate-uid',
      vaultCallTimeoutMs: 5_000,
      sandbox: 'bubblewrap',
      concurrency: 2,
      pollIntervalMs: 1_000,
      leaseMs: 60_000,
      runtimeDir: undefined,
      chromiumPath: undefined,
      dockerImage: undefined,
      resultTtlMinutes: 60,
      logLevel: 'info',
    });
  });

  it('reads every variable', () => {
    const config = loadWorkerConfig({
      ...minimal,
      AAB_WORKER_SANDBOX: 'docker',
      AAB_WORKER_CONCURRENCY: '4',
      AAB_WORKER_POLL_MS: '250',
      AAB_WORKER_LEASE_MS: '30000',
      AAB_WORKER_RUNTIME_DIR: '/run/aab',
      AAB_CHROMIUM_PATH: '/usr/bin/chromium',
      AAB_WORKER_DOCKER_IMAGE: 'aab/browser-runner:1.2',
      AAB_JOB_RESULT_TTL_MINUTES: '15',
      AAB_LOG_LEVEL: 'debug',
      AAB_VAULT_ISOLATION: 'shared-uid',
      AAB_VAULT_CALL_TIMEOUT_MS: '2500',
    });
    expect(config).toMatchObject({
      vaultIsolation: 'shared-uid',
      vaultCallTimeoutMs: 2_500,
      sandbox: 'docker',
      concurrency: 4,
      pollIntervalMs: 250,
      leaseMs: 30_000,
      runtimeDir: '/run/aab',
      chromiumPath: '/usr/bin/chromium',
      dockerImage: 'aab/browser-runner:1.2',
      resultTtlMinutes: 15,
      logLevel: 'debug',
    });
  });

  it('names missing required variables', () => {
    const error = configError({});
    expect(error.message).toContain('DATABASE_URL');
    expect(error.message).toContain('AAB_VAULT_SOCKET');
    // Blank counts as missing.
    expect(configError({ ...minimal, AAB_VAULT_SOCKET: '  ' }).message).toContain(
      'AAB_VAULT_SOCKET',
    );
  });

  it('refuses to start when a key directory is configured (P3-1), whatever else is wrong', () => {
    const error = configError({ ...minimal, AAB_KEK_DIR: '/var/lib/aab/kek' });
    expect(error.message).toContain('AAB_KEK_DIR');
    expect(error.message).toContain('must not be set');
    expect(error.message).not.toContain('/var/lib/aab/kek');
    // Not hidden behind another problem, and a relative or odd value is refused all the same.
    expect(configError({ AAB_KEK_DIR: 'relative' }).message).toContain('AAB_KEK_DIR');
    // A blank variable is the same as an unset one.
    expect(() => loadWorkerConfig({ ...minimal, AAB_KEK_DIR: '' })).not.toThrow();
  });

  it('rejects bad values without echoing them', () => {
    const error = configError({
      DATABASE_URL: 'mysql://root:hunter2-synthetic@db/aab',
      AAB_VAULT_SOCKET: 'relative/vault.sock',
      AAB_VAULT_ISOLATION: 'neither',
      AAB_VAULT_CALL_TIMEOUT_MS: '5',
      AAB_WORKER_SANDBOX: 'none',
      AAB_WORKER_CONCURRENCY: '0',
      AAB_WORKER_LEASE_MS: 'soon',
      AAB_CHROMIUM_PATH: 'chromium',
      AAB_LOG_LEVEL: 'loud',
    });
    for (const name of [
      'DATABASE_URL',
      'AAB_VAULT_SOCKET',
      'AAB_VAULT_ISOLATION',
      'AAB_VAULT_CALL_TIMEOUT_MS',
      'AAB_WORKER_SANDBOX',
      'AAB_WORKER_CONCURRENCY',
      'AAB_WORKER_LEASE_MS',
      'AAB_CHROMIUM_PATH',
      'AAB_LOG_LEVEL',
    ]) {
      expect(error.message).toContain(name);
    }
    expect(error.message).not.toContain('hunter2-synthetic');
    expect(error.message).not.toContain('relative/vault.sock');
    expect(configError({ ...minimal, AAB_VAULT_SOCKET: 'relative/vault.sock' }).message).toContain(
      'absolute path',
    );
  });
});

describe('lifetime and timeout settings (P3-7, VS-6: no lifetime by accident)', () => {
  // The supervisor reads no capability or token lifetime: the token lifetime it requests is the
  // contract default constant. What it does read are call, lease and result lifetimes; each is a
  // bounded integer and the process refuses to start on a value outside its bounds.
  const bounds = [
    ['AAB_VAULT_CALL_TIMEOUT_MS', 100, 60_000],
    ['AAB_WORKER_LEASE_MS', 5_000, 3_600_000],
    ['AAB_JOB_RESULT_TTL_MINUTES', 1, 10_080],
  ] as const;

  it.each(bounds)(
    'refuses %s when it is zero, negative, fractional, NaN, Infinity or out of range',
    (name, min, max) => {
      for (const value of [
        '0',
        '-1',
        String(-min),
        String(min - 1),
        String(max + 1),
        String(min + 0.5),
        'NaN',
        'Infinity',
        '-Infinity',
        '1e400',
        'soon',
      ]) {
        const error = configError({ ...minimal, [name]: value });
        expect(error.message, `${name}=${value}`).toContain(name);
        if (value === 'soon') expect(error.message).not.toContain(value);
      }
    },
  );

  it.each(bounds)(
    'accepts exactly the bounds of %s, and blank is the default',
    (name, min, max) => {
      expect(() => loadWorkerConfig({ ...minimal, [name]: String(min) })).not.toThrow();
      expect(() => loadWorkerConfig({ ...minimal, [name]: String(max) })).not.toThrow();
      expect(() => loadWorkerConfig({ ...minimal, [name]: '' })).not.toThrow();
    },
  );

  it('has no setting for a capability or token lifetime, and requests an in-bound token lifetime', () => {
    const config = loadWorkerConfig({
      ...minimal,
      AAB_VAULT_AUTHORIZATION_TTL_SECONDS: '99999',
      AAB_VAULT_TOKEN_TTL_SECONDS: '99999',
    });
    expect(JSON.stringify(config)).not.toContain('99999');
    expect(Number.isSafeInteger(DEFAULT_TOKEN_TTL_SECONDS)).toBe(true);
    expect(DEFAULT_TOKEN_TTL_SECONDS).toBeGreaterThanOrEqual(TOKEN_TTL_MIN_SECONDS);
    expect(DEFAULT_TOKEN_TTL_SECONDS).toBeLessThanOrEqual(TOKEN_TTL_MAX_SECONDS);
  });

  it('refuses to start as a process on an out-of-range lease, before opening anything', async () => {
    for (const value of ['0', '-5', 'Infinity']) {
      const result = await run(TSX, ['src/main.ts'], {
        cwd: WORKER_DIR,
        env: {
          PATH: process.env['PATH'] ?? '',
          DATABASE_URL: 'postgres://aab:synthetic-db-password@127.0.0.1:1/aab',
          AAB_VAULT_SOCKET: '/nonexistent/supervisor/vault.sock',
          AAB_WORKER_LEASE_MS: value,
        },
        timeout: 60_000,
      }).catch((error: { code: number; stdout: string; stderr: string }) => error);
      expect((result as { code?: number }).code, value).toBe(1);
      expect(result.stderr).toContain('AAB_WORKER_LEASE_MS');
      expect(result.stderr).not.toContain('synthetic-db-password');
    }
  }, 180_000);
});

describe('logger', () => {
  it('redacts secret-shaped fields and logs only the type of an error', () => {
    const lines: string[] = [];
    const logger = createLogger('info', { write: (line: string) => void lines.push(line) });
    logger.info(
      {
        storageState: { cookies: [{ value: 'redact-me-1' }] },
        job: { arguments: { q: 'redact-me-2' }, result: { a: 'redact-me-3' } },
        err: Object.assign(new Error('params: redact-me-4'), { code: '23505' }),
      },
      'test',
    );
    const text = lines.join('');
    expect(text).not.toMatch(/redact-me/);
    expect(text).toContain('23505');
  });
});

describe('init-kek script', () => {
  it('creates kek-v1.key in a 0700 directory, prints only the path, and refuses to overwrite', async () => {
    const parent = await mkdtemp(path.join(tmpdir(), 'aab-kek-test-'));
    const directory = path.join(parent, 'keys');
    try {
      const first = await run(TSX, ['src/scripts/init-kek.ts', directory], { cwd: WORKER_DIR });
      expect(first.stdout.trim()).toBe(path.join(directory, 'kek-v1.key'));
      expect(first.stderr).toBe('');
      expect((await stat(directory)).mode & 0o777).toBe(0o700);
      expect((await stat(path.join(directory, 'kek-v1.key'))).mode & 0o777).toBe(0o600);

      const second = await run(TSX, ['src/scripts/init-kek.ts', directory], {
        cwd: WORKER_DIR,
      }).catch((error: { code: number; stdout: string; stderr: string }) => error);
      expect((second as { code?: number }).code).toBe(1);
      expect(second.stdout).toBe('');
      expect(second.stderr).toContain('refusing to overwrite');
      expect(await readdir(directory)).toEqual(['kek-v1.key']);
    } finally {
      await rm(parent, { recursive: true, force: true });
    }
  });

  it('requires an absolute directory', async () => {
    const result = await run(TSX, ['src/scripts/init-kek.ts', 'relative'], {
      cwd: WORKER_DIR,
      env: { ...process.env, AAB_KEK_DIR: '' },
    }).catch((error: { code: number; stderr: string }) => error);
    expect((result as { code?: number }).code).toBe(2);
  });
});
