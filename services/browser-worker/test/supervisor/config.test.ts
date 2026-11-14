import { execFile } from 'node:child_process';
import { mkdtemp, readdir, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { describe, expect, it } from 'vitest';
import { ConfigError, loadWorkerConfig } from '../../src/config.js';
import { createLogger } from '../../src/logging.js';

const run = promisify(execFile);
const here = path.dirname(fileURLToPath(import.meta.url));
const WORKER_DIR = path.resolve(here, '..', '..');
const TSX = path.resolve(WORKER_DIR, '..', '..', 'node_modules', '.bin', 'tsx');

const minimal = {
  DATABASE_URL: 'postgres://aab:synthetic-db-password@127.0.0.1:5432/aab',
  AAB_KEK_DIR: '/var/lib/aab/kek',
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
  it('applies defaults', () => {
    expect(loadWorkerConfig(minimal)).toEqual({
      databaseUrl: minimal.DATABASE_URL,
      kekDir: '/var/lib/aab/kek',
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
    });
    expect(config).toMatchObject({
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
    expect(error.message).toContain('AAB_KEK_DIR');
    // Blank counts as missing.
    expect(configError({ ...minimal, AAB_KEK_DIR: '  ' }).message).toContain('AAB_KEK_DIR');
  });

  it('rejects bad values without echoing them', () => {
    const error = configError({
      DATABASE_URL: 'mysql://root:hunter2-synthetic@db/aab',
      AAB_KEK_DIR: 'relative/kek',
      AAB_WORKER_SANDBOX: 'none',
      AAB_WORKER_CONCURRENCY: '0',
      AAB_WORKER_LEASE_MS: 'soon',
      AAB_CHROMIUM_PATH: 'chromium',
      AAB_LOG_LEVEL: 'loud',
    });
    for (const name of [
      'DATABASE_URL',
      'AAB_KEK_DIR',
      'AAB_WORKER_SANDBOX',
      'AAB_WORKER_CONCURRENCY',
      'AAB_WORKER_LEASE_MS',
      'AAB_CHROMIUM_PATH',
      'AAB_LOG_LEVEL',
    ]) {
      expect(error.message).toContain(name);
    }
    expect(error.message).not.toContain('hunter2-synthetic');
    expect(error.message).not.toContain('relative/kek');
    expect(configError({ ...minimal, AAB_KEK_DIR: 'relative/kek' }).message).toContain(
      'absolute path',
    );
  });
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
