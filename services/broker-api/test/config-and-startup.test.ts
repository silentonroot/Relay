import { execFile } from 'node:child_process';
import { chmod, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { generateLocalKek } from '@aab/crypto';
import { createTestDatabase } from '@aab/database/testing';
import { afterAll, describe, expect, it } from 'vitest';
import { ConfigError, loadConfig } from '../src/config.js';
import { createOwner, OwnerInputError } from '../src/owner.js';
import { TEST_SCRYPT } from './helpers.js';

const run = promisify(execFile);
const SERVICE_DIR = fileURLToPath(new URL('..', import.meta.url));
const DB_URL = 'postgres://aab:synthetic-db-password@127.0.0.1:1/aab';

describe('loadConfig', () => {
  it('applies the documented defaults', () => {
    expect(loadConfig({ DATABASE_URL: DB_URL, AAB_KEK_DIR: '' })).toEqual({
      databaseUrl: DB_URL,
      host: '127.0.0.1',
      port: 4000,
      kekDir: undefined,
      sessionTtlMinutes: 480,
      cookieSecure: true,
      logLevel: 'info',
      trustProxy: false,
      passwordConcurrency: 2,
      passwordQueueLimit: 8,
      jobWaitMs: 20_000,
    });
  });

  it('validates AAB_JOB_WAIT_MS', () => {
    expect(loadConfig({ DATABASE_URL: DB_URL, AAB_JOB_WAIT_MS: '5' }).jobWaitMs).toBe(5);
    expect(loadConfig({ DATABASE_URL: DB_URL, AAB_JOB_WAIT_MS: '0' }).jobWaitMs).toBe(0);
    for (const value of ['-1', '120001', 'soon', '1.5']) {
      expect(() => loadConfig({ DATABASE_URL: DB_URL, AAB_JOB_WAIT_MS: value })).toThrow(
        'AAB_JOB_WAIT_MS',
      );
    }
  });

  it('validates the password limiter settings (F-5)', () => {
    expect(
      loadConfig({
        DATABASE_URL: DB_URL,
        AAB_PASSWORD_CONCURRENCY: '1',
        AAB_PASSWORD_QUEUE_LIMIT: '0',
      }),
    ).toMatchObject({ passwordConcurrency: 1, passwordQueueLimit: 0 });
    for (const [name, value] of [
      ['AAB_PASSWORD_CONCURRENCY', '0'],
      ['AAB_PASSWORD_CONCURRENCY', '64'],
      ['AAB_PASSWORD_CONCURRENCY', 'two'],
      ['AAB_PASSWORD_QUEUE_LIMIT', '-1'],
      ['AAB_PASSWORD_QUEUE_LIMIT', '1000'],
    ] as const) {
      expect(() => loadConfig({ DATABASE_URL: DB_URL, [name]: value })).toThrow(name);
    }
  });

  it('parses explicit values', () => {
    const config = loadConfig({
      DATABASE_URL: DB_URL,
      AAB_HOST: '0.0.0.0',
      AAB_PORT: '8081',
      AAB_KEK_DIR: '/run/aab/keys',
      AAB_SESSION_TTL_MINUTES: '30',
      AAB_COOKIE_SECURE: 'false',
      AAB_LOG_LEVEL: 'warn',
      AAB_TRUST_PROXY: 'true',
    });
    expect(config).toMatchObject({
      port: 8081,
      kekDir: '/run/aab/keys',
      sessionTtlMinutes: 30,
      cookieSecure: false,
      logLevel: 'warn',
      trustProxy: true,
    });
  });

  it('fails with variable names and never the values', () => {
    let error: unknown;
    try {
      loadConfig({
        DATABASE_URL: 'mysql://root:synthetic-db-password@db/aab',
        AAB_PORT: '99999',
        AAB_COOKIE_SECURE: 'yes',
        AAB_KEK_DIR: 'relative/keys',
        AAB_LOG_LEVEL: 'loud',
      });
    } catch (caught) {
      error = caught;
    }
    expect(error).toBeInstanceOf(ConfigError);
    const message = (error as Error).message;
    for (const name of [
      'DATABASE_URL',
      'AAB_PORT',
      'AAB_COOKIE_SECURE',
      'AAB_KEK_DIR',
      'AAB_LOG_LEVEL',
    ]) {
      expect(message).toContain(name);
    }
    expect(message).not.toContain('synthetic-db-password');
    expect(message).not.toContain('relative/keys');
    expect(() => loadConfig({})).toThrow(/DATABASE_URL: is required/);
  });
});

describe('main.ts startup', () => {
  const directories: string[] = [];
  afterAll(async () => {
    for (const directory of directories) await rm(directory, { recursive: true, force: true });
  });

  const start = async (env: Record<string, string>) => {
    try {
      await run(process.execPath, ['--import', 'tsx', 'src/main.ts'], {
        cwd: SERVICE_DIR,
        env: { PATH: process.env.PATH ?? '', ...env },
        timeout: 20_000,
      });
      return { code: 0, stderr: '' };
    } catch (error) {
      const failed = error as { code: number; stderr: string };
      return { code: failed.code, stderr: failed.stderr };
    }
  };

  it('fails fast with a clear message when DATABASE_URL is missing', async () => {
    const result = await start({});
    expect(result.code).toBe(1);
    expect(result.stderr).toContain('DATABASE_URL: is required');
  });

  it('refuses to start when a key directory is configured, without opening it', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'aab-kek-'));
    directories.push(directory);
    await chmod(directory, 0o700);
    await generateLocalKek(directory, 1);
    const result = await start({ DATABASE_URL: DB_URL, AAB_KEK_DIR: directory });
    expect(result.code).toBe(1);
    expect(result.stderr).toContain('AAB_KEK_DIR must not be set for the API');
    expect(result.stderr).not.toContain(directory);
    expect(result.stderr).not.toContain('synthetic-db-password');
  });
});

describe('createOwner (the create-owner command)', () => {
  it('creates the first owner and refuses once any user exists', async () => {
    const database = await createTestDatabase();
    try {
      const hashOptions = { params: TEST_SCRYPT };
      await expect(
        createOwner(database.db, { email: 'owner@example.test', password: 'short', hashOptions }),
      ).rejects.toThrow(/at least 12 characters/);
      await expect(
        createOwner(database.db, {
          email: 'not-an-email',
          password: 'long enough password',
          hashOptions,
        }),
      ).rejects.toBeInstanceOf(OwnerInputError);

      const created = await createOwner(database.db, {
        email: 'Owner@Example.test',
        password: 'long enough password',
        hashOptions,
      });
      expect(created.user.email).toBe('owner@example.test');
      expect(created.membership.role).toBe('owner');

      await expect(
        createOwner(database.db, {
          email: 'second@example.test',
          password: 'another long password',
          hashOptions,
        }),
      ).rejects.toThrow(/a user already exists/);
    } finally {
      await database.close();
    }
  });
});
