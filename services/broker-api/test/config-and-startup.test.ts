import { execFile, spawn } from 'node:child_process';
import { chmod, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { generateLocalKek } from '@aab/crypto';
import {
  AUTHORIZATION_TTL_MAX_SECONDS,
  AUTHORIZATION_TTL_MIN_SECONDS,
  DEFAULT_AUTHORIZATION_TTL_SECONDS,
} from '@aab/contracts';
import { createTestDatabase } from '@aab/database/testing';
import { afterAll, describe, expect, it, vi } from 'vitest';
import {
  ConfigError,
  LOGIN_AUTHORIZATION_TTL_SECONDS,
  loadConfig,
  requireVaultSocket,
} from '../src/config.js';
import { createOwner, OwnerInputError } from '../src/owner.js';
import { createVaultGateway, VaultStartupRefusal } from '../src/vault/gateway.js';
import { verifyVaultAtStart } from '../src/vault/startup.js';
import { startFakeVault } from './fake-vault.js';
import type { FakeVault } from './fake-vault.js';
import { TEST_SCRYPT } from './helpers.js';

// Tests here start tsx child processes and hash passwords; under load 5 s is not enough.
vi.setConfig({ testTimeout: 30_000 });

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
      vaultSocket: undefined,
      vaultIsolation: 'separate-uid',
      vaultAuthorizationTtlSeconds: 600,
      vaultCallTimeoutMs: 5_000,
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

describe('vault settings', () => {
  it('parses the vault settings and keeps the safe defaults', () => {
    expect(
      loadConfig({
        DATABASE_URL: DB_URL,
        AAB_VAULT_SOCKET: '/run/aab-vault/api/vault.sock',
        AAB_VAULT_ISOLATION: 'shared-uid',
        AAB_VAULT_AUTHORIZATION_TTL_SECONDS: '900',
        AAB_VAULT_CALL_TIMEOUT_MS: '2500',
      }),
    ).toMatchObject({
      vaultSocket: '/run/aab-vault/api/vault.sock',
      vaultIsolation: 'shared-uid',
      vaultAuthorizationTtlSeconds: 900,
      vaultCallTimeoutMs: 2500,
    });
    // Blank is "not set", as everywhere else in this file's schema.
    expect(
      loadConfig({ DATABASE_URL: DB_URL, AAB_VAULT_SOCKET: '', AAB_VAULT_ISOLATION: '' }),
    ).toMatchObject({ vaultSocket: undefined, vaultIsolation: 'separate-uid' });
  });

  it('refuses a missing socket where the vault is required, and bad values, naming only variables', () => {
    expect(() => requireVaultSocket(loadConfig({ DATABASE_URL: DB_URL }))).toThrow(
      /AAB_VAULT_SOCKET: is required/,
    );
    for (const [name, value] of [
      ['AAB_VAULT_SOCKET', 'relative/vault.sock'],
      ['AAB_VAULT_ISOLATION', 'whatever'],
      ['AAB_VAULT_AUTHORIZATION_TTL_SECONDS', '9'],
      ['AAB_VAULT_AUTHORIZATION_TTL_SECONDS', '3601'],
      ['AAB_VAULT_AUTHORIZATION_TTL_SECONDS', '1e2'],
      ['AAB_VAULT_AUTHORIZATION_TTL_SECONDS', '600.5'],
      ['AAB_VAULT_CALL_TIMEOUT_MS', '99'],
      ['AAB_VAULT_CALL_TIMEOUT_MS', 'soon'],
    ] as const) {
      let message = '';
      try {
        loadConfig({ DATABASE_URL: DB_URL, [name]: value });
      } catch (error) {
        message = (error as Error).message;
      }
      expect(message, `${name}=${value}`).toContain(name);
      expect(message).not.toContain(value);
    }
  });
});

describe('the authorization lifetime setting (P3-7, VS-6: no lifetime by accident)', () => {
  const NAME = 'AAB_VAULT_AUTHORIZATION_TTL_SECONDS';
  const load = (value: string | undefined) =>
    loadConfig({ DATABASE_URL: DB_URL, ...(value === undefined ? {} : { [NAME]: value }) });

  it('refuses a lifetime that is not a safe integer inside 10 to 3,600, naming only the variable', () => {
    for (const value of [
      '0',
      '-1',
      '-600',
      '9',
      '3601',
      '1000000',
      '99999999999999999999',
      '600.5',
      '1e2',
      '0x20',
      '+600',
      '0600',
      ' 600',
      '600 ',
      'NaN',
      'Infinity',
      '-Infinity',
      'soon',
    ]) {
      let message = '';
      try {
        load(value);
      } catch (error) {
        expect(error).toBeInstanceOf(ConfigError);
        message = (error as Error).message;
      }
      expect(message, `value ${JSON.stringify(value)} must be refused`).toContain(NAME);
      // Values that are not short numbers must not be echoed back.
      if (value.length > 6) expect(message).not.toContain(value);
    }
  });

  it('accepts exactly the bounds, and an unset or blank setting is the default inside the bounds', () => {
    expect(load('10').vaultAuthorizationTtlSeconds).toBe(AUTHORIZATION_TTL_MIN_SECONDS);
    expect(load('3600').vaultAuthorizationTtlSeconds).toBe(AUTHORIZATION_TTL_MAX_SECONDS);
    // "Missing" is not a refusal here: the owner decision (phase 3, question 6) is a default of 600 s
    // inside the bounds, and the loaded value is always a safe integer inside them.
    for (const value of [undefined, '', '   ']) {
      const seconds = load(value).vaultAuthorizationTtlSeconds;
      expect(seconds).toBe(DEFAULT_AUTHORIZATION_TTL_SECONDS);
      expect(Number.isSafeInteger(seconds)).toBe(true);
      expect(seconds).toBeGreaterThanOrEqual(AUTHORIZATION_TTL_MIN_SECONDS);
      expect(seconds).toBeLessThanOrEqual(AUTHORIZATION_TTL_MAX_SECONDS);
    }
  });

  it('keeps the login lifetime, which is not a setting, inside the bounds', () => {
    expect(Number.isSafeInteger(LOGIN_AUTHORIZATION_TTL_SECONDS)).toBe(true);
    expect(LOGIN_AUTHORIZATION_TTL_SECONDS).toBeGreaterThanOrEqual(AUTHORIZATION_TTL_MIN_SECONDS);
    expect(LOGIN_AUTHORIZATION_TTL_SECONDS).toBeLessThanOrEqual(AUTHORIZATION_TTL_MAX_SECONDS);
  });

  it('refuses to start as a process on an out-of-range lifetime, before any other work', async () => {
    for (const value of ['0', '-5', '3601', 'Infinity']) {
      const result = await run(process.execPath, ['--import', 'tsx', 'src/main.ts'], {
        cwd: SERVICE_DIR,
        env: {
          PATH: process.env.PATH ?? '',
          DATABASE_URL: DB_URL,
          AAB_VAULT_SOCKET: '/nonexistent/api/vault.sock',
          [NAME]: value,
        },
        timeout: 20_000,
      }).catch((error: { code: number; stderr: string }) => error);
      expect((result as { code?: number }).code, value).toBe(1);
      expect(result.stderr).toContain(NAME);
      expect(result.stderr).not.toContain('synthetic-db-password');
    }
  }, 60_000);
});

describe('the start-up hello check (ADR-014 section 3, P3-1)', () => {
  const vaults: FakeVault[] = [];
  const directories: string[] = [];
  afterAll(async () => {
    for (const vault of vaults) await vault.close();
    for (const directory of directories) await rm(directory, { recursive: true, force: true });
  });
  const gatewayFor = async (
    hello: Parameters<typeof startFakeVault>[0] extends infer O
      ? O extends { hello?: infer H }
        ? H
        : never
      : never,
    isolation: 'separate-uid' | 'shared-uid',
  ) => {
    const vault = await startFakeVault({ hello });
    vaults.push(vault);
    return createVaultGateway({ socketPath: vault.socketPath, isolation, timeoutMs: 500 });
  };

  it('accepts an api-role vault whose key directory this user cannot open', async () => {
    const gateway = await gatewayFor(
      { isolation: 'separate-uid', keyDirectory: '/nonexistent/aab-keys' },
      'separate-uid',
    );
    expect(await verifyVaultAtStart(gateway)).toEqual({ state: 'ready' });
    expect(gateway.state()).toBe('ready');
  });

  it("refuses to start when the vault's key directory is readable", async () => {
    const directory = await mkdtemp(join(tmpdir(), 'aab-readable-keys-'));
    directories.push(directory);
    const gateway = await gatewayFor(
      { isolation: 'separate-uid', keyDirectory: directory },
      'separate-uid',
    );
    await expect(verifyVaultAtStart(gateway)).rejects.toBeInstanceOf(VaultStartupRefusal);
    await expect(verifyVaultAtStart(gateway)).rejects.toThrow(directory);
    expect(gateway.state()).toBe('refused');
    // A refused vault is never used afterwards, whatever it would answer.
    await expect(
      gateway.authorizeJobAccess('8a1b6f5e-3c47-4b0e-9d52-0f1c2e3d4a5b', 600),
    ).rejects.toBeInstanceOf(VaultStartupRefusal);
  });

  it('starts with a readable key directory only in the explicit shared-uid mode', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'aab-readable-keys-'));
    directories.push(directory);
    const gateway = await gatewayFor(
      { isolation: 'shared-uid', keyDirectory: directory },
      'shared-uid',
    );
    expect(await verifyVaultAtStart(gateway)).toEqual({ state: 'ready' });
  });

  it('refuses a vault that answers as another role', async () => {
    for (const role of ['supervisor', 'admin']) {
      const gateway = await gatewayFor({ role }, 'shared-uid');
      await expect(verifyVaultAtStart(gateway)).rejects.toThrow(/other than api/);
    }
  });

  it('refuses a vault whose isolation mode differs from the configured one', async () => {
    const gateway = await gatewayFor({ isolation: 'shared-uid' }, 'separate-uid');
    await expect(verifyVaultAtStart(gateway)).rejects.toThrow(/AAB_VAULT_ISOLATION/);
  });

  it('starts degraded when the vault does not answer, and never authorizes through an unchecked vault', async () => {
    const gateway = createVaultGateway({
      socketPath: '/nonexistent/aab-vault/api/vault.sock',
      isolation: 'separate-uid',
      timeoutMs: 300,
    });
    expect(await verifyVaultAtStart(gateway)).toEqual({
      state: 'unreachable',
      code: 'unreachable',
    });
    expect(gateway.state()).toBe('unverified');
    await expect(
      gateway.authorizeJobAccess('8a1b6f5e-3c47-4b0e-9d52-0f1c2e3d4a5b', 600),
    ).rejects.toMatchObject({ kind: 'unavailable' });

    // A vault that answers wrongly on the first hello is a refusal, even when it came up late.
    const late = await startFakeVault({ hello: { role: 'admin' } });
    vaults.push(late);
    const lateGateway = createVaultGateway({
      socketPath: late.socketPath,
      isolation: 'shared-uid',
      timeoutMs: 300,
    });
    await expect(
      lateGateway.authorizeJobAccess('8a1b6f5e-3c47-4b0e-9d52-0f1c2e3d4a5b', 600),
    ).rejects.toBeInstanceOf(VaultStartupRefusal);
    expect(late.requests.map((request) => request.operation)).toEqual(['hello']);
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

  it('refuses to start without AAB_VAULT_SOCKET', async () => {
    const result = await start({ DATABASE_URL: DB_URL });
    expect(result.code).toBe(1);
    expect(result.stderr).toContain('AAB_VAULT_SOCKET: is required');
    expect(result.stderr).not.toContain('synthetic-db-password');
  }, 30_000);

  it("refuses to start when the vault's key directory is readable", async () => {
    const keys = await mkdtemp(join(tmpdir(), 'aab-readable-keys-'));
    directories.push(keys);
    const vault = await startFakeVault({
      hello: { isolation: 'separate-uid', keyDirectory: keys },
    });
    try {
      const result = await start({
        DATABASE_URL: DB_URL,
        AAB_VAULT_SOCKET: vault.socketPath,
        AAB_VAULT_ISOLATION: 'separate-uid',
      });
      expect(result.code).toBe(1);
      expect(result.stderr).toContain("the API can open the vault's key directory");
      expect(result.stderr).toContain(keys);
      expect(result.stderr).not.toContain('synthetic-db-password');
    } finally {
      await vault.close();
    }
  }, 30_000);

  it('refuses to start when the vault answers as the wrong role', async () => {
    const vault = await startFakeVault({ hello: { role: 'supervisor', isolation: 'shared-uid' } });
    try {
      const result = await start({
        DATABASE_URL: DB_URL,
        AAB_VAULT_SOCKET: vault.socketPath,
        AAB_VAULT_ISOLATION: 'shared-uid',
      });
      expect(result.code).toBe(1);
      expect(result.stderr).toContain('role other than api');
    } finally {
      await vault.close();
    }
  }, 30_000);

  it('starts degraded, and says so, when the vault does not answer', async () => {
    const child = spawn(process.execPath, ['--import', 'tsx', 'src/main.ts'], {
      cwd: SERVICE_DIR,
      env: {
        PATH: process.env.PATH ?? '',
        DATABASE_URL: DB_URL,
        AAB_VAULT_SOCKET: '/nonexistent/aab-vault/api/vault.sock',
        AAB_PORT: String(40_000 + (process.pid % 20_000)),
        AAB_VAULT_ISOLATION: 'shared-uid',
        AAB_VAULT_CALL_TIMEOUT_MS: '500',
      },
    });
    let output = '';
    child.stdout.on('data', (chunk: Buffer) => (output += chunk.toString('utf8')));
    child.stderr.on('data', (chunk: Buffer) => (output += chunk.toString('utf8')));
    try {
      const deadline = Date.now() + 15_000;
      while (!output.includes('starting degraded') && Date.now() < deadline) {
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
      expect(output).toContain('starting degraded');
      expect(child.exitCode).toBeNull();
    } finally {
      child.kill('SIGTERM');
      await new Promise((resolve) => child.once('exit', resolve));
    }
  }, 40_000);
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
  }, 60_000);
});
