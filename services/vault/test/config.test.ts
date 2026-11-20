import { describe, expect, it } from 'vitest';
import { ConfigError, loadVaultConfig } from '../src/config.js';

const GOOD = {
  DATABASE_URL: 'postgres://aab:hunter2-secret@localhost:5432/aab',
  AAB_KEK_DIR: '/var/lib/aab-vault/keys',
  AAB_VAULT_SOCKET_DIR: '/run/aab-vault',
  AAB_VAULT_GROUP_API: 'aab-vault-api',
  AAB_VAULT_GROUP_SUPERVISOR: 'aab-vault-supervisor',
  AAB_VAULT_GROUP_ADMIN: 'aab-vault-admin',
};

function issues(env: Record<string, string | undefined>): string {
  try {
    loadVaultConfig(env);
  } catch (error) {
    expect(error).toBeInstanceOf(ConfigError);
    return (error as ConfigError).message;
  }
  throw new Error('expected a ConfigError');
}

describe('vault configuration', () => {
  it('defaults to separate-uid and the ADR-014 lifetimes', () => {
    const config = loadVaultConfig(GOOD);
    expect(config.isolation).toBe('separate-uid');
    expect('authorizationTtlSeconds' in config).toBe(false);
    expect(config.tokenTtlSeconds).toBe(30);
    expect(config.roleGroups).toEqual({
      api: 'aab-vault-api',
      supervisor: 'aab-vault-supervisor',
      admin: 'aab-vault-admin',
    });
  });

  it('accepts shared-uid only when set explicitly, and then takes no role groups', () => {
    const base = {
      DATABASE_URL: GOOD.DATABASE_URL,
      AAB_KEK_DIR: GOOD.AAB_KEK_DIR,
      AAB_VAULT_SOCKET_DIR: GOOD.AAB_VAULT_SOCKET_DIR,
      AAB_VAULT_ISOLATION: 'shared-uid',
    };
    expect(loadVaultConfig(base).isolation).toBe('shared-uid');
    expect(issues({ ...base, AAB_VAULT_GROUP_API: 'aab-vault-api' })).toContain(
      'AAB_VAULT_GROUP_*: must not be set when AAB_VAULT_ISOLATION=shared-uid',
    );
  });

  it.each([
    ['DATABASE_URL', undefined, 'DATABASE_URL: is required'],
    ['DATABASE_URL', '', 'DATABASE_URL'],
    ['DATABASE_URL', 'mysql://x', 'DATABASE_URL: expected a postgres'],
    ['AAB_KEK_DIR', undefined, 'AAB_KEK_DIR: is required'],
    ['AAB_KEK_DIR', 'relative/keys', 'AAB_KEK_DIR: expected an absolute path'],
    ['AAB_KEK_DIR', '/a/../b', 'AAB_KEK_DIR: expected a normalized path'],
    ['AAB_VAULT_SOCKET_DIR', undefined, 'AAB_VAULT_SOCKET_DIR: is required'],
    ['AAB_VAULT_SOCKET_DIR', 'run/aab', 'AAB_VAULT_SOCKET_DIR: expected an absolute path'],
    ['AAB_VAULT_SOCKET_DIR', '/run/aab/', 'AAB_VAULT_SOCKET_DIR: expected a normalized path'],
    ['AAB_VAULT_SOCKET_DIR', '/run/./aab', 'AAB_VAULT_SOCKET_DIR: expected a normalized path'],
    ['AAB_VAULT_ISOLATION', 'none', 'AAB_VAULT_ISOLATION: expected "separate-uid" or "shared-uid"'],
    ['AAB_VAULT_ISOLATION', 'Shared-UID', 'AAB_VAULT_ISOLATION'],
    ['AAB_VAULT_GROUP_API', 'Bad Group!', 'AAB_VAULT_GROUP_API: expected a group name'],
    ['AAB_VAULT_GROUP_API', '99999999999', 'AAB_VAULT_GROUP_API'],
    ['AAB_VAULT_GROUP_API', undefined, 'AAB_VAULT_GROUP_API: is required'],
    ['AAB_VAULT_GROUP_ADMIN', undefined, 'AAB_VAULT_GROUP_ADMIN: is required'],
    ['AAB_VAULT_GROUP_SUPERVISOR', 'aab-vault-api', 'each role needs its own group'],
    ['AAB_LOG_LEVEL', 'verbose', 'AAB_LOG_LEVEL'],
  ])('refuses %s=%j', (name, value, expected) => {
    expect(issues({ ...GOOD, [name]: value })).toContain(expected);
  });

  it('ignores AAB_VAULT_AUTHORIZATION_TTL_SECONDS: the API owns that lifetime, the vault never used it', () => {
    for (const value of ['4321', '99999', 'nonsense']) {
      const config = loadVaultConfig({ ...GOOD, AAB_VAULT_AUTHORIZATION_TTL_SECONDS: value });
      expect(JSON.stringify(config)).not.toContain(value);
    }
  });

  describe('lifetimes (P3-7: no lifetime by accident)', () => {
    const cases: Array<[string, string, number, number]> = [
      ['AAB_VAULT_TOKEN_TTL_SECONDS', 'token', 1, 120],
    ];
    for (const [name, label, min, max] of cases) {
      it(`refuses every ${label} lifetime that is blank, out of range or not a plain integer`, () => {
        const bad = [
          '',
          ' ',
          String(min - 1),
          String(max + 1),
          '-1',
          '0',
          '1.5',
          '1e2',
          '0x10',
          ' 30',
          '30 ',
          '+30',
          'NaN',
          'Infinity',
          '030',
          '9007199254740993',
          '99999999999999999999',
          'thirty',
        ];
        for (const value of bad) {
          expect(issues({ ...GOOD, [name]: value }), `${name}=${JSON.stringify(value)}`).toContain(
            name,
          );
        }
      });

      it(`accepts the ${label} bounds ${min} and ${max}`, () => {
        for (const value of [min, max]) {
          const config = loadVaultConfig({ ...GOOD, [name]: String(value) });
          expect(config.tokenTtlSeconds).toBe(value);
        }
      });
    }
  });

  it('reports every problem at once and never echoes a value', () => {
    const message = issues({
      DATABASE_URL: 'mysql://aab:hunter2-secret@db/aab',
      AAB_KEK_DIR: 'relative-secret-dir',
      AAB_VAULT_SOCKET_DIR: undefined,
      AAB_VAULT_ISOLATION: 'secret-mode',
      AAB_VAULT_TOKEN_TTL_SECONDS: '99999',
    });
    for (const name of [
      'DATABASE_URL',
      'AAB_KEK_DIR',
      'AAB_VAULT_SOCKET_DIR',
      'AAB_VAULT_ISOLATION',
      'AAB_VAULT_TOKEN_TTL_SECONDS',
    ]) {
      expect(message).toContain(name);
    }
    for (const leaked of ['hunter2', 'relative-secret-dir', 'secret-mode', '99999']) {
      expect(message).not.toContain(leaked);
    }
  });
});

describe('admin request timeout (B2 review fix 3)', () => {
  it('defaults to 120 s, separate from the 10 s request timeout, and is bounded', () => {
    const config = loadVaultConfig(GOOD);
    expect(config.requestTimeoutMs).toBe(10_000);
    expect(config.adminRequestTimeoutMs).toBe(120_000);
    expect(
      loadVaultConfig({ ...GOOD, AAB_VAULT_ADMIN_REQUEST_TIMEOUT_MS: '30000' })
        .adminRequestTimeoutMs,
    ).toBe(30_000);
    for (const bad of ['999', '600001', '1e4', '', ' 5000']) {
      expect(issues({ ...GOOD, AAB_VAULT_ADMIN_REQUEST_TIMEOUT_MS: bad })).toContain(
        'AAB_VAULT_ADMIN_REQUEST_TIMEOUT_MS',
      );
    }
  });
});
