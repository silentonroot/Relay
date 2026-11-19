import { afterEach, describe, expect, it } from 'vitest';
import { createLogger, isSensitiveKey, redactLogObject } from '../src/logging.js';
import { call, LogCapture, startTestVault } from './helpers.js';
import type { Harness } from './helpers.js';

/** Secret-shaped values: if any of these reaches the output the redactor failed (P3-15). */
const SECRETS = {
  token: 'tok-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  mac: 'mac-0123456789abcdef0123456789abcdef',
  hash: 'hash-fedcba9876543210fedcba9876543210',
  kek: 'kek-bytes-do-not-print',
  plaintext: 'plaintext-session-cookie-value',
  storageState: '{"cookies":[{"name":"sid","value":"cookie-secret-value"}]}',
  wrappedDek: 'wrapped-dek-bytes',
  databaseUrl: 'postgres://aab:db-password-secret@db/aab',
};

function allSecretValues(): string[] {
  return [
    ...Object.values(SECRETS),
    'cookie-secret-value',
    'nested-secret-1',
    'nested-secret-2',
    'deep-secret',
    'array-secret',
    'buffer-secret',
    'upper-secret',
  ];
}

describe('log redaction (P3-15, logging part)', () => {
  it('removes secret-shaped fields at the top level, nested, in arrays and in any letter case', () => {
    const capture = new LogCapture();
    const logger = createLogger('trace', capture);
    logger.info(
      {
        ...SECRETS,
        token_hash: 'nested-secret-1',
        tokenMac: 'nested-secret-2',
        authorizationMac: 'nested-secret-2',
        TOKEN: 'upper-secret',
        capability: { token: 'nested-secret-1', deeper: { kek: 'deep-secret' } },
        list: [{ plaintext: 'array-secret' }, { ok: 1 }],
        bytes: Buffer.from('buffer-secret'),
        params: { token: 'nested-secret-2' },
        result: { plaintext: 'nested-secret-1' },
        jobId: 'visible-job',
        role: 'api',
        kekVersion: 3,
        keyDirectory: '/var/lib/aab/keys',
      },
      'a message',
    );
    logger.child({ token: 'nested-secret-2', plaintext: 'nested-secret-1' }).warn('child binding');
    const text = capture.text();
    for (const secret of allSecretValues()) expect(text, secret).not.toContain(secret);
    const first = JSON.parse(capture.lines[0] ?? '{}') as Record<string, unknown>;
    expect(first['jobId']).toBe('visible-job');
    expect(first['role']).toBe('api');
    expect(first['kekVersion']).toBe(3);
    expect(first['keyDirectory']).toBe('/var/lib/aab/keys');
    expect(first['token']).toBe('[REDACTED]');
    expect(first['storageState']).toBe('[REDACTED]');
  });

  it('logs only the type and code of an error object, never its message or stack', () => {
    const capture = new LogCapture();
    const logger = createLogger('trace', capture);
    const error = Object.assign(new Error('connection to postgres://u:pw@h failed token=abc'), {
      code: '28P01',
    });
    logger.error({ err: error }, 'failed');
    const text = capture.text();
    expect(text).not.toContain('postgres://');
    expect(text).not.toContain('token=abc');
    expect(text).not.toContain('stack');
    expect(text).toContain('28P01');
  });

  it('classifies keys', () => {
    for (const key of [
      'token',
      'Token',
      'tokenHash',
      'token_hash',
      'authorizationMac',
      'mac',
      'hash',
      'argumentsHash',
      'kek',
      'wrappedDek',
      'plaintext',
      'storageState',
      'cookies',
      'password',
      'databaseUrl',
      'params',
    ]) {
      expect(isSensitiveKey(key), key).toBe(true);
    }
    for (const key of [
      'jobId',
      'role',
      'operation',
      'kekVersion',
      'keyDirectory',
      'isolation',
      'requestId',
    ]) {
      expect(isSensitiveKey(key), key).toBe(false);
    }
  });

  it('does not mutate the object it was given and survives cycles by depth', () => {
    const input: Record<string, unknown> = { token: 'x', jobId: 'j' };
    input['self'] = input;
    const out = redactLogObject(input) as Record<string, unknown>;
    expect(input['token']).toBe('x');
    expect(out['token']).toBe('[REDACTED]');
    expect(JSON.stringify(out)).toContain('[REDACTED]');
  });

  describe('through a running vault', () => {
    let harness: Harness;
    afterEach(async () => {
      await harness.cleanup();
    });

    it('logs no request value for refused, malformed, failing and not-implemented requests', async () => {
      harness = await startTestVault();
      const secret = 'S3cr3t-request-value-ABCDEFGHIJKLMNOPQRSTUV';
      const token = 'T'.repeat(43);
      const bodies: Array<[string, Record<string, unknown>]> = [
        ['api', { id: 'a1', operation: 'readForWorker', params: { token: secret } }],
        ['supervisor', { id: 'a2', operation: 'readForWorker', params: { token: secret } }],
        [
          'supervisor',
          {
            id: 'a3',
            operation: 'completeLogin',
            params: {
              token,
              jobId: '3f1c2b0e-8a54-4a52-9d57-0e1c2d3e4f50',
              connectionId: '3f1c2b0e-8a54-4a52-9d57-0e1c2d3e4f50',
              plaintext: 'cGxhaW50ZXh0LXNlc3Npb24',
              externalAccountHint: null,
              sessionExpiresAt: null,
            },
          },
        ],
        ['api', { id: 'a4', operation: 'hello', params: { protocolVersion: 1 }, role: secret }],
        ['admin', { id: 'a5', operation: secret, params: {} }],
      ];
      for (const [role, body] of bodies) {
        await call(harness.vault.sockets[role as 'api'], body);
      }
      const text = harness.log.text();
      for (const value of [secret, token, 'cGxhaW50ZXh0LXNlc3Npb24']) {
        expect(text).not.toContain(value);
      }
      expect(text).toContain('vault.request_refused');
    });
  });
});
