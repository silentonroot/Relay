import { canonicalJson, JsonObject } from '@aab/contracts';
import { describe, expect, it } from 'vitest';
import {
  isSecretKeyName,
  MAX_ARRAY_LENGTH,
  MAX_DEPTH,
  MAX_OBJECT_KEYS,
  MAX_STRING_LENGTH,
  REDACTED,
  redactMetadata,
} from '../src/index.js';

// Obviously fake values. Nothing here is a real credential.
const FAKE = 'synthetic-not-a-real-secret';

describe('isSecretKeyName', () => {
  it.each([
    'password',
    'Password',
    'userPassword',
    'passwd',
    'pwd',
    'passphrase',
    'secret',
    'clientSecret',
    'client_secret',
    'token',
    'accessToken',
    'refresh_token',
    'csrfToken',
    'cookie',
    'Cookie',
    'cookies',
    'set-cookie',
    'Set-Cookie',
    'authorization',
    'Authorization',
    'proxy-authorization',
    'apiKey',
    'api_key',
    'api-key',
    'API KEY',
    'x-api-key',
    'sessionId',
    'session_id',
    'session-id',
    'sid',
    'session',
    'credential',
    'credentials',
    'privateKey',
    'private_key',
    'PRIVATE-KEY',
    'dek',
    'wrappedDek',
    'wrapped_dek',
    'kek',
    'kekMaterial',
    'storageState',
    'jwt',
    'otp',
    'auth',
  ])('treats %s as secret-bearing', (key) => {
    expect(isSecretKeyName(key)).toBe(true);
  });

  it.each([
    'displayName',
    'operation',
    'status',
    'reason',
    'connectionId',
    'authModes',
    'sessionExpiresAt',
    'deck',
    'index',
    'keyVersion',
    'allowedOrigins',
    'from',
    'to',
  ])('keeps %s', (key) => {
    expect(isSecretKeyName(key)).toBe(false);
  });
});

describe('redactMetadata', () => {
  it('passes ordinary metadata through unchanged', () => {
    const input = { operation: 'orders.list', limit: 25, ok: true, note: null, tags: ['a', 'b'] };
    expect(redactMetadata(input)).toEqual(input);
  });

  it('redacts top-level secrets whatever the value type', () => {
    expect(
      redactMetadata({
        password: FAKE,
        token: { value: FAKE },
        cookies: [FAKE],
        apiKey: 12345,
        kept: 'yes',
      }),
    ).toEqual({
      password: REDACTED,
      token: REDACTED,
      cookies: REDACTED,
      apiKey: REDACTED,
      kept: 'yes',
    });
  });

  it('redacts secrets nested in objects and in arrays of objects', () => {
    const output = redactMetadata({
      request: {
        headers: { Authorization: `Bearer ${FAKE}`, 'Set-Cookie': FAKE, accept: 'text/html' },
      },
      attempts: [
        { index: 0, session_id: FAKE },
        { index: 1, nested: [{ refreshToken: FAKE }, { fine: 'value' }] },
      ],
    });
    expect(output).toEqual({
      request: {
        headers: { Authorization: REDACTED, 'Set-Cookie': REDACTED, accept: 'text/html' },
      },
      attempts: [
        { index: 0, session_id: REDACTED },
        { index: 1, nested: [{ refreshToken: REDACTED }, { fine: 'value' }] },
      ],
    });
    expect(JSON.stringify(output)).not.toContain(FAKE);
  });

  it('scrubs credential-shaped strings stored under innocuous keys', () => {
    // gitleaks:allow (synthetic unsigned token; the payload is {"sub":"synthetic"})
    const jwt = 'eyJhbGciOiJub25lIn0.eyJzdWIiOiJzeW50aGV0aWMifQ.c3ludGhldGlj'; // gitleaks:allow
    const output = redactMetadata({
      note: `request failed with header Bearer ${FAKE}`,
      detail: `id token ${jwt} rejected`,
      list: [`Basic c3ludGhldGljOnN5bnRoZXRpYw==`],
    });
    const serialized = JSON.stringify(output);
    expect(serialized).not.toContain(FAKE);
    expect(serialized).not.toContain(jwt);
    expect(serialized).not.toContain('c3ludGhldGljOnN5bnRoZXRpYw');
    expect(output.note).toBe(`request failed with header ${REDACTED}`);
  });

  it('does not mutate its input', () => {
    const input = {
      password: FAKE,
      nested: { token: FAKE, list: [{ secret: FAKE }, 'x'.repeat(MAX_STRING_LENGTH + 50)] },
    };
    const snapshot = structuredClone(input);
    const output = redactMetadata(input);
    expect(input).toEqual(snapshot);
    expect(output).not.toBe(input);
    expect(output.nested).not.toBe(input.nested);
  });

  it('truncates long strings and says how much was dropped', () => {
    const output = redactMetadata({ html: 'x'.repeat(MAX_STRING_LENGTH + 123) });
    expect(output.html).toBe(`${'x'.repeat(MAX_STRING_LENGTH)}…[truncated 123 chars]`);
  });

  it('caps array length', () => {
    const output = redactMetadata({
      items: Array.from({ length: MAX_ARRAY_LENGTH + 7 }, (_, i) => i),
    });
    const items = output.items as unknown[];
    expect(items).toHaveLength(MAX_ARRAY_LENGTH + 1);
    expect(items.at(-1)).toBe('[TRUNCATED: 7 more items]');
  });

  it('caps object width', () => {
    const wide = Object.fromEntries(
      Array.from({ length: MAX_OBJECT_KEYS + 5 }, (_, i) => [`k${i}`, i]),
    );
    const output = redactMetadata(wide);
    expect(Object.keys(output)).toHaveLength(MAX_OBJECT_KEYS + 1);
    expect(output['[TRUNCATED]']).toBe('5 more keys');
  });

  it('caps nesting depth', () => {
    let deep: Record<string, unknown> = { leaf: 'bottom', password: FAKE };
    for (let i = 0; i < MAX_DEPTH + 5; i += 1) deep = { child: deep };
    const serialized = JSON.stringify(redactMetadata(deep));
    expect(serialized).toContain('[TRUNCATED: depth]');
    expect(serialized).not.toContain('bottom');
    expect(serialized).not.toContain(FAKE);
  });

  it('survives cycles', () => {
    const cyclic: Record<string, unknown> = { name: 'loop' };
    cyclic.self = cyclic;
    cyclic.list = [cyclic];
    expect(redactMetadata(cyclic)).toEqual({
      name: 'loop',
      self: '[CIRCULAR]',
      list: ['[CIRCULAR]'],
    });
  });

  it('normalizes values that are not JSON', () => {
    class Custom {
      secretField = FAKE;
    }
    const output = redactMetadata({
      missing: undefined,
      fn: () => FAKE,
      when: new Date('2026-11-11T00:00:00.000Z'),
      badDate: new Date(Number.NaN),
      big: 10n,
      nan: Number.NaN,
      inf: Number.POSITIVE_INFINITY,
      map: new Map([['k', FAKE]]),
      instance: new Custom(),
      list: [undefined, () => 1],
    });
    expect(output).toEqual({
      when: '2026-11-11T00:00:00.000Z',
      badDate: null,
      big: '10',
      nan: null,
      inf: null,
      map: '[UNSERIALIZABLE]',
      instance: '[UNSERIALIZABLE]',
      list: [null, '[UNSERIALIZABLE]'],
    });
    expect(JSON.stringify(output)).not.toContain(FAKE);
  });

  it('removes characters jsonb cannot store', () => {
    const output = redactMetadata({ 'ke\u0000y': 'a\u0000b', lone: 'x\ud800y' });
    expect(output).toEqual({ key: 'ab', lone: 'x�y' });
  });

  it('keeps a hostile __proto__ key as plain data', () => {
    const input = JSON.parse('{"__proto__": {"polluted": true}, "ok": 1}') as unknown;
    const output = redactMetadata(input);
    expect(Object.getPrototypeOf(output)).toBe(Object.prototype);
    expect(Object.keys(output).sort()).toEqual(['__proto__', 'ok']);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });

  it('wraps non-object input and maps undefined to an empty object', () => {
    expect(redactMetadata('plain')).toEqual({ value: 'plain' });
    expect(redactMetadata([{ password: FAKE }])).toEqual({ value: [{ password: REDACTED }] });
    expect(redactMetadata(null)).toEqual({ value: null });
    expect(redactMetadata(undefined)).toEqual({});
  });

  it('always produces canonicalizable JSON that satisfies the contracts schema', () => {
    const output = redactMetadata({
      a: new Date(0),
      b: [1n, undefined, { c: Symbol('s'), token: FAKE }],
      d: { e: Number.NEGATIVE_INFINITY },
    });
    expect(JsonObject.safeParse(output).success).toBe(true);
    expect(() => canonicalJson(output)).not.toThrow();
  });
});

describe('isSecretKeyName: cryptographic material (F-10)', () => {
  it.each([
    'ciphertext',
    'Ciphertext',
    'cipherText',
    'cipher_text',
    'CIPHERTEXT',
    'secretCiphertext',
    'nonce',
    'Nonce',
    'gcm_nonce',
    'NONCE',
    'iv',
    'IV',
    'gcmIv',
    'iv_hex',
    'ivBase64',
    'authTag',
    'auth_tag',
    'AUTH-TAG',
    'AuthTag',
    'gcmTag',
    'aead_tag',
    'macTag',
    'wrappedDek',
    'wrapped_dek',
    'WRAPPED-DEK',
    'wrappedKey',
    'wrapped_key',
    'salt',
    'Salt',
    'kdf_salt',
    'saltHex',
    'signature',
    'Signature',
    'requestSignature',
    'x-signature',
    'tokenHash',
    'token_hash',
    'TOKEN-HASH',
    'sessionTokenHash',
    'passwordHash',
    'storageState',
    'storage_state',
    'STORAGE-STATE',
    'accessKey',
    'access_key',
  ])('treats %s as secret-bearing', (key) => {
    expect(isSecretKeyName(key)).toBe(true);
  });

  it.each([
    // fields the broker API writes into audit metadata today
    'applicationId',
    'name',
    'adapterId',
    'adapterVersion',
    'allowedOrigins',
    'connectionId',
    'displayName',
    'status',
    'hasReason',
    'agentId',
    'clientIdentity',
    'grantId',
    'operation',
    'effect',
    'approvalMode',
    'constraintKeys',
    'expiresAt',
    'reason',
    'method',
    // look-alikes that must not trip the short words
    'tag',
    'tags',
    'eventHash',
    'previousHash',
    'contentHash',
    'positive',
    'privacy',
    'division',
    'devices',
    'salted_count',
    'announce',
  ])('keeps %s', (key) => {
    expect(isSecretKeyName(key)).toBe(false);
  });

  it('redacts cryptographic fields at every depth and keeps the ordinary ones', () => {
    const output = redactMetadata({
      grantId: 'grt_1',
      operation: 'orders.list',
      status: 'active',
      tags: ['a'],
      envelope: {
        ciphertext: FAKE,
        nonce: FAKE,
        iv: FAKE,
        authTag: FAKE,
        wrapped_dek: FAKE,
        salt: FAKE,
        signature: FAKE,
        tokenHash: FAKE,
      },
      snapshots: [{ storage_state: { cookies: [FAKE] }, connectionId: 'con_1' }],
    });
    expect(output).toEqual({
      grantId: 'grt_1',
      operation: 'orders.list',
      status: 'active',
      tags: ['a'],
      envelope: {
        ciphertext: REDACTED,
        nonce: REDACTED,
        iv: REDACTED,
        authTag: REDACTED,
        wrapped_dek: REDACTED,
        salt: REDACTED,
        signature: REDACTED,
        tokenHash: REDACTED,
      },
      snapshots: [{ storage_state: REDACTED, connectionId: 'con_1' }],
    });
    expect(JSON.stringify(output)).not.toContain(FAKE);
  });
});
