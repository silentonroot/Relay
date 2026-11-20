import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import {
  ALLOWED_FIELD_NAMES,
  FORBIDDEN_FIELD_NAME,
  isForbiddenFieldName,
  suspiciousValue,
  walkJson,
  walkSchema,
} from './forbidden-fields.js';
import { VAULT_DASHBOARD_RESPONSE_SCHEMAS } from '../src/index.js';

describe('the forbidden-field walker (self-test: it cannot pass vacuously)', () => {
  const badNames = [
    'tokenHash',
    'token_hash',
    'token',
    'tokenMac',
    'authorizationMac',
    'mac',
    'ciphertext',
    'wrappedDek',
    'wrapped_dek',
    'dek',
    'nonce',
    'authTag',
    'plaintext',
    'secretValue',
    'secret_value',
    'apiKey',
    'keyMaterial',
    'kekBytes',
    'kek',
    'passwordHash',
    'salt',
  ];

  it.each(badNames)('flags a schema field named %s, wherever it sits', (name) => {
    const nested = z.strictObject({
      ok: z.string(),
      list: z.array(z.strictObject({ inner: z.strictObject({ [name]: z.string() }) })),
    });
    const walk = walkSchema(nested);
    expect(walk.violations.map((entry) => entry.name)).toEqual([name]);
    expect(walk.violations[0]!.path).toBe(`list[].inner.${name}`);
    for (const wrapped of [
      z.strictObject({ [name]: z.string() }).nullable(),
      z.strictObject({ [name]: z.string() }).optional(),
      z.union([z.string(), z.strictObject({ [name]: z.number() })]),
      z.record(z.string(), z.strictObject({ [name]: z.number() })),
      z.tuple([z.strictObject({ [name]: z.number() })]),
      z.strictObject({ a: z.string() }).and(z.strictObject({ [name]: z.string() })),
      z.lazy(() => z.strictObject({ [name]: z.string() })),
      z.strictObject({ [name]: z.string() }).default({ [name]: 'x' }),
    ]) {
      expect(walkSchema(wrapped).violations.map((entry) => entry.name)).toEqual([name]);
    }
    expect(walkJson({ rows: [{ deep: { [name]: 'x' } }] }).violations.map((v) => v.path)).toEqual([
      `rows[].deep.${name}`,
    ]);
  });

  it('allows the explicitly listed key-version fields and nothing that merely resembles them', () => {
    for (const name of ALLOWED_FIELD_NAMES) expect(isForbiddenFieldName(name)).toBe(false);
    expect(ALLOWED_FIELD_NAMES.size).toBe(5);
    for (const name of ['kekVersionSecret', 'kekMaterial', 'kekVersionBytes', 'currentKek']) {
      expect(isForbiddenFieldName(name), name).toBe(true);
    }
    for (const name of ['status', 'activeVersion', 'secretType', 'lastAccessedAt', 'reason']) {
      expect(isForbiddenFieldName(name), name).toBe(false);
    }
  });

  it('counts the fields it visits and refuses a Zod kind it does not know', () => {
    const walk = walkSchema(
      z.strictObject({ a: z.string(), b: z.array(z.strictObject({ c: z.number() })) }),
    );
    expect(walk.fields.map((entry) => entry.path)).toEqual(['a', 'b', 'b[].c']);
    expect(() => walkSchema(z.custom(() => true))).toThrow(/does not know/);
    expect(() => walkSchema({})).toThrow(/not a Zod schema/);
  });

  it('reports free-key record schemas as dynamic-key places a response test must cover', () => {
    const walk = walkSchema(z.strictObject({ counters: z.record(z.string(), z.number()) }));
    expect(walk.dynamicKeyPaths).toEqual(['counters']);
    expect(walkSchema(z.record(z.number(), z.number())).dynamicKeyPaths).toEqual(['']);
  });

  it('treats the keys of an enum or literal record as field names, checked like any other', () => {
    const bad = walkSchema(z.strictObject({ m: z.record(z.enum(['tokenHash']), z.number()) }));
    expect(bad.violations.map((v) => v.path)).toEqual(['m.tokenHash']);
    expect(bad.dynamicKeyPaths).toEqual([]);
    const badLiteral = walkSchema(z.record(z.literal('ciphertext'), z.string()));
    expect(badLiteral.violations.map((v) => v.name)).toEqual(['ciphertext']);
    const good = walkSchema(z.record(z.enum(['used', 'revoked']), z.number()));
    expect(good.violations).toEqual([]);
    expect(good.fields.map((f) => f.path)).toEqual(['used', 'revoked']);
  });

  it.each([
    ['looseObject', z.looseObject({ a: z.string() })],
    ['catchall(unknown)', z.object({ a: z.string() }).catchall(z.unknown())],
    ['catchall(string)', z.object({ a: z.string() }).catchall(z.string())],
    ['unknown field', z.strictObject({ a: z.unknown() })],
    ['any field', z.strictObject({ a: z.any() })],
    ['nested any in an array', z.strictObject({ list: z.array(z.any()) })],
    ['unknown as record value', z.strictObject({ m: z.record(z.string(), z.unknown()) })],
    ['root unknown', z.unknown()],
  ])('fails an open-ended schema: %s', (_name, schema) => {
    const open = walkSchema(schema).violations.filter((v) => v.name.startsWith('<open-ended:'));
    expect(open.length).toBeGreaterThan(0);
  });

  it('accepts strict objects, plain objects without a catchall, and a never catchall', () => {
    expect(walkSchema(z.strictObject({ a: z.string() })).violations).toEqual([]);
    expect(walkSchema(z.object({ a: z.string() })).violations).toEqual([]);
    expect(walkSchema(z.object({ a: z.string() }).catchall(z.never())).violations).toEqual([]);
  });

  it('walks a shared sub-schema once per path, so a second path is checked and recorded', () => {
    const shared = z.strictObject({ tokenHash: z.string() });
    const walk = walkSchema(z.strictObject({ first: shared, second: shared }));
    expect(walk.violations.map((v) => v.path)).toEqual(['first.tokenHash', 'second.tokenHash']);
    // A self-referencing lazy schema still terminates.
    type Tree = { children: Tree[] };
    const tree: z.ZodType<Tree> = z.lazy(() => z.strictObject({ children: z.array(tree) }));
    expect(walkSchema(tree).fields.map((f) => f.path)).toEqual(['children']);
  });
});

describe('the response value scan (walkJson flags key-looking values)', () => {
  it('flags a 64-hex string and a long base64 or base64url string, wherever they sit', () => {
    const hex = 'ab'.repeat(32);
    const b64 = Buffer.from('x'.repeat(48)).toString('base64');
    const b64url = Buffer.from('y'.repeat(48)).toString('base64url');
    const walk = walkJson({ rows: [{ note: hex }, { other: [b64, b64url] }] });
    expect(walk.violations.map((v) => v.path)).toEqual([
      'rows[].note',
      'rows[].other[]',
      'rows[].other[]',
    ]);
    expect(suspiciousValue('A'.repeat(31))).toBeNull();
    expect(suspiciousValue('A'.repeat(32))).not.toBeNull();
  });

  it('does not flag ids, timestamps, enum values or the protection statement', () => {
    const walk = walkJson({
      id: crypto.randomUUID(),
      zero: '00000000-0000-4000-8000-000000000000',
      at: new Date().toISOString(),
      status: 'authentication_required',
      reason: 'connection_not_active',
      text: VAULT_DASHBOARD_RESPONSE_SCHEMAS.vaultStatus.shape.protectionStatement.value,
    });
    expect(walk.violations).toEqual([]);
  });
});

describe('every vault dashboard response schema (ADR-014 section 12: metadata only)', () => {
  const entries = Object.entries(VAULT_DASHBOARD_RESPONSE_SCHEMAS);

  it('lists the four routes of step B5a', () => {
    expect(entries.map(([name]) => name).sort()).toEqual([
      'connectionVault',
      'deleteStoredSession',
      'revokeCapabilities',
      'vaultStatus',
    ]);
  });

  it.each(entries)('%s has no ciphertext-, key-, token- or MAC-named field', (_name, schema) => {
    const walk = walkSchema(schema);
    expect(walk.fields.length).toBeGreaterThanOrEqual(2);
    expect(walk.violations).toEqual([]);
  });

  it('walked a non-trivial number of fields, including the nested ones and the key versions', () => {
    const all = entries.flatMap(([, schema]) => walkSchema(schema).fields.map((f) => f.path));
    expect(all.length).toBeGreaterThanOrEqual(25);
    for (const expected of [
      'secrets[].kekVersion',
      'secrets[].activeVersion',
      'capabilities.rejected[].reason',
      'kekVersions',
      'versionsByKek',
      'missingKekVersions',
      'protectionStatement',
      'versionsDeleted',
    ]) {
      expect(all, expected).toContain(expected);
    }
  });

  it('the key-version fields are on the allow-list on purpose: every forbidden-looking name present is listed', () => {
    const names = new Set(
      entries.flatMap(([, schema]) => walkSchema(schema).fields.map((f) => f.name)),
    );
    const looksForbidden = [...names].filter((name) => FORBIDDEN_FIELD_NAME.test(name));
    expect(looksForbidden.sort()).toEqual(
      [
        'currentKekVersion',
        'kekVersion',
        'kekVersions',
        'missingKekVersions',
        'versionsByKek',
      ].sort(),
    );
  });

  it('every free-key record is listed here, so a new one needs a response test on purpose', () => {
    const dynamic = entries.flatMap(([name, schema]) =>
      walkSchema(schema).dynamicKeyPaths.map((path) => `${name}.${path}`),
    );
    expect(dynamic.sort()).toEqual(['vaultStatus.counters', 'vaultStatus.versionsByKek']);
  });

  it('no response schema is open-ended (any, unknown, loose object, catchall)', () => {
    for (const [, schema] of entries) {
      expect(walkSchema(schema).violations.filter((v) => v.name.startsWith('<open'))).toEqual([]);
    }
  });

  it('the vault status schema is strict: an extra field is refused, not passed through', () => {
    const status = {
      isolation: 'shared-uid',
      kekVersions: [1],
      currentKekVersion: 1,
      versionsByKek: { '1': 1 },
      missingKekVersions: [],
      counters: {},
      protectionStatement:
        VAULT_DASHBOARD_RESPONSE_SCHEMAS.vaultStatus.shape.protectionStatement.value,
    };
    expect(VAULT_DASHBOARD_RESPONSE_SCHEMAS.vaultStatus.safeParse(status).success).toBe(true);
    expect(
      VAULT_DASHBOARD_RESPONSE_SCHEMAS.vaultStatus.safeParse({ ...status, tokenHash: 'x' }).success,
    ).toBe(false);
    expect(
      VAULT_DASHBOARD_RESPONSE_SCHEMAS.connectionVault.safeParse({
        connectionId: crypto.randomUUID(),
        connectionStatus: 'active',
        secrets: [
          {
            secretType: 't',
            status: 'active',
            activeVersion: 1,
            kekVersion: 1,
            lastAccessedAt: null,
            wrappedDek: 'x',
          },
        ],
        capabilities: { windowHours: 24, authorized: 0, used: 0, revoked: 0, rejected: [] },
      }).success,
    ).toBe(false);
  });
});
