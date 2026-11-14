import { describe, expect, it } from 'vitest';
import {
  canonicalJson,
  checkPlainJson,
  isPlainJson,
  MAX_JSON_DEPTH,
  Origin,
} from '../src/index.js';

describe('Origin rejects IP-literal hosts other than loopback', () => {
  it.each([
    'https://169.254.169.254',
    'https://10.0.0.5',
    'https://192.168.1.10:8443',
    'https://172.16.0.1',
    'https://8.8.8.8',
    'http://0.0.0.0:4100',
    'https://[fe80::1]',
    'https://[fd00::1]',
  ])('rejects %s', (origin) => {
    expect(Origin.safeParse(origin).success).toBe(false);
  });

  it.each(['http://127.0.0.1:4100', 'http://[::1]:4100', 'http://localhost:4100'])(
    'still accepts loopback %s',
    (origin) => {
      expect(Origin.safeParse(origin).success).toBe(true);
    },
  );

  it('rejects alternative spellings of an IPv4 address', () => {
    // The URL parser normalises these to dotted form, so they never equal their own origin.
    for (const origin of ['https://2130706433', 'https://0x7f.0.0.1', 'https://017700000001']) {
      expect(Origin.safeParse(origin).success).toBe(false);
    }
  });
});

describe('canonicalJson rejects values JSON cannot represent faithfully', () => {
  it('rejects sparse arrays instead of emitting empty slots', () => {
    const sparse: unknown[] = [1, 2, 3];
    delete sparse[1];
    expect(() => canonicalJson(sparse)).toThrow(/sparse/);
    expect(() => canonicalJson({ a: new Array(2) })).toThrow(/sparse/);
  });

  it('rejects symbol keys instead of dropping them', () => {
    expect(() => canonicalJson({ a: 1, [Symbol('hidden')]: 2 })).toThrow(/symbol/);
  });
});

describe('checkPlainJson', () => {
  it('accepts ordinary JSON', () => {
    expect(checkPlainJson({ status: 'held', limit: 25, tags: ['a', null, true], nested: {} })).toBe(
      null,
    );
    expect(isPlainJson([])).toBe(true);
  });

  it('flags keys that parsers drop or that reach the prototype', () => {
    const parsed: unknown = JSON.parse('{"status":"held","__proto__":{"admin":true}}');
    expect(checkPlainJson(parsed)).toBe('forbidden_key');
    expect(checkPlainJson({ a: { constructor: 1 } })).toBe('forbidden_key');
    expect(checkPlainJson([{ prototype: {} }])).toBe('forbidden_key');
  });

  it('flags cycles but allows a shared reference', () => {
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    expect(checkPlainJson(cyclic)).toBe('cyclic');

    const shared = { n: 1 };
    expect(checkPlainJson({ a: shared, b: shared })).toBe(null);
  });

  it('bounds nesting depth', () => {
    const nest = (levels: number): unknown => {
      let value: unknown = 1;
      for (let i = 0; i < levels; i += 1) value = [value];
      return value;
    };
    expect(checkPlainJson(nest(MAX_JSON_DEPTH))).toBe(null);
    expect(checkPlainJson(nest(MAX_JSON_DEPTH + 1))).toBe('too_deep');
  });

  it.each([
    ['undefined', { a: undefined }],
    ['NaN', { a: Number.NaN }],
    ['bigint', { a: 1n }],
    ['Date', { a: new Date(0) }],
    ['Map', new Map()],
    ['function', { a: () => 1 }],
    ['symbol key', { [Symbol('s')]: 1 }],
    ['sparse array', new Array(1)],
  ])('flags %s as not JSON', (_label, value) => {
    expect(checkPlainJson(value)).toBe('not_json');
  });
});
