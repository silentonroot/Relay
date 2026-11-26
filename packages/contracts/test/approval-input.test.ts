import { describe, expect, it } from 'vitest';
import {
  canonicalJson,
  checkApprovalInput,
  checkPlainJson,
  findRawJsonIssue,
  MAX_JSON_DEPTH,
  MAX_PATH_LENGTH,
  MAX_PATH_SEGMENT,
} from '../src/index.js';

const code = (value: unknown): string | null => checkApprovalInput(value)?.code ?? null;

describe('checkApprovalInput (P4-20)', () => {
  it('accepts ordinary values, including the safe-range edges (positive control)', () => {
    expect(code({ a: 1, b: 'text', c: [true, null, 1.5, -3], d: { e: 'x' } })).toBeNull();
    expect(code({ n: Number.MAX_SAFE_INTEGER })).toBeNull();
    expect(code({ n: -Number.MAX_SAFE_INTEGER })).toBeNull();
    expect(code({ s: 'pair \u{1f600} and \u00e9 and \ud83d\ude00' })).toBeNull();
    expect(code({})).toBeNull();
    expect(code([])).toBeNull();
    expect(code(0)).toBeNull();
    expect(code(1.0)).toBeNull();
  });

  it.each([
    ['2^53', 2 ** 53],
    ['2^53 + 1 (parses to 2^53)', JSON.parse('9007199254740993') as number],
    ['-(2^53 + 1)', -(2 ** 53) - 1],
    ['a very large integer', 1e300],
  ])('refuses %s as unsafe_integer', (_label, n) => {
    expect(code({ n })).toBe('unsafe_integer');
  });

  it('refuses -0 as negative_zero, but not 0', () => {
    expect(code({ n: -0 })).toBe('negative_zero');
    expect(code({ n: 0 })).toBeNull();
    expect(code({ n: JSON.parse('-0') })).toBe('negative_zero');
  });

  it.each([
    ['a lone high surrogate', 'a\ud800b'],
    ['a lone low surrogate', 'a\udc00b'],
    ['a trailing high surrogate', 'a\ud83d'],
    ['reversed surrogates', '\ude00\ud83d'],
  ])('refuses %s in a value', (_label, s) => {
    expect(code({ s })).toBe('lone_surrogate');
  });

  it('refuses a lone surrogate in a key', () => {
    expect(code({ ['k\ud800']: 1 })).toBe('lone_surrogate');
    expect(code({ ['k\udc00']: 1 })).toBe('lone_surrogate');
    expect(checkApprovalInput({ a: { ['k\ud800']: 1 } })?.path).toBe('$.a.k\ufffd');
  });

  it('refuses NaN and the infinities as non_finite_number', () => {
    expect(code({ n: Number.NaN })).toBe('non_finite_number');
    expect(code({ n: Number.POSITIVE_INFINITY })).toBe('non_finite_number');
    expect(code({ n: Number.NEGATIVE_INFINITY })).toBe('non_finite_number');
  });

  it('reaches nested arrays and objects, and reports the path', () => {
    expect(checkApprovalInput({ a: [{ b: [1, 2, { c: 2 ** 53 }] }] })).toEqual({
      code: 'unsafe_integer',
      path: '$.a[0].b[2].c',
    });
    expect(code([[[[-0]]]])).toBe('negative_zero');
    expect(code({ a: { b: { c: { d: 'x\udfff' } } } })).toBe('lone_surrogate');
    expect(code({ a: [[], [[{ ok: 1 }]]] })).toBeNull();
  });

  it('refuses values that are not JSON', () => {
    expect(code({ a: undefined })).toBe('not_json');
    expect(code({ a: 10n })).toBe('not_json');
    expect(code({ a: () => 1 })).toBe('not_json');
  });

  it('does not change canonicalJson: it still accepts the values the strict check refuses', () => {
    // The strict check is separate on purpose (audit hashing and other callers are unchanged).
    expect(canonicalJson({ n: 2 ** 53 })).toBe('{"n":9007199254740992}');
    expect(canonicalJson({ n: -0 })).toBe('{"n":0}');
    expect(() => canonicalJson({ s: 'a\ud800' })).not.toThrow();
  });
});

describe('findRawJsonIssue: duplicate keys in a raw body (P4-20)', () => {
  it('passes valid JSON with unique keys (positive control)', () => {
    for (const body of [
      '{}',
      '[]',
      '{"a":1,"b":{"a":2},"c":[{"a":1},{"a":2}]}',
      '  {"a" : 1 ,\n"b":[1,2.5e3,-0.5,true,false,null,"x"]}  ',
      '{"orderId":"ORD-1","changes":{"status":"held"}}',
      '"just a string"',
      '123',
    ]) {
      expect(findRawJsonIssue(body)).toBeNull();
    }
  });

  it('finds a top-level duplicate', () => {
    expect(findRawJsonIssue('{"a":1,"a":2}')).toEqual({ code: 'duplicate_key', path: '$.a' });
    expect(findRawJsonIssue('{"a":1,"b":2,"a":1}')?.code).toBe('duplicate_key');
  });

  it('finds nested duplicates, in objects inside arrays and objects', () => {
    expect(findRawJsonIssue('{"x":{"a":1,"a":2}}')).toEqual({
      code: 'duplicate_key',
      path: '$.x.a',
    });
    expect(findRawJsonIssue('{"x":[{"a":1},{"b":1,"b":2}]}')).toEqual({
      code: 'duplicate_key',
      path: '$.x[1].b',
    });
    expect(findRawJsonIssue('[[{"k":{"k":1,"k":2}}]]')?.code).toBe('duplicate_key');
  });

  it('does not mistake a key-looking text inside a string value for a key', () => {
    expect(findRawJsonIssue('{"a":"\\"a\\":1","b":"{\\"a\\":2,\\"a\\":3}"}')).toBeNull();
    expect(findRawJsonIssue('{"a":"x","b":"a"}')).toBeNull();
    expect(findRawJsonIssue('{"a":["a","a"],"b":"a"}')).toBeNull();
  });

  it('handles escaped quotes and backslashes in keys', () => {
    expect(findRawJsonIssue('{"a\\"b":1,"a\\"b":2}')?.code).toBe('duplicate_key');
    expect(findRawJsonIssue('{"a\\"b":1,"a":2}')).toBeNull();
    expect(findRawJsonIssue('{"a\\\\":1,"a":2}')).toBeNull();
    expect(findRawJsonIssue('{"a\\\\":1,"a\\\\":2}')?.code).toBe('duplicate_key');
  });

  it('treats keys that decode to the same string as duplicates', () => {
    expect(findRawJsonIssue('{"a":1,"\\u0061":2}')).toEqual({ code: 'duplicate_key', path: '$.a' });
    expect(findRawJsonIssue('{"\\u0061\\u0062":1,"ab":2}')?.code).toBe('duplicate_key');
    expect(findRawJsonIssue('{"\\u00e9":1,"\u00e9":2}')?.code).toBe('duplicate_key');
    expect(findRawJsonIssue('{"\\ud83d\\ude00":1,"\u{1f600}":2}')?.code).toBe('duplicate_key');
    expect(findRawJsonIssue('{"\\u0061":1,"\\u0062":2}')).toBeNull();
  });

  it('treats a key that differs only in case or in an escape of another character as distinct', () => {
    expect(findRawJsonIssue('{"a":1,"A":2}')).toBeNull();
    expect(findRawJsonIssue('{"a":1,"a ":2}')).toBeNull();
  });

  it('refuses text that is not JSON', () => {
    for (const body of [
      '',
      '{',
      '{"a":1,}',
      '{"a":1 "b":2}',
      "{'a':1}",
      '{"a":01}',
      '{"a":1}x',
      '{"a":"\\x"}',
      '{"a":"\\u12G4"}',
      '{"a":"line\nbreak"}',
      '{a:1}',
      '[1,]',
      '{"a":tru}',
      '\ufeff{"a":1}',
      '{"a":1}{"a":2}',
    ]) {
      expect(findRawJsonIssue(body)?.code).toBe('invalid_json');
    }
  });

  it('agrees with JSON.parse on what is valid for a corpus of bodies', () => {
    const bodies = [
      '{"a":1}',
      '[1,2,3]',
      '{"a":{"b":[null,true,"x",1e5,-2.5E-3]}}',
      '{"a":1,}',
      '[1 2]',
      '{"a":"\\u00zz"}',
      '"\\/"',
    ];
    for (const body of bodies) {
      let parses = true;
      try {
        JSON.parse(body);
      } catch {
        parses = false;
      }
      expect(findRawJsonIssue(body) === null).toBe(parses);
    }
  });
});

describe('one depth boundary in all three checks (L2)', () => {
  const nestArrays = (levels: number, inner: unknown): unknown => {
    let value = inner;
    for (let i = 0; i < levels; i += 1) value = [value];
    return value;
  };
  const nestObjects = (levels: number, inner: unknown): unknown => {
    let value = inner;
    for (let i = 0; i < levels; i += 1) value = { k: value };
    return value;
  };
  const raw = (levels: number, inner: string): string =>
    '['.repeat(levels) + inner + ']'.repeat(levels);

  // `levels` counts every array or object, the innermost included.
  it.each([
    ['a scalar', 1, 0],
    ['an empty array', [], 1],
    ['an empty object', {}, 1],
  ])('64 levels pass and 65 are refused with too_deep, innermost %s', (_label, inner, own) => {
    const text = JSON.stringify(inner);
    for (const nest of [nestArrays, nestObjects]) {
      expect(checkPlainJson(nest(MAX_JSON_DEPTH - own, inner))).toBeNull();
      expect(checkApprovalInput(nest(MAX_JSON_DEPTH - own, inner))).toBeNull();
      expect(checkPlainJson(nest(MAX_JSON_DEPTH + 1 - own, inner))).toBe('too_deep');
      expect(checkApprovalInput(nest(MAX_JSON_DEPTH + 1 - own, inner))?.code).toBe('too_deep');
    }
    expect(findRawJsonIssue(raw(MAX_JSON_DEPTH - own, text))).toBeNull();
    expect(findRawJsonIssue(raw(MAX_JSON_DEPTH + 1 - own, text))?.code).toBe('too_deep');
  });

  it('does not overflow the stack on very deep input', () => {
    expect(findRawJsonIssue(raw(100_000, '1'))?.code).toBe('too_deep');
    expect(checkApprovalInput(nestArrays(100_000, 1))?.code).toBe('too_deep');
  });
});

describe('error paths are bounded (L3)', () => {
  it('cuts a long key segment and the whole path, in all three paths that carry one', () => {
    const longKey = 'k'.repeat(5_000);
    // Positive control: a short path is reported whole.
    expect(checkApprovalInput({ a: { b: 2 ** 53 } })?.path).toBe('$.a.b');

    const walk = checkApprovalInput({ [longKey]: -0 });
    expect(walk?.code).toBe('negative_zero');
    expect(walk!.path.length).toBeLessThanOrEqual(MAX_PATH_SEGMENT + 4);

    const dup = findRawJsonIssue(`{"${longKey}":1,"${longKey}":2}`);
    expect(dup?.code).toBe('duplicate_key');
    expect(dup!.path.length).toBeLessThanOrEqual(MAX_PATH_SEGMENT + 4);

    let deep: unknown = 2 ** 53;
    for (let i = 0; i < 30; i += 1) deep = { ['x'.repeat(30)]: deep };
    const long = checkApprovalInput(deep);
    expect(long?.code).toBe('unsafe_integer');
    expect(long!.path.length).toBeLessThanOrEqual(MAX_PATH_LENGTH + 1);
    expect(long!.path.endsWith('\u2026')).toBe(true);
  });

  it('never puts a lone surrogate from a key into the path', () => {
    const issue = checkApprovalInput({ ['k\ud800']: 1 });
    expect(issue?.code).toBe('lone_surrogate');
    expect(issue!.path.isWellFormed()).toBe(true);
  });
});
