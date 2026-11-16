import { createHash } from 'node:crypto';
import { JOB_ARGUMENTS_HASH_DOMAIN, jobArgumentsHashInput } from '@aab/contracts';
import type { JobArgumentsBinding } from '@aab/contracts';
import { describe, expect, it } from 'vitest';
import { hashJobArguments, verifyJobArgumentsHash } from '../src/index.js';

const CONNECTION = '11111111-1111-4111-8111-111111111111';
const OTHER_CONNECTION = '22222222-2222-4222-8222-222222222222';

const ORGANIZATION = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const AGENT = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const DECISION = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';

const base = (): JobArgumentsBinding => ({
  organizationId: ORGANIZATION,
  agentId: AGENT,
  operation: 'orders.list',
  connectionId: CONNECTION,
  arguments: { status: 'open', limit: 5 },
  policyDecisionId: DECISION,
  timeoutMs: 30_000,
  retrySafe: true,
});

describe('hashJobArguments (threat model PE-14)', () => {
  it('matches a pinned vector computed outside JavaScript', () => {
    // sha256 of the literal text below, computed with Python's hashlib over a hand-built string.
    expect(jobArgumentsHashInput(base())).toBe(
      'aab.job-arguments.v1\n{"agentId":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","arguments":{"limit":5,"status":"open"},"connectionId":"11111111-1111-4111-8111-111111111111","operation":"orders.list","organizationId":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","policyDecisionId":"dddddddd-dddd-4ddd-8ddd-dddddddddddd","retrySafe":true,"timeoutMs":30000}',
    );
    expect(hashJobArguments(base())).toBe(
      '2fc594ff39291fb92295ddf86b18cd01d1b47c5b93a2a6ff5e039f1da79b1410',
    );
  });

  it('writes a missing decision id as JSON null (second pinned vector, also from Python)', () => {
    expect(hashJobArguments({ ...base(), policyDecisionId: null })).toBe(
      'b18c62c4621e84e2d441d5b053efdc4afa13365a244b4c5c845481dd40225ff7',
    );
  });

  it('is lowercase hex SHA-256', () => {
    expect(hashJobArguments(base())).toMatch(/^[0-9a-f]{64}$/);
  });

  it('does not depend on key order, at any depth', () => {
    const a = hashJobArguments({
      ...base(),
      arguments: { b: 1, a: { y: [1, { q: 1, p: 2 }], x: null } },
    });
    const b = hashJobArguments({
      ...base(),
      arguments: { a: { x: null, y: [1, { p: 2, q: 1 }] }, b: 1 },
    });
    expect(a).toBe(b);
  });

  it('changes when any value, key, type or array order changes', () => {
    const reference = hashJobArguments(base());
    const variants: JobArgumentsBinding['arguments'][] = [
      { status: 'open', limit: 6 },
      { status: 'Open', limit: 5 },
      { status: 'open ', limit: 5 },
      { status: 'open', limit: '5' },
      { status: 'open', limit: 5.5 },
      { status: 'open', limit: 5, extra: null },
      { status: 'open' },
      { status: ['open'], limit: 5 },
      { Status: 'open', limit: 5 },
      {},
    ];
    const hashes = variants.map((args) => hashJobArguments({ ...base(), arguments: args }));
    for (const hash of hashes) expect(hash).not.toBe(reference);
    expect(new Set(hashes).size).toBe(hashes.length);
    expect(hashJobArguments({ ...base(), arguments: { ids: [1, 2] } })).not.toBe(
      hashJobArguments({ ...base(), arguments: { ids: [2, 1] } }),
    );
  });

  it('binds the operation and the connection', () => {
    const reference = hashJobArguments(base());
    expect(hashJobArguments({ ...base(), operation: 'orders.get' })).not.toBe(reference);
    expect(hashJobArguments({ ...base(), operation: 'orders.list ' })).not.toBe(reference);
    expect(hashJobArguments({ ...base(), connectionId: OTHER_CONNECTION })).not.toBe(reference);
    // Ids are compared as stored: an uppercase spelling is a different binding.
    const lettered = 'abcdef12-3456-4789-8abc-def123456789';
    expect(hashJobArguments({ ...base(), connectionId: lettered.toUpperCase() })).not.toBe(
      hashJobArguments({ ...base(), connectionId: lettered }),
    );
  });

  it('binds the organization, agent, decision, timeout and retry flag', () => {
    const reference = hashJobArguments(base());
    const variants: JobArgumentsBinding[] = [
      { ...base(), organizationId: OTHER_CONNECTION },
      { ...base(), agentId: OTHER_CONNECTION },
      { ...base(), policyDecisionId: OTHER_CONNECTION },
      { ...base(), policyDecisionId: null },
      { ...base(), timeoutMs: 30_001 },
      { ...base(), retrySafe: false },
    ];
    const hashes = variants.map((binding) => hashJobArguments(binding));
    for (const hash of hashes) expect(hash).not.toBe(reference);
    expect(new Set(hashes).size).toBe(hashes.length);
  });

  it('cannot be shifted between fields', () => {
    // Moving text between the operation name and an argument changes the hashed object.
    const a = hashJobArguments({ ...base(), operation: 'a', arguments: { b: 'c' } });
    const b = hashJobArguments({ ...base(), operation: 'a","arguments":{"b":"c"}', arguments: {} });
    expect(a).not.toBe(b);
  });

  it('uses the domain prefix: the bare canonical JSON hashes differently', () => {
    const input = jobArgumentsHashInput(base());
    expect(input.startsWith(JOB_ARGUMENTS_HASH_DOMAIN)).toBe(true);
    expect(JOB_ARGUMENTS_HASH_DOMAIN).toBe('aab.job-arguments.v1\n');
    const withoutPrefix = input.slice(JOB_ARGUMENTS_HASH_DOMAIN.length);
    const sha = (text: string) => createHash('sha256').update(text, 'utf8').digest('hex');
    expect(sha(input)).toBe(hashJobArguments(base()));
    expect(sha(withoutPrefix)).not.toBe(hashJobArguments(base()));
    expect(sha(`aab.job-arguments.v2\n${withoutPrefix}`)).not.toBe(hashJobArguments(base()));
  });

  it('throws on arguments that are not plain JSON', () => {
    expect(() =>
      hashJobArguments({ ...base(), arguments: { limit: Number.NaN } as never }),
    ).toThrow(TypeError);
    expect(() =>
      hashJobArguments({ ...base(), arguments: { when: new Date(0) } as never }),
    ).toThrow(TypeError);
  });
});

describe('verifyJobArgumentsHash', () => {
  it('accepts the matching hash only', () => {
    const hash = hashJobArguments(base());
    expect(verifyJobArgumentsHash(base(), hash)).toBe(true);
    expect(
      verifyJobArgumentsHash({ ...base(), arguments: { status: 'open', limit: 50 } }, hash),
    ).toBe(false);
    expect(verifyJobArgumentsHash({ ...base(), operation: 'orders.get' }, hash)).toBe(false);
    expect(verifyJobArgumentsHash({ ...base(), connectionId: OTHER_CONNECTION }, hash)).toBe(false);
    expect(verifyJobArgumentsHash({ ...base(), agentId: OTHER_CONNECTION }, hash)).toBe(false);
    expect(verifyJobArgumentsHash({ ...base(), policyDecisionId: null }, hash)).toBe(false);
    expect(verifyJobArgumentsHash({ ...base(), timeoutMs: 1 }, hash)).toBe(false);
    expect(verifyJobArgumentsHash({ ...base(), retrySafe: false }, hash)).toBe(false);
  });

  it('rejects malformed, truncated and differently cased expectations', () => {
    const hash = hashJobArguments(base());
    for (const expected of [
      '',
      hash.slice(0, 63),
      `${hash}0`,
      hash.toUpperCase(),
      'x'.repeat(64),
    ]) {
      expect(verifyJobArgumentsHash(base(), expected)).toBe(false);
    }
  });

  it('returns false instead of throwing for arguments that cannot be hashed', () => {
    const hash = hashJobArguments(base());
    expect(verifyJobArgumentsHash({ ...base(), arguments: { n: Infinity } as never }, hash)).toBe(
      false,
    );
  });
});
