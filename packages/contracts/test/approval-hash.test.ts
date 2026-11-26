import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  actionHashInput,
  APPROVAL_ACTION_HASH_DOMAIN,
  APPROVAL_ACTION_HASH_FIELDS,
  ApprovalInputError,
  JOB_ARGUMENTS_HASH_DOMAIN,
  JOB_ARGUMENTS_HASH_DOMAIN_V2,
  jobArgumentsHashInput,
  jobArgumentsHashInputV2,
} from '../src/index.js';
import type {
  ApprovalActionBinding,
  JobArgumentsBinding,
  JobArgumentsBindingV2,
} from '../src/index.js';
import {
  computeActionHash,
  computeJobArgumentsHashV2,
  verifyActionHash,
  verifyJobArgumentsHashV2,
} from '../src/hashing.js';

const ORG = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const AGENT = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const OWNER = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const DECISION = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
const RUN = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
const APPROVAL = 'ffffffff-ffff-4fff-8fff-ffffffffffff';
const CONNECTION = '11111111-1111-4111-8111-111111111111';

const sha256Hex = (text: string): string => createHash('sha256').update(text, 'utf8').digest('hex');

const NAMES = { resourceArgument: 'orderId', versionArgument: 'expectedVersion' };

const hash = (b: ApprovalActionBinding): string => computeActionHash(b, NAMES);
const verify = (b: ApprovalActionBinding, expected: string): boolean =>
  verifyActionHash(b, NAMES, expected);

const binding = (): ApprovalActionBinding => ({
  organizationId: ORG,
  ownerUserId: OWNER,
  agentId: AGENT,
  runId: RUN,
  connectionId: CONNECTION,
  operation: 'orders.applyApprovedUpdate',
  arguments: { orderId: 'ORD-1001', expectedVersion: 3, changes: { status: 'held' } },
  targetResourceId: 'ORD-1001',
  expectedResourceVersion: 3,
});

// The layout written out by hand from the documentation, with no call to canonicalJson: keys in
// UTF-16 order, no whitespace. The hex values below were computed once with Python's hashlib over
// this same text, so neither the implementation nor this test produced them.
const GOLDEN_TEXT =
  'aab.approval-action.v1\n{"agentId":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","arguments":{"changes":{"status":"held"},"expectedVersion":3,"orderId":"ORD-1001"},"connectionId":"11111111-1111-4111-8111-111111111111","expectedResourceVersion":3,"operation":"orders.applyApprovedUpdate","organizationId":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","ownerUserId":"cccccccc-cccc-4ccc-8ccc-cccccccccccc","runId":"eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee","targetResourceId":"ORD-1001"}';
const GOLDEN_HASH = 'd77a7e5d5c434aa934bb71414f835d976914ed3b4f1bc548ac2a8327a4085d40';
const GOLDEN_HASH_NULL_RUN = '879fd895e024b6d95fe6e7a06304f78910335c1a5ae46d8f6dfc2ff3a98fad62';

describe('action hash (P4-3, P4-20)', () => {
  it('matches a golden vector, recomputed here from the documented layout', () => {
    expect(APPROVAL_ACTION_HASH_DOMAIN).toBe('aab.approval-action.v1\n');
    expect(actionHashInput(binding(), NAMES)).toBe(GOLDEN_TEXT);
    expect(hash(binding())).toBe(GOLDEN_HASH);
    // Independent recomputation with node:crypto over the hand-written layout text.
    expect(sha256Hex(GOLDEN_TEXT)).toBe(GOLDEN_HASH);
    expect(hash(binding())).toMatch(/^[0-9a-f]{64}$/);
  });

  it('writes a missing run as JSON null (second golden vector)', () => {
    expect(hash({ ...binding(), runId: null })).toBe(GOLDEN_HASH_NULL_RUN);
    expect(sha256Hex(GOLDEN_TEXT.replace(`"runId":"${RUN}"`, '"runId":null'))).toBe(
      GOLDEN_HASH_NULL_RUN,
    );
  });

  it('covers exactly the nine documented fields', () => {
    expect([...APPROVAL_ACTION_HASH_FIELDS].sort()).toEqual([
      'agentId',
      'arguments',
      'connectionId',
      'expectedResourceVersion',
      'operation',
      'organizationId',
      'ownerUserId',
      'runId',
      'targetResourceId',
    ]);
    const text = actionHashInput(binding(), NAMES);
    const parsed = JSON.parse(text.slice(APPROVAL_ACTION_HASH_DOMAIN.length)) as object;
    expect(Object.keys(parsed).sort()).toEqual([...APPROVAL_ACTION_HASH_FIELDS].sort());
  });

  it('does not depend on key order, at any depth', () => {
    const reordered: ApprovalActionBinding = {
      ...binding(),
      arguments: { changes: { status: 'held' }, orderId: 'ORD-1001', expectedVersion: 3 },
    };
    expect(hash(reordered)).toBe(GOLDEN_HASH);
    const base = binding().arguments;
    const nestedA = {
      ...binding(),
      arguments: { ...base, a: { y: [1, { q: 1, p: 2 }], x: null }, b: 1 },
    };
    const nestedB = {
      ...binding(),
      arguments: { b: 1, a: { x: null, y: [1, { p: 2, q: 1 }] }, ...base },
    };
    expect(hash(nestedA)).toBe(hash(nestedB));
  });

  it.each<[string, Partial<ApprovalActionBinding>]>([
    ['organizationId', { organizationId: '99999999-9999-4999-8999-999999999999' }],
    ['ownerUserId', { ownerUserId: '99999999-9999-4999-8999-999999999999' }],
    ['agentId', { agentId: '99999999-9999-4999-8999-999999999999' }],
    ['runId (another run)', { runId: '99999999-9999-4999-8999-999999999999' }],
    ['runId (none)', { runId: null }],
    ['connectionId', { connectionId: '99999999-9999-4999-8999-999999999999' }],
    ['operation', { operation: 'orders.proposeUpdate' }],
    [
      'arguments',
      { arguments: { orderId: 'ORD-1001', expectedVersion: 3, changes: { status: 'open' } } },
    ],
    [
      'targetResourceId (with its argument)',
      {
        targetResourceId: 'ORD-1002',
        arguments: { orderId: 'ORD-1002', expectedVersion: 3, changes: { status: 'held' } },
      },
    ],
    [
      'expectedResourceVersion (with its argument)',
      {
        expectedResourceVersion: 4,
        arguments: { orderId: 'ORD-1001', expectedVersion: 4, changes: { status: 'held' } },
      },
    ],
    [
      'expectedResourceVersion (string, not number)',
      {
        expectedResourceVersion: '3',
        arguments: { orderId: 'ORD-1001', expectedVersion: '3', changes: { status: 'held' } },
      },
    ],
  ])('changes when %s changes', (_field, override) => {
    // Positive control: the unchanged binding still hashes to the golden value.
    expect(hash(binding())).toBe(GOLDEN_HASH);
    expect(hash({ ...binding(), ...override })).not.toBe(GOLDEN_HASH);
  });

  it('changes when one key is added to the arguments', () => {
    const extra = { ...binding(), arguments: { ...binding().arguments, note: 'x' } };
    expect(hash(extra)).not.toBe(GOLDEN_HASH);
  });

  it('hashes 1 and 1.0 the same after JSON.parse', () => {
    const one = JSON.parse(
      '{"orderId":"ORD-1001","expectedVersion":3,"changes":{"status":"held"}}',
    );
    const oneDotZero = JSON.parse(
      '{"orderId":"ORD-1001","expectedVersion":3.0,"changes":{"status":"held"}}',
    );
    expect(hash({ ...binding(), arguments: one })).toBe(
      hash({ ...binding(), arguments: oneDotZero }),
    );
    expect(hash({ ...binding(), arguments: oneDotZero })).toBe(GOLDEN_HASH);
  });

  it('refuses to hash an ambiguous input, with the stable code', () => {
    const attempt = (args: ApprovalActionBinding['arguments']): unknown => {
      try {
        return hash({ ...binding(), arguments: { ...binding().arguments, ...args } });
      } catch (error) {
        return error;
      }
    };
    expect(typeof attempt({ n: 1 })).toBe('string');
    expect(attempt({ n: 1 })).toMatch(/^[0-9a-f]{64}$/);
    for (const [args, code] of [
      [{ n: 2 ** 53 }, 'unsafe_integer'],
      [{ n: -0 }, 'negative_zero'],
      [{ s: 'a\ud800' }, 'lone_surrogate'],
      [{ n: Number.NaN }, 'non_finite_number'],
    ] as const) {
      const error = attempt(args);
      expect(error).toBeInstanceOf(ApprovalInputError);
      expect((error as ApprovalInputError).code).toBe(code);
    }
    expect(() => hash({ ...binding(), expectedResourceVersion: 2 ** 53 })).toThrow(
      ApprovalInputError,
    );
  });

  it('refuses a target or version that differs from the descriptor-named arguments', () => {
    expect(hash(binding())).toBe(GOLDEN_HASH); // positive control
    const refuse = (b: ApprovalActionBinding, names = NAMES): unknown => {
      try {
        return computeActionHash(b, names);
      } catch (error) {
        return error;
      }
    };
    for (const wrong of <ApprovalActionBinding[]>[
      { ...binding(), targetResourceId: 'ORD-1002' },
      { ...binding(), expectedResourceVersion: 4 },
      { ...binding(), expectedResourceVersion: '3' },
      { ...binding(), arguments: { expectedVersion: 3, changes: { status: 'held' } } },
      { ...binding(), arguments: { orderId: 'ORD-1001', changes: { status: 'held' } } },
    ]) {
      const error = refuse(wrong);
      expect(error).toBeInstanceOf(ApprovalInputError);
      expect((error as ApprovalInputError).code).toBe('argument_mismatch');
    }
    // Naming other arguments than the ones the binding was built from is also a mismatch.
    const other = refuse(binding(), { resourceArgument: 'changes', versionArgument: 'orderId' });
    expect((other as ApprovalInputError).code).toBe('argument_mismatch');
  });

  it('verifies only the matching hash', () => {
    expect(verify(binding(), GOLDEN_HASH)).toBe(true);
    expect(verify({ ...binding(), targetResourceId: 'ORD-9' }, GOLDEN_HASH)).toBe(false);
    expect(verify(binding(), GOLDEN_HASH.toUpperCase())).toBe(false);
    expect(verify(binding(), '')).toBe(false);
    expect(verify({ ...binding(), arguments: { n: -0 } }, GOLDEN_HASH)).toBe(false);
  });
});

const jobBase = (): JobArgumentsBinding => ({
  organizationId: ORG,
  agentId: AGENT,
  operation: 'orders.list',
  connectionId: CONNECTION,
  arguments: { status: 'open', limit: 5 },
  policyDecisionId: DECISION,
  timeoutMs: 30_000,
  retrySafe: true,
});

describe('job arguments hash layouts (PE-14)', () => {
  it('leaves layout 1 byte-identical (golden vector from the Phase 3 test)', () => {
    expect(JOB_ARGUMENTS_HASH_DOMAIN).toBe('aab.job-arguments.v1\n');
    const text = jobArgumentsHashInput(jobBase());
    expect(text).toBe(
      'aab.job-arguments.v1\n{"agentId":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","arguments":{"limit":5,"status":"open"},"connectionId":"11111111-1111-4111-8111-111111111111","operation":"orders.list","organizationId":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","policyDecisionId":"dddddddd-dddd-4ddd-8ddd-dddddddddddd","retrySafe":true,"timeoutMs":30000}',
    );
    expect(sha256Hex(text)).toBe(
      '2fc594ff39291fb92295ddf86b18cd01d1b47c5b93a2a6ff5e039f1da79b1410',
    );
  });

  const writeJob = (): JobArgumentsBindingV2 => ({
    organizationId: ORG,
    agentId: AGENT,
    operation: 'orders.applyApprovedUpdate',
    connectionId: CONNECTION,
    arguments: { orderId: 'ORD-1001', expectedVersion: 3, changes: { status: 'held' } },
    policyDecisionId: DECISION,
    timeoutMs: 30_000,
    retrySafe: false,
    approvalRequestId: APPROVAL,
    actionHash: GOLDEN_HASH,
  });
  const readJob = (): JobArgumentsBindingV2 => ({
    ...jobBase(),
    approvalRequestId: null,
    actionHash: null,
  });

  it('has a v2 golden vector for a write, recomputed here (computed once with Python)', () => {
    expect(JOB_ARGUMENTS_HASH_DOMAIN_V2).toBe('aab.job-arguments.v2\n');
    const text =
      'aab.job-arguments.v2\n{"actionHash":"d77a7e5d5c434aa934bb71414f835d976914ed3b4f1bc548ac2a8327a4085d40","agentId":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","approvalRequestId":"ffffffff-ffff-4fff-8fff-ffffffffffff","arguments":{"changes":{"status":"held"},"expectedVersion":3,"orderId":"ORD-1001"},"connectionId":"11111111-1111-4111-8111-111111111111","operation":"orders.applyApprovedUpdate","organizationId":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","policyDecisionId":"dddddddd-dddd-4ddd-8ddd-dddddddddddd","retrySafe":false,"timeoutMs":30000}';
    expect(jobArgumentsHashInputV2(writeJob())).toBe(text);
    expect(computeJobArgumentsHashV2(writeJob())).toBe(
      '60e2656d81e523e914d569e84ecc7ffe9f5f15f94a566f83a9da92ddb86204f1',
    );
    expect(sha256Hex(text)).toBe(computeJobArgumentsHashV2(writeJob()));
  });

  it('has a v2 golden vector for a read, with both approval fields null', () => {
    expect(computeJobArgumentsHashV2(readJob())).toBe(
      'f46c1b2b22a7c88dfa36eb9012ded6049568a6dc5551e2ed1aeb523e80c8ea3f',
    );
  });

  it('never gives a v1 hash and a v2 hash for the same job', () => {
    expect(computeJobArgumentsHashV2(readJob())).not.toBe(
      sha256Hex(jobArgumentsHashInput(jobBase())),
    );
  });

  it('covers the approval id and the action hash', () => {
    const reference = computeJobArgumentsHashV2(writeJob());
    expect(computeJobArgumentsHashV2(writeJob())).toBe(reference);
    expect(
      computeJobArgumentsHashV2({
        ...writeJob(),
        approvalRequestId: '99999999-9999-4999-8999-999999999999',
      }),
    ).not.toBe(reference);
    expect(computeJobArgumentsHashV2({ ...writeJob(), actionHash: 'a'.repeat(64) })).not.toBe(
      reference,
    );
  });

  it('refuses a job bound to only half of an approval, or to a malformed action hash', () => {
    expect(() => computeJobArgumentsHashV2({ ...writeJob(), actionHash: null })).toThrow(TypeError);
    expect(() => computeJobArgumentsHashV2({ ...writeJob(), approvalRequestId: null })).toThrow(
      TypeError,
    );
    expect(() => computeJobArgumentsHashV2({ ...writeJob(), actionHash: 'ABC' })).toThrow(
      TypeError,
    );
    expect(() => computeJobArgumentsHashV2(writeJob())).not.toThrow();
  });

  it('verifies only the matching hash', () => {
    const good = computeJobArgumentsHashV2(writeJob());
    expect(verifyJobArgumentsHashV2(writeJob(), good)).toBe(true);
    expect(verifyJobArgumentsHashV2({ ...writeJob(), retrySafe: true }, good)).toBe(false);
    expect(verifyJobArgumentsHashV2(writeJob(), '')).toBe(false);
  });
});
