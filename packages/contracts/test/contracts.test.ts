import { describe, expect, it } from 'vitest';
import {
  canTransitionConnection,
  canonicalJson,
  ConnectionStatus,
  CreateGrantRequest,
  GrantConstraints,
  isConnectionExecutable,
  JOB_ARGUMENTS_HASH_DOMAIN,
  jobArgumentsHashInput,
  OperationName,
  Origin,
} from '../src/index.js';
import type { JobArgumentsBinding } from '../src/index.js';

describe('canonicalJson', () => {
  it('sorts keys at every depth and drops whitespace', () => {
    expect(canonicalJson({ b: 1, a: { d: [3, { z: 1, y: 2 }], c: null } })).toBe(
      '{"a":{"c":null,"d":[3,{"y":2,"z":1}]},"b":1}',
    );
  });

  it('is independent of key insertion order', () => {
    expect(canonicalJson({ x: 1, y: 'two' })).toBe(canonicalJson({ y: 'two', x: 1 }));
  });

  it('distinguishes values that loose serializers conflate', () => {
    expect(canonicalJson({ a: '1' })).not.toBe(canonicalJson({ a: 1 }));
    expect(canonicalJson([])).not.toBe(canonicalJson({}));
  });

  it.each([
    ['undefined member', { a: undefined }],
    ['NaN', { a: Number.NaN }],
    ['Infinity', [Number.POSITIVE_INFINITY]],
    ['bigint', { a: 1n }],
    ['Date', { a: new Date(0) }],
    ['Map', new Map()],
    ['function', { a: () => 1 }],
  ])('rejects %s instead of coercing it', (_label, value) => {
    expect(() => canonicalJson(value)).toThrow(TypeError);
  });

  it('rejects cycles but allows repeated references', () => {
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    expect(() => canonicalJson(cyclic)).toThrow(/cyclic/);

    const shared = { n: 1 };
    expect(canonicalJson({ a: shared, b: shared })).toBe('{"a":{"n":1},"b":{"n":1}}');
  });
});

describe('connection lifecycle', () => {
  it('follows the documented happy path', () => {
    const path: ConnectionStatus[] = [
      'created',
      'authentication_required',
      'authenticating',
      'active',
      'expired',
      'reconnect_required',
      'authenticating',
      'active',
      'revoked',
    ];
    for (let i = 0; i < path.length - 1; i += 1) {
      expect(canTransitionConnection(path[i]!, path[i + 1]!)).toBe(true);
    }
  });

  it('treats revoked as terminal', () => {
    for (const status of ConnectionStatus.options) {
      expect(canTransitionConnection('revoked', status)).toBe(false);
    }
  });

  it('can be revoked from every non-terminal state', () => {
    for (const status of ConnectionStatus.options.filter((s) => s !== 'revoked')) {
      expect(canTransitionConnection(status, 'revoked')).toBe(true);
    }
  });

  it('does not let a connection become active without authenticating', () => {
    expect(canTransitionConnection('created', 'active')).toBe(false);
    expect(canTransitionConnection('expired', 'active')).toBe(false);
    expect(canTransitionConnection('reconnect_required', 'active')).toBe(false);
  });

  it('only executes on active or degraded connections', () => {
    expect(ConnectionStatus.options.filter(isConnectionExecutable)).toEqual(['active', 'degraded']);
  });
});

describe('Origin', () => {
  it.each([
    'https://app.example.com',
    'https://app.example.com:8443',
    'http://localhost:4100',
    'http://127.0.0.1:4100',
  ])('accepts %s', (origin) => {
    expect(Origin.safeParse(origin).success).toBe(true);
  });

  it.each([
    'http://app.example.com',
    'https://app.example.com/',
    'https://app.example.com/path',
    'https://user:pw@app.example.com',
    'javascript:alert(1)',
    'file:///etc/passwd',
    'app.example.com',
    'https://*.example.com',
  ])('rejects %s', (origin) => {
    expect(Origin.safeParse(origin).success).toBe(false);
  });
});

describe('grants', () => {
  it('accepts well-formed operation names only', () => {
    expect(OperationName.safeParse('orders.applyApprovedUpdate').success).toBe(true);
    for (const bad of [
      'orders',
      'Orders.list',
      'orders..list',
      'orders.list;drop',
      '*',
      'orders.*',
    ]) {
      expect(OperationName.safeParse(bad).success).toBe(false);
    }
  });

  it('rejects unknown constraint keys rather than ignoring them', () => {
    expect(GrantConstraints.safeParse({ maxResults: 50 }).success).toBe(true);
    expect(GrantConstraints.safeParse({ maxResult: 50 }).success).toBe(false);
  });

  it('defaults a grant to allow with no approval and no constraints', () => {
    const grant = CreateGrantRequest.parse({
      connectionId: '0b9f6f0e-2f0b-4c8e-9d43-0d9c1b1f7a11',
      operation: 'orders.list',
    });
    expect(grant).toMatchObject({ effect: 'allow', approvalMode: 'none', constraints: {} });
  });
});

describe('jobArgumentsHashInput (PE-14)', () => {
  const connectionId = '11111111-1111-4111-8111-111111111111';
  const organizationId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  const agentId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  const policyDecisionId = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
  const binding = (overrides: Partial<JobArgumentsBinding> = {}): JobArgumentsBinding => ({
    organizationId,
    agentId,
    connectionId,
    operation: 'orders.list',
    arguments: { b: 1, a: 2 },
    policyDecisionId,
    timeoutMs: 30_000,
    retrySafe: true,
    ...overrides,
  });

  it('is the versioned prefix followed by one canonical object of all eight fields', () => {
    expect(JOB_ARGUMENTS_HASH_DOMAIN).toBe('aab.job-arguments.v1\n');
    expect(jobArgumentsHashInput(binding())).toBe(
      `aab.job-arguments.v1\n{"agentId":"${agentId}","arguments":{"a":2,"b":1},"connectionId":"${connectionId}","operation":"orders.list","organizationId":"${organizationId}","policyDecisionId":"${policyDecisionId}","retrySafe":true,"timeoutMs":30000}`,
    );
  });

  it('writes a missing decision id as null, a boolean as a boolean and a timeout as a number', () => {
    const parsed = JSON.parse(
      jobArgumentsHashInput(binding({ policyDecisionId: null, retrySafe: false })).slice(
        JOB_ARGUMENTS_HASH_DOMAIN.length,
      ),
    ) as Record<string, unknown>;
    expect(parsed.policyDecisionId).toBeNull();
    expect(parsed.retrySafe).toBe(false);
    expect(parsed.timeoutMs).toBe(30_000);
  });

  it('escapes field values, so text cannot move from one field into another', () => {
    const input = jobArgumentsHashInput(
      binding({ operation: 'x","connectionId":"other', arguments: {} }),
    );
    expect(JSON.parse(input.slice(JOB_ARGUMENTS_HASH_DOMAIN.length))).toEqual({
      agentId,
      arguments: {},
      connectionId,
      operation: 'x","connectionId":"other',
      organizationId,
      policyDecisionId,
      retrySafe: true,
      timeoutMs: 30_000,
    });
  });

  it('refuses arguments that are not plain JSON', () => {
    expect(() => jobArgumentsHashInput(binding({ arguments: { n: Number.NaN } }))).toThrow(
      TypeError,
    );
  });
});
