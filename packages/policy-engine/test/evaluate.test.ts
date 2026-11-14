import { PolicyDecision, PolicyReasonCode } from '@aab/contracts';
import type { AgentGrant, OperationDescriptor } from '@aab/contracts';
import { describe, expect, it } from 'vitest';
import { evaluate } from '../src/index.js';
import type { EvaluateInput } from '../src/index.js';

/* ---------------------------------------------------------------------------------------------
 * Fixtures (synthetic identifiers only)
 * ------------------------------------------------------------------------------------------ */

const uuid = (n: number): string => `00000000-0000-4000-8000-${n.toString(16).padStart(12, '0')}`;

const AGENT = uuid(0xa1);
const OTHER_AGENT = uuid(0xa2);
const CONNECTION = uuid(0xc1);
const OTHER_CONNECTION = uuid(0xc2);
const OWNER = uuid(0xe1);
const ORG = uuid(0xf1);

const NOW = new Date('2026-11-11T12:00:00.000Z');
const PAST = '2026-11-11T11:59:59.999Z';
const FUTURE = '2026-11-11T12:00:00.001Z';

const LIST: OperationDescriptor = {
  name: 'orders.list',
  sensitivity: 'read',
  requiresApproval: false,
  limitArgument: 'limit',
};
const GET: OperationDescriptor = {
  name: 'orders.get',
  sensitivity: 'read',
  requiresApproval: false,
  resourceArgument: 'orderId',
};
const APPLY: OperationDescriptor = {
  name: 'orders.applyApprovedUpdate',
  sensitivity: 'write',
  requiresApproval: true,
  resourceArgument: 'orderId',
};
const DELETE: OperationDescriptor = {
  name: 'orders.delete',
  sensitivity: 'destructive',
  requiresApproval: false,
  resourceArgument: 'orderId',
};
/** An operation with neither a resource argument nor a limit argument. */
const PING: OperationDescriptor = {
  name: 'session.ping',
  sensitivity: 'read',
  requiresApproval: false,
};

function grant(id: number, overrides: Partial<AgentGrant> = {}): AgentGrant {
  return {
    id: uuid(id),
    agentId: AGENT,
    connectionId: CONNECTION,
    operation: 'orders.list',
    effect: 'allow',
    constraints: {},
    approvalMode: 'none',
    expiresAt: null,
    revokedAt: null,
    createdAt: '2026-11-01T00:00:00.000Z',
    updatedAt: '2026-11-01T00:00:00.000Z',
    ...overrides,
  };
}

/** Build a grant whose stored shape is damaged in a way the type system would not allow. */
function damaged(id: number, overrides: Record<string, unknown>): AgentGrant {
  return { ...grant(id), ...overrides } as unknown as AgentGrant;
}

interface Scenario {
  operation?: OperationDescriptor | undefined;
  args?: Record<string, unknown>;
  request?: unknown;
  grants?: readonly AgentGrant[];
  agent?: Partial<EvaluateInput['agent']>;
  connection?: Partial<EvaluateInput['connection']>;
  now?: Date;
}

function input(scenario: Scenario = {}): EvaluateInput {
  const operation = 'operation' in scenario ? scenario.operation : LIST;
  return {
    request: scenario.request ?? {
      agentId: AGENT,
      connectionId: CONNECTION,
      operation: operation?.name ?? 'orders.list',
      arguments: scenario.args ?? {},
    },
    operation,
    grants: scenario.grants ?? [],
    agent: {
      id: AGENT,
      status: 'active',
      ownerUserId: OWNER,
      organizationId: ORG,
      ...scenario.agent,
    },
    connection: {
      id: CONNECTION,
      status: 'active',
      ownerUserId: OWNER,
      organizationId: ORG,
      ...scenario.connection,
    },
    now: scenario.now ?? NOW,
  };
}

const run = (scenario: Scenario = {}): PolicyDecision => evaluate(input(scenario));

function expectDeny(decision: PolicyDecision, reasonCode: PolicyReasonCode): void {
  expect(decision.outcome).toBe('deny');
  expect(decision.reasonCode).toBe(reasonCode);
  expect(decision.obligations).toEqual({});
}

/* ---------------------------------------------------------------------------------------------
 * Tests
 * ------------------------------------------------------------------------------------------ */

describe('default deny', () => {
  it('denies when there are no grants', () => {
    const decision = run();
    expectDeny(decision, 'no_matching_grant');
    expect(decision.matchedGrantIds).toEqual([]);
  });

  it('allows a request covered by a plain allow grant', () => {
    expect(run({ grants: [grant(1)] })).toEqual({
      outcome: 'allow',
      reasonCode: 'allowed',
      reason: `Allowed by grant ${uuid(1)}.`,
      matchedGrantIds: [uuid(1)],
      obligations: {},
    });
  });

  it('always returns a decision that satisfies the PolicyDecision contract', () => {
    const decisions = [
      run(),
      run({ grants: [grant(1)] }),
      run({ grants: [grant(1, { approvalMode: 'required' })] }),
      run({ grants: [grant(1), grant(2, { effect: 'deny' })] }),
      run({ grants: [grant(1, { constraints: { maxResults: 5 } })] }),
      run({ request: null }),
    ];
    for (const decision of decisions) {
      expect(PolicyDecision.safeParse(decision).success).toBe(true);
    }
  });

  it('can produce every reason code', () => {
    const produced = new Set<string>([
      run({ grants: [grant(1)] }).reasonCode,
      run({ grants: [grant(1, { approvalMode: 'required' })] }).reasonCode,
      run().reasonCode,
      run({ grants: [grant(1, { effect: 'deny' })] }).reasonCode,
      run({ grants: [grant(1, { constraints: { maxResults: 5 } })], args: { limit: 6 } })
        .reasonCode,
      run({ grants: [grant(1)], agent: { status: 'disabled' } }).reasonCode,
      run({ grants: [grant(1)], connection: { status: 'expired' } }).reasonCode,
      run({ grants: [grant(1)], connection: { ownerUserId: uuid(0xe2) } }).reasonCode,
      run({ grants: [grant(1)], operation: undefined }).reasonCode,
      run({ grants: [grant(1)], request: {} }).reasonCode,
    ]);
    expect([...produced].sort()).toEqual([...PolicyReasonCode.options].sort());
  });
});

describe('rule 1: request validation', () => {
  it.each([
    ['null', null],
    ['undefined', undefined],
    ['a string', 'orders.list'],
    ['an array', []],
    ['an empty object', {}],
    ['a missing operation', { agentId: AGENT, connectionId: CONNECTION, arguments: {} }],
    ['missing arguments', { agentId: AGENT, connectionId: CONNECTION, operation: 'orders.list' }],
    [
      'array arguments',
      { agentId: AGENT, connectionId: CONNECTION, operation: 'orders.list', arguments: [] },
    ],
    [
      'a wildcard operation',
      { agentId: AGENT, connectionId: CONNECTION, operation: 'orders.*', arguments: {} },
    ],
    [
      'a non-UUID agent id',
      { agentId: 'agent-1', connectionId: CONNECTION, operation: 'orders.list', arguments: {} },
    ],
    [
      'non-JSON arguments',
      {
        agentId: AGENT,
        connectionId: CONNECTION,
        operation: 'orders.list',
        arguments: { when: new Date(0) },
      },
    ],
  ])('denies %s as invalid_request', (_label, request) => {
    // `undefined` cannot go through the scenario helper, which would substitute a default.
    const decision = evaluate({ ...input({ grants: [grant(1)] }), request });
    expectDeny(decision, 'invalid_request');
  });

  it('denies an invalid evaluation time', () => {
    expectDeny(run({ grants: [grant(1)], now: new Date(Number.NaN) }), 'invalid_request');
    expectDeny(
      evaluate({ ...input({ grants: [grant(1)] }), now: '2026-11-11' as unknown as Date }),
      'invalid_request',
    );
  });
});

describe('rule 2: the request must match the resolved agent and connection', () => {
  it('denies a request naming a different agent than the one resolved', () => {
    const decision = run({
      grants: [grant(1), grant(2, { agentId: OTHER_AGENT })],
      request: {
        agentId: OTHER_AGENT,
        connectionId: CONNECTION,
        operation: 'orders.list',
        arguments: {},
      },
    });
    expectDeny(decision, 'invalid_request');
  });

  it('denies a request naming a different connection than the one resolved', () => {
    const decision = run({
      grants: [grant(1), grant(2, { connectionId: OTHER_CONNECTION })],
      request: {
        agentId: AGENT,
        connectionId: OTHER_CONNECTION,
        operation: 'orders.list',
        arguments: {},
      },
    });
    expectDeny(decision, 'invalid_request');
  });
});

describe('rule 3: the adapter must define the operation', () => {
  it('denies when the adapter has no such operation', () => {
    expectDeny(run({ grants: [grant(1)], operation: undefined }), 'operation_unknown');
  });

  it('denies when the descriptor is for a different operation', () => {
    const decision = run({
      grants: [grant(1)],
      operation: GET,
      request: {
        agentId: AGENT,
        connectionId: CONNECTION,
        operation: 'orders.list',
        arguments: {},
      },
    });
    expectDeny(decision, 'operation_unknown');
  });

  it.each([
    ['null', null],
    ['an incomplete descriptor', { name: 'orders.list' }],
    ['an unknown sensitivity', { ...LIST, sensitivity: 'harmless' }],
    ['a non-boolean requiresApproval', { ...LIST, requiresApproval: 'no' }],
    ['a __proto__ limit argument', { ...LIST, limitArgument: '__proto__' }],
  ])('denies a damaged descriptor: %s', (_label, operation) => {
    const decision = evaluate({
      ...input({ grants: [grant(1)] }),
      operation: operation as unknown as OperationDescriptor,
    });
    expectDeny(decision, 'operation_unknown');
  });
});

describe('rule 4: the agent must be active', () => {
  it.each(['disabled', 'suspended', undefined, null, 1])('denies agent status %s', (status) => {
    const decision = run({ grants: [grant(1)], agent: { status: status as never } });
    expectDeny(decision, 'agent_not_active');
  });
});

describe('rule 5: agent and connection must share owner and organization', () => {
  it('denies a connection owned by another user', () => {
    expectDeny(
      run({ grants: [grant(1)], connection: { ownerUserId: uuid(0xe2) } }),
      'ownership_mismatch',
    );
  });

  it('denies a connection in another organization', () => {
    expectDeny(
      run({ grants: [grant(1)], connection: { organizationId: uuid(0xf2) } }),
      'ownership_mismatch',
    );
  });

  it('does not treat two missing owners as the same owner', () => {
    const decision = run({
      grants: [grant(1)],
      agent: { ownerUserId: undefined as never, organizationId: undefined as never },
      connection: { ownerUserId: undefined as never, organizationId: undefined as never },
    });
    expectDeny(decision, 'ownership_mismatch');
  });
});

describe('rule 6: the connection must be executable', () => {
  it.each(['active', 'degraded'] as const)('runs on a %s connection', (status) => {
    expect(run({ grants: [grant(1)], connection: { status } }).outcome).toBe('allow');
  });

  it.each([
    'created',
    'authentication_required',
    'authenticating',
    'expired',
    'reconnect_required',
    'revoked',
  ] as const)('denies a %s connection', (status) => {
    const decision = run({ grants: [grant(1)], connection: { status } });
    expectDeny(decision, 'connection_not_active');
    expect(decision.reason).toContain(status);
  });

  it('denies an unknown connection status without echoing it', () => {
    const decision = run({ grants: [grant(1)], connection: { status: 'totally-fine' as never } });
    expectDeny(decision, 'connection_not_active');
    expect(decision.reason).not.toContain('totally-fine');
  });
});

describe('check ordering: the first failing rule decides', () => {
  it('reports an unknown operation before an inactive agent', () => {
    expectDeny(run({ operation: undefined, agent: { status: 'disabled' } }), 'operation_unknown');
  });

  it('reports an inactive agent before an ownership mismatch', () => {
    const decision = run({
      agent: { status: 'disabled' },
      connection: { ownerUserId: uuid(0xe2) },
    });
    expectDeny(decision, 'agent_not_active');
  });

  it('reports an ownership mismatch before an inactive connection', () => {
    const decision = run({ connection: { ownerUserId: uuid(0xe2), status: 'revoked' } });
    expectDeny(decision, 'ownership_mismatch');
  });

  it('reports an inactive connection before looking at grants', () => {
    const decision = run({
      grants: [grant(1, { effect: 'deny' })],
      connection: { status: 'revoked' },
    });
    expectDeny(decision, 'connection_not_active');
  });
});

describe('rule 7: only live grants for exactly this agent, connection and operation count', () => {
  it.each([
    ['another agent', { agentId: OTHER_AGENT }],
    ['another connection', { connectionId: OTHER_CONNECTION }],
    ['a different operation', { operation: 'orders.get' }],
    ['a longer lookalike operation', { operation: 'orders.listAll' }],
    ['a shorter lookalike operation', { operation: 'orders.lis' }],
    ['a nested lookalike operation', { operation: 'orders.list.all' }],
    ['a wildcard operation', { operation: 'orders.*' }],
    ['a bare wildcard', { operation: '*' }],
  ])('ignores an allow grant for %s', (_label, overrides) => {
    expectDeny(run({ grants: [grant(1, overrides)] }), 'no_matching_grant');
  });

  it.each([
    ['another agent', { agentId: OTHER_AGENT }],
    ['another connection', { connectionId: OTHER_CONNECTION }],
    ['a different operation', { operation: 'orders.get' }],
    ['a lookalike operation', { operation: 'orders.listAll' }],
  ])('ignores a deny grant for %s', (_label, overrides) => {
    const decision = run({ grants: [grant(1), grant(2, { effect: 'deny', ...overrides })] });
    expect(decision.outcome).toBe('allow');
    expect(decision.matchedGrantIds).toEqual([uuid(1)]);
  });

  it('does not let a grant for orders.list authorize orders.listAll', () => {
    const listAll: OperationDescriptor = { ...LIST, name: 'orders.listAll' };
    expectDeny(run({ operation: listAll, grants: [grant(1)] }), 'no_matching_grant');
  });

  it('ignores a revoked allow grant', () => {
    expectDeny(run({ grants: [grant(1, { revokedAt: PAST })] }), 'no_matching_grant');
  });

  it('ignores an allow grant with any non-null revokedAt, even a future one', () => {
    expectDeny(run({ grants: [grant(1, { revokedAt: FUTURE })] }), 'no_matching_grant');
  });

  it('treats expiry as strictly after now', () => {
    expect(run({ grants: [grant(1, { expiresAt: FUTURE })] }).outcome).toBe('allow');
    expectDeny(run({ grants: [grant(1, { expiresAt: PAST })] }), 'no_matching_grant');
    expectDeny(run({ grants: [grant(1, { expiresAt: NOW.toISOString() })] }), 'no_matching_grant');
  });

  it('ignores revoked and expired deny grants', () => {
    const grants = [
      grant(1),
      grant(2, { effect: 'deny', revokedAt: PAST }),
      grant(3, { effect: 'deny', expiresAt: PAST }),
      grant(4, { effect: 'deny', expiresAt: NOW.toISOString() }),
    ];
    expect(run({ grants }).outcome).toBe('allow');
  });

  it('keeps a deny grant in force until its expiry or revocation has taken effect', () => {
    expectDeny(
      run({ grants: [grant(1), grant(2, { effect: 'deny', expiresAt: FUTURE })] }),
      'explicit_deny',
    );
    expectDeny(
      run({ grants: [grant(1), grant(2, { effect: 'deny', revokedAt: FUTURE })] }),
      'explicit_deny',
    );
  });
});

describe('rule 8: damaged grants fail closed', () => {
  it('ignores an allow grant with an unknown constraint key', () => {
    const decision = run({ grants: [damaged(1, { constraints: { maxResult: 50 } })] });
    expectDeny(decision, 'no_matching_grant');
  });

  it.each([
    ['null constraints', { constraints: null }],
    ['array constraints', { constraints: [] }],
    ['string constraints', { constraints: '{}' }],
    ['a non-positive maxResults', { constraints: { maxResults: 0 } }],
    ['an empty resourceIds list', { constraints: { resourceIds: [] } }],
    ['a non-primitive argumentEquals value', { constraints: { argumentEquals: { a: {} } } }],
    ['an unparseable expiry', { expiresAt: 'tomorrow' }],
    ['a numeric expiry', { expiresAt: NOW.getTime() + 60_000 }],
    ['a missing expiry', { expiresAt: undefined }],
    ['a missing revokedAt', { revokedAt: undefined }],
    ['a false revokedAt', { revokedAt: false }],
    ['an unknown approval mode', { approvalMode: 'optional' }],
    ['a non-UUID id', { id: 'grant-1' }],
  ])('ignores an allow grant with %s', (_label, overrides) => {
    expectDeny(run({ grants: [damaged(1, overrides)] }), 'no_matching_grant');
  });

  it.each([
    ['an unknown constraint key', { constraints: { argumentEqual: { status: 'held' } } }],
    ['null constraints', { constraints: null }],
    ['a __proto__ constraint key', { constraints: JSON.parse('{"__proto__":{"a":1}}') }],
    ['an unparseable expiry', { expiresAt: 'yesterday' }],
    ['an unparseable revokedAt', { revokedAt: 'yes' }],
    ['a missing revokedAt', { revokedAt: undefined }],
  ])('still applies a deny grant with %s', (_label, overrides) => {
    const decision = run({
      grants: [grant(1), damaged(2, { effect: 'deny', ...overrides })],
      args: { status: 'open' },
    });
    expectDeny(decision, 'explicit_deny');
    expect(decision.matchedGrantIds).toEqual([uuid(2)]);
  });

  it('applies a deny grant whose id is unreadable, without reporting the id', () => {
    const decision = run({ grants: [grant(1), damaged(2, { effect: 'deny', id: 'grant-2' })] });
    expectDeny(decision, 'explicit_deny');
    expect(decision.matchedGrantIds).toEqual([]);
  });

  it('treats a targeted grant with an unreadable effect as a deny', () => {
    for (const effect of ['Allow', 'permit', undefined, null, true]) {
      const decision = run({ grants: [grant(1), damaged(2, { effect })] });
      expectDeny(decision, 'explicit_deny');
    }
  });

  it('skips entries that are not objects', () => {
    const grants = [null, undefined, 'allow', 42, [], grant(1)] as unknown as AgentGrant[];
    expect(run({ grants }).outcome).toBe('allow');
    expectDeny(run({ grants: grants.slice(0, 5) }), 'no_matching_grant');
  });
});

describe('rule 9: explicit deny overrides allow', () => {
  it('denies in every ordering of allow and deny grants', () => {
    const allowA = grant(1);
    const allowB = grant(2, { approvalMode: 'required' });
    const denyGrant = grant(3, { effect: 'deny' });
    const orderings = [
      [allowA, allowB, denyGrant],
      [allowA, denyGrant, allowB],
      [denyGrant, allowA, allowB],
      [allowB, allowA, denyGrant],
      [allowB, denyGrant, allowA],
      [denyGrant, allowB, allowA],
    ];
    for (const grants of orderings) {
      const decision = run({ grants });
      expectDeny(decision, 'explicit_deny');
      expect(decision.matchedGrantIds).toEqual([uuid(3)]);
    }
  });

  it('denies even without any allow grant', () => {
    expectDeny(run({ grants: [grant(1, { effect: 'deny' })] }), 'explicit_deny');
  });

  it('reports every applying deny grant, sorted', () => {
    const decision = run({
      grants: [
        grant(9, { effect: 'deny' }),
        grant(1),
        grant(4, { effect: 'deny' }),
        grant(6, { effect: 'deny', constraints: { argumentEquals: { status: 'shipped' } } }),
      ],
      args: { status: 'held' },
    });
    expectDeny(decision, 'explicit_deny');
    expect(decision.matchedGrantIds).toEqual([uuid(4), uuid(9)]);
  });

  it('ignores the approval mode of a deny grant', () => {
    expectDeny(
      run({ grants: [grant(1), grant(2, { effect: 'deny', approvalMode: 'required' })] }),
      'explicit_deny',
    );
  });

  describe('constrained deny grants', () => {
    const allow = grant(1);

    it('blocks when argumentEquals matches', () => {
      const denyHeld = grant(2, {
        effect: 'deny',
        constraints: { argumentEquals: { status: 'held' } },
      });
      expectDeny(run({ grants: [allow, denyHeld], args: { status: 'held' } }), 'explicit_deny');
    });

    it('does not block when argumentEquals clearly does not match', () => {
      const denyHeld = grant(2, {
        effect: 'deny',
        constraints: { argumentEquals: { status: 'held' } },
      });
      expect(run({ grants: [allow, denyHeld], args: { status: 'open' } }).outcome).toBe('allow');
      // No type coercion in either direction.
      const denyOne = grant(3, { effect: 'deny', constraints: { argumentEquals: { page: 1 } } });
      expect(run({ grants: [allow, denyOne], args: { page: '1' } }).outcome).toBe('allow');
    });

    it('blocks when the constrained argument is absent, because the default is unknown', () => {
      const denyHeld = grant(2, {
        effect: 'deny',
        constraints: { argumentEquals: { status: 'held' } },
      });
      expectDeny(run({ grants: [allow, denyHeld], args: {} }), 'explicit_deny');
    });

    it('applies argumentOneOf as a predicate', () => {
      const denySome = grant(2, {
        effect: 'deny',
        constraints: { argumentOneOf: { status: ['held', 'cancelled'] } },
      });
      expectDeny(
        run({ grants: [allow, denySome], args: { status: 'cancelled' } }),
        'explicit_deny',
      );
      expect(run({ grants: [allow, denySome], args: { status: 'open' } }).outcome).toBe('allow');
    });

    it('requires every predicate of the deny to hold', () => {
      const denyBoth = grant(2, {
        effect: 'deny',
        constraints: {
          argumentEquals: { status: 'held' },
          argumentOneOf: { region: ['eu', 'us'] },
        },
      });
      expectDeny(
        run({ grants: [allow, denyBoth], args: { status: 'held', region: 'eu' } }),
        'explicit_deny',
      );
      expect(
        run({ grants: [allow, denyBoth], args: { status: 'held', region: 'apac' } }).outcome,
      ).toBe('allow');
    });

    it('applies resourceIds to the operation resource argument', () => {
      const allowGet = grant(1, { operation: 'orders.get' });
      const denyOne = grant(2, {
        operation: 'orders.get',
        effect: 'deny',
        constraints: { resourceIds: ['NS-1001'] },
      });
      expectDeny(
        run({ operation: GET, grants: [allowGet, denyOne], args: { orderId: 'NS-1001' } }),
        'explicit_deny',
      );
      expect(
        run({ operation: GET, grants: [allowGet, denyOne], args: { orderId: 'NS-1002' } }).outcome,
      ).toBe('allow');
    });

    it('blocks when a resourceIds deny cannot be evaluated for the operation', () => {
      const denyOne = grant(2, { effect: 'deny', constraints: { resourceIds: ['NS-1001'] } });
      // orders.list has no resource argument, so the deny cannot be narrowed.
      expectDeny(run({ grants: [allow, denyOne], args: { orderId: 'NS-1002' } }), 'explicit_deny');
    });

    it('does not let maxResults narrow a deny', () => {
      const denyCapped = grant(2, { effect: 'deny', constraints: { maxResults: 5 } });
      expectDeny(run({ grants: [allow, denyCapped], args: { limit: 500 } }), 'explicit_deny');
    });
  });
});

describe('rule 10: allow constraints', () => {
  describe('argumentEquals', () => {
    const held = grant(1, { constraints: { argumentEquals: { status: 'held', archived: false } } });

    it('is satisfied when every named argument is strictly equal', () => {
      const decision = run({ grants: [held], args: { status: 'held', archived: false, page: 2 } });
      expect(decision.outcome).toBe('allow');
    });

    it.each([
      ['a different value', { status: 'open', archived: false }],
      ['a missing argument', { status: 'held' }],
      ['a string instead of a boolean', { status: 'held', archived: 'false' }],
      ['null instead of false', { status: 'held', archived: null }],
      ['a different case', { status: 'HELD', archived: false }],
      ['an array wrapping the value', { status: ['held'], archived: false }],
    ])('is violated by %s', (_label, args) => {
      const decision = run({ grants: [held], args });
      expectDeny(decision, 'constraint_violation');
      expect(decision.matchedGrantIds).toEqual([uuid(1)]);
    });

    it('does not coerce numbers and strings', () => {
      const numeric = grant(1, { constraints: { argumentEquals: { page: 1 } } });
      expect(run({ grants: [numeric], args: { page: 1 } }).outcome).toBe('allow');
      expectDeny(run({ grants: [numeric], args: { page: '1' } }), 'constraint_violation');
      expectDeny(run({ grants: [numeric], args: { page: true } }), 'constraint_violation');
    });

    it('can require an explicit null', () => {
      const nullOnly = grant(1, { constraints: { argumentEquals: { cursor: null } } });
      expect(run({ grants: [nullOnly], args: { cursor: null } }).outcome).toBe('allow');
      expectDeny(run({ grants: [nullOnly], args: {} }), 'constraint_violation');
    });

    it('is not satisfied by an inherited property name', () => {
      const inherited = grant(1, { constraints: { argumentOneOf: { toString: ['x'] } } });
      expectDeny(run({ grants: [inherited], args: {} }), 'constraint_violation');
    });
  });

  describe('argumentOneOf', () => {
    const some = grant(1, { constraints: { argumentOneOf: { status: ['held', 'open'] } } });

    it('is satisfied by any listed value', () => {
      expect(run({ grants: [some], args: { status: 'held' } }).outcome).toBe('allow');
      expect(run({ grants: [some], args: { status: 'open' } }).outcome).toBe('allow');
    });

    it.each([
      ['an unlisted value', { status: 'shipped' }],
      ['a missing argument', {}],
      ['an array of listed values', { status: ['held', 'open'] }],
      ['an object', { status: { eq: 'held' } }],
    ])('is violated by %s', (_label, args) => {
      expectDeny(run({ grants: [some], args }), 'constraint_violation');
    });
  });

  describe('resourceIds', () => {
    const two = grant(1, {
      operation: 'orders.get',
      constraints: { resourceIds: ['NS-1001', 'NS-1002'] },
    });

    it('is satisfied when the resource argument is a listed id', () => {
      const decision = run({ operation: GET, grants: [two], args: { orderId: 'NS-1002' } });
      expect(decision.outcome).toBe('allow');
    });

    it.each([
      ['an unlisted id', { orderId: 'NS-1003' }],
      ['a missing resource argument', {}],
      ['a prefix of a listed id', { orderId: 'NS-100' }],
      ['a listed id with trailing space', { orderId: 'NS-1001 ' }],
      ['a numeric id', { orderId: 1001 }],
      ['an array of listed ids', { orderId: ['NS-1001'] }],
      ['the id under a different argument name', { id: 'NS-1001' }],
    ])('is violated by %s', (_label, args) => {
      expectDeny(run({ operation: GET, grants: [two], args }), 'constraint_violation');
    });

    it('cannot be satisfied when the operation declares no resource argument', () => {
      const decision = run({
        grants: [grant(1, { constraints: { resourceIds: ['NS-1001'] } })],
        args: { orderId: 'NS-1001' },
      });
      expectDeny(decision, 'constraint_violation');
    });
  });

  describe('maxResults', () => {
    const capped = grant(1, { constraints: { maxResults: 50 } });

    it.each([1, 25, 50])('allows a limit of %d without an obligation', (limit) => {
      const decision = run({ grants: [capped], args: { limit } });
      expect(decision.outcome).toBe('allow');
      expect(decision.obligations).toEqual({});
    });

    it.each([
      ['one above the cap', 51],
      ['zero', 0],
      ['negative', -1],
      ['a numeric string', '5'],
      ['fractional', 2.5],
      ['null', null],
      ['a boolean', true],
      ['an array', [5]],
    ])('rejects a limit that is %s', (_label, limit) => {
      const decision = run({ grants: [capped], args: { limit } });
      expectDeny(decision, 'constraint_violation');
      expect(decision.matchedGrantIds).toEqual([uuid(1)]);
    });

    it('adds a clamping obligation when the request omits the limit', () => {
      const decision = run({ grants: [capped], args: { status: 'held' } });
      expect(decision.outcome).toBe('allow');
      expect(decision.obligations).toEqual({ limit: 50 });
      expect(decision.reason).toContain('capped');
    });

    it('uses the limit argument named by the operation', () => {
      const paged: OperationDescriptor = { ...LIST, limitArgument: 'pageSize' };
      expect(run({ operation: paged, grants: [capped], args: {} }).obligations).toEqual({
        pageSize: 50,
      });
      // `limit` is not this operation's limit argument, so it is not checked against the cap.
      const decision = run({ operation: paged, grants: [capped], args: { limit: 9999 } });
      expect(decision.obligations).toEqual({ pageSize: 50 });
      expectDeny(
        run({ operation: paged, grants: [capped], args: { pageSize: 51 } }),
        'constraint_violation',
      );
    });

    it('cannot be satisfied when the operation declares no limit argument', () => {
      const decision = run({
        operation: PING,
        grants: [grant(1, { operation: 'session.ping', constraints: { maxResults: 50 } })],
      });
      expectDeny(decision, 'constraint_violation');
    });
  });

  it('requires all constraints of one grant to hold together', () => {
    const combined = grant(1, {
      constraints: { maxResults: 10, argumentEquals: { status: 'held' } },
    });
    expect(run({ grants: [combined], args: { status: 'held', limit: 10 } }).outcome).toBe('allow');
    expectDeny(
      run({ grants: [combined], args: { status: 'held', limit: 11 } }),
      'constraint_violation',
    );
    expectDeny(
      run({ grants: [combined], args: { status: 'open', limit: 10 } }),
      'constraint_violation',
    );
  });

  it('does not combine constraints across grants to widen authority', () => {
    // Neither grant alone covers { status: 'open', limit: 100 }.
    const grants = [
      grant(1, { constraints: { argumentEquals: { status: 'held' } } }),
      grant(2, { constraints: { maxResults: 10 } }),
    ];
    const decision = run({ grants, args: { status: 'open', limit: 100 } });
    expectDeny(decision, 'constraint_violation');
    expect(decision.matchedGrantIds).toEqual([uuid(1), uuid(2)]);
  });

  it('allows when any one grant is satisfied', () => {
    const grants = [
      grant(1, { constraints: { argumentEquals: { status: 'held' } } }),
      grant(2, { constraints: { argumentEquals: { status: 'open' } } }),
    ];
    const decision = run({ grants, args: { status: 'open' } });
    expect(decision.outcome).toBe('allow');
    expect(decision.matchedGrantIds).toEqual([uuid(2)]);
  });
});

describe('rule 11: approval and grant selection', () => {
  it('requires approval when the only satisfied grant requires it', () => {
    const decision = run({ grants: [grant(1, { approvalMode: 'required' })] });
    expect(decision).toMatchObject({
      outcome: 'approval_required',
      reasonCode: 'approval_required',
      matchedGrantIds: [uuid(1)],
      obligations: {},
    });
    expect(decision.reason).toContain('the grant requires approval');
  });

  it('allows without approval when any satisfied grant does not require it', () => {
    const grants = [grant(1, { approvalMode: 'required' }), grant(2)];
    const decision = run({ grants });
    expect(decision.outcome).toBe('allow');
    expect(decision.matchedGrantIds).toEqual([uuid(2)]);
  });

  it('does not count an unsatisfied no-approval grant', () => {
    const grants = [
      grant(1, { approvalMode: 'required' }),
      grant(2, { constraints: { argumentEquals: { status: 'held' } } }),
    ];
    const decision = run({ grants, args: { status: 'open' } });
    expect(decision.outcome).toBe('approval_required');
    expect(decision.matchedGrantIds).toEqual([uuid(1)]);
  });

  it('never allows an operation that always requires approval', () => {
    const grants = [
      grant(1, { operation: APPLY.name }),
      grant(2, { operation: APPLY.name, approvalMode: 'required' }),
    ];
    const decision = run({ operation: APPLY, grants, args: { orderId: 'NS-1001' } });
    expect(decision.outcome).toBe('approval_required');
    expect(decision.reasonCode).toBe('approval_required');
    expect(decision.matchedGrantIds).toEqual([uuid(1)]);
    expect(decision.reason).toContain('always requires approval');
  });

  it('never allows a destructive operation', () => {
    const decision = run({
      operation: DELETE,
      grants: [grant(1, { operation: DELETE.name })],
      args: { orderId: 'NS-1001' },
    });
    expect(decision.outcome).toBe('approval_required');
    expect(decision.reason).toContain('destructive');
  });

  it('never returns allow for forced-approval operations under any grant mix', () => {
    for (const operation of [APPLY, DELETE, { ...DELETE, requiresApproval: true }]) {
      const pool = [
        grant(1, { operation: operation.name }),
        grant(2, { operation: operation.name, approvalMode: 'required' }),
        grant(3, { operation: operation.name, constraints: { resourceIds: ['NS-1001'] } }),
        grant(4, { operation: operation.name, expiresAt: FUTURE }),
      ];
      for (let mask = 0; mask < 1 << pool.length; mask += 1) {
        const grants = pool.filter((_grant, index) => (mask & (1 << index)) !== 0);
        const decision = run({ operation, grants, args: { orderId: 'NS-1001' } });
        expect(decision.outcome).not.toBe('allow');
      }
    }
  });

  it('still denies a forced-approval operation that has no grant', () => {
    expectDeny(run({ operation: DELETE, args: { orderId: 'NS-1001' } }), 'no_matching_grant');
  });

  it('prefers a grant that imposes no obligation', () => {
    const grants = [grant(1, { constraints: { maxResults: 10 } }), grant(2)];
    const decision = run({ grants });
    expect(decision.matchedGrantIds).toEqual([uuid(2)]);
    expect(decision.obligations).toEqual({});
  });

  it('breaks ties by the smallest grant id', () => {
    const grants = [grant(7), grant(3), grant(5)];
    expect(run({ grants }).matchedGrantIds).toEqual([uuid(3)]);
  });

  it('takes obligations from the chosen grant only', () => {
    const grants = [
      grant(5, { constraints: { maxResults: 10 } }),
      grant(2, { constraints: { maxResults: 99 } }),
    ];
    const decision = run({ grants });
    expect(decision.matchedGrantIds).toEqual([uuid(2)]);
    expect(decision.obligations).toEqual({ limit: 99 });
  });

  it('prefers a no-approval grant even when it carries an obligation', () => {
    const grants = [
      grant(1, { approvalMode: 'required' }),
      grant(2, { constraints: { maxResults: 10 } }),
    ];
    const decision = run({ grants });
    expect(decision.outcome).toBe('allow');
    expect(decision.matchedGrantIds).toEqual([uuid(2)]);
    expect(decision.obligations).toEqual({ limit: 10 });
  });

  it('carries the obligation on an approval_required decision', () => {
    const decision = run({
      grants: [grant(1, { approvalMode: 'required', constraints: { maxResults: 10 } })],
    });
    expect(decision.outcome).toBe('approval_required');
    expect(decision.obligations).toEqual({ limit: 10 });
  });
});

describe('determinism', () => {
  /** Small seeded PRNG so failures are reproducible. */
  function mulberry32(seed: number): () => number {
    let state = seed >>> 0;
    return () => {
      state = (state + 0x6d2b79f5) >>> 0;
      let t = state;
      t = Math.imul(t ^ (t >>> 15), t | 1);
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  function shuffled<T>(items: readonly T[], random: () => number): T[] {
    const copy = [...items];
    for (let i = copy.length - 1; i > 0; i -= 1) {
      const j = Math.floor(random() * (i + 1));
      [copy[i], copy[j]] = [copy[j]!, copy[i]!];
    }
    return copy;
  }

  const noise = [
    grant(20, { agentId: OTHER_AGENT }),
    grant(21, { connectionId: OTHER_CONNECTION, effect: 'deny' }),
    grant(22, { operation: 'orders.listAll', effect: 'deny' }),
    grant(23, { revokedAt: PAST }),
    grant(24, { expiresAt: PAST, effect: 'deny' }),
    damaged(25, { constraints: { surprise: true } }),
  ];

  const sets: [string, AgentGrant[], Record<string, unknown>][] = [
    [
      'allow',
      [
        ...noise,
        grant(1, { constraints: { maxResults: 10 } }),
        grant(2, { approvalMode: 'required' }),
        grant(3, { constraints: { argumentEquals: { status: 'held' } } }),
        grant(4, { constraints: { maxResults: 99 } }),
        grant(5, { constraints: { argumentEquals: { status: 'open' } } }),
        grant(6, { effect: 'deny', constraints: { argumentEquals: { status: 'shipped' } } }),
      ],
      { status: 'held' },
    ],
    [
      'approval_required',
      [
        ...noise,
        grant(8, { approvalMode: 'required', constraints: { maxResults: 10 } }),
        grant(7, { approvalMode: 'required', constraints: { maxResults: 20 } }),
        grant(9, { constraints: { argumentEquals: { status: 'open' } } }),
      ],
      { status: 'held' },
    ],
    [
      'explicit_deny',
      [
        ...noise,
        grant(1),
        grant(12, { effect: 'deny' }),
        grant(11, { effect: 'deny', constraints: { argumentOneOf: { status: ['held'] } } }),
        damaged(10, { effect: 'deny', constraints: 'broken' }),
      ],
      { status: 'held' },
    ],
    [
      'constraint_violation',
      [
        ...noise,
        grant(14, { constraints: { argumentEquals: { status: 'open' } } }),
        grant(13, { constraints: { maxResults: 5 } }),
        grant(15, { constraints: { resourceIds: ['NS-1001'] } }),
      ],
      { status: 'held', limit: 6 },
    ],
  ];

  it.each(sets)('gives the same %s decision for any grant order', (expected, grants, args) => {
    const baseline = run({ grants, args });
    expect(baseline.reasonCode === 'allowed' ? 'allow' : baseline.reasonCode).toBe(expected);

    const random = mulberry32(0xaab);
    for (let round = 0; round < 250; round += 1) {
      expect(run({ grants: shuffled(grants, random), args })).toEqual(baseline);
    }
    expect(run({ grants: [...grants].reverse(), args })).toEqual(baseline);
  });

  it('is unaffected by duplicated grants', () => {
    const grants = [grant(1), grant(1), grant(2, { effect: 'deny' }), grant(2, { effect: 'deny' })];
    const decision = run({ grants });
    expectDeny(decision, 'explicit_deny');
    expect(decision.matchedGrantIds).toEqual([uuid(2)]);
  });

  it('does not mutate its input', () => {
    const scenario = input({
      grants: [grant(1, { constraints: { maxResults: 10 } }), grant(2, { effect: 'deny' })],
      args: { status: 'held' },
    });
    const snapshot = structuredClone(scenario);
    evaluate(scenario);
    expect(scenario).toEqual(snapshot);
  });
});

describe('robustness: garbage never throws and never allows', () => {
  const garbage: unknown[] = [
    null,
    undefined,
    0,
    '',
    'allow',
    [],
    {},
    { request: null },
    { request: {}, grants: null },
    { request: {}, operation: LIST, grants: [], agent: null, connection: null, now: null },
    { ...input({ grants: [grant(1)] }), agent: null },
    { ...input({ grants: [grant(1)] }), connection: 'active' },
    { ...input({ grants: [grant(1)] }), grants: null },
    { ...input({ grants: [grant(1)] }), grants: { 0: grant(1), length: 1 } },
    { ...input({ grants: [grant(1)] }), now: null },
    { ...input({ grants: [grant(1)] }), agent: [] },
  ];

  it.each(garbage.map((value, index) => [index, value] as const))(
    'denies malformed input #%d',
    (_index, value) => {
      let decision: PolicyDecision | undefined;
      expect(() => {
        decision = evaluate(value as EvaluateInput);
      }).not.toThrow();
      expect(decision?.outcome).toBe('deny');
      expect(decision?.obligations).toEqual({});
      expect(PolicyDecision.safeParse(decision).success).toBe(true);
    },
  );

  it('denies when reading the input throws', () => {
    const hostile = input({ grants: [grant(1)] });
    Object.defineProperty(hostile, 'grants', {
      get() {
        throw new Error('boom');
      },
    });
    expectDeny(evaluate(hostile), 'invalid_request');

    const hostileGrant = grant(1);
    Object.defineProperty(hostileGrant, 'effect', {
      get() {
        throw new Error('boom');
      },
    });
    expectDeny(run({ grants: [hostileGrant] }), 'invalid_request');
  });

  it('denies a cyclic request without hanging', () => {
    const args: Record<string, unknown> = {};
    args.self = args;
    expectDeny(run({ grants: [grant(1)], args }), 'invalid_request');
  });

  it('denies extremely deep arguments instead of overflowing the stack', () => {
    let nested: unknown = 'leaf';
    for (let depth = 0; depth < 100_000; depth += 1) nested = { next: nested };
    const decision = run({ grants: [grant(1)], args: { nested } });
    expect(decision.outcome).toBe('deny');
  });

  describe('prototype pollution', () => {
    it('denies arguments carrying a __proto__ key', () => {
      const args = JSON.parse('{"__proto__":{"status":"held"},"limit":5}') as Record<
        string,
        unknown
      >;
      expectDeny(run({ grants: [grant(1)], args }), 'invalid_request');
    });

    it('denies a nested __proto__ key', () => {
      const args = JSON.parse('{"filter":{"deep":[{"__proto__":{"admin":true}}]}}') as Record<
        string,
        unknown
      >;
      expectDeny(run({ grants: [grant(1)], args }), 'invalid_request');
    });

    it('denies a request object carrying a __proto__ key', () => {
      const request = JSON.parse(
        `{"__proto__":{"arguments":{}},"agentId":"${AGENT}","connectionId":"${CONNECTION}","operation":"orders.list","arguments":{}}`,
      ) as unknown;
      expectDeny(run({ grants: [grant(1)], request }), 'invalid_request');
    });

    it('does not let inherited argument values satisfy a constraint', () => {
      const args = Object.create({ status: 'held' }) as Record<string, unknown>;
      const held = grant(1, { constraints: { argumentEquals: { status: 'held' } } });
      expect(run({ grants: [held], args }).outcome).toBe('deny');
    });

    it('ignores an allow grant whose constraints carry a __proto__ key', () => {
      const constraints = JSON.parse('{"__proto__":{"maxResults":5}}') as unknown;
      expectDeny(run({ grants: [damaged(1, { constraints })] }), 'no_matching_grant');

      const nested = JSON.parse('{"argumentEquals":{"__proto__":"x"}}') as unknown;
      expectDeny(run({ grants: [damaged(1, { constraints: nested })] }), 'no_matching_grant');
    });

    it('leaves Object.prototype untouched', () => {
      const args = JSON.parse(
        '{"__proto__":{"polluted":true},"constructor":{"prototype":{"polluted":true}}}',
      );
      run({
        grants: [grant(1, { constraints: JSON.parse('{"__proto__":{"polluted":true}}') })],
        args,
      });
      expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    });

    it('treats constructor and prototype as ordinary argument names', () => {
      const decision = run({ grants: [grant(1)], args: { constructor: 'x', prototype: 'y' } });
      expect(decision.outcome).toBe('allow');
    });
  });
});

describe('reasons never leak argument values', () => {
  const SENTINEL = 'SENTINEL-7f3c-customer-secret';

  const scenarios: [string, Scenario][] = [
    ['allow', { grants: [grant(1)] }],
    ['allow with obligation', { grants: [grant(1, { constraints: { maxResults: 5 } })] }],
    ['approval_required', { grants: [grant(1, { approvalMode: 'required' })] }],
    ['no_matching_grant', {}],
    ['explicit_deny', { grants: [grant(1), grant(2, { effect: 'deny' })] }],
    [
      'constrained explicit_deny',
      {
        grants: [
          grant(1),
          grant(2, { effect: 'deny', constraints: { argumentEquals: { note: SENTINEL } } }),
        ],
      },
    ],
    [
      'constraint_violation',
      { grants: [grant(1, { constraints: { argumentEquals: { note: 'something else' } } })] },
    ],
    ['agent_not_active', { grants: [grant(1)], agent: { status: 'disabled' } }],
    ['connection_not_active', { grants: [grant(1)], connection: { status: 'expired' } }],
    ['ownership_mismatch', { grants: [grant(1)], connection: { organizationId: uuid(0xf2) } }],
    ['operation_unknown', { grants: [grant(1)], operation: undefined }],
  ];

  it.each(scenarios)('%s', (_label, scenario) => {
    const decision = run({
      ...scenario,
      args: { note: SENTINEL, nested: { inner: SENTINEL }, list: [SENTINEL] },
    });
    expect(JSON.stringify(decision)).not.toContain(SENTINEL);
  });

  it('does not echo a malformed request', () => {
    const decision = run({
      request: {
        agentId: SENTINEL,
        connectionId: SENTINEL,
        operation: SENTINEL,
        arguments: SENTINEL,
      },
    });
    expectDeny(decision, 'invalid_request');
    expect(JSON.stringify(decision)).not.toContain(SENTINEL);
  });

  it('names the deciding grants in the reason', () => {
    expect(run({ grants: [grant(1)] }).reason).toContain(uuid(1));
    const denied = run({
      grants: [grant(1), grant(2, { effect: 'deny' }), grant(3, { effect: 'deny' })],
    });
    expect(denied.reason).toContain(uuid(2));
    expect(denied.reason).toContain(uuid(3));
    const violated = run({
      grants: [grant(4, { constraints: { maxResults: 1 } })],
      args: { limit: 2 },
    });
    expect(violated.reason).toContain(uuid(4));
  });
});
