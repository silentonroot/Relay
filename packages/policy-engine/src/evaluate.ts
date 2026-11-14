import {
  ConnectionStatus,
  GrantConstraints,
  IsoDateTime,
  isConnectionExecutable,
  OperationDescriptor,
  PolicyRequest,
  Uuid,
} from '@aab/contracts';
import type {
  AgentGrant,
  EntityStatus,
  JsonObject,
  PolicyDecision,
  PolicyReasonCode,
} from '@aab/contracts';

/** The agent making the request, as loaded by the caller from the registry. */
export interface PolicyAgent {
  id: string;
  status: EntityStatus;
  ownerUserId: string;
  organizationId: string;
}

/** The connection the request targets, as loaded by the caller from the registry. */
export interface PolicyConnection {
  id: string;
  status: ConnectionStatus;
  ownerUserId: string;
  organizationId: string;
}

export interface EvaluateInput {
  /** The agent's raw request. Validated here; the caller does not need to pre-validate it. */
  request: unknown;
  /** The adapter's descriptor for the requested operation, or undefined if it has none. */
  operation: OperationDescriptor | undefined;
  /** Whatever grants the caller loaded. They are filtered here and never trusted as pre-filtered. */
  grants: readonly AgentGrant[];
  agent: PolicyAgent;
  connection: PolicyConnection;
  now: Date;
}

/**
 * Decide whether an agent may run one operation on one connection.
 *
 * Pure and deterministic: no I/O, no clock access, and the same inputs in any grant order give
 * the same decision. Default deny: the function never throws, and anything it does not
 * understand becomes a deny.
 */
export function evaluate(input: EvaluateInput): PolicyDecision {
  try {
    return decide(input);
  } catch {
    return deny('invalid_request', 'The request could not be evaluated and was denied.');
  }
}

function decide(input: EvaluateInput): PolicyDecision {
  if (!isRecord(input)) {
    return deny('invalid_request', 'The policy input is malformed and was denied.');
  }
  const { now, agent, connection } = input;

  // 1. The request must be well-formed. The schema parser silently drops `__proto__` keys, so
  // they are rejected first: the engine must judge exactly the arguments the worker would get.
  if (containsProtoKey(input.request)) {
    return deny('invalid_request', 'The request contains a forbidden key and was denied.');
  }
  // The schema parser also accepts cyclic argument graphs, which are not JSON and could not be
  // hashed, stored or sent to a worker, so arguments are checked structurally first.
  if (isRecord(input.request) && !isBoundedJson(input.request.arguments, 0)) {
    return deny('invalid_request', 'The request arguments are not plain JSON and were denied.');
  }
  const parsed = PolicyRequest.safeParse(input.request);
  if (!parsed.success) {
    return deny('invalid_request', 'The request is malformed and was denied.');
  }
  const request = parsed.data;

  if (!(now instanceof Date) || Number.isNaN(now.getTime())) {
    return deny('invalid_request', 'The evaluation time is invalid, so the request was denied.');
  }
  if (!isRecord(agent) || !isRecord(connection) || !Array.isArray(input.grants)) {
    return deny('invalid_request', 'The policy input is malformed and was denied.');
  }

  // 2. The request must be about the agent and connection the caller resolved.
  if (request.agentId !== agent.id || request.connectionId !== connection.id) {
    return deny(
      'invalid_request',
      'The request does not match the agent and connection it was evaluated for.',
    );
  }

  // 3. The adapter must define the operation.
  const operation = parseOperation(input.operation);
  if (operation === undefined || operation.name !== request.operation) {
    return deny(
      'operation_unknown',
      `Operation "${request.operation}" is not defined by the adapter for this connection.`,
    );
  }

  // 4. The agent must be active.
  if (agent.status !== 'active') {
    return deny('agent_not_active', `Agent ${request.agentId} is not active.`);
  }

  // 5. Agent and connection must share an owner and an organization.
  if (
    !isNonEmptyString(agent.organizationId) ||
    !isNonEmptyString(agent.ownerUserId) ||
    agent.organizationId !== connection.organizationId ||
    agent.ownerUserId !== connection.ownerUserId
  ) {
    return deny(
      'ownership_mismatch',
      'The agent and the connection do not belong to the same owner and organization.',
    );
  }

  // 6. The connection must be in a state where operations may run.
  const status = ConnectionStatus.safeParse(connection.status);
  if (!status.success || !isConnectionExecutable(status.data)) {
    const detail = status.success ? ` (status: ${status.data})` : '';
    return deny(
      'connection_not_active',
      `Connection ${request.connectionId} is not in an executable state${detail}.`,
    );
  }

  // 7 and 8. Keep only live grants for exactly this agent, connection and operation.
  const nowMs = now.getTime();
  const denies: DenyGrant[] = [];
  const allows: AllowGrant[] = [];
  for (const raw of input.grants as readonly unknown[]) {
    const grant = classifyGrant(raw, request, nowMs);
    if (grant.kind === 'deny') denies.push(grant);
    else if (grant.kind === 'allow') allows.push(grant);
  }

  // 9. Any applying deny wins, whatever the allows say.
  const applyingDenies = denies.filter((grant) =>
    denyApplies(grant.constraints, request.arguments, operation),
  );
  if (applyingDenies.length > 0) {
    const ids = sortedIds(applyingDenies);
    return deny(
      'explicit_deny',
      ids.length > 0
        ? `Denied by explicit deny ${plural('grant', ids.length)} ${ids.join(', ')}.`
        : 'Denied by an explicit deny grant.',
      ids,
    );
  }

  // 10. At least one allow grant must be satisfied.
  if (allows.length === 0) {
    return deny(
      'no_matching_grant',
      `No active grant allows operation "${request.operation}" for this agent on this connection.`,
    );
  }
  const satisfied: SatisfiedGrant[] = [];
  for (const grant of allows) {
    const result = checkAllow(grant.constraints, request.arguments, operation);
    if (result.satisfied) satisfied.push({ grant, obligations: result.obligations });
  }
  if (satisfied.length === 0) {
    const ids = sortedIds(allows);
    return deny(
      'constraint_violation',
      `The request does not satisfy the constraints of ${plural('grant', ids.length)} ${ids.join(', ')}.`,
      ids,
    );
  }

  // 11. Authority is the union of the satisfied grants, except that the operation itself can
  // force approval.
  const forcedBy = operation.requiresApproval
    ? 'the operation always requires approval'
    : operation.sensitivity === 'destructive'
      ? 'the operation is destructive'
      : undefined;
  const withoutApproval = satisfied.filter((entry) => entry.grant.approvalMode === 'none');

  if (forcedBy === undefined && withoutApproval.length > 0) {
    const chosen = choose(withoutApproval);
    const capped = Object.keys(chosen.obligations).length > 0;
    return {
      outcome: 'allow',
      reasonCode: 'allowed',
      reason: `Allowed by grant ${chosen.grant.id}.${capped ? ' The result size is capped by the grant.' : ''}`,
      matchedGrantIds: [chosen.grant.id],
      obligations: chosen.obligations,
    };
  }

  const chosen = choose(satisfied);
  return {
    outcome: 'approval_required',
    reasonCode: 'approval_required',
    reason: `Grant ${chosen.grant.id} permits operation "${request.operation}", but approval is required because ${forcedBy ?? 'the grant requires approval'}.`,
    matchedGrantIds: [chosen.grant.id],
    obligations: chosen.obligations,
  };
}

/* ---------------------------------------------------------------------------------------------
 * Grants
 * ------------------------------------------------------------------------------------------ */

interface DenyGrant {
  kind: 'deny';
  /** Undefined when the stored id is not a valid UUID; the deny still applies. */
  id: string | undefined;
  /** Undefined means unconditional: the grant denies every request it targets. */
  constraints: GrantConstraints | undefined;
}

interface AllowGrant {
  kind: 'allow';
  id: string;
  constraints: GrantConstraints;
  approvalMode: 'none' | 'required';
}

interface SatisfiedGrant {
  grant: AllowGrant;
  obligations: JsonObject;
}

/**
 * Sort one loaded grant into allow, deny or not-applicable.
 *
 * Every doubt resolves toward less authority. A damaged allow grant is dropped. A damaged deny
 * grant keeps denying, and denies everything it targets if its constraints cannot be read.
 */
function classifyGrant(
  raw: unknown,
  request: PolicyRequest,
  nowMs: number,
): DenyGrant | AllowGrant | { kind: 'skip' } {
  const skip = { kind: 'skip' } as const;
  if (!isRecord(raw)) return skip;

  // Exact match only: no wildcards, no prefixes.
  if (
    raw.agentId !== request.agentId ||
    raw.connectionId !== request.connectionId ||
    raw.operation !== request.operation
  ) {
    return skip;
  }

  const revokedAt = readTimestamp(raw.revokedAt);
  const expiresAt = readTimestamp(raw.expiresAt);
  const id = Uuid.safeParse(raw.id);
  const constraints = parseConstraints(raw.constraints);

  if (raw.effect === 'allow') {
    if (!id.success) return skip;
    if (revokedAt.kind !== 'null') return skip;
    if (expiresAt.kind === 'invalid') return skip;
    if (expiresAt.kind === 'time' && expiresAt.ms <= nowMs) return skip;
    if (raw.approvalMode !== 'none' && raw.approvalMode !== 'required') return skip;
    if (constraints === undefined) return skip;
    return { kind: 'allow', id: id.data, constraints, approvalMode: raw.approvalMode };
  }

  // Deny grants, and grants whose effect is unreadable, which are treated as denies. A deny is
  // lifted only by a readable revocation or expiry that has already taken effect.
  if (revokedAt.kind === 'time' && revokedAt.ms <= nowMs) return skip;
  if (expiresAt.kind === 'time' && expiresAt.ms <= nowMs) return skip;
  return {
    kind: 'deny',
    id: id.success ? id.data : undefined,
    constraints: raw.effect === 'deny' ? constraints : undefined,
  };
}

type Timestamp = { kind: 'null' } | { kind: 'time'; ms: number } | { kind: 'invalid' };

function readTimestamp(value: unknown): Timestamp {
  if (value === null) return { kind: 'null' };
  const parsed = IsoDateTime.safeParse(value);
  if (!parsed.success) return { kind: 'invalid' };
  const ms = Date.parse(parsed.data);
  return Number.isNaN(ms) ? { kind: 'invalid' } : { kind: 'time', ms };
}

function parseConstraints(raw: unknown): GrantConstraints | undefined {
  if (!isRecord(raw) || containsProtoKey(raw)) return undefined;
  const parsed = GrantConstraints.safeParse(raw);
  return parsed.success ? parsed.data : undefined;
}

function parseOperation(raw: unknown): OperationDescriptor | undefined {
  if (!isRecord(raw)) return undefined;
  const parsed = OperationDescriptor.safeParse(raw);
  if (!parsed.success) return undefined;
  const { resourceArgument, limitArgument } = parsed.data;
  if (resourceArgument === '__proto__' || limitArgument === '__proto__') return undefined;
  return parsed.data;
}

/* ---------------------------------------------------------------------------------------------
 * Constraints
 * ------------------------------------------------------------------------------------------ */

/**
 * A deny grant narrows itself with argument predicates. It applies unless the request clearly
 * falls outside them: a named argument that is present and different lifts the deny, while an
 * absent argument does not, because the engine cannot tell what the adapter would default to.
 * `maxResults` is not a predicate and never narrows a deny.
 */
function denyApplies(
  constraints: GrantConstraints | undefined,
  args: JsonObject,
  operation: OperationDescriptor,
): boolean {
  if (constraints === undefined) return true;

  for (const [name, expected] of Object.entries(constraints.argumentEquals ?? {})) {
    if (Object.hasOwn(args, name) && args[name] !== expected) return false;
  }
  for (const [name, options] of Object.entries(constraints.argumentOneOf ?? {})) {
    if (Object.hasOwn(args, name) && !includesValue(options, args[name])) return false;
  }
  if (constraints.resourceIds !== undefined && operation.resourceArgument !== undefined) {
    const name = operation.resourceArgument;
    if (Object.hasOwn(args, name) && !includesValue(constraints.resourceIds, args[name])) {
      return false;
    }
  }
  return true;
}

/** An allow grant is satisfied only when every one of its constraints provably holds. */
function checkAllow(
  constraints: GrantConstraints,
  args: JsonObject,
  operation: OperationDescriptor,
): { satisfied: false } | { satisfied: true; obligations: JsonObject } {
  const unsatisfied = { satisfied: false } as const;

  for (const [name, expected] of Object.entries(constraints.argumentEquals ?? {})) {
    if (!Object.hasOwn(args, name) || args[name] !== expected) return unsatisfied;
  }
  for (const [name, options] of Object.entries(constraints.argumentOneOf ?? {})) {
    if (!Object.hasOwn(args, name) || !includesValue(options, args[name])) return unsatisfied;
  }

  if (constraints.resourceIds !== undefined) {
    const name = operation.resourceArgument;
    if (name === undefined || !Object.hasOwn(args, name)) return unsatisfied;
    const value = args[name];
    if (typeof value !== 'string' || !constraints.resourceIds.includes(value)) return unsatisfied;
  }

  const obligations: JsonObject = {};
  if (constraints.maxResults !== undefined) {
    const name = operation.limitArgument;
    if (name === undefined) return unsatisfied;
    if (Object.hasOwn(args, name)) {
      const value = args[name];
      if (typeof value !== 'number' || !Number.isInteger(value)) return unsatisfied;
      if (value < 1 || value > constraints.maxResults) return unsatisfied;
    } else {
      obligations[name] = constraints.maxResults;
    }
  }

  return { satisfied: true, obligations };
}

/** Strict membership for JSON primitives. Objects and arrays never match. */
function includesValue(options: readonly unknown[], value: unknown): boolean {
  if (value !== null && typeof value === 'object') return false;
  return options.includes(value);
}

/* ---------------------------------------------------------------------------------------------
 * Helpers
 * ------------------------------------------------------------------------------------------ */

/** Prefer a grant that imposes no obligation, then the smallest id, so order never matters. */
function choose(candidates: readonly SatisfiedGrant[]): SatisfiedGrant {
  const ranked = [...candidates].sort((a, b) => {
    const byObligation = Object.keys(a.obligations).length - Object.keys(b.obligations).length;
    if (byObligation !== 0) return byObligation;
    return a.grant.id < b.grant.id ? -1 : a.grant.id > b.grant.id ? 1 : 0;
  });
  const first = ranked[0];
  if (first === undefined) throw new Error('choose() requires at least one candidate');
  return first;
}

function sortedIds(grants: readonly { id: string | undefined }[]): string[] {
  const ids = new Set<string>();
  for (const grant of grants) {
    if (grant.id !== undefined) ids.add(grant.id);
  }
  return [...ids].sort();
}

function deny(
  reasonCode: PolicyReasonCode,
  reason: string,
  matchedGrantIds: string[] = [],
): PolicyDecision {
  return { outcome: 'deny', reasonCode, reason, matchedGrantIds, obligations: {} };
}

function plural(word: string, count: number): string {
  return count === 1 ? word : `${word}s`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0;
}

/** Deepest argument nesting the engine accepts. Cycles always exceed it. */
const MAX_ARGUMENT_DEPTH = 64;

/** True for plain JSON (finite numbers, arrays, plain objects) no deeper than the limit. */
function isBoundedJson(value: unknown, depth: number): boolean {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return true;
  if (typeof value === 'number') return Number.isFinite(value);
  if (typeof value !== 'object' || depth >= MAX_ARGUMENT_DEPTH) return false;
  if (Array.isArray(value)) {
    return (value as unknown[]).every((item) => isBoundedJson(item, depth + 1));
  }
  const prototype: unknown = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return false;
  return Object.values(value).every((item) => isBoundedJson(item, depth + 1));
}

/** True if the value has an own `__proto__` key at any depth. Tolerates cycles. */
function containsProtoKey(root: unknown): boolean {
  const seen = new Set<object>();
  const pending: unknown[] = [root];
  while (pending.length > 0) {
    const value = pending.pop();
    if (typeof value !== 'object' || value === null || seen.has(value)) continue;
    seen.add(value);
    if (Array.isArray(value)) {
      pending.push(...(value as unknown[]));
      continue;
    }
    if (Object.hasOwn(value, '__proto__')) return true;
    pending.push(...Object.values(value));
  }
  return false;
}
