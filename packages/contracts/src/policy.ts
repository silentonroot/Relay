import { z } from 'zod';
import { OperationSensitivity } from './enums.js';
import { JsonObject, OperationName, Uuid } from './primitives.js';

/**
 * What the policy engine needs to know about an adapter operation. Adapters publish one of
 * these per operation; the engine never inspects adapter code.
 */
export const OperationDescriptor = z.object({
  name: OperationName,
  sensitivity: OperationSensitivity,
  /** When true the operation always needs approval, whatever the grant says. */
  requiresApproval: z.boolean(),
  /** Name of the argument that identifies the target resource, if the operation has one. */
  resourceArgument: z.string().min(1).optional(),
  /** Name of the argument that bounds result size, if the operation has one. */
  limitArgument: z.string().min(1).optional(),
});
export type OperationDescriptor = z.infer<typeof OperationDescriptor>;

/** An agent asking to run one operation on one connection. */
export const PolicyRequest = z.object({
  agentId: Uuid,
  connectionId: Uuid,
  operation: OperationName,
  arguments: JsonObject,
});
export type PolicyRequest = z.infer<typeof PolicyRequest>;

export const PolicyOutcome = z.enum(['allow', 'deny', 'approval_required']);
export type PolicyOutcome = z.infer<typeof PolicyOutcome>;

export const PolicyReasonCode = z.enum([
  'allowed',
  'approval_required',
  'no_matching_grant',
  'explicit_deny',
  'constraint_violation',
  'agent_not_active',
  'connection_not_active',
  'ownership_mismatch',
  'operation_unknown',
  'invalid_request',
]);
export type PolicyReasonCode = z.infer<typeof PolicyReasonCode>;

export const PolicyDecision = z.object({
  outcome: PolicyOutcome,
  reasonCode: PolicyReasonCode,
  /** Human-readable rationale shown in the dashboard and audit log. Contains no argument values. */
  reason: z.string(),
  /** Grants that produced this outcome (the allowing grant, or the denying grants). */
  matchedGrantIds: z.array(Uuid),
  /**
   * Argument overrides the broker must apply before execution, e.g. a clamped result limit.
   * Empty unless the outcome is allow or approval_required.
   */
  obligations: JsonObject,
});
export type PolicyDecision = z.infer<typeof PolicyDecision>;
