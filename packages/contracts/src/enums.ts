import { z } from 'zod';

/** Connection lifecycle states (spec §5.2). Transitions live in connection-lifecycle.ts. */
export const ConnectionStatus = z.enum([
  'created',
  'authentication_required',
  'authenticating',
  'active',
  'degraded',
  'expired',
  'reconnect_required',
  'revoked',
]);
export type ConnectionStatus = z.infer<typeof ConnectionStatus>;

export const AuthMode = z.enum(['browser_session', 'oauth', 'api_key']);
export type AuthMode = z.infer<typeof AuthMode>;

/** Status shared by users, organizations, agents and application definitions. */
export const EntityStatus = z.enum(['active', 'disabled']);
export type EntityStatus = z.infer<typeof EntityStatus>;

export const MembershipRole = z.enum(['owner', 'admin', 'member']);
export type MembershipRole = z.infer<typeof MembershipRole>;

/** A grant either allows an operation or explicitly denies it. Deny always wins (spec §8.1). */
export const GrantEffect = z.enum(['allow', 'deny']);
export type GrantEffect = z.infer<typeof GrantEffect>;

/** Whether an allowed operation still needs a human to approve the exact action. */
export const ApprovalMode = z.enum(['none', 'required']);
export type ApprovalMode = z.infer<typeof ApprovalMode>;

export const ActorType = z.enum(['user', 'agent', 'worker', 'system']);
export type ActorType = z.infer<typeof ActorType>;

/** How dangerous an adapter operation is. Drives default approval requirements. */
export const OperationSensitivity = z.enum(['read', 'write', 'destructive']);
export type OperationSensitivity = z.infer<typeof OperationSensitivity>;

export const AuditDecision = z.enum(['allow', 'deny', 'approval_required', 'not_applicable']);
export type AuditDecision = z.infer<typeof AuditDecision>;

/**
 * Stable machine-readable error codes. The last five are the normalized operation outcomes
 * agents will see through the tool gateway (spec Phase 6).
 */
export const ErrorCode = z.enum([
  'unauthenticated',
  'forbidden',
  'not_found',
  'validation_failed',
  'conflict',
  'rate_limited',
  'csrf_failed',
  'service_unavailable',
  'internal_error',
  'denied',
  'approval_required',
  'reauth_required',
  'retryable',
  'outcome_unknown',
]);
export type ErrorCode = z.infer<typeof ErrorCode>;
