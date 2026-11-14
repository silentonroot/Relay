import { z } from 'zod';
import {
  ActorType,
  ApprovalMode,
  AuditDecision,
  AuthMode,
  ConnectionStatus,
  EntityStatus,
  GrantEffect,
  MembershipRole,
} from './enums.js';
import {
  AdapterId,
  DisplayName,
  IsoDateTime,
  JsonObject,
  JsonPrimitive,
  OperationName,
  Origin,
  SemVer,
  Uuid,
} from './primitives.js';

/*
 * API-visible shapes. None of these ever carries a password hash, session token, cookie,
 * vault ciphertext or key material. If a field would be secret, it does not belong here.
 */

const timestamps = { createdAt: IsoDateTime, updatedAt: IsoDateTime };

export const User = z.object({
  id: Uuid,
  email: z.email(),
  status: EntityStatus,
  ...timestamps,
});
export type User = z.infer<typeof User>;

export const Organization = z.object({
  id: Uuid,
  name: DisplayName,
  status: EntityStatus,
  ...timestamps,
});
export type Organization = z.infer<typeof Organization>;

export const Membership = z.object({
  organizationId: Uuid,
  userId: Uuid,
  role: MembershipRole,
});
export type Membership = z.infer<typeof Membership>;

export const ApplicationDefinition = z.object({
  id: Uuid,
  organizationId: Uuid,
  adapterId: AdapterId,
  adapterVersion: SemVer,
  name: DisplayName,
  allowedOrigins: z.array(Origin).min(1).max(20),
  authModes: z.array(AuthMode).min(1),
  status: EntityStatus,
  ...timestamps,
});
export type ApplicationDefinition = z.infer<typeof ApplicationDefinition>;

export const Connection = z.object({
  id: Uuid,
  ownerUserId: Uuid,
  organizationId: Uuid,
  applicationId: Uuid,
  displayName: DisplayName,
  /** Non-secret label for the remote account, e.g. a masked username. Never a credential. */
  externalAccountHint: z.string().max(120).nullable(),
  status: ConnectionStatus,
  statusReason: z.string().max(500).nullable(),
  lastVerifiedAt: IsoDateTime.nullable(),
  /**
   * Earliest expiry among the stored session's cookies, when the application sets one. An
   * estimate for the dashboard only: the application can end a session earlier.
   */
  sessionExpiresAt: IsoDateTime.nullable(),
  ...timestamps,
});
export type Connection = z.infer<typeof Connection>;

export const Agent = z.object({
  id: Uuid,
  organizationId: Uuid,
  ownerUserId: Uuid,
  name: DisplayName,
  /** Stable client identifier, independent of model provider or conversation. */
  clientIdentity: z.string().trim().min(1).max(200),
  status: EntityStatus,
  ...timestamps,
});
export type Agent = z.infer<typeof Agent>;

/**
 * Constraints narrow an allow grant. The object is strict on purpose: a constraint the policy
 * engine does not understand must be rejected at write time, never silently ignored.
 */
export const GrantConstraints = z.strictObject({
  /** Upper bound for the operation's limit argument. */
  maxResults: z.number().int().positive().max(10_000).optional(),
  /** Each named argument must equal the given value. */
  argumentEquals: z.record(z.string(), JsonPrimitive).optional(),
  /** Each named argument must be one of the given values. */
  argumentOneOf: z.record(z.string(), z.array(JsonPrimitive).min(1).max(100)).optional(),
  /** The operation's resource argument must be one of these identifiers. */
  resourceIds: z.array(z.string().min(1).max(200)).min(1).max(500).optional(),
});
export type GrantConstraints = z.infer<typeof GrantConstraints>;

export const AgentGrant = z.object({
  id: Uuid,
  agentId: Uuid,
  connectionId: Uuid,
  operation: OperationName,
  effect: GrantEffect,
  constraints: GrantConstraints,
  approvalMode: ApprovalMode,
  expiresAt: IsoDateTime.nullable(),
  revokedAt: IsoDateTime.nullable(),
  ...timestamps,
});
export type AgentGrant = z.infer<typeof AgentGrant>;

/** Dotted `domain.action` event names. Extend this list as phases add behavior. */
export const AuditEventType = z.enum([
  'auth.login_succeeded',
  'auth.login_failed',
  'auth.logout',
  'application.registered',
  'connection.created',
  'connection.status_changed',
  'connection.revoked',
  'agent.created',
  'agent.disabled',
  'grant.created',
  'grant.revoked',
  'policy.evaluated',
  'connection.auth_started',
  'connection.auth_completed',
  'connection.auth_failed',
  'operation.succeeded',
  'operation.failed',
  'operation.denied',
  'operation.reauth_required',
  'vault.secret_stored',
  'vault.secret_read',
  'vault.secret_deleted',
]);
export type AuditEventType = z.infer<typeof AuditEventType>;

export const AuditEvent = z.object({
  id: Uuid,
  /** Monotonic position in the organization's hash chain. */
  sequence: z.number().int().nonnegative(),
  timestamp: IsoDateTime,
  organizationId: Uuid,
  actorType: ActorType,
  actorId: Uuid.nullable(),
  agentId: Uuid.nullable(),
  runId: Uuid.nullable(),
  connectionId: Uuid.nullable(),
  eventType: AuditEventType,
  decision: AuditDecision,
  /** Redacted summary only. Never secrets, cookies, headers or raw page content. */
  metadata: JsonObject,
  previousHash: z.string().nullable(),
  eventHash: z.string(),
});
export type AuditEvent = z.infer<typeof AuditEvent>;
