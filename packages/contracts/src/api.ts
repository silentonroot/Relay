import { z } from 'zod';
import {
  Agent,
  AgentGrant,
  ApplicationDefinition,
  AuditEvent,
  AuditEventType,
  Connection,
  GrantConstraints,
  Organization,
  User,
} from './entities.js';
import { ApprovalMode, AuthMode, ErrorCode, GrantEffect } from './enums.js';
import {
  AdapterId,
  DisplayName,
  IsoDateTime,
  OperationName,
  Origin,
  SemVer,
  Uuid,
} from './primitives.js';

export const API_PREFIX = '/v1';

/** Name of the HttpOnly dashboard session cookie. */
export const SESSION_COOKIE = 'aab_session';
/** Header carrying the CSRF token on every cookie-authenticated mutation. */
export const CSRF_HEADER = 'x-csrf-token';
export const REQUEST_ID_HEADER = 'x-request-id';

/** Phase 1 and Phase 2 routes. Paths are relative to API_PREFIX. */
export const Routes = {
  health: '/health',
  authLogin: '/auth/login',
  authLogout: '/auth/logout',
  authSession: '/auth/session',
  applications: '/applications',
  applicationsRegister: '/applications/register',
  connections: '/connections',
  connection: '/connections/:id',
  connectionRevoke: '/connections/:id/revoke',
  connectionAuthStart: '/connections/:id/auth/start',
  connectionAuthComplete: '/connections/:id/auth/complete',
  operationsExecute: '/operations/execute',
  operation: '/operations/:jobId',
  agents: '/agents',
  agent: '/agents/:id',
  agentDisable: '/agents/:id/disable',
  agentGrants: '/agents/:id/grants',
  agentGrant: '/agents/:id/grants/:grantId',
  auditEvents: '/audit-events',
} as const;

/** Every non-2xx response has this body. */
export const ErrorResponse = z.object({
  error: z.object({
    code: ErrorCode,
    message: z.string(),
    requestId: z.string(),
    /** Field-level validation issues. Never echoes submitted secret values. */
    details: z.array(z.object({ path: z.string(), message: z.string() })).optional(),
  }),
});
export type ErrorResponse = z.infer<typeof ErrorResponse>;

export const HealthResponse = z.object({
  status: z.enum(['ok', 'degraded']),
  version: z.string(),
  checks: z.object({ database: z.enum(['ok', 'unavailable']) }),
});
export type HealthResponse = z.infer<typeof HealthResponse>;

export const LoginRequest = z.strictObject({
  email: z.email().max(254),
  password: z.string().min(1).max(1024),
});
export type LoginRequest = z.infer<typeof LoginRequest>;

export const SessionResponse = z.object({
  user: User,
  organization: Organization,
  csrfToken: z.string(),
  expiresAt: IsoDateTime,
});
export type SessionResponse = z.infer<typeof SessionResponse>;

export const RegisterApplicationRequest = z.strictObject({
  adapterId: AdapterId,
  adapterVersion: SemVer,
  name: DisplayName,
  allowedOrigins: z.array(Origin).min(1).max(20),
  authModes: z.array(AuthMode).min(1),
});
export type RegisterApplicationRequest = z.infer<typeof RegisterApplicationRequest>;

export const CreateConnectionRequest = z.strictObject({
  applicationId: Uuid,
  displayName: DisplayName,
  externalAccountHint: z.string().trim().max(120).optional(),
});
export type CreateConnectionRequest = z.infer<typeof CreateConnectionRequest>;

export const RevokeConnectionRequest = z.strictObject({
  reason: z.string().trim().max(500).optional(),
});
export type RevokeConnectionRequest = z.infer<typeof RevokeConnectionRequest>;

export const CreateAgentRequest = z.strictObject({
  name: DisplayName,
  clientIdentity: z.string().trim().min(1).max(200),
});
export type CreateAgentRequest = z.infer<typeof CreateAgentRequest>;

export const CreateGrantRequest = z.strictObject({
  connectionId: Uuid,
  operation: OperationName,
  effect: GrantEffect.default('allow'),
  constraints: GrantConstraints.default({}),
  approvalMode: ApprovalMode.default('none'),
  expiresAt: IsoDateTime.optional(),
});
export type CreateGrantRequest = z.infer<typeof CreateGrantRequest>;

export const IdParams = z.object({ id: Uuid });
export const GrantParams = z.object({ id: Uuid, grantId: Uuid });

export const ListQuery = z.object({
  limit: z.coerce.number().int().min(1).max(200).default(50),
  cursor: z.string().max(200).optional(),
});
export type ListQuery = z.infer<typeof ListQuery>;

export const AuditEventsQuery = ListQuery.extend({
  agentId: Uuid.optional(),
  connectionId: Uuid.optional(),
  eventType: AuditEventType.optional(),
});
export type AuditEventsQuery = z.infer<typeof AuditEventsQuery>;

const listOf = <T extends z.ZodType>(item: T) =>
  z.object({ items: z.array(item), nextCursor: z.string().nullable() });

export const ApplicationList = listOf(ApplicationDefinition);
export type ApplicationList = z.infer<typeof ApplicationList>;
export const ConnectionList = listOf(Connection);
export type ConnectionList = z.infer<typeof ConnectionList>;
export const AgentList = listOf(Agent);
export type AgentList = z.infer<typeof AgentList>;
export const AgentGrantList = listOf(AgentGrant);
export type AgentGrantList = z.infer<typeof AgentGrantList>;
export const AuditEventList = listOf(AuditEvent);
export type AuditEventList = z.infer<typeof AuditEventList>;
