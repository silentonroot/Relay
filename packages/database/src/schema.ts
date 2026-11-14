/*
 * Phase 1 relational schema (spec §11).
 *
 * This file is deliberately self-contained: drizzle-kit loads it with its own bundler, which
 * does not follow the workspace's `.js`-suffixed TypeScript imports. The enum value lists
 * below therefore duplicate the ones in @aab/contracts; test/schema.test.ts fails if the two
 * ever drift apart.
 *
 * Phase 2 adds execution jobs, operation requests and the vault (migration 0003). Approval and
 * workflow tables arrive with their phases as later migrations.
 */
import { sql } from 'drizzle-orm';
import type { SQL } from 'drizzle-orm';
import {
  bigint,
  boolean,
  check,
  customType,
  index,
  integer,
  jsonb,
  pgTable,
  primaryKey,
  text,
  timestamp,
  uniqueIndex,
  uuid,
} from 'drizzle-orm/pg-core';
import type { AnyPgColumn } from 'drizzle-orm/pg-core';

export const ENTITY_STATUSES = ['active', 'disabled'] as const;
export const MEMBERSHIP_ROLES = ['owner', 'admin', 'member'] as const;
export const CONNECTION_STATUSES = [
  'created',
  'authentication_required',
  'authenticating',
  'active',
  'degraded',
  'expired',
  'reconnect_required',
  'revoked',
] as const;
export const GRANT_EFFECTS = ['allow', 'deny'] as const;
export const APPROVAL_MODES = ['none', 'required'] as const;
export const ACTOR_TYPES = ['user', 'agent', 'worker', 'system'] as const;
export const AUDIT_DECISIONS = ['allow', 'deny', 'approval_required', 'not_applicable'] as const;
export const JOB_KINDS = ['operation', 'login'] as const;
export const JOB_STATUSES = [
  'queued',
  'running',
  'succeeded',
  'failed',
  'denied',
  'reauth_required',
  'outcome_unknown',
  'cancelled',
] as const;
export const JOB_ERROR_CODES = [
  'denied',
  'invalid_arguments',
  'adapter_unavailable',
  'origin_not_allowed',
  'navigation_blocked',
  'output_rejected',
  'not_found',
  'unexpected_page',
  'session_expired',
  'identity_mismatch',
  'timeout',
  'cancelled',
  'worker_failure',
  'login_not_completed',
  'login_window_closed',
] as const;
export const VAULT_SECRET_STATUSES = ['pending', 'active', 'deleted'] as const;

/** Millisecond precision so a value survives the round trip through a JavaScript Date. */
const instant = (name: string) =>
  timestamp(name, { withTimezone: true, precision: 3, mode: 'date' });

/** Binary column. Always surfaces as a Buffer, whichever driver produced the row. */
const bytea = customType<{ data: Buffer; driverData: Uint8Array }>({
  dataType: () => 'bytea',
  toDriver: (value) => value,
  fromDriver: (value) => Buffer.from(value),
});

const createdAt = () => instant('created_at').notNull().defaultNow();
const updatedAt = () =>
  instant('updated_at')
    .notNull()
    .defaultNow()
    .$onUpdate(() => new Date());

/** The values are compile-time constants from this file, never user input. */
function oneOf(column: AnyPgColumn, values: readonly string[]): SQL {
  return sql`${column} in (${sql.raw(values.map((value) => `'${value}'`).join(', '))})`;
}

export const organizations = pgTable(
  'organizations',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    name: text('name').notNull(),
    status: text('status', { enum: ENTITY_STATUSES }).notNull().default('active'),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (table) => [check('organizations_status_check', oneOf(table.status, ENTITY_STATUSES))],
);

export const users = pgTable(
  'users',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    email: text('email').notNull(),
    passwordHash: text('password_hash').notNull(),
    status: text('status', { enum: ENTITY_STATUSES }).notNull().default('active'),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (table) => [
    uniqueIndex('users_email_unique').on(table.email),
    check('users_email_lowercase_check', sql`${table.email} = lower(${table.email})`),
    check('users_status_check', oneOf(table.status, ENTITY_STATUSES)),
  ],
);

export const memberships = pgTable(
  'memberships',
  {
    organizationId: uuid('organization_id')
      .notNull()
      .references(() => organizations.id),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id),
    role: text('role', { enum: MEMBERSHIP_ROLES }).notNull(),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (table) => [
    primaryKey({ name: 'memberships_pk', columns: [table.organizationId, table.userId] }),
    index('memberships_user_idx').on(table.userId),
    check('memberships_role_check', oneOf(table.role, MEMBERSHIP_ROLES)),
  ],
);

/** Dashboard sessions. Only hashes of the session and CSRF tokens are stored. */
export const userSessions = pgTable(
  'user_sessions',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id),
    organizationId: uuid('organization_id')
      .notNull()
      .references(() => organizations.id),
    tokenHash: text('token_hash').notNull(),
    csrfTokenHash: text('csrf_token_hash').notNull(),
    expiresAt: instant('expires_at').notNull(),
    revokedAt: instant('revoked_at'),
    lastSeenAt: instant('last_seen_at').notNull().defaultNow(),
    createdAt: createdAt(),
  },
  (table) => [
    uniqueIndex('user_sessions_token_hash_unique').on(table.tokenHash),
    index('user_sessions_user_idx').on(table.userId),
    index('user_sessions_expires_at_idx').on(table.expiresAt),
  ],
);

export const applicationDefinitions = pgTable(
  'application_definitions',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    organizationId: uuid('organization_id')
      .notNull()
      .references(() => organizations.id),
    adapterId: text('adapter_id').notNull(),
    adapterVersion: text('adapter_version').notNull(),
    name: text('name').notNull(),
    allowedOrigins: jsonb('allowed_origins').$type<string[]>().notNull(),
    authModes: jsonb('auth_modes').$type<string[]>().notNull(),
    status: text('status', { enum: ENTITY_STATUSES }).notNull().default('active'),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (table) => [
    uniqueIndex('application_definitions_adapter_unique').on(
      table.organizationId,
      table.adapterId,
      table.adapterVersion,
    ),
    index('application_definitions_list_idx').on(table.organizationId, table.createdAt, table.id),
    check('application_definitions_status_check', oneOf(table.status, ENTITY_STATUSES)),
    check(
      'application_definitions_origins_check',
      sql`jsonb_typeof(${table.allowedOrigins}) = 'array' and jsonb_array_length(${table.allowedOrigins}) > 0`,
    ),
    check(
      'application_definitions_auth_modes_check',
      sql`jsonb_typeof(${table.authModes}) = 'array' and jsonb_array_length(${table.authModes}) > 0`,
    ),
  ],
);

export const connections = pgTable(
  'connections',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    ownerUserId: uuid('owner_user_id')
      .notNull()
      .references(() => users.id),
    organizationId: uuid('organization_id')
      .notNull()
      .references(() => organizations.id),
    applicationId: uuid('application_id')
      .notNull()
      .references(() => applicationDefinitions.id),
    displayName: text('display_name').notNull(),
    externalAccountHint: text('external_account_hint'),
    status: text('status', { enum: CONNECTION_STATUSES }).notNull().default('created'),
    statusReason: text('status_reason'),
    lastVerifiedAt: instant('last_verified_at'),
    sessionExpiresAt: instant('session_expires_at'),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (table) => [
    uniqueIndex('connections_owner_application_name_unique').on(
      table.ownerUserId,
      table.applicationId,
      table.displayName,
    ),
    index('connections_list_idx').on(
      table.organizationId,
      table.ownerUserId,
      table.createdAt,
      table.id,
    ),
    index('connections_application_idx').on(table.applicationId),
    check('connections_status_check', oneOf(table.status, CONNECTION_STATUSES)),
  ],
);

/** One row per status transition (spec §5.2). `from_status` is null for the creation row. */
export const connectionStatusEvents = pgTable(
  'connection_status_events',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    connectionId: uuid('connection_id')
      .notNull()
      .references(() => connections.id),
    fromStatus: text('from_status', { enum: CONNECTION_STATUSES }),
    toStatus: text('to_status', { enum: CONNECTION_STATUSES }).notNull(),
    reason: text('reason'),
    actorType: text('actor_type', { enum: ACTOR_TYPES }).notNull(),
    actorId: uuid('actor_id'),
    createdAt: createdAt(),
  },
  (table) => [
    index('connection_status_events_connection_idx').on(table.connectionId, table.createdAt),
    check(
      'connection_status_events_from_status_check',
      sql`${table.fromStatus} is null or ${oneOf(table.fromStatus, CONNECTION_STATUSES)}`,
    ),
    check('connection_status_events_to_status_check', oneOf(table.toStatus, CONNECTION_STATUSES)),
    check('connection_status_events_actor_type_check', oneOf(table.actorType, ACTOR_TYPES)),
  ],
);

export const agents = pgTable(
  'agents',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    organizationId: uuid('organization_id')
      .notNull()
      .references(() => organizations.id),
    ownerUserId: uuid('owner_user_id')
      .notNull()
      .references(() => users.id),
    name: text('name').notNull(),
    clientIdentity: text('client_identity').notNull(),
    status: text('status', { enum: ENTITY_STATUSES }).notNull().default('active'),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (table) => [
    // Unique per owner, not per organization: an organization-wide constraint would let one
    // member learn another member's agent identity from a 409 (migration 0001).
    uniqueIndex('agents_owner_client_identity_unique').on(table.ownerUserId, table.clientIdentity),
    index('agents_list_idx').on(table.organizationId, table.ownerUserId, table.createdAt, table.id),
    check('agents_status_check', oneOf(table.status, ENTITY_STATUSES)),
  ],
);

export const agentGrants = pgTable(
  'agent_grants',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    agentId: uuid('agent_id')
      .notNull()
      .references(() => agents.id),
    connectionId: uuid('connection_id')
      .notNull()
      .references(() => connections.id),
    operation: text('operation').notNull(),
    effect: text('effect', { enum: GRANT_EFFECTS }).notNull(),
    constraints: jsonb('constraints').$type<Record<string, unknown>>().notNull(),
    approvalMode: text('approval_mode', { enum: APPROVAL_MODES }).notNull(),
    expiresAt: instant('expires_at'),
    revokedAt: instant('revoked_at'),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (table) => [
    index('agent_grants_evaluation_idx').on(table.agentId, table.connectionId, table.operation),
    index('agent_grants_agent_list_idx').on(table.agentId, table.createdAt, table.id),
    index('agent_grants_connection_idx').on(table.connectionId),
    check('agent_grants_effect_check', oneOf(table.effect, GRANT_EFFECTS)),
    check('agent_grants_approval_mode_check', oneOf(table.approvalMode, APPROVAL_MODES)),
    check('agent_grants_constraints_check', sql`jsonb_typeof(${table.constraints}) = 'object'`),
  ],
);

/**
 * Append-only, hash-chained per organization. The repository exposes no update or delete.
 * agent_id, run_id, connection_id and actor_id carry no foreign keys on purpose: the trail
 * must outlive the rows it describes once retention deletes them.
 */
export const auditEvents = pgTable(
  'audit_events',
  {
    id: uuid('id').primaryKey(),
    organizationId: uuid('organization_id')
      .notNull()
      .references(() => organizations.id),
    sequence: bigint('sequence', { mode: 'number' }).notNull(),
    timestamp: instant('timestamp').notNull(),
    actorType: text('actor_type', { enum: ACTOR_TYPES }).notNull(),
    actorId: uuid('actor_id'),
    agentId: uuid('agent_id'),
    runId: uuid('run_id'),
    connectionId: uuid('connection_id'),
    eventType: text('event_type').notNull(),
    decision: text('decision', { enum: AUDIT_DECISIONS }).notNull(),
    metadata: jsonb('metadata').$type<Record<string, unknown>>().notNull(),
    previousHash: text('previous_hash'),
    eventHash: text('event_hash').notNull(),
  },
  (table) => [
    uniqueIndex('audit_events_org_sequence_unique').on(table.organizationId, table.sequence),
    index('audit_events_connection_idx').on(table.organizationId, table.connectionId),
    index('audit_events_agent_idx').on(table.organizationId, table.agentId),
    index('audit_events_event_type_idx').on(table.organizationId, table.eventType),
    check('audit_events_sequence_check', sql`${table.sequence} >= 1`),
    check('audit_events_actor_type_check', oneOf(table.actorType, ACTOR_TYPES)),
    check('audit_events_decision_check', oneOf(table.decision, AUDIT_DECISIONS)),
    check('audit_events_event_type_check', sql`${table.eventType} ~ '^[a-z_]+\\.[a-z_]+$'`),
    check('audit_events_metadata_check', sql`jsonb_typeof(${table.metadata}) = 'object'`),
    check('audit_events_event_hash_check', sql`${table.eventHash} ~ '^[0-9a-f]{64}$'`),
    check(
      'audit_events_chain_start_check',
      sql`(${table.sequence} = 1) = (${table.previousHash} is null)`,
    ),
  ],
);

/**
 * One unit of work for the browser worker: an adapter operation or a login handoff.
 * policy_decision_id references a `policy.evaluated` audit event, run_id and audit_event_id
 * are likewise plain uuids: the trail outlives the rows it describes.
 */
export const executionJobs = pgTable(
  'execution_jobs',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    organizationId: uuid('organization_id')
      .notNull()
      .references(() => organizations.id),
    requestedByUserId: uuid('requested_by_user_id')
      .notNull()
      .references(() => users.id),
    kind: text('kind', { enum: JOB_KINDS }).notNull(),
    agentId: uuid('agent_id').references(() => agents.id),
    connectionId: uuid('connection_id')
      .notNull()
      .references(() => connections.id),
    runId: uuid('run_id'),
    operation: text('operation'),
    arguments: jsonb('arguments').$type<Record<string, unknown>>(),
    retrySafe: boolean('retry_safe').notNull().default(false),
    policyDecisionId: uuid('policy_decision_id'),
    approvalRequestId: uuid('approval_request_id'),
    capabilityRef: text('capability_ref'),
    status: text('status', { enum: JOB_STATUSES }).notNull().default('queued'),
    attemptCount: integer('attempt_count').notNull().default(0),
    timeoutMs: integer('timeout_ms').notNull(),
    workerId: text('worker_id'),
    leaseExpiresAt: instant('lease_expires_at'),
    completionRequestedAt: instant('completion_requested_at'),
    cancelRequestedAt: instant('cancel_requested_at'),
    startedAt: instant('started_at'),
    finishedAt: instant('finished_at'),
    result: jsonb('result').$type<Record<string, unknown>>(),
    resultPurgedAt: instant('result_purged_at'),
    errorCode: text('error_code', { enum: JOB_ERROR_CODES }),
    errorMessage: text('error_message'),
    auditEventId: uuid('audit_event_id'),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (table) => [
    index('execution_jobs_claim_idx').on(table.status, table.createdAt),
    index('execution_jobs_connection_status_idx').on(table.connectionId, table.status),
    uniqueIndex('execution_jobs_active_login_unique')
      .on(table.connectionId)
      .where(sql`${table.kind} = 'login' and ${table.status} in ('queued', 'running')`),
    check('execution_jobs_kind_check', oneOf(table.kind, JOB_KINDS)),
    check('execution_jobs_status_check', oneOf(table.status, JOB_STATUSES)),
    check(
      'execution_jobs_error_code_check',
      sql`${table.errorCode} is null or ${oneOf(table.errorCode, JOB_ERROR_CODES)}`,
    ),
    check(
      'execution_jobs_kind_fields_check',
      sql`(${table.kind} = 'operation' and ${table.agentId} is not null and ${table.operation} is not null and ${table.arguments} is not null) or (${table.kind} = 'login' and ${table.agentId} is null and ${table.operation} is null and ${table.arguments} is null)`,
    ),
    check(
      'execution_jobs_arguments_check',
      sql`${table.arguments} is null or jsonb_typeof(${table.arguments}) = 'object'`,
    ),
    check(
      'execution_jobs_result_check',
      sql`${table.result} is null or jsonb_typeof(${table.result}) = 'object'`,
    ),
    check('execution_jobs_attempt_count_check', sql`${table.attemptCount} >= 0`),
    check('execution_jobs_timeout_check', sql`${table.timeoutMs} > 0`),
  ],
);

/** Idempotency record for `POST /v1/operations/execute` (spec §12.2). */
export const operationRequests = pgTable(
  'operation_requests',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    agentId: uuid('agent_id')
      .notNull()
      .references(() => agents.id),
    idempotencyKey: text('idempotency_key').notNull(),
    requestHash: text('request_hash').notNull(),
    jobId: uuid('job_id')
      .notNull()
      .references(() => executionJobs.id),
    createdAt: createdAt(),
  },
  (table) => [
    uniqueIndex('operation_requests_agent_key_unique').on(table.agentId, table.idempotencyKey),
    index('operation_requests_job_idx').on(table.jobId),
    check('operation_requests_hash_check', sql`${table.requestHash} ~ '^[0-9a-f]{64}$'`),
  ],
);

/**
 * One row per (connection, secret type). `last_version` is the highest version number ever
 * issued, so a number is never reused after the versions were deleted. active_version_id has
 * no foreign key: versions are deleted while the metadata row stays.
 */
export const vaultSecrets = pgTable(
  'vault_secrets',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    connectionId: uuid('connection_id')
      .notNull()
      .references(() => connections.id),
    secretType: text('secret_type').notNull(),
    activeVersionId: uuid('active_version_id'),
    status: text('status', { enum: VAULT_SECRET_STATUSES }).notNull().default('pending'),
    lastVersion: integer('last_version').notNull().default(0),
    lastAccessedAt: instant('last_accessed_at'),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (table) => [
    uniqueIndex('vault_secrets_connection_type_unique').on(table.connectionId, table.secretType),
    check('vault_secrets_status_check', oneOf(table.status, VAULT_SECRET_STATUSES)),
    check('vault_secrets_last_version_check', sql`${table.lastVersion} >= 0`),
  ],
);

/** Ciphertext only. Plaintext and key material never reach this package. */
export const vaultSecretVersions = pgTable(
  'vault_secret_versions',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    secretId: uuid('secret_id')
      .notNull()
      .references(() => vaultSecrets.id),
    version: integer('version').notNull(),
    algorithm: text('algorithm').notNull(),
    ciphertext: bytea('ciphertext').notNull(),
    nonce: bytea('nonce').notNull(),
    authTag: bytea('auth_tag').notNull(),
    wrappedDek: bytea('wrapped_dek').notNull(),
    kekVersion: integer('kek_version').notNull(),
    aadVersion: integer('aad_version').notNull(),
    createdAt: createdAt(),
  },
  (table) => [
    uniqueIndex('vault_secret_versions_secret_version_unique').on(table.secretId, table.version),
    check('vault_secret_versions_version_check', sql`${table.version} >= 1`),
    check('vault_secret_versions_kek_version_check', sql`${table.kekVersion} >= 1`),
    check('vault_secret_versions_aad_version_check', sql`${table.aadVersion} >= 1`),
  ],
);
