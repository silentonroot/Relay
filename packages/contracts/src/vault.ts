import { z } from 'zod';
import type { ErrorCode } from './enums.js';
import { SESSION_SNAPSHOT_SECRET_TYPE } from './execution.js';
import { IsoDateTime, OperationName, Uuid } from './primitives.js';

/*
 * The vault wire protocol (ADR-014 sections 2 and 4): newline-delimited JSON over one Unix
 * socket per caller role. Every schema is strict. Nothing here names a caller: the role of a
 * request is the socket it arrived on, so no request field may carry one, and `.strict()` on
 * the envelope and on every parameter object refuses a stray `role` as malformed (P3-2).
 *
 * Request:   { id, operation, params }
 * Response:  { id, ok: true, result } | { id, ok: false, error: { code } }
 *
 * An error response carries a code and nothing else: no message, no stack, no echo of any
 * request value. A capability refused for any reason is `forbidden` with no detail (the
 * reason goes to the audit event, ADR-014 section 4).
 */

export const VAULT_PROTOCOL_VERSION = 1;

// ---------------------------------------------------------------------------------------------
// Roles and the operation table

export const VAULT_ROLES = ['api', 'supervisor', 'admin'] as const;
export const VaultRole = z.enum(VAULT_ROLES);
export type VaultRole = z.infer<typeof VaultRole>;

export const VAULT_OPERATIONS = [
  'hello',
  'authorizeJobAccess',
  'issueAccessCapability',
  'readForWorker',
  'completeLogin',
  'status',
  'rewrap',
  'kekRetirementCheck',
] as const;
export const VaultOperation = z.enum(VAULT_OPERATIONS);
export type VaultOperation = z.infer<typeof VaultOperation>;

/** Which roles may call each operation (ADR-014 section 4). Data, so tests iterate it. */
export const VAULT_OPERATION_ROLES: Readonly<Record<VaultOperation, readonly VaultRole[]>> = {
  hello: ['api', 'supervisor', 'admin'],
  authorizeJobAccess: ['api'],
  issueAccessCapability: ['supervisor'],
  readForWorker: ['supervisor'],
  completeLogin: ['supervisor'],
  status: ['api', 'admin'],
  rewrap: ['admin'],
  kekRetirementCheck: ['admin'],
};

export function isVaultOperation(value: unknown): value is VaultOperation {
  return typeof value === 'string' && Object.hasOwn(VAULT_OPERATION_ROLES, value);
}

export function isOperationAllowedForRole(operation: VaultOperation, role: VaultRole): boolean {
  return VAULT_OPERATION_ROLES[operation].includes(role);
}

// ---------------------------------------------------------------------------------------------
// Limits

/** Largest request line on the `api` and `admin` sockets. */
export const VAULT_MAX_LINE_BYTES = 64 * 1024;
/**
 * Largest request line on the `supervisor` socket, the only one that carries a session:
 * `completeLogin` holds up to 2 MiB of storage state as base64url (ADR-014 section 4 gives the
 * line cap as 4 MiB). Larger lines are refused before they are parsed.
 */
export const VAULT_MAX_SUPERVISOR_LINE_BYTES = 4 * 1024 * 1024;
/** Storage-state size cap (the worker's `MAX_SNAPSHOT_BYTES`), before base64url encoding. */
export const VAULT_MAX_PLAINTEXT_BYTES = 2 * 1024 * 1024;
/** Base64url length of `VAULT_MAX_PLAINTEXT_BYTES` bytes without padding. */
export const VAULT_MAX_PLAINTEXT_CHARS = Math.ceil((VAULT_MAX_PLAINTEXT_BYTES * 4) / 3);

/** Authorization lifetime bounds in seconds (ADR-014 section 5, P3-7). */
export const AUTHORIZATION_TTL_MIN_SECONDS = 10;
export const AUTHORIZATION_TTL_MAX_SECONDS = 3_600;
/** Token lifetime bounds in seconds. */
export const TOKEN_TTL_MIN_SECONDS = 1;
export const TOKEN_TTL_MAX_SECONDS = 120;
export const DEFAULT_AUTHORIZATION_TTL_SECONDS = 600;
export const DEFAULT_TOKEN_TTL_SECONDS = 30;

// ---------------------------------------------------------------------------------------------
// Field types

const Id = z.string().min(1).max(128);
const ttl = (min: number, max: number) => z.number().int().min(min).max(max);

/** 256-bit token from `generateToken()`: 43 characters of unpadded base64url. */
export const VaultToken = z.string().regex(/^[A-Za-z0-9_-]{43}$/, 'expected a vault token');

/** Unpadded base64url bytes, size-capped at the storage-state limit. */
export const VaultPlaintext = z
  .string()
  .min(1)
  .max(VAULT_MAX_PLAINTEXT_CHARS)
  .regex(/^[A-Za-z0-9_-]+$/, 'expected unpadded base64url');

export const VaultIsolation = z.enum(['separate-uid', 'shared-uid']);
export type VaultIsolation = z.infer<typeof VaultIsolation>;

const KekVersionNumber = z.number().int().min(1).max(999_999_999);

// ---------------------------------------------------------------------------------------------
// Parameters (`params` of each request). Strict: an unknown field is refused, never ignored.

export const HelloParams = z.strictObject({ protocolVersion: z.literal(VAULT_PROTOCOL_VERSION) });
export const AuthorizeJobAccessParams = z.strictObject({
  jobId: Uuid,
  ttlSeconds: ttl(AUTHORIZATION_TTL_MIN_SECONDS, AUTHORIZATION_TTL_MAX_SECONDS),
});
export const IssueAccessCapabilityParams = z.strictObject({
  capabilityId: Uuid,
  jobId: Uuid,
  workerId: Id,
  attempt: z.number().int().min(1).max(1_000_000),
  ttlSeconds: ttl(TOKEN_TTL_MIN_SECONDS, TOKEN_TTL_MAX_SECONDS),
});
export const ReadForWorkerParams = z.strictObject({
  token: VaultToken,
  jobId: Uuid,
  connectionId: Uuid,
  operation: OperationName,
});
export const CompleteLoginParams = z.strictObject({
  token: VaultToken,
  jobId: Uuid,
  connectionId: Uuid,
  plaintext: VaultPlaintext,
  externalAccountHint: z.string().max(256).nullable(),
  sessionExpiresAt: IsoDateTime.nullable(),
});
export const StatusParams = z.strictObject({});
export const RewrapParams = z.strictObject({
  batchSize: z.number().int().min(1).max(1_000),
  maxBatches: z.number().int().min(1).max(10_000),
  /** Continue after this version id (the `nextAfterId` of the previous call); omitted: from the start. */
  afterId: Uuid.optional(),
});
export const KekRetirementCheckParams = z.strictObject({ kekVersion: KekVersionNumber });

// ---------------------------------------------------------------------------------------------
// Results

export const HelloResult = z.strictObject({
  protocolVersion: z.literal(VAULT_PROTOCOL_VERSION),
  serviceVersion: z.string().min(1).max(64),
  isolation: VaultIsolation,
  /** The socket the request arrived on, never a value from the request. */
  role: VaultRole,
  /** The key directory, so a caller can refuse to start if it can open it (ADR-014 section 3). */
  keyDirectory: z.string().min(1).max(4096),
  currentKekVersion: KekVersionNumber,
});
export const AuthorizeJobAccessResult = z.strictObject({
  capabilityId: Uuid,
  expiresAt: IsoDateTime,
});
export const IssueAccessCapabilityResult = z.strictObject({
  token: VaultToken,
  tokenExpiresAt: IsoDateTime,
  secretVersion: z.number().int().min(0),
});
export const ReadForWorkerResult = z.strictObject({
  /** The Phase 2 secret type of a stored session (`session_snapshot`); it is also the AAD type. */
  secretType: z.literal(SESSION_SNAPSHOT_SECRET_TYPE),
  secretVersion: z.number().int().min(1),
  kekVersion: KekVersionNumber,
  argumentsHash: z
    .string()
    .regex(/^[0-9a-f]{64}$/)
    .nullable(),
  plaintext: VaultPlaintext,
});
export const CompleteLoginResult = z.strictObject({
  secretId: Uuid,
  secretVersion: z.number().int().min(1),
  kekVersion: KekVersionNumber,
});
export const StatusResult = z.strictObject({
  isolation: VaultIsolation,
  kekVersions: z.array(KekVersionNumber).max(1_000),
  currentKekVersion: KekVersionNumber,
  /** Count of secret versions wrapped under each KEK version, keyed by the version number. */
  versionsByKek: z.record(z.string().regex(/^[1-9]\d{0,8}$/), z.number().int().min(0)),
  missingKekVersions: z.array(KekVersionNumber).max(1_000),
  counters: z.record(z.string().max(64), z.number().int().min(0)),
});
export const RewrapResult = z.strictObject({
  rewrapped: z.number().int().min(0),
  skipped: z.number().int().min(0),
  failed: z.number().int().min(0),
  remaining: z.number().int().min(0),
  /**
   * Present when this call stopped at its bound with more candidates behind the last one it
   * examined: pass it as `afterId` to continue past rows that could not be rewrapped. Absent when
   * the candidate list was exhausted.
   */
  nextAfterId: Uuid.optional(),
});
export const KekRetirementCheckResult = z.strictObject({
  referencingVersions: z.number().int().min(0),
  safeToRemove: z.boolean(),
});

/** Parameter and result schema of every operation, keyed by operation name. */
export const VAULT_OPERATION_SCHEMAS = {
  hello: { params: HelloParams, result: HelloResult },
  authorizeJobAccess: { params: AuthorizeJobAccessParams, result: AuthorizeJobAccessResult },
  issueAccessCapability: {
    params: IssueAccessCapabilityParams,
    result: IssueAccessCapabilityResult,
  },
  readForWorker: { params: ReadForWorkerParams, result: ReadForWorkerResult },
  completeLogin: { params: CompleteLoginParams, result: CompleteLoginResult },
  status: { params: StatusParams, result: StatusResult },
  rewrap: { params: RewrapParams, result: RewrapResult },
  kekRetirementCheck: { params: KekRetirementCheckParams, result: KekRetirementCheckResult },
} as const satisfies Record<VaultOperation, { params: z.ZodType; result: z.ZodType }>;

export type VaultParams<Op extends VaultOperation> = z.infer<
  (typeof VAULT_OPERATION_SCHEMAS)[Op]['params']
>;
export type VaultResult<Op extends VaultOperation> = z.infer<
  (typeof VAULT_OPERATION_SCHEMAS)[Op]['result']
>;

// ---------------------------------------------------------------------------------------------
// Envelopes

/** Request id: chosen by the caller, echoed back, never interpreted. */
export const VaultRequestId = z
  .string()
  .min(1)
  .max(64)
  .regex(/^[A-Za-z0-9._-]+$/, 'expected a short identifier');

/**
 * The request line. `operation` is a plain string here so an unknown operation can be told
 * apart from a malformed envelope; the server looks it up in `VAULT_OPERATION_SCHEMAS`.
 * `params` is parsed with the operation's own strict schema after the role check.
 */
export const VaultRequestEnvelope = z.strictObject({
  id: VaultRequestId,
  operation: z.string().min(1).max(64),
  params: z.record(z.string(), z.unknown()),
});
export type VaultRequestEnvelope = z.infer<typeof VaultRequestEnvelope>;

export const VAULT_ERROR_CODES = [
  'forbidden',
  'malformed',
  'not_found',
  'validation_failed',
  'conflict',
  'service_unavailable',
  'internal_error',
  'not_implemented',
] as const;
export const VaultErrorCode = z.enum(VAULT_ERROR_CODES);
export type VaultErrorCode = z.infer<typeof VaultErrorCode>;

/**
 * How a vault error code reads in the existing error contract (`ErrorCode`). `malformed` is
 * protocol-level (bad framing, envelope, unknown operation or parameters) and is a
 * `validation_failed` to anything that reports it; `not_implemented` is a vault that does not
 * offer the operation yet, a `service_unavailable`.
 */
export const VAULT_ERROR_TO_ERROR_CODE: Readonly<Record<VaultErrorCode, ErrorCode>> = {
  forbidden: 'forbidden',
  malformed: 'validation_failed',
  not_found: 'not_found',
  validation_failed: 'validation_failed',
  conflict: 'conflict',
  service_unavailable: 'service_unavailable',
  internal_error: 'internal_error',
  not_implemented: 'service_unavailable',
};

export const VaultSuccessResponse = z.strictObject({
  id: VaultRequestId,
  ok: z.literal(true),
  result: z.record(z.string(), z.unknown()),
});
/** `id` is null when the request line was too broken to yield one. */
export const VaultErrorResponse = z.strictObject({
  id: VaultRequestId.nullable(),
  ok: z.literal(false),
  error: z.strictObject({ code: VaultErrorCode }),
});
export const VaultResponse = z.discriminatedUnion('ok', [VaultSuccessResponse, VaultErrorResponse]);
export type VaultResponse = z.infer<typeof VaultResponse>;
