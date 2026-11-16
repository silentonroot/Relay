import { z } from 'zod';
import { canonicalJson } from './canonical.js';
import { Connection } from './entities.js';
import { IsoDateTime, JsonObject, OperationName, Uuid } from './primitives.js';

/*
 * Phase 2: operation execution and the login handoff (spec §5.3, §8.3, §12).
 *
 * The API creates jobs and never touches a browser or a key. The browser worker claims jobs,
 * and runs each one in its own sandbox (ADR-001).
 */

/** `operation` runs one adapter operation. `login` is one interactive login handoff. */
export const JobKind = z.enum(['operation', 'login']);
export type JobKind = z.infer<typeof JobKind>;

export const JobStatus = z.enum([
  'queued',
  'running',
  'succeeded',
  'failed',
  /** Policy no longer allowed the job when the worker re-evaluated it. Nothing was executed. */
  'denied',
  /** The target application no longer accepts the stored session. */
  'reauth_required',
  /** A job that may have changed the target application ended without a verified outcome. */
  'outcome_unknown',
  'cancelled',
]);
export type JobStatus = z.infer<typeof JobStatus>;

export const TERMINAL_JOB_STATUSES: readonly JobStatus[] = [
  'succeeded',
  'failed',
  'denied',
  'reauth_required',
  'outcome_unknown',
  'cancelled',
];

export function isTerminalJobStatus(status: JobStatus): boolean {
  return TERMINAL_JOB_STATUSES.includes(status);
}

/** Machine-readable reason a job did not succeed. Never contains page content. */
export const JobErrorCode = z.enum([
  'denied',
  'invalid_arguments',
  'adapter_unavailable',
  'origin_not_allowed',
  'navigation_blocked',
  'output_rejected',
  /** The adapter reported that the requested resource does not exist for this account. */
  'not_found',
  /** The application's page did not have the shape the adapter expects. */
  'unexpected_page',
  'session_expired',
  'identity_mismatch',
  'timeout',
  'cancelled',
  'worker_failure',
  'login_not_completed',
  'login_window_closed',
]);
export type JobErrorCode = z.infer<typeof JobErrorCode>;

export const JobError = z.object({
  code: JobErrorCode,
  /** Fixed, generic text chosen by the broker. Never text read from a page. */
  message: z.string().max(300),
});
export type JobError = z.infer<typeof JobError>;

/** `POST /v1/operations/execute` body (spec §12.2). */
export const ExecuteOperationRequest = z.strictObject({
  agentId: Uuid,
  connectionId: Uuid,
  operation: OperationName,
  /** Plain JSON, checked with `checkPlainJson` before anything else looks at it. */
  arguments: JsonObject,
  runId: Uuid.optional(),
  idempotencyKey: z
    .string()
    .min(8)
    .max(200)
    .regex(/^[A-Za-z0-9._:-]+$/),
});
export type ExecuteOperationRequest = z.infer<typeof ExecuteOperationRequest>;

/**
 * An operation job as an owner or agent sees it (spec §12.3). `result` has passed the
 * operation's output schema twice: in the sandbox and again in the worker outside it.
 */
export const OperationJob = z.object({
  jobId: Uuid,
  status: JobStatus,
  operation: OperationName,
  agentId: Uuid,
  connectionId: Uuid,
  runId: Uuid.nullable(),
  result: JsonObject.nullable(),
  error: JobError.nullable(),
  /** The audit event that recorded the outcome, or the policy decision while the job runs. */
  auditEventId: Uuid.nullable(),
  createdAt: IsoDateTime,
  finishedAt: IsoDateTime.nullable(),
});
export type OperationJob = z.infer<typeof OperationJob>;

export const JobParams = z.object({ jobId: Uuid });

/** `POST /v1/connections/:id/auth/start` and `/auth/complete` responses. */
export const ConnectionAuthResponse = z.object({
  connection: Connection,
  jobId: Uuid,
  jobStatus: JobStatus,
  error: JobError.nullable(),
});
export type ConnectionAuthResponse = z.infer<typeof ConnectionAuthResponse>;

/** How long `execute` and `auth/complete` wait for a terminal status before answering 202. */
export const DEFAULT_JOB_WAIT_MS = 20_000;
/** A login handoff the owner does not complete within this time is abandoned. */
export const LOGIN_HANDOFF_TIMEOUT_MS = 10 * 60_000;
/** The only secret type Phase 2 stores. */
export const SESSION_SNAPSHOT_SECRET_TYPE = 'session_snapshot';

/**
 * Domain-separation prefix of the job arguments hash (threat model PE-14). It names the purpose
 * and the layout version; a change to what is hashed needs a new version, never a reuse of v1.
 */
export const JOB_ARGUMENTS_HASH_DOMAIN = 'aab.job-arguments.v1\n';

/**
 * What the job arguments hash binds: the final arguments and the job row they were judged for.
 * Every field is the exact value the execute route inserts and the worker reads back from the
 * claimed row.
 */
export interface JobArgumentsBinding {
  /** The organization id as the database returns it (lowercase). */
  organizationId: string;
  /** The agent id as the database returns it (lowercase). */
  agentId: string;
  /** The connection id as the database returns it (lowercase). */
  connectionId: string;
  /** The operation name exactly as stored in the job. */
  operation: string;
  /** The final arguments, obligations applied, exactly as stored in the job. */
  arguments: JsonObject;
  /** The id of the `policy.evaluated` event that allowed the job; null when the row has none. */
  policyDecisionId: string | null;
  /** The job's timeout in milliseconds. */
  timeoutMs: number;
  /** Whether the supervisor may retry the job after an interrupted run. */
  retrySafe: boolean;
}

/**
 * The exact text whose SHA-256 is `execution_jobs.arguments_hash`: the domain prefix followed by
 * the canonical JSON of one object with the keys `agentId`, `arguments`, `connectionId`,
 * `operation`, `organizationId`, `policyDecisionId` (a string or null), `retrySafe` (a boolean)
 * and `timeoutMs` (a number). One JSON object holds everything, so no choice of operation name
 * or argument value can shift bytes from one field into another, and a hash copied to a job of
 * another operation, connection, agent or decision does not match there. Migration
 * `0004_job_arguments_hash` reproduces this text in SQL for its backfill.
 */
export function jobArgumentsHashInput(binding: JobArgumentsBinding): string {
  return (
    JOB_ARGUMENTS_HASH_DOMAIN +
    canonicalJson({
      agentId: binding.agentId,
      arguments: binding.arguments,
      connectionId: binding.connectionId,
      operation: binding.operation,
      organizationId: binding.organizationId,
      policyDecisionId: binding.policyDecisionId,
      retrySafe: binding.retrySafe,
      timeoutMs: binding.timeoutMs,
    })
  );
}
