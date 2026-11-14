import { JobErrorCode, JsonObject } from '@aab/contracts';
import type { JobError } from '@aab/contracts';
import { z } from 'zod';

/*
 * The wire protocol between the supervisor (outside the sandbox) and the runner (inside it).
 * Both directions are newline-delimited JSON. The supervisor writes to the runner's stdin; the
 * runner writes only protocol messages to stdout. Every message is size-capped, checked with
 * `checkPlainJson` and parsed with a strict schema by the side that receives it.
 *
 * The supervisor treats everything in `RunnerMessage` as hostile input.
 */

/** Largest single line the runner accepts on stdin (the job carries the storage state). */
export const MAX_JOB_LINE_BYTES = 8 * 1024 * 1024;
/** Default cap on everything a runner may write to stdout over its whole life. */
export const DEFAULT_MAX_RUNNER_STDOUT_BYTES = 4 * 1024 * 1024;

// ---------------------------------------------------------------------------------------------
// Storage state. Bounds follow browser limits with some headroom: Chromium caps a cookie's name
// plus value at 4096 bytes and keeps at most 180 cookies per domain.

export const MAX_COOKIES = 300;
export const MAX_COOKIE_FIELD_LENGTH = 4096;
export const MAX_STORAGE_ORIGINS = 50;
export const MAX_LOCAL_STORAGE_ENTRIES = 1000;
export const MAX_LOCAL_STORAGE_VALUE_LENGTH = 256 * 1024;

export const StorageCookieSchema = z.strictObject({
  name: z.string().min(1).max(MAX_COOKIE_FIELD_LENGTH),
  value: z.string().max(MAX_COOKIE_FIELD_LENGTH),
  domain: z.string().min(1).max(253),
  path: z.string().min(1).max(1024),
  expires: z
    .number()
    .refine((value) => Number.isFinite(value) && (value === -1 || value >= 0), 'bad expiry'),
  httpOnly: z.boolean(),
  secure: z.boolean(),
  sameSite: z.enum(['Strict', 'Lax', 'None']),
});

export const StorageOriginSchema = z.strictObject({
  origin: z.string().min(1).max(255),
  localStorage: z
    .array(
      z.strictObject({
        name: z.string().max(1024),
        value: z.string().max(MAX_LOCAL_STORAGE_VALUE_LENGTH),
      }),
    )
    .max(MAX_LOCAL_STORAGE_ENTRIES),
});

export const StorageStateSchema = z.strictObject({
  cookies: z.array(StorageCookieSchema).max(MAX_COOKIES),
  origins: z.array(StorageOriginSchema).max(MAX_STORAGE_ORIGINS),
});

// ---------------------------------------------------------------------------------------------
// Supervisor -> runner

const AdapterRef = {
  jobId: z.string().min(1).max(128),
  adapterId: z.string().min(1).max(64),
  adapterVersion: z.string().min(1).max(64),
  allowedOrigins: z.array(z.string().min(1).max(255)).min(1).max(16),
  timeoutMs: z
    .number()
    .int()
    .min(1)
    .max(60 * 60_000),
};

export const OperationJobMessage = z.strictObject({
  type: z.literal('operation'),
  job: z.strictObject({
    ...AdapterRef,
    connectionId: z.string().min(1).max(128),
    operation: z.string().min(1).max(128),
    arguments: JsonObject,
    storageState: StorageStateSchema,
    expectedAccountHint: z.string().max(256).nullable(),
  }),
});
export type OperationJobMessage = z.infer<typeof OperationJobMessage>;

export const LoginJobMessage = z.strictObject({
  type: z.literal('login'),
  job: z.strictObject({ ...AdapterRef, connectionId: z.string().min(1).max(128) }),
});
export type LoginJobMessage = z.infer<typeof LoginJobMessage>;

/** Start-up probe: confirms the sandbox has no network and, optionally, that Chromium starts. */
export const SelfCheckMessage = z.strictObject({
  type: z.literal('self_check'),
  /** A TCP port listening on the host's loopback that the sandbox must not reach. */
  hostLoopbackPort: z.number().int().min(1).max(65535),
  launchBrowser: z.boolean(),
});
export type SelfCheckMessage = z.infer<typeof SelfCheckMessage>;

export const JobMessage = z.discriminatedUnion('type', [
  OperationJobMessage,
  LoginJobMessage,
  SelfCheckMessage,
]);
export type JobMessage = z.infer<typeof JobMessage>;

/** Control messages during a login handoff. */
export const ControlMessage = z.discriminatedUnion('type', [
  z.strictObject({ type: z.literal('complete') }),
  z.strictObject({ type: z.literal('cancel') }),
]);
export type ControlMessage = z.infer<typeof ControlMessage>;

// ---------------------------------------------------------------------------------------------
// Runner -> supervisor (hostile)

/** The runner's error text is ignored: the supervisor substitutes its own fixed message. */
const RunnerJobError = z.strictObject({
  code: JobErrorCode,
  message: z.string().max(300),
});

export const RunnerOperationOutcome = z.discriminatedUnion('status', [
  z.strictObject({ status: z.literal('succeeded'), data: JsonObject }),
  z.strictObject({ status: z.literal('reauth_required') }),
  /** The adapter could not tell whether a job that may change the application took effect. */
  z.strictObject({ status: z.literal('outcome_unknown') }),
  z.strictObject({ status: z.literal('failed'), error: RunnerJobError }),
]);

export const RunnerLoginOutcome = z.discriminatedUnion('status', [
  z.strictObject({
    status: z.literal('succeeded'),
    storageState: StorageStateSchema,
    externalAccountHint: z.string().max(256).nullable(),
  }),
  z.strictObject({ status: z.literal('failed'), error: RunnerJobError }),
]);

export const RunnerMessage = z.discriminatedUnion('type', [
  z.strictObject({ type: z.literal('operation_result'), outcome: RunnerOperationOutcome }),
  /** The login window is open and showing the login page. */
  z.strictObject({ type: z.literal('login_ready') }),
  z.strictObject({ type: z.literal('login_result'), outcome: RunnerLoginOutcome }),
  z.strictObject({
    type: z.literal('self_check_result'),
    interfaces: z.array(z.string().max(64)).max(64),
    hostLoopbackReachable: z.boolean(),
    browserStarted: z.boolean().nullable(),
  }),
]);
export type RunnerMessage = z.infer<typeof RunnerMessage>;

// ---------------------------------------------------------------------------------------------
// Fixed error text. Both sides use only these strings; nothing read from a page or raised by
// adapter code ever becomes an error message.

export const JOB_ERROR_MESSAGES: Readonly<Record<JobErrorCode, string>> = {
  denied: 'the operation is not allowed',
  invalid_arguments: 'the operation arguments are invalid',
  adapter_unavailable: 'the adapter for this connection is not available in the worker',
  origin_not_allowed: 'the connection has no origin the adapter may reach',
  navigation_blocked: 'a navigation left the operation allowlist',
  output_rejected: 'the operation output did not match its declared schema',
  session_expired: 'the connection session has expired',
  identity_mismatch: 'the signed-in account is not the account recorded at login',
  timeout: 'the job exceeded its time limit',
  cancelled: 'the job was cancelled',
  worker_failure: 'the browser worker failed to run the job',
  login_not_completed: 'sign-in was not completed',
  login_window_closed: 'the login window was closed',
  not_found: 'the requested resource was not found',
  unexpected_page: 'the application showed a page the adapter did not expect',
};

export function jobError(code: JobErrorCode): JobError {
  return { code, message: JOB_ERROR_MESSAGES[code] };
}

/**
 * Codes an adapter's `execute` may report in a `failed` result, mapped onto job error codes.
 * Anything else becomes `worker_failure`.
 */
const ADAPTER_ERROR_CODES: Readonly<Record<string, JobErrorCode>> = {
  not_found: 'not_found',
  unexpected_page: 'unexpected_page',
  invalid_arguments: 'invalid_arguments',
  aborted: 'cancelled',
};

export function mapAdapterErrorCode(code: unknown): JobErrorCode {
  if (typeof code !== 'string' || !Object.hasOwn(ADAPTER_ERROR_CODES, code)) {
    return 'worker_failure';
  }
  return ADAPTER_ERROR_CODES[code] ?? 'worker_failure';
}

// ---------------------------------------------------------------------------------------------
// Runner diagnostics on stderr. The supervisor forwards a stderr line to its own log only when
// its `event` is one of these fixed names; everything else is counted and dropped.

export const RUNNER_DIAGNOSTIC_EVENTS = [
  'runner_started',
  'job_received',
  'job_rejected',
  'adapter_unavailable',
  'browser_launched',
  'browser_launch_failed',
  'navigation_blocked',
  'subframe_blocked',
  'reauth_detected',
  'popup_closed',
  'operation_finished',
  'login_window_open',
  'login_finished',
  'adapter_log',
  'browser_action_failed',
  'runner_error',
] as const;
export type RunnerDiagnosticEvent = (typeof RUNNER_DIAGNOSTIC_EVENTS)[number];
