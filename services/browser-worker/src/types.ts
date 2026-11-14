import type { JobError, JsonObject } from '@aab/contracts';

/*
 * The seam between the supervisor (trusted, outside the sandbox) and everything that runs a
 * browser (untrusted, inside it). See docs/adr/ADR-013-per-job-sandbox-egress-proxy.md.
 *
 * `src/sandbox`, `src/egress` and `src/runner` implement `JobRunner`.
 * `src/supervisor` and `src/session-store` consume it and never import a browser library.
 */

/** Browser storage state in the shape Playwright's `storageState()` returns. Secret. */
export interface StorageState {
  cookies: StorageCookie[];
  origins: StorageOrigin[];
}

export interface StorageCookie {
  name: string;
  value: string;
  domain: string;
  path: string;
  /** Seconds since the epoch, or -1 for a session cookie. */
  expires: number;
  httpOnly: boolean;
  secure: boolean;
  sameSite: 'Strict' | 'Lax' | 'None';
}

export interface StorageOrigin {
  origin: string;
  localStorage: { name: string; value: string }[];
}

interface JobTarget {
  adapterId: string;
  adapterVersion: string;
  /** Already the intersection of the adapter's and the application's origins. Never empty. */
  allowedOrigins: readonly string[];
}

export interface OperationJobSpec extends JobTarget {
  jobId: string;
  connectionId: string;
  operation: string;
  /** Arguments after policy obligations were applied. Re-validated inside the runner. */
  arguments: JsonObject;
  storageState: StorageState;
  /** Account label recorded at login, or null when the adapter reported none. */
  expectedAccountHint: string | null;
  timeoutMs: number;
}

export type OperationJobOutcome =
  | { status: 'succeeded'; data: JsonObject }
  | { status: 'reauth_required' }
  /** A job that may have changed the target application ended without a verified outcome. */
  | { status: 'outcome_unknown' }
  | { status: 'failed'; error: JobError };

export interface LoginJobSpec extends JobTarget {
  jobId: string;
  connectionId: string;
  timeoutMs: number;
}

export type LoginOutcome =
  | {
      status: 'succeeded';
      /** Unfiltered. The supervisor filters it to the allowed origins before sealing. */
      storageState: StorageState;
      externalAccountHint: string | null;
    }
  | { status: 'failed'; error: JobError };

/** A login window that is open and waiting for the owner. */
export interface LoginHandle {
  /**
   * Resolves when the window is gone for any reason: the owner closed it, the handoff timed
   * out, `complete` or `cancel` finished, or the sandbox died.
   */
  readonly closed: Promise<void>;
  /**
   * The owner says sign-in is done: run the adapter's `checkSession`, capture storage state,
   * close the window and destroy the sandbox. Callable once.
   */
  complete(): Promise<LoginOutcome>;
  /** Close the window and destroy the sandbox without capturing anything. Idempotent. */
  cancel(): Promise<void>;
}

export interface JobRunner {
  /** Which launcher is in use, for logs and for the health report. */
  readonly sandbox: 'bubblewrap' | 'docker' | 'unsafe-process';
  /**
   * Runs one operation in a fresh sandbox and destroys it. Never throws for a job-level
   * failure: a crash, a timeout, an abort or malformed runner output all become a `failed`
   * outcome. The returned `data` has passed `sanitizeOperationOutput` outside the sandbox.
   */
  runOperation(spec: OperationJobSpec, signal: AbortSignal): Promise<OperationJobOutcome>;
  /** Opens the headed login window. Rejects if the window cannot be opened. */
  startLogin(spec: LoginJobSpec, signal: AbortSignal): Promise<LoginHandle>;
  /** Verifies at start-up that a sandbox can actually be created. Throws with the reason. */
  selfCheck(): Promise<void>;
}
