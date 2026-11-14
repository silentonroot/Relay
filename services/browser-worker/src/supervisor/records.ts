import { canTransitionConnection } from '@aab/contracts';
import type {
  AuditDecision,
  AuditEvent,
  AuditEventType,
  ConnectionStatus,
  JobErrorCode,
  JsonObject,
} from '@aab/contracts';
import { InvalidTransitionError, NotFoundError } from '@aab/database';
import type { ExecutionJob, Repositories } from '@aab/database';

/*
 * Audit and connection-status helpers shared by the job handlers and recovery. Metadata keys
 * avoid words the audit redactor blanks (secret, token, cookie, kek, ...): `vaultEntryId`,
 * `keyVersion`.
 */

/** Appends an event attributed to the worker. Pass the transaction's repositories. */
export function auditAsWorker(
  repos: Repositories,
  job: ExecutionJob,
  now: Date,
  event: { eventType: AuditEventType; decision?: AuditDecision; metadata: JsonObject },
): Promise<AuditEvent> {
  return repos.audit.append({
    organizationId: job.organizationId,
    actorType: 'worker',
    actorId: null,
    agentId: job.agentId,
    connectionId: job.connectionId,
    runId: job.runId,
    eventType: event.eventType,
    decision: event.decision ?? 'not_applicable',
    metadata: event.metadata,
    timestamp: now,
  });
}

/**
 * Moves the connection only when the lifecycle table allows it from its current status, so a
 * connection revoked (or otherwise moved) meanwhile is left alone. Returns whether it moved.
 */
export async function transitionIfAllowed(
  repos: Repositories,
  connectionId: string,
  to: ConnectionStatus,
  reason: string,
): Promise<boolean> {
  const current = await repos.connections.getForExecution(connectionId);
  if (current === null || !canTransitionConnection(current.connection.status, to)) return false;
  try {
    await repos.connections.transitionStatusInternal(connectionId, { to, reason });
    return true;
  } catch (error) {
    if (error instanceof InvalidTransitionError || error instanceof NotFoundError) return false;
    throw error;
  }
}

/** Shown on the dashboard when a login handoff ends without a stored session. */
export const LOGIN_FAILURE_REASONS: Readonly<Record<JobErrorCode, string>> = {
  denied: 'The login was not allowed.',
  invalid_arguments: 'The login could not be started because its request was invalid.',
  adapter_unavailable:
    'The browser worker has no adapter that can sign in to this application, so the login could not start.',
  origin_not_allowed:
    'The application and its adapter share no origin the login window may open, so the login could not start.',
  navigation_blocked:
    'The login window tried to leave the allowed origins, so the login was stopped.',
  output_rejected: 'The login result was rejected by the browser worker.',
  session_expired: 'The application ended the session before it could be stored; sign in again.',
  identity_mismatch:
    'A different account was signed in than the one this connection belongs to; create a new connection for that account.',
  timeout: 'The login window timed out before sign-in was confirmed.',
  cancelled: 'The login was cancelled before sign-in was confirmed.',
  worker_failure: 'The browser worker could not complete the login; try again.',
  login_not_completed: 'Sign-in was not finished in the login window; start the login again.',
  login_window_closed: 'The login window was closed before sign-in was confirmed.',
  not_found: 'The application did not show its sign-in page; try again.',
  unexpected_page: 'The application showed a page the adapter did not expect; try again.',
};

/** A login job whose lease expired (the worker stopped) and was ended by recovery. */
export const LOGIN_LEASE_EXPIRED_REASON =
  'The browser worker stopped during the login; start the login again.';

/** Connection reasons written by operation jobs. */
export const OPERATION_REASONS = {
  reauthRequired: 'The application no longer accepts the stored session; sign in again.',
  noSnapshot: 'No stored session was found for this connection; sign in again.',
  identityMismatch:
    'The application is signed in to a different account than the one recorded at login; reconnect this connection.',
} as const;
