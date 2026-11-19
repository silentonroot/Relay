import { AuditEventType } from '@aab/contracts';
import type { Repositories } from '@aab/database';
import type { Logger } from 'pino';
import { errorFacts } from './logging.js';
import type { VaultCounters } from './operations.js';
import type { RequestRefusedEvent } from './server.js';

/*
 * `vault.request_refused` (ADR-014 section 10): a request for an operation the socket's role may
 * not call. It is appended to the audit chain in its own transaction (there is no state change to
 * join) when the organization can be resolved, which here means: the refused request's params
 * carried a `jobId` that is a UUID naming an existing job (the role check runs before parameters
 * are validated, so this is the only handle there is). Otherwise it is logged and counted in
 * `status` (a known gap, as ADR-014 says). Appends are rate limited so a caller that is refused in
 * a loop cannot fill an organization's chain; the overflow is counted.
 */

const WINDOW_MS = 60_000;
const MAX_APPENDS_PER_WINDOW = 60;

export function createRefusalAuditor(deps: {
  repositories: Repositories;
  logger: Logger;
  counters: VaultCounters;
  clock?: () => Date;
}): (event: RequestRefusedEvent) => Promise<void> {
  const clock = deps.clock ?? (() => new Date());
  let windowStart = 0;
  let inWindow = 0;
  return async (event) => {
    const nowMs = clock().getTime();
    if (nowMs - windowStart >= WINDOW_MS) {
      windowStart = nowMs;
      inWindow = 0;
    }
    try {
      const job =
        event.jobId === undefined ? null : await deps.repositories.jobs.getInternal(event.jobId);
      if (job === null || inWindow >= MAX_APPENDS_PER_WINDOW) {
        deps.counters.refusedUnattributed += 1;
        return;
      }
      inWindow += 1;
      await deps.repositories.audit.append({
        organizationId: job.organizationId,
        actorType: 'system',
        actorId: null,
        connectionId: job.connectionId,
        eventType: AuditEventType.parse('vault.request_refused'),
        decision: 'deny',
        timestamp: clock(),
        metadata: {
          role: event.role,
          operation: event.operation,
          requestId: event.requestId,
          jobId: job.id,
        },
      });
    } catch (error) {
      // The refusal itself already happened; a failed audit append must not change the answer.
      deps.counters.refusedUnattributed += 1;
      deps.logger.error(errorFacts(error), 'vault request failed');
    }
  };
}
