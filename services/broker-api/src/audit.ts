import type { AuditDecision, AuditEventType, JsonObject } from '@aab/contracts';
import type { Repositories, Scope } from '@aab/database';

export interface UserAuditEvent {
  eventType: AuditEventType;
  decision?: AuditDecision;
  agentId?: string | null;
  connectionId?: string | null;
  runId?: string | null;
  /**
   * A small summary: ids and names only. Never credentials, tokens or request bodies. The
   * repository runs it through redactMetadata again before storing it.
   */
  metadata: JsonObject;
}

/** Appends an event attributed to the signed-in user. Pass the transaction's repositories. */
export function auditAsUser(repos: Repositories, scope: Scope, now: Date, event: UserAuditEvent) {
  return repos.audit.append({
    organizationId: scope.organizationId,
    actorType: 'user',
    actorId: scope.userId,
    agentId: event.agentId ?? null,
    connectionId: event.connectionId ?? null,
    runId: event.runId ?? null,
    eventType: event.eventType,
    decision: event.decision ?? 'not_applicable',
    metadata: event.metadata,
    timestamp: now,
  });
}
