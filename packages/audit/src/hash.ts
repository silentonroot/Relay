import { createHash } from 'node:crypto';
import { canonicalJson } from '@aab/contracts';
import type { AuditEvent } from '@aab/contracts';

/**
 * Version of the hashed-field layout. It is part of the hashed input (`v`), so two layouts
 * can never produce the same hash for the same event.
 *
 * It is NOT stored per row: `audit_events` has no version column, and `verifyChain` always
 * recomputes with the current constant. Bumping it today would therefore make every existing
 * event fail verification with `event_hash_mismatch`. A future change to the hashed fields
 * needs, first, a stored per-row hash-version column (added by a migration, with existing rows
 * set to 1) and a verifier that reads that column and hashes each event with its own layout;
 * only then may this constant change for new events.
 */
export const AUDIT_HASH_VERSION = 1;

/** Every persisted field of an audit event except the two chain links. */
export type AuditHashFields = Omit<AuditEvent, 'eventHash' | 'previousHash'>;

/**
 * Lowercase hex SHA-256 over the canonical JSON of the event and the hash of its predecessor.
 * The first event of an organization's chain has `previousHash === null`.
 *
 * Fields are listed explicitly so an unexpected extra property on the input can never change
 * the hash, and a missing one fails loudly inside canonicalJson (undefined is rejected).
 */
export function computeEventHash(fields: AuditHashFields, previousHash: string | null): string {
  const payload = {
    v: AUDIT_HASH_VERSION,
    previousHash,
    id: fields.id,
    sequence: fields.sequence,
    timestamp: fields.timestamp,
    organizationId: fields.organizationId,
    actorType: fields.actorType,
    actorId: fields.actorId,
    agentId: fields.agentId,
    runId: fields.runId,
    connectionId: fields.connectionId,
    eventType: fields.eventType,
    decision: fields.decision,
    metadata: fields.metadata,
  };
  return createHash('sha256').update(canonicalJson(payload), 'utf8').digest('hex');
}
