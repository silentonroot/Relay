import type { AuditEvent } from '@aab/contracts';
import { computeEventHash } from './hash.js';

/** Sequence number of the first event in every organization's chain. */
export const AUDIT_FIRST_SEQUENCE = 1;

export type ChainBreakReason =
  /** The first event is not the start of the chain (or does not follow the anchor). */
  | 'unexpected_start'
  /** Sequence numbers are not consecutive: an event was removed, inserted or reordered. */
  | 'sequence_gap'
  /** previousHash does not equal the preceding event's eventHash. */
  | 'previous_hash_mismatch'
  /** The stored eventHash does not match the event's contents. */
  | 'event_hash_mismatch'
  /** The event belongs to a different organization than the rest of the chain. */
  | 'organization_mismatch'
  /** The event could not be hashed at all (for example its metadata is not plain JSON). */
  | 'malformed_event';

/** Position to resume from when a chain is verified in batches. */
export interface ChainAnchor {
  organizationId: string;
  sequence: number;
  eventHash: string;
}

export type ChainVerification =
  | { ok: true; count: number; head: ChainAnchor | null }
  | {
      ok: false;
      /** Index into the array that was passed in. */
      index: number;
      sequence: number;
      eventId: string;
      reason: ChainBreakReason;
      /** Number of events that verified before the break. */
      verifiedCount: number;
    };

export interface VerifyChainOptions {
  /**
   * The already-verified event immediately before `events[0]`. Omit it to verify from the
   * start of the chain, in which case the first event must have sequence 1 and no previousHash.
   */
  anchor?: ChainAnchor | null;
}

/**
 * Verifies a run of one organization's audit events, ordered by ascending sequence.
 *
 * Detects: any modified hashed field, an event deleted from or inserted into the middle,
 * reordered events, a forged previousHash, and events from another organization's chain.
 *
 * Cannot detect (spec §11.1):
 *  - truncation of the tail: removing the newest N events leaves a shorter chain that is
 *    still internally consistent. Detecting that needs the head hash (returned as `head`)
 *    to be recorded somewhere the attacker cannot write, such as an exported checkpoint.
 *  - a full rewrite: someone with write access to the table who recomputes every hash from
 *    the altered event onward produces a valid chain. The hashes are tamper evidence against
 *    partial edits, not a signature.
 *  - deletion of the entire chain, which is indistinguishable from an organization that has
 *    no events yet.
 */
export function verifyChain(
  events: readonly AuditEvent[],
  options: VerifyChainOptions = {},
): ChainVerification {
  let previous: ChainAnchor | null = options.anchor ?? null;

  for (let index = 0; index < events.length; index += 1) {
    const event = events[index]!;
    const fail = (reason: ChainBreakReason): ChainVerification => ({
      ok: false,
      index,
      sequence: event.sequence,
      eventId: event.id,
      reason,
      verifiedCount: index,
    });

    if (previous === null) {
      if (event.sequence !== AUDIT_FIRST_SEQUENCE || event.previousHash !== null) {
        return fail('unexpected_start');
      }
    } else {
      if (event.organizationId !== previous.organizationId) return fail('organization_mismatch');
      if (event.sequence !== previous.sequence + 1) return fail('sequence_gap');
      if (event.previousHash !== previous.eventHash) return fail('previous_hash_mismatch');
    }

    let expectedHash: string;
    try {
      expectedHash = computeEventHash(event, event.previousHash);
    } catch {
      return fail('malformed_event');
    }
    if (expectedHash !== event.eventHash) return fail('event_hash_mismatch');

    previous = {
      organizationId: event.organizationId,
      sequence: event.sequence,
      eventHash: event.eventHash,
    };
  }

  return { ok: true, count: events.length, head: previous };
}
