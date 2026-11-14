import { AuditEvent } from '@aab/contracts';
import { describe, expect, it } from 'vitest';
import { AUDIT_FIRST_SEQUENCE, computeEventHash, verifyChain } from '../src/index.js';
import type { AuditHashFields } from '../src/index.js';

const ORG_A = '11111111-1111-4111-8111-111111111111';
const ORG_B = '22222222-2222-4222-8222-222222222222';
const USER = '33333333-3333-4333-8333-333333333333';

function eventId(n: number): string {
  return `00000000-0000-4000-8000-${n.toString().padStart(12, '0')}`;
}

function buildChain(length: number, organizationId = ORG_A): AuditEvent[] {
  const events: AuditEvent[] = [];
  let previousHash: string | null = null;
  for (let i = 0; i < length; i += 1) {
    const fields: AuditHashFields = {
      id: eventId(i + 1),
      sequence: AUDIT_FIRST_SEQUENCE + i,
      timestamp: new Date(Date.UTC(2026, 10, 11, 0, 0, i)).toISOString(),
      organizationId,
      actorType: 'user',
      actorId: USER,
      agentId: null,
      runId: null,
      connectionId: null,
      eventType: 'connection.created',
      decision: 'not_applicable',
      metadata: { displayName: `synthetic-${i}`, nested: { index: i } },
    };
    const eventHash = computeEventHash(fields, previousHash);
    events.push({ ...fields, previousHash, eventHash });
    previousHash = eventHash;
  }
  return events;
}

describe('computeEventHash', () => {
  const [first] = buildChain(1);

  it('returns a lowercase hex SHA-256 digest', () => {
    expect(first!.eventHash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('is deterministic and independent of property order', () => {
    const reordered = Object.fromEntries(Object.entries(first!).reverse()) as AuditEvent;
    expect(computeEventHash(reordered, null)).toBe(first!.eventHash);
    const metadataReordered = {
      ...first!,
      metadata: { nested: { index: 0 }, displayName: 'synthetic-0' },
    };
    expect(computeEventHash(metadataReordered, null)).toBe(first!.eventHash);
  });

  it('ignores properties that are not part of the event', () => {
    const withExtra = { ...first!, somethingElse: 'ignored' } as AuditHashFields;
    expect(computeEventHash(withExtra, null)).toBe(first!.eventHash);
  });

  it.each([
    ['id', { id: eventId(999) }],
    ['sequence', { sequence: 2 }],
    ['timestamp', { timestamp: '2026-11-11T00:00:00.001Z' }],
    ['organizationId', { organizationId: ORG_B }],
    ['actorType', { actorType: 'agent' }],
    ['actorId', { actorId: null }],
    ['agentId', { agentId: USER }],
    ['runId', { runId: USER }],
    ['connectionId', { connectionId: USER }],
    ['eventType', { eventType: 'connection.revoked' }],
    ['decision', { decision: 'allow' }],
    ['metadata', { metadata: { displayName: 'synthetic-0', nested: { index: 1 } } }],
  ] as const)('changes when %s changes', (_field, patch) => {
    expect(computeEventHash({ ...first!, ...patch } as AuditHashFields, null)).not.toBe(
      first!.eventHash,
    );
  });

  it('changes when the previous hash changes', () => {
    expect(computeEventHash(first!, 'a'.repeat(64))).not.toBe(first!.eventHash);
  });

  it('throws rather than hashing an event with a missing field', () => {
    const { decision: _decision, ...incomplete } = first!;
    expect(() => computeEventHash(incomplete as unknown as AuditHashFields, null)).toThrow(
      TypeError,
    );
  });
});

describe('verifyChain', () => {
  it('accepts an empty chain', () => {
    expect(verifyChain([])).toEqual({ ok: true, count: 0, head: null });
  });

  it('accepts an intact chain and reports its head', () => {
    const chain = buildChain(6);
    expect(chain.every((event) => AuditEvent.safeParse(event).success)).toBe(true);
    expect(verifyChain(chain)).toEqual({
      ok: true,
      count: 6,
      head: { organizationId: ORG_A, sequence: 6, eventHash: chain[5]!.eventHash },
    });
  });

  it('verifies in batches when given the previous batch head as anchor', () => {
    const chain = buildChain(7);
    const firstBatch = verifyChain(chain.slice(0, 3));
    expect(firstBatch.ok).toBe(true);
    if (!firstBatch.ok) return;
    expect(verifyChain(chain.slice(3), { anchor: firstBatch.head })).toMatchObject({
      ok: true,
      count: 4,
    });
  });

  it('detects a modified field', () => {
    const chain = buildChain(5);
    chain[2] = { ...chain[2]!, metadata: { displayName: 'tampered' } };
    expect(verifyChain(chain)).toMatchObject({
      ok: false,
      index: 2,
      sequence: 3,
      eventId: eventId(3),
      reason: 'event_hash_mismatch',
      verifiedCount: 2,
    });
  });

  it('detects a modified decision even when the attacker leaves the hashes alone', () => {
    const chain = buildChain(3);
    chain[1] = { ...chain[1]!, decision: 'allow' };
    expect(verifyChain(chain)).toMatchObject({
      ok: false,
      index: 1,
      reason: 'event_hash_mismatch',
    });
  });

  it('detects a modified event whose own hash was recomputed', () => {
    const chain = buildChain(4);
    const altered = { ...chain[1]!, eventType: 'connection.revoked' as const };
    chain[1] = { ...altered, eventHash: computeEventHash(altered, altered.previousHash) };
    expect(verifyChain(chain)).toMatchObject({
      ok: false,
      index: 2,
      reason: 'previous_hash_mismatch',
    });
  });

  it('detects an event deleted from the middle', () => {
    const chain = buildChain(5);
    chain.splice(2, 1);
    expect(verifyChain(chain)).toMatchObject({ ok: false, index: 2, reason: 'sequence_gap' });
  });

  it('detects a middle deletion disguised by renumbering', () => {
    const chain = buildChain(5);
    chain.splice(2, 1);
    for (let i = 2; i < chain.length; i += 1) {
      const renumbered = { ...chain[i]!, sequence: chain[i]!.sequence - 1 };
      chain[i] = renumbered;
    }
    expect(verifyChain(chain)).toMatchObject({ ok: false, index: 2 });
  });

  it('detects a deleted first event', () => {
    const chain = buildChain(3).slice(1);
    expect(verifyChain(chain)).toMatchObject({ ok: false, index: 0, reason: 'unexpected_start' });
  });

  it('detects reordering', () => {
    const chain = buildChain(4);
    [chain[1], chain[2]] = [chain[2]!, chain[1]!];
    expect(verifyChain(chain)).toMatchObject({ ok: false, index: 1, reason: 'sequence_gap' });
  });

  it('detects a forged previousHash', () => {
    const chain = buildChain(3);
    chain[2] = { ...chain[2]!, previousHash: 'f'.repeat(64) };
    expect(verifyChain(chain)).toMatchObject({
      ok: false,
      index: 2,
      reason: 'previous_hash_mismatch',
    });
  });

  it('detects a first event that claims a predecessor', () => {
    const [first] = buildChain(1);
    const forged = { ...first!, previousHash: 'f'.repeat(64) };
    const rehashed = { ...forged, eventHash: computeEventHash(forged, forged.previousHash) };
    expect(verifyChain([rehashed])).toMatchObject({ ok: false, reason: 'unexpected_start' });
  });

  it('detects an event spliced in from another organization', () => {
    const chain = buildChain(3);
    const foreign = buildChain(3, ORG_B);
    chain[1] = foreign[1]!;
    expect(verifyChain(chain)).toMatchObject({
      ok: false,
      index: 1,
      reason: 'organization_mismatch',
    });
  });

  it('rejects a batch that does not follow its anchor', () => {
    const chain = buildChain(4);
    const anchor = { organizationId: ORG_A, sequence: 1, eventHash: chain[0]!.eventHash };
    expect(verifyChain(chain.slice(2), { anchor })).toMatchObject({
      ok: false,
      index: 0,
      reason: 'sequence_gap',
    });
  });

  it('reports malformed metadata instead of throwing', () => {
    const chain = buildChain(2);
    chain[1] = { ...chain[1]!, metadata: { when: new Date(0) } as never };
    expect(verifyChain(chain)).toMatchObject({ ok: false, index: 1, reason: 'malformed_event' });
  });

  it('cannot detect tail truncation without an external head checkpoint (documented limit)', () => {
    const chain = buildChain(5);
    const full = verifyChain(chain);
    const truncated = verifyChain(chain.slice(0, 3));
    expect(truncated.ok).toBe(true);
    // The recorded head is what exposes the truncation.
    expect(full.ok && truncated.ok && full.head?.eventHash !== truncated.head?.eventHash).toBe(
      true,
    );
  });
});
