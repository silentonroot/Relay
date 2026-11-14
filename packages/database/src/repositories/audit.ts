import { randomUUID } from 'node:crypto';
import { AUDIT_FIRST_SEQUENCE, computeEventHash, redactMetadata, verifyChain } from '@aab/audit';
import type { AuditHashFields, ChainAnchor, ChainBreakReason } from '@aab/audit';
import { ActorType, AuditDecision, AuditEventType } from '@aab/contracts';
import type { AuditEvent } from '@aab/contracts';
import { and, asc, desc, eq, gt, lt, sql } from 'drizzle-orm';
import type { Db } from '../client.js';
import { translateDbErrors, ValidationError } from '../errors.js';
import { auditEvents } from '../schema.js';
import {
  decodeSequenceCursor,
  encodeSequenceCursor,
  isUuid,
  isValidScope,
  pageSize,
  toAuditEvent,
  toPage,
} from '../support.js';
import type { Page, PageRequest, Scope } from '../support.js';

export interface AuditAppendInput {
  organizationId: string;
  actorType: ActorType;
  actorId?: string | null | undefined;
  agentId?: string | null | undefined;
  runId?: string | null | undefined;
  connectionId?: string | null | undefined;
  eventType: AuditEventType;
  /** Defaults to `not_applicable`. */
  decision?: AuditDecision | undefined;
  /** A redacted summary. It is passed through redactMetadata again before it is stored. */
  metadata?: unknown;
  /** Defaults to now. Mainly for tests. */
  timestamp?: Date | undefined;
}

export interface AuditListFilters extends PageRequest {
  agentId?: string | undefined;
  connectionId?: string | undefined;
  eventType?: AuditEventType | undefined;
}

export type AuditVerification =
  | { ok: true; count: number; head: ChainAnchor | null }
  | {
      ok: false;
      sequence: number;
      eventId: string;
      reason: ChainBreakReason;
      /** Events that verified before the break. */
      verifiedCount: number;
    };

const VERIFY_BATCH_SIZE = 500;

function optionalUuid(value: string | null | undefined, field: string): string | null {
  if (value === null || value === undefined) return null;
  if (!isUuid(value)) {
    throw new ValidationError('invalid audit event', [{ path: field, message: 'expected a UUID' }]);
  }
  return value;
}

/**
 * The audit trail is append-only: this repository has no update and no delete, and nothing
 * else in the package writes to the table.
 */
export function createAuditRepository(db: Db) {
  return {
    /**
     * Appends one event to the organization's hash chain.
     *
     * A per-organization advisory lock, held until the surrounding transaction ends,
     * serializes appends so every event links to the true previous one. The unique index on
     * (organization_id, sequence) is the backstop if that lock is ever bypassed. When called
     * through `repositories.transaction`, the event commits or rolls back together with the
     * change it describes.
     */
    async append(input: AuditAppendInput): Promise<AuditEvent> {
      if (!isUuid(input.organizationId)) {
        throw new ValidationError('invalid audit event', [
          { path: 'organizationId', message: 'expected a UUID' },
        ]);
      }
      const actorType = ActorType.safeParse(input.actorType);
      const eventType = AuditEventType.safeParse(input.eventType);
      const decision = AuditDecision.safeParse(input.decision ?? 'not_applicable');
      if (!actorType.success || !eventType.success || !decision.success) {
        throw new ValidationError('invalid audit event');
      }
      const actorId = optionalUuid(input.actorId, 'actorId');
      const agentId = optionalUuid(input.agentId, 'agentId');
      const runId = optionalUuid(input.runId, 'runId');
      const connectionId = optionalUuid(input.connectionId, 'connectionId');
      const metadata = redactMetadata(input.metadata ?? {});
      const timestamp = input.timestamp ?? new Date();

      return translateDbErrors('audit event', () =>
        db.transaction(async (tx) => {
          await tx.execute(
            sql`select pg_advisory_xact_lock(hashtextextended(${`aab.audit:${input.organizationId}`}, 0))`,
          );
          const [last] = await tx
            .select({ sequence: auditEvents.sequence, eventHash: auditEvents.eventHash })
            .from(auditEvents)
            .where(eq(auditEvents.organizationId, input.organizationId))
            .orderBy(desc(auditEvents.sequence))
            .limit(1);

          const previousHash = last?.eventHash ?? null;
          const fields: AuditHashFields = {
            id: randomUUID(),
            sequence: last === undefined ? AUDIT_FIRST_SEQUENCE : last.sequence + 1,
            timestamp: timestamp.toISOString(),
            organizationId: input.organizationId,
            actorType: actorType.data,
            actorId,
            agentId,
            runId,
            connectionId,
            eventType: eventType.data,
            decision: decision.data,
            metadata,
          };
          const eventHash = computeEventHash(fields, previousHash);

          const [row] = await tx
            .insert(auditEvents)
            .values({ ...fields, timestamp, previousHash, eventHash })
            .returning();
          return toAuditEvent(row!);
        }),
      );
    },

    /** The organization's events, newest first. Visible to the whole organization. */
    async list(scope: Scope, filters: AuditListFilters = {}): Promise<Page<AuditEvent>> {
      if (!isValidScope(scope)) return { items: [], nextCursor: null };
      const limit = pageSize(filters);
      const before = decodeSequenceCursor(filters.cursor);
      // A filter that cannot match anything returns an empty page rather than a database error.
      if (
        (filters.agentId !== undefined && !isUuid(filters.agentId)) ||
        (filters.connectionId !== undefined && !isUuid(filters.connectionId))
      ) {
        return { items: [], nextCursor: null };
      }
      const rows = await db
        .select()
        .from(auditEvents)
        .where(
          and(
            eq(auditEvents.organizationId, scope.organizationId),
            filters.agentId === undefined ? undefined : eq(auditEvents.agentId, filters.agentId),
            filters.connectionId === undefined
              ? undefined
              : eq(auditEvents.connectionId, filters.connectionId),
            filters.eventType === undefined
              ? undefined
              : eq(auditEvents.eventType, filters.eventType),
            before === null ? undefined : lt(auditEvents.sequence, before),
          ),
        )
        .orderBy(desc(auditEvents.sequence))
        .limit(limit + 1);
      return toPage(rows, limit, toAuditEvent, (row) => encodeSequenceCursor(row.sequence));
    },

    /**
     * Recomputes the organization's whole chain, in batches. See `verifyChain` in @aab/audit
     * for exactly what this does and does not prove.
     */
    async verify(scope: Scope): Promise<AuditVerification> {
      if (!isValidScope(scope)) return { ok: true, count: 0, head: null };
      let anchor: ChainAnchor | null = null;
      let count = 0;
      for (;;) {
        const rows = await db
          .select()
          .from(auditEvents)
          .where(
            and(
              eq(auditEvents.organizationId, scope.organizationId),
              anchor === null ? undefined : gt(auditEvents.sequence, anchor.sequence),
            ),
          )
          .orderBy(asc(auditEvents.sequence))
          .limit(VERIFY_BATCH_SIZE);
        if (rows.length === 0) return { ok: true, count, head: anchor };

        const result = verifyChain(rows.map(toAuditEvent), { anchor });
        if (!result.ok) {
          return {
            ok: false,
            sequence: result.sequence,
            eventId: result.eventId,
            reason: result.reason,
            verifiedCount: count + result.verifiedCount,
          };
        }
        count += result.count;
        anchor = result.head;
        if (rows.length < VERIFY_BATCH_SIZE) return { ok: true, count, head: anchor };
      }
    },
  };
}
