import type {
  Agent,
  AgentGrant,
  ApplicationDefinition,
  AuditEvent,
  Connection,
  GrantConstraints,
  JsonObject,
  Membership,
  Organization,
  User,
} from '@aab/contracts';
import { sql } from 'drizzle-orm';
import type { SQL } from 'drizzle-orm';
import type { AnyPgColumn } from 'drizzle-orm/pg-core';
import { InvalidCursorError } from './errors.js';
import type {
  agentGrants,
  agents,
  applicationDefinitions,
  auditEvents,
  connections,
  memberships,
  organizations,
  users,
} from './schema.js';

/**
 * Who is asking. Every tenant-scoped repository function takes one and filters on it in SQL.
 * It must come from a validated session, never from request parameters.
 */
export interface Scope {
  organizationId: string;
  userId: string;
}

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Guards uuid columns: a malformed ID is simply "not found", not a database error. */
export function isUuid(value: unknown): value is string {
  return typeof value === 'string' && UUID_PATTERN.test(value);
}

export function isValidScope(scope: Scope): boolean {
  return isUuid(scope.organizationId) && isUuid(scope.userId);
}

/* ---------------------------------------------------------------- pagination */

export interface PageRequest {
  /** 1 to 200, default 50. */
  limit?: number | undefined;
  /** Opaque value from a previous page's `nextCursor`. */
  cursor?: string | undefined;
}

export interface Page<T> {
  items: T[];
  nextCursor: string | null;
}

export const DEFAULT_PAGE_SIZE = 50;
export const MAX_PAGE_SIZE = 200;

export function pageSize(request: PageRequest | undefined): number {
  const limit = request?.limit ?? DEFAULT_PAGE_SIZE;
  if (!Number.isInteger(limit) || limit < 1) return DEFAULT_PAGE_SIZE;
  return Math.min(limit, MAX_PAGE_SIZE);
}

function encodeCursor(value: unknown): string {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}

function decodeCursor(cursor: string): unknown {
  if (cursor.length > 200) throw new InvalidCursorError();
  try {
    return JSON.parse(Buffer.from(cursor, 'base64url').toString('utf8')) as unknown;
  } catch {
    throw new InvalidCursorError();
  }
}

/** Keyset position for lists ordered by (created_at desc, id desc). */
export interface TimeCursor {
  t: string;
  id: string;
}

export function encodeTimeCursor(row: { createdAt: Date; id: string }): string {
  return encodeCursor({ t: row.createdAt.toISOString(), id: row.id });
}

export function decodeTimeCursor(cursor: string | undefined): TimeCursor | null {
  if (cursor === undefined) return null;
  const value = decodeCursor(cursor) as Partial<TimeCursor> | null;
  if (
    typeof value !== 'object' ||
    value === null ||
    typeof value.t !== 'string' ||
    Number.isNaN(Date.parse(value.t)) ||
    !isUuid(value.id)
  ) {
    throw new InvalidCursorError();
  }
  return { t: new Date(value.t).toISOString(), id: value.id };
}

/** Rows strictly after the cursor in (created_at desc, id desc) order. */
export function afterTimeCursor(
  createdAt: AnyPgColumn,
  id: AnyPgColumn,
  cursor: TimeCursor | null,
): SQL | undefined {
  if (cursor === null) return undefined;
  return sql`(${createdAt}, ${id}) < (${cursor.t}::timestamptz, ${cursor.id}::uuid)`;
}

export function encodeSequenceCursor(sequence: number): string {
  return encodeCursor({ s: sequence });
}

export function decodeSequenceCursor(cursor: string | undefined): number | null {
  if (cursor === undefined) return null;
  const value = decodeCursor(cursor) as { s?: unknown } | null;
  if (typeof value !== 'object' || value === null || !Number.isSafeInteger(value.s)) {
    throw new InvalidCursorError();
  }
  return value.s as number;
}

/** Turns `limit + 1` fetched rows into a page. */
export function toPage<Row, Item>(
  rows: Row[],
  limit: number,
  toItem: (row: Row) => Item,
  cursorOf: (row: Row) => string,
): Page<Item> {
  const pageRows = rows.slice(0, limit);
  const last = pageRows.at(-1);
  return {
    items: pageRows.map(toItem),
    nextCursor: rows.length > limit && last !== undefined ? cursorOf(last) : null,
  };
}

/* ---------------------------------------------------------------- row mappers */
/*
 * Each mapper lists the DTO fields explicitly. A column added to a table (a hash, say) is
 * therefore never exposed until someone adds it here on purpose.
 */

const iso = (value: Date): string => value.toISOString();
const isoOrNull = (value: Date | null): string | null => (value === null ? null : iso(value));

export function toUser(row: typeof users.$inferSelect): User {
  return {
    id: row.id,
    email: row.email,
    status: row.status,
    createdAt: iso(row.createdAt),
    updatedAt: iso(row.updatedAt),
  };
}

export function toOrganization(row: typeof organizations.$inferSelect): Organization {
  return {
    id: row.id,
    name: row.name,
    status: row.status,
    createdAt: iso(row.createdAt),
    updatedAt: iso(row.updatedAt),
  };
}

export function toMembership(row: typeof memberships.$inferSelect): Membership {
  return { organizationId: row.organizationId, userId: row.userId, role: row.role };
}

export function toApplication(
  row: typeof applicationDefinitions.$inferSelect,
): ApplicationDefinition {
  return {
    id: row.id,
    organizationId: row.organizationId,
    adapterId: row.adapterId,
    adapterVersion: row.adapterVersion,
    name: row.name,
    allowedOrigins: row.allowedOrigins,
    authModes: row.authModes as ApplicationDefinition['authModes'],
    status: row.status,
    createdAt: iso(row.createdAt),
    updatedAt: iso(row.updatedAt),
  };
}

export function toConnection(row: typeof connections.$inferSelect): Connection {
  return {
    id: row.id,
    ownerUserId: row.ownerUserId,
    organizationId: row.organizationId,
    applicationId: row.applicationId,
    displayName: row.displayName,
    externalAccountHint: row.externalAccountHint,
    status: row.status,
    statusReason: row.statusReason,
    lastVerifiedAt: isoOrNull(row.lastVerifiedAt),
    sessionExpiresAt: isoOrNull(row.sessionExpiresAt),
    createdAt: iso(row.createdAt),
    updatedAt: iso(row.updatedAt),
  };
}

export function toAgent(row: typeof agents.$inferSelect): Agent {
  return {
    id: row.id,
    organizationId: row.organizationId,
    ownerUserId: row.ownerUserId,
    name: row.name,
    clientIdentity: row.clientIdentity,
    status: row.status,
    createdAt: iso(row.createdAt),
    updatedAt: iso(row.updatedAt),
  };
}

export function toGrant(row: typeof agentGrants.$inferSelect): AgentGrant {
  return {
    id: row.id,
    agentId: row.agentId,
    connectionId: row.connectionId,
    operation: row.operation,
    effect: row.effect,
    // Stored exactly as validated at write time. The policy engine re-validates on read and
    // fails closed if a row was altered behind the repository's back.
    constraints: row.constraints as GrantConstraints,
    approvalMode: row.approvalMode,
    expiresAt: isoOrNull(row.expiresAt),
    revokedAt: isoOrNull(row.revokedAt),
    createdAt: iso(row.createdAt),
    updatedAt: iso(row.updatedAt),
  };
}

export function toAuditEvent(row: typeof auditEvents.$inferSelect): AuditEvent {
  return {
    id: row.id,
    sequence: row.sequence,
    timestamp: iso(row.timestamp),
    organizationId: row.organizationId,
    actorType: row.actorType,
    actorId: row.actorId,
    agentId: row.agentId,
    runId: row.runId,
    connectionId: row.connectionId,
    eventType: row.eventType as AuditEvent['eventType'],
    decision: row.decision,
    metadata: row.metadata as JsonObject,
    previousHash: row.previousHash,
    eventHash: row.eventHash,
  };
}
