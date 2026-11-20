import { AuditEventType } from '@aab/contracts';
import type { ActorType, CapabilityRejectionReason } from '@aab/contracts';
import { and, eq, sql } from 'drizzle-orm';
import type { SQL } from 'drizzle-orm';
import { PgTransaction } from 'drizzle-orm/pg-core';
import type { Db } from '../client.js';
import { rowsOf } from '../client.js';
import { ConflictError, NotFoundError, translateDbErrors, ValidationError } from '../errors.js';
import {
  agents,
  auditEvents,
  connections,
  executionJobs,
  vaultAccessCapabilities,
} from '../schema.js';
import type { CAPABILITY_REVOCATION_REASONS } from '../schema.js';
import { isUuid, isValidScope } from '../support.js';
import type { Scope } from '../support.js';
import { createAuditRepository } from './audit.js';

/*
 * Worker capabilities (ADR-014 sections 5 to 7). THE CONDITIONAL STATEMENTS IN THIS FILE ARE THE
 * ACCESS CONTROL: every validity condition of a capability is a predicate of one UPDATE, never a
 * read followed by a write.
 *
 * Clock: every function takes the current time as `now: Date` from its caller (the vault passes
 * `new Date()` immediately before the call), like every other repository in this package, and
 * the database clock is the authority over it. A consume compares expiry with `now` AND with
 * `statement_timestamp()` (no grace interval: a stale caller cannot extend a capability), and
 * `insertAuthorization` and `issueToken` refuse a `now` more than `MAX_CLOCK_SKEW_SECONDS` away
 * from `statement_timestamp()`, so a caller cannot stretch a window by passing a future time or
 * shorten the DB's view of it with a past one. ADR-014 writes `now()`; the as-built note records
 * the choice. The vault is the only caller.
 *
 * Audit metadata key names avoid the words `secret`, `token` and `kek`: the audit redactor
 * replaces the value under any such key. The events say `vaultEntryId`, `entryVersion`,
 * `accessTtlSeconds` and `keyVersionFrom` instead.
 *
 * Locks, in one order everywhere: the connection row, then the secret row, then capability and
 * job rows. A consume takes the connection FOR SHARE (read) or FOR UPDATE (seal); revocation takes
 * it FOR NO KEY UPDATE (the lock a status update takes), which conflicts with both, so whichever
 * transaction commits first is what the other sees (ADR-014 section 7).
 */

export type CapabilityPurpose = 'read' | 'seal';
export type CapabilityRevocationReason = (typeof CAPABILITY_REVOCATION_REASONS)[number];

/** Authorization lifetime bounds in seconds (ADR-014 section 5; repeated by a CHECK). */
export const AUTHORIZATION_TTL_SECONDS = { min: 10, max: 3600 } as const;
/** Token lifetime bounds in seconds (ADR-014 section 5; repeated by a CHECK). */
export const TOKEN_TTL_SECONDS = { min: 1, max: 120 } as const;
/**
 * How far the caller's `now` may be from the database clock (`statement_timestamp()`) when an
 * authorization is created or a token issued. Computed in SQL, so the database is authoritative.
 */
export const MAX_CLOCK_SKEW_SECONDS = 5;
/**
 * How far the `policy.evaluated` event of an operation job may be from the job's creation:
 * the decision and the job are written in one request, so a decision hours away from the job
 * is not the decision that created it. The upper bound of an authorization's lifetime.
 */
export const POLICY_DECISION_WINDOW_SECONDS = AUTHORIZATION_TTL_SECONDS.max;
/** Used and expired capability ids are kept this long after `expires_at` (ADR-014 section 6). */
export const CAPABILITY_RETENTION_MS = 7 * 24 * 60 * 60 * 1000;

const SHA256_HEX = /^[0-9a-f]{64}$/;
const MAX_LISTED_IDS = 50;

/**
 * A lifetime that was not asked for explicitly is never accepted: it must be a number, a safe
 * integer and inside the bounds. NaN, Infinity, fractions, strings and undefined are refused.
 */
function requireTtl(
  value: unknown,
  bounds: { readonly min: number; readonly max: number },
  field: string,
): number {
  if (
    typeof value !== 'number' ||
    !Number.isSafeInteger(value) ||
    value < bounds.min ||
    value > bounds.max
  ) {
    throw new ValidationError('invalid capability lifetime', [
      {
        path: field,
        message: `expected a whole number of seconds from ${bounds.min} to ${bounds.max}`,
      },
    ]);
  }
  return value;
}

function requireNow(now: unknown): Date {
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) {
    throw new ValidationError('invalid time', [{ path: 'now', message: 'expected a valid Date' }]);
  }
  return now;
}

/**
 * The window an authorization created at `now` gets, as the exact strings the database will
 * store. The vault computes its authorization MAC over these before it calls
 * `insertAuthorization`, which derives the same two instants. Throws ValidationError for a
 * lifetime outside 10 to 3,600 whole seconds.
 */
export function authorizationWindow(
  now: Date,
  ttlSeconds: unknown,
): { issuedAt: string; expiresAt: string } {
  const ttl = requireTtl(ttlSeconds, AUTHORIZATION_TTL_SECONDS, 'ttlSeconds');
  const issued = requireNow(now);
  return {
    issuedAt: issued.toISOString(),
    expiresAt: new Date(issued.getTime() + ttl * 1000).toISOString(),
  };
}

function requireUuidFields(values: Record<string, string | null>, entity: string): void {
  for (const [field, value] of Object.entries(values)) {
    if (value !== null && !isUuid(value)) {
      throw new ValidationError(`invalid ${entity}`, [{ path: field, message: 'expected a UUID' }]);
    }
  }
}

function requireHex(value: unknown, field: string): string {
  if (typeof value !== 'string' || !SHA256_HEX.test(value)) {
    throw new ValidationError('invalid capability', [
      { path: field, message: 'expected 64 lowercase hex characters' },
    ]);
  }
  return value;
}

/** What the vault needs to verify the MACs and to act; internal to the broker, never a DTO. */
export interface CapabilityRecord {
  id: string;
  organizationId: string;
  jobId: string;
  agentId: string | null;
  connectionId: string;
  secretId: string;
  purpose: CapabilityPurpose;
  operation: string | null;
  argumentsHash: string | null;
  issuedAt: string;
  expiresAt: string;
  authorizationMac: string;
  macKekVersion: number;
  workerId: string | null;
  attempt: number | null;
  secretVersion: number | null;
  tokenHash: string | null;
  tokenIssuedAt: string | null;
  tokenExpiresAt: string | null;
  tokenMac: string | null;
  usedAt: string | null;
  revokedAt: string | null;
  revokedReason: CapabilityRevocationReason | null;
}

const iso = (value: unknown): string | null => {
  if (value === null || value === undefined) return null;
  if (value instanceof Date) return value.toISOString();
  return new Date(String(value)).toISOString();
};

function toRecord(row: Record<string, unknown>): CapabilityRecord {
  const nullableNumber = (value: unknown): number | null =>
    value === null || value === undefined ? null : Number(value);
  const nullableString = (value: unknown): string | null =>
    value === null || value === undefined ? null : String(value);
  return {
    id: String(row.id),
    organizationId: String(row.organization_id),
    jobId: String(row.job_id),
    agentId: nullableString(row.agent_id),
    connectionId: String(row.connection_id),
    secretId: String(row.secret_id),
    purpose: row.purpose as CapabilityPurpose,
    operation: nullableString(row.operation),
    argumentsHash: nullableString(row.arguments_hash),
    issuedAt: iso(row.issued_at)!,
    expiresAt: iso(row.expires_at)!,
    authorizationMac: String(row.authorization_mac),
    macKekVersion: Number(row.mac_kek_version),
    workerId: nullableString(row.worker_id),
    attempt: nullableNumber(row.attempt),
    secretVersion: nullableNumber(row.secret_version),
    tokenHash: nullableString(row.token_hash),
    tokenIssuedAt: iso(row.token_issued_at),
    tokenExpiresAt: iso(row.token_expires_at),
    tokenMac: nullableString(row.token_mac),
    usedAt: iso(row.used_at),
    revokedAt: iso(row.revoked_at),
    revokedReason: nullableString(row.revoked_reason) as CapabilityRevocationReason | null,
  };
}

/** Who an audit event is attributed to. Defaults to the broker itself (`system`, no id). */
export interface CapabilityActor {
  type: ActorType;
  id: string | null;
}
const SYSTEM_ACTOR: CapabilityActor = { type: 'system', id: null };

export interface InsertAuthorizationInput {
  /** Generated by the vault: the authorization MAC covers it. */
  capabilityId: string;
  jobId: string;
  secretId: string;
  purpose: CapabilityPurpose;
  /**
   * The binding the vault computed its MAC over. The statement requires each value to equal the
   * job row's own column, so the binding cannot differ from the job it authorizes.
   */
  organizationId: string;
  agentId: string | null;
  connectionId: string;
  operation: string | null;
  argumentsHash: string | null;
  now: Date;
  /** 10 to 3,600, required: there is no default. */
  ttlSeconds: number;
  /** Hex HMAC computed by the vault over the binding and `authorizationWindow`. */
  authorizationMac: string;
  macKekVersion: number;
  actor?: CapabilityActor | undefined;
}

export interface IssueTokenInput {
  capabilityId: string;
  jobId: string;
  workerId: string;
  attempt: number;
  /** Lowercase hex SHA-256 of the 256-bit token. The token itself never reaches this package. */
  tokenHash: string;
  /** 1 to 120, required: there is no default. The token never outlives the authorization. */
  tokenTtlSeconds: number;
  now: Date;
  /** The authorization MAC the vault verified; the statement requires the row to still hold it. */
  authorizationMac: string;
  /**
   * Called inside the transaction with the row the conditional update produced (it holds the
   * bound secret version and the token times); returns the hex token MAC, which is stored
   * before the transaction commits. A row with no token MAC is never consumable.
   */
  computeTokenMac: (issued: CapabilityRecord) => string;
  actor?: CapabilityActor | undefined;
}

export interface ConsumeInput {
  /** Lowercase hex SHA-256 of the presented token. */
  tokenHash: string;
  jobId: string;
  connectionId: string;
  /** Required for `read`, must be null for `seal`. */
  operation: string | null;
  now: Date;
}

export interface Rejection {
  reason: CapabilityRejectionReason;
  /** Null when neither the capability nor the presented job resolves: log and count only. */
  organizationId: string | null;
  capabilityId: string | null;
  jobId: string | null;
  connectionId: string | null;
  purpose: CapabilityPurpose;
}

export interface RevocationResult {
  revoked: number;
  capabilityIds: string[];
}

export interface CapabilitySummary {
  authorized: number;
  issued: number;
  used: number;
  revoked: number;
  rejectedByReason: Partial<Record<CapabilityRejectionReason, number>>;
}

function sqlTime(value: Date) {
  return sql`${value.toISOString()}::timestamptz`;
}

/** True when the database clock and `at` are no more than `MAX_CLOCK_SKEW_SECONDS` apart. */
function withinClockSkew(at: SQL) {
  return sql`abs(extract(epoch from (${at} - statement_timestamp()))) <= ${MAX_CLOCK_SKEW_SECONDS}::numeric`;
}

/**
 * Runs `work` in the caller's transaction when `db` already is one, and opens a transaction
 * otherwise. A nested `db.transaction` would open a savepoint; the consume has nothing to roll
 * back on its own, and using the ambient transaction makes it explicit that the connection lock
 * it takes is held until the CALLER commits.
 */
function inTransaction<T>(db: Db, work: (tx: Db) => Promise<T>): Promise<T> {
  return db instanceof PgTransaction ? work(db as unknown as Db) : db.transaction(work);
}

type OnRevoked = (capabilityIds: string[]) => Promise<Record<string, string | number | boolean>>;

/**
 * The dashboard counts of `summarizeForConnection`. `since` is a SQL timestamp expression. What
 * each count means, all within the window starting at `since`: `authorized` = capabilities
 * authorized (issued_at) in the window; `issued` = of those, the ones that got a token;
 * `used` = capabilities consumed (used_at) in the window; `revoked` = capabilities revoked
 * (revoked_at) in the window, whenever they were authorized; `rejected` = capability_rejected
 * audit events in the window. So `used` and `revoked` count events of the window and can exceed
 * `authorized`. The
 * ownership check and the counts are scoped by the caller's organization and user; nothing but
 * counts and reason codes is selected.
 */
async function summarize(
  db: Db,
  scope: Scope,
  connectionId: string,
  since: SQL,
): Promise<CapabilitySummary> {
  if (!isValidScope(scope) || !isUuid(connectionId)) throw new NotFoundError('connection');
  const [owned] = await db
    .select({ id: connections.id })
    .from(connections)
    .where(
      and(
        eq(connections.id, connectionId),
        eq(connections.organizationId, scope.organizationId),
        eq(connections.ownerUserId, scope.userId),
      ),
    )
    .limit(1);
  if (owned === undefined) throw new NotFoundError('connection');

  const [counts] = rowsOf(
    await db.execute(sql`
      select count(*) filter (where issued_at >= ${since})::int as authorized,
             count(*) filter (where token_hash is not null and issued_at >= ${since})::int as issued,
             count(*) filter (where used_at >= ${since})::int as used,
             count(*) filter (where revoked_at >= ${since})::int as revoked
      from vault_access_capabilities
      where connection_id = ${connectionId}::uuid
        and organization_id = ${scope.organizationId}::uuid`),
  );
  const rejected = await db
    .select({
      reason: sql<string>`${auditEvents.metadata} ->> 'reason'`,
      total: sql<number>`count(*)::int`,
    })
    .from(auditEvents)
    .where(
      and(
        eq(auditEvents.organizationId, scope.organizationId),
        eq(auditEvents.connectionId, connectionId),
        eq(auditEvents.eventType, 'vault.capability_rejected'),
        sql`${auditEvents.timestamp} >= ${since}`,
      ),
    )
    .groupBy(sql`${auditEvents.metadata} ->> 'reason'`);
  const rejectedByReason: Partial<Record<CapabilityRejectionReason, number>> = {};
  for (const row of rejected) {
    rejectedByReason[row.reason as CapabilityRejectionReason] = Number(row.total);
  }
  return {
    authorized: Number(counts?.authorized ?? 0),
    issued: Number(counts?.issued ?? 0),
    used: Number(counts?.used ?? 0),
    revoked: Number(counts?.revoked ?? 0),
    rejectedByReason,
  };
}

/**
 * Capability rows for the vault. The vault calls these inside `repositories.transaction`, so
 * every state change commits with its audit event (INV-10), or not at all.
 */
export function createCapabilityRepository(db: Db) {
  /** Takes the connection lock a consume or an issue needs. Silent when the row is absent. */
  async function lockConnection(
    tx: Db,
    connectionId: string,
    mode: 'share' | 'update' | 'no key update',
  ): Promise<void> {
    await tx
      .select({ id: connections.id })
      .from(connections)
      .where(eq(connections.id, connectionId))
      .for(mode);
  }

  /**
   * Takes the agent row lock (ADR-014 section 7). `share` for an authorization, `no key update`
   * for whoever revokes the agent's access. Silent when the row is absent.
   */
  async function lockAgent(
    tx: Db,
    agentId: string,
    mode: 'share' | 'no key update',
  ): Promise<void> {
    await tx.select({ id: agents.id }).from(agents).where(eq(agents.id, agentId)).for(mode);
  }

  /** Marks every unused capability that matches `target` revoked, and audits it. */
  async function revokeWhere(
    tx: Db,
    target: SQL,
    input: {
      reason: CapabilityRevocationReason;
      now: Date;
      actor?: CapabilityActor | undefined;
      onRevoked?: OnRevoked | undefined;
    },
    extraMetadata: Record<string, unknown>,
  ): Promise<RevocationResult> {
    // Lock the target rows first, in id order, in a statement of their own: two revocations that
    // overlap on several rows (an agent disabled while one of its connections is revoked) then
    // wait for each other instead of deadlocking, and the UPDATE below starts from a snapshot
    // taken after the locks were granted.
    const locked = rowsOf(
      await tx.execute(sql`
        select id from vault_access_capabilities
        where used_at is null and revoked_at is null and ${target}
        order by id
        for update`),
    );
    if (locked.length === 0) return { revoked: 0, capabilityIds: [] };
    const rows = rowsOf(
      await tx.execute(sql`
        update vault_access_capabilities
        set revoked_at = ${sqlTime(input.now)}, revoked_reason = ${input.reason}
        where id in (${sql.join(
          locked.map((row) => sql`${String(row.id)}::uuid`),
          sql`, `,
        )})
          and used_at is null and revoked_at is null
        returning id, organization_id, agent_id, connection_id, job_id`),
    );
    if (rows.length === 0) return { revoked: 0, capabilityIds: [] };
    // Same transaction, after the capability rows and before the audit event: the caller's
    // follow-up writes (cancelling the queued jobs of these capabilities) and the metadata it
    // wants on the event.
    const followUp =
      input.onRevoked === undefined ? {} : await input.onRevoked(rows.map((row) => String(row.id)));
    const actor = input.actor ?? SYSTEM_ACTOR;
    const audit = createAuditRepository(tx);
    // One event per organization: an audit event belongs to exactly one chain.
    const byOrganization = new Map<string, Record<string, unknown>[]>();
    for (const row of rows) {
      const list = byOrganization.get(String(row.organization_id)) ?? [];
      list.push(row);
      byOrganization.set(String(row.organization_id), list);
    }
    for (const [organizationId, group] of byOrganization) {
      const connectionIds = [...new Set(group.map((row) => String(row.connection_id)))];
      const agentIds = [...new Set(group.map((row) => row.agent_id).filter((id) => id !== null))];
      await audit.append({
        organizationId,
        actorType: actor.type,
        actorId: actor.id,
        agentId: agentIds.length === 1 ? String(agentIds[0]) : null,
        connectionId: connectionIds.length === 1 ? connectionIds[0]! : null,
        eventType: AuditEventType.parse('vault.capability_revoked'),
        decision: 'not_applicable',
        timestamp: input.now,
        metadata: {
          ...extraMetadata,
          ...(byOrganization.size === 1 ? followUp : {}),
          reason: input.reason,
          count: group.length,
          capabilityIds: group.slice(0, MAX_LISTED_IDS).map((row) => String(row.id)),
        },
      });
    }
    return { revoked: rows.length, capabilityIds: rows.map((row) => String(row.id)) };
  }

  /**
   * ONE conditional UPDATE ... RETURNING. Every validity condition of ADR-014 section 6 is a
   * predicate; zero rows means refused and nothing changed. There is no read-then-write path.
   */
  async function consume(
    purpose: CapabilityPurpose,
    input: ConsumeInput,
  ): Promise<CapabilityRecord | null> {
    const now = requireNow(input.now);
    if (
      typeof input.tokenHash !== 'string' ||
      !SHA256_HEX.test(input.tokenHash) ||
      !isUuid(input.jobId) ||
      !isUuid(input.connectionId)
    ) {
      return null;
    }
    if (purpose === 'read' ? typeof input.operation !== 'string' : input.operation !== null) {
      return null;
    }
    return inTransaction(db, async (tx) => {
      // Reads share the connection, a seal owns it: revocation (which needs it exclusively)
      // and a seal can then never interleave.
      await lockConnection(tx, input.connectionId, purpose === 'read' ? 'share' : 'update');
      const at = sqlTime(now);
      const rows = rowsOf(
        await tx.execute(sql`
          update vault_access_capabilities as c
          set used_at = ${at}
          from execution_jobs as j,
               connections as k,
               vault_secrets as s
               left join vault_secret_versions as v on v.id = s.active_version_id
          where c.token_hash = ${input.tokenHash}
            and c.purpose = ${purpose}
            and c.job_id = ${input.jobId}
            and c.connection_id = ${input.connectionId}
            and c.operation is not distinct from ${input.operation}::text
            and c.token_mac is not null
            and c.used_at is null
            and c.revoked_at is null
            and c.token_expires_at > ${at}
            and c.expires_at > ${at}
            and c.token_expires_at > statement_timestamp()
            and c.expires_at > statement_timestamp()
            and j.id = c.job_id
            and j.organization_id = c.organization_id
            and j.connection_id = c.connection_id
            and j.capability_ref = c.id
            and j.kind = ${purpose === 'read' ? 'operation' : 'login'}
            and j.status = 'running'
            and j.worker_id = c.worker_id
            and j.attempt_count = c.attempt
            and j.cancel_requested_at is null
            and k.id = c.connection_id
            and k.organization_id = c.organization_id
            and k.status = ${purpose === 'read' ? 'active' : 'authenticating'}
            and s.id = c.secret_id
            and s.connection_id = c.connection_id
            and s.status ${purpose === 'read' ? sql`= 'active'` : sql`<> 'revoked'`}
            and coalesce(v.version, 0) = c.secret_version
            and ${purpose === 'read' ? sql`v.id is not null` : sql`true`}
          returning c.*`),
      );
      return rows[0] === undefined ? null : toRecord(rows[0]);
    });
  }

  return {
    /**
     * Stage 1 (ADR-014 section 5). One INSERT ... SELECT creates the capability only if the job
     * is queued, has no capability and no cancellation, its own columns equal the binding that
     * was passed, the connection is `active` (read) or `authenticating` (seal) and the policy
     * decision of an operation job is an `allow` `policy.evaluated` event for the same
     * organization, agent, connection and operation, written within
     * `POLICY_DECISION_WINDOW_SECONDS` of the job, whose matched grant is still an unrevoked,
     * unexpired `allow` grant of that agent, connection and operation, with the agent `active`
     * and no newer live `deny` grant, and the secret is not `revoked`, and `now` is within
     * `MAX_CLOCK_SKEW_SECONDS` of the database clock; then a conditional UPDATE sets
     * `execution_jobs.capability_ref`. ConflictError otherwise (the transaction rolls back and
     * nothing is left behind). The agent row is locked FOR SHARE first (a read authorization),
     * so a concurrent grant revocation or agent disabling is either seen or waited for.
     * Appends `vault.capability_authorized`.
     */
    async insertAuthorization(
      input: InsertAuthorizationInput,
    ): Promise<{ capabilityId: string; issuedAt: string; expiresAt: string }> {
      const window = authorizationWindow(input.now, input.ttlSeconds);
      requireUuidFields(
        {
          capabilityId: input.capabilityId,
          jobId: input.jobId,
          secretId: input.secretId,
          organizationId: input.organizationId,
          agentId: input.agentId,
          connectionId: input.connectionId,
        },
        'capability',
      );
      if (input.purpose !== 'read' && input.purpose !== 'seal') {
        throw new ValidationError('invalid capability', [
          { path: 'purpose', message: 'expected read or seal' },
        ]);
      }
      requireHex(input.authorizationMac, 'authorizationMac');
      if (!Number.isSafeInteger(input.macKekVersion) || input.macKekVersion < 1) {
        throw new ValidationError('invalid capability', [
          { path: 'macKekVersion', message: 'expected a positive integer' },
        ]);
      }
      if (input.argumentsHash !== null) requireHex(input.argumentsHash, 'argumentsHash');
      const read = input.purpose === 'read';
      if (
        read
          ? input.agentId === null || input.operation === null || input.argumentsHash === null
          : input.agentId !== null || input.operation !== null || input.argumentsHash !== null
      ) {
        throw new ValidationError('invalid capability', [
          { path: 'purpose', message: 'binding does not match the purpose' },
        ]);
      }
      const actor = input.actor ?? SYSTEM_ACTOR;
      const issuedAt = sql`${window.issuedAt}::timestamptz`;
      // An operation job is authorized only while what its policy decision rested on still
      // holds: the agent is active and a grant the decision matched (exact agent, connection and
      // operation, the policy engine's grant model) is still an unrevoked, unexpired `allow`.
      // The grant's constraints are not re-evaluated here (they are JSON rules over the job's
      // arguments, which the policy engine owns); what is re-checked is every way a grant stops
      // being in force, plus a conservative refusal when a deny appeared after the decision: any
      // live `deny` grant for the same agent, connection and operation created later than it.
      const purposeCondition = read
        ? sql`(j.kind = 'operation' and k.status = 'active'
            and exists (
              select 1 from agents as ag
              where ag.id = j.agent_id
                and ag.organization_id = j.organization_id
                and ag.status = 'active')
            and exists (
              select 1 from audit_events as a
              where a.id = j.policy_decision_id
                and a.organization_id = j.organization_id
                and a.event_type = 'policy.evaluated'
                and a.decision = 'allow'
                and a.agent_id = j.agent_id
                and a.connection_id = j.connection_id
                and a.metadata ->> 'operation' = j.operation
                and abs(extract(epoch from (a.timestamp - j.created_at)))
                      <= ${POLICY_DECISION_WINDOW_SECONDS}::numeric
                and jsonb_typeof(a.metadata -> 'matchedGrantIds') = 'array'
                and exists (
                  select 1 from agent_grants as g
                  where a.metadata -> 'matchedGrantIds' @> to_jsonb(g.id::text)
                    and g.agent_id = j.agent_id
                    and g.connection_id = j.connection_id
                    and g.operation = j.operation
                    and g.effect = 'allow'
                    and g.revoked_at is null
                    and (g.expires_at is null
                         or (g.expires_at > ${issuedAt} and g.expires_at > statement_timestamp())))
                and not exists (
                  select 1 from agent_grants as d
                  where d.agent_id = j.agent_id
                    and d.connection_id = j.connection_id
                    and d.operation = j.operation
                    and d.effect = 'deny'
                    and d.revoked_at is null
                    and (d.expires_at is null
                         or (d.expires_at > ${issuedAt} and d.expires_at > statement_timestamp()))
                    and d.created_at > a.timestamp)))`
        : sql`(j.kind = 'login' and k.status = 'authenticating')`;

      return translateDbErrors('capability', () =>
        db.transaction(async (tx) => {
          // Agent first, then connection (the lock order of ADR-014 section 7): disabling the
          // agent and revoking one of its grants take the agent row FOR NO KEY UPDATE before they
          // revoke, so whichever commits first is what this statement's snapshot sees.
          if (read) await lockAgent(tx, input.agentId!, 'share');
          await lockConnection(tx, input.connectionId, 'share');
          const inserted = rowsOf(
            await tx.execute(sql`
              insert into vault_access_capabilities
                (id, organization_id, job_id, agent_id, connection_id, secret_id, purpose,
                 operation, arguments_hash, issued_at, expires_at, authorization_mac,
                 mac_kek_version)
              select ${input.capabilityId}::uuid, j.organization_id, j.id, j.agent_id,
                     j.connection_id, s.id, ${input.purpose}, j.operation, j.arguments_hash,
                     ${window.issuedAt}::timestamptz, ${window.expiresAt}::timestamptz,
                     ${input.authorizationMac}, ${input.macKekVersion}::int
              from execution_jobs as j
              join connections as k on k.id = j.connection_id
              join vault_secrets as s on s.id = ${input.secretId}::uuid and s.connection_id = j.connection_id
              where j.id = ${input.jobId}::uuid
                and j.organization_id = ${input.organizationId}::uuid
                and j.connection_id = ${input.connectionId}::uuid
                and j.agent_id is not distinct from ${input.agentId}::uuid
                and j.operation is not distinct from ${input.operation}::text
                and j.arguments_hash is not distinct from ${input.argumentsHash}::text
                and j.status = 'queued'
                and j.capability_ref is null
                and j.cancel_requested_at is null
                and k.organization_id = j.organization_id
                and s.status <> 'revoked'
                and ${withinClockSkew(issuedAt)}
                and ${purposeCondition}
              returning id`),
          );
          if (inserted.length !== 1) throw new ConflictError('capability cannot be authorized');

          const linked = await tx
            .execute(
              sql`
              update execution_jobs
              set capability_ref = ${input.capabilityId}::uuid, updated_at = ${sqlTime(input.now)}
              where id = ${input.jobId}::uuid and capability_ref is null and status = 'queued'
              returning id`,
            )
            .then(rowsOf);
          if (linked.length !== 1) throw new ConflictError('capability cannot be authorized');

          await createAuditRepository(tx).append({
            organizationId: input.organizationId,
            actorType: actor.type,
            actorId: actor.id,
            agentId: input.agentId,
            connectionId: input.connectionId,
            eventType: AuditEventType.parse('vault.capability_authorized'),
            timestamp: input.now,
            metadata: {
              capabilityId: input.capabilityId,
              jobId: input.jobId,
              vaultEntryId: input.secretId,
              purpose: input.purpose,
              ttlSeconds: input.ttlSeconds,
              expiresAt: window.expiresAt,
            },
          });
          return { capabilityId: input.capabilityId, ...window };
        }),
      );
    },

    /**
     * Stage 2. ONE conditional UPDATE sets the token hash, its times, the worker, the attempt
     * and the bound secret version, only while the authorization is unexpired, unrevoked,
     * unused and holds the verified MAC, has no token yet, the job is `running` under that
     * worker and attempt without cancellation and is the one this capability authorizes, the
     * connection is `active` (read) or `authenticating` (seal) and the secret is `active` (read)
     * or not `revoked` (seal). The token expiry is the smaller of now + ttl and the
     * authorization's expiry, and `now` must be within `MAX_CLOCK_SKEW_SECONDS` of the database
     * clock. The job row is locked FOR SHARE first, so a lease recovery that is deciding about
     * the job is waited for and its outcome seen. Returns the row (the vault MACs it) or null when refused, then
     * stores the MAC `computeTokenMac` returned and appends `vault.capability_issued`.
     */
    async issueToken(input: IssueTokenInput): Promise<CapabilityRecord | null> {
      const now = requireNow(input.now);
      const ttl = requireTtl(input.tokenTtlSeconds, TOKEN_TTL_SECONDS, 'tokenTtlSeconds');
      requireUuidFields({ capabilityId: input.capabilityId, jobId: input.jobId }, 'capability');
      requireHex(input.tokenHash, 'tokenHash');
      requireHex(input.authorizationMac, 'authorizationMac');
      if (typeof input.workerId !== 'string' || input.workerId === '') {
        throw new ValidationError('invalid capability', [
          { path: 'workerId', message: 'required' },
        ]);
      }
      if (!Number.isSafeInteger(input.attempt) || input.attempt < 1) {
        throw new ValidationError('invalid capability', [
          { path: 'attempt', message: 'expected a positive integer' },
        ]);
      }
      const actor = input.actor ?? SYSTEM_ACTOR;
      const at = sqlTime(now);

      return translateDbErrors('capability', () =>
        db.transaction(async (tx) => {
          const [owner] = await tx
            .select({ connectionId: vaultAccessCapabilities.connectionId })
            .from(vaultAccessCapabilities)
            .where(eq(vaultAccessCapabilities.id, input.capabilityId))
            .limit(1);
          if (owner === undefined) return null;
          await lockConnection(tx, owner.connectionId, 'share');
          // The job row, locked by a statement of its own BEFORE the UPDATE: lease recovery holds
          // it FOR UPDATE while it decides, and an UPDATE ... FROM would otherwise judge the job
          // from a snapshot older than the recovery that committed while it waited for the
          // capability row (the join's other rows are not re-read after a lock wait).
          await tx
            .select({ id: executionJobs.id })
            .from(executionJobs)
            .where(eq(executionJobs.id, input.jobId))
            .for('share');

          const rows = rowsOf(
            await tx.execute(sql`
              update vault_access_capabilities as c
              set token_hash = ${input.tokenHash},
                  token_issued_at = ${at},
                  token_expires_at = least(${at} + ${ttl}::int * interval '1 second', c.expires_at),
                  worker_id = ${input.workerId},
                  attempt = ${input.attempt}::int,
                  secret_version = coalesce(v.version, 0)
              from execution_jobs as j,
                   connections as k,
                   vault_secrets as s
                   left join vault_secret_versions as v on v.id = s.active_version_id
              where c.id = ${input.capabilityId}::uuid
                and c.job_id = ${input.jobId}::uuid
                and c.authorization_mac = ${input.authorizationMac}
                and c.token_hash is null
                and c.used_at is null
                and c.revoked_at is null
                and c.expires_at > ${at}
                and ${withinClockSkew(at)}
                and j.id = c.job_id
                and j.organization_id = c.organization_id
                and j.connection_id = c.connection_id
                and j.capability_ref = c.id
                and j.status = 'running'
                and j.worker_id = ${input.workerId}
                and j.attempt_count = ${input.attempt}::int
                and j.cancel_requested_at is null
                and j.kind = case c.purpose when 'read' then 'operation' else 'login' end
                and k.id = c.connection_id
                and k.organization_id = c.organization_id
                and k.status = case c.purpose when 'read' then 'active' else 'authenticating' end
                and s.id = c.secret_id
                and s.connection_id = c.connection_id
                and s.status <> 'revoked'
                and (c.purpose = 'seal' or (s.status = 'active' and v.id is not null))
              returning c.*`),
          );
          if (rows[0] === undefined) return null;
          const issued = toRecord(rows[0]);

          const mac = requireHex(input.computeTokenMac(issued), 'tokenMac');
          const stored = rowsOf(
            await tx.execute(sql`
              update vault_access_capabilities
              set token_mac = ${mac}
              where id = ${issued.id}::uuid and token_hash = ${input.tokenHash}
                and token_mac is null and used_at is null and revoked_at is null
              returning id`),
          );
          if (stored.length !== 1) throw new ConflictError('capability cannot be issued');

          await createAuditRepository(tx).append({
            organizationId: issued.organizationId,
            actorType: actor.type,
            actorId: actor.id,
            agentId: issued.agentId,
            connectionId: issued.connectionId,
            eventType: AuditEventType.parse('vault.capability_issued'),
            timestamp: now,
            metadata: {
              capabilityId: issued.id,
              jobId: issued.jobId,
              purpose: issued.purpose,
              workerId: issued.workerId,
              attempt: issued.attempt,
              entryVersion: issued.secretVersion,
              accessTtlSeconds: ttl,
              accessExpiresAt: issued.tokenExpiresAt,
            },
          });
          return { ...issued, tokenMac: mac };
        }),
      );
    },

    /**
     * Stage 3 for an operation job: one conditional UPDATE ... RETURNING that sets `used_at`
     * only if the token hash matches, the purpose is `read`, job, connection and operation equal
     * the request, the capability is unused, unrevoked, carries a token MAC and neither the
     * token nor the authorization has expired, the job is `running` under the bound worker and
     * attempt with no cancellation and is the job this capability authorizes, the connection is
     * `active`, and the secret is `active` with the bound version as its active version. Null
     * means refused and nothing changed. It writes no audit event: which event follows (the
     * vault's `vault.secret_read`, or `vault.capability_rejected` when a MAC check or the open
     * fails) depends on checks only the vault can make, so the caller runs this inside
     * `repositories.transaction` and appends the event there.
     */
    consumeRead(input: ConsumeInput): Promise<CapabilityRecord | null> {
      return consume('read', input);
    },

    /**
     * Stage 3 for a login job: the same single statement with purpose `seal`, `operation` null,
     * the connection `authenticating`, the secret not `revoked`, and the bound version (0 when
     * there was none) still the secret's active version. Takes the connection FOR UPDATE.
     */
    consumeSeal(input: ConsumeInput): Promise<CapabilityRecord | null> {
      return consume('seal', input);
    },

    /** The authorization row, for the vault to verify its MAC before it issues. Internal. */
    async getAuthorization(capabilityId: string): Promise<CapabilityRecord | null> {
      if (!isUuid(capabilityId)) return null;
      const rows = rowsOf(
        await db.execute(
          sql`select * from vault_access_capabilities where id = ${capabilityId}::uuid`,
        ),
      );
      return rows[0] === undefined ? null : toRecord(rows[0]);
    },

    /**
     * Revokes every unused capability of the connection (reason `connection_revoked`,
     * `session_deleted` or `owner_requested`) and appends `vault.capability_revoked` when any
     * changed. Takes the connection FOR NO KEY UPDATE first (ADR-014 section 7). Used capabilities
     * keep their `used_at`; they cannot be used again.
     */
    async revokeForConnection(input: {
      connectionId: string;
      reason: Extract<
        CapabilityRevocationReason,
        'connection_revoked' | 'session_deleted' | 'owner_requested'
      >;
      now: Date;
      actor?: CapabilityActor | undefined;
      /**
       * Called in the same transaction with the ids just revoked, before the audit event; the
       * metadata it returns (small counts only) is added to the event.
       */
      onRevoked?: OnRevoked | undefined;
    }): Promise<RevocationResult> {
      requireNow(input.now);
      if (!isUuid(input.connectionId)) return { revoked: 0, capabilityIds: [] };
      return db.transaction(async (tx) => {
        await lockConnection(tx, input.connectionId, 'no key update');
        return revokeWhere(tx, sql`connection_id = ${input.connectionId}::uuid`, input, {
          connectionId: input.connectionId,
        });
      });
    },

    /**
     * Grant revoked or agent disabled (ADR-014 section 7): revokes every unused capability of
     * the agent for the connection, or for all its connections when `connectionId` is null.
     * Needs no connection lock: it writes the capability rows a consume writes, and the
     * consume's own predicate re-checks `revoked_at` on the conflicting row.
     */
    async revokeForAgentConnection(input: {
      agentId: string;
      connectionId: string | null;
      reason: Extract<CapabilityRevocationReason, 'grant_revoked' | 'agent_disabled'>;
      now: Date;
      actor?: CapabilityActor | undefined;
    }): Promise<RevocationResult> {
      requireNow(input.now);
      if (!isUuid(input.agentId) || (input.connectionId !== null && !isUuid(input.connectionId))) {
        return { revoked: 0, capabilityIds: [] };
      }
      return db.transaction((tx) =>
        revokeWhere(
          tx,
          input.connectionId === null
            ? sql`agent_id = ${input.agentId}::uuid`
            : sql`agent_id = ${input.agentId}::uuid and connection_id = ${input.connectionId}::uuid`,
          input,
          { agentId: input.agentId, connectionId: input.connectionId },
        ),
      );
    },

    /**
     * Revokes the unused capability of one job (lease recovery). Same statement shape, one job.
     */
    async revokeForJob(input: {
      jobId: string;
      reason: Extract<CapabilityRevocationReason, 'lease_recovery'>;
      now: Date;
      actor?: CapabilityActor | undefined;
    }): Promise<RevocationResult> {
      requireNow(input.now);
      if (!isUuid(input.jobId)) return { revoked: 0, capabilityIds: [] };
      return db.transaction((tx) =>
        revokeWhere(tx, sql`job_id = ${input.jobId}::uuid`, input, { jobId: input.jobId }),
      );
    },

    /**
     * Why a consume of this presentation was refused, for the `vault.capability_rejected`
     * event. A plain read: it labels a refusal and never changes its outcome. It returns only
     * the reason code and the ids the event needs; the vault answers its caller with
     * `forbidden` and no detail, so nothing here may reach a response. The ids come from the
     * capability when the token resolves, otherwise from the presented job and connection,
     * and only if they exist (the organization is the job's). A presentation that resolves to
     * no organization has `organizationId: null` and cannot be put on a chain (ADR-014
     * section 10).
     */
    async describeForRejection(
      input: ConsumeInput & { purpose: CapabilityPurpose },
    ): Promise<Rejection> {
      const now = requireNow(input.now);
      const presentedJob = isUuid(input.jobId) ? input.jobId : null;
      const presentedConnection = isUuid(input.connectionId) ? input.connectionId : null;
      const found =
        typeof input.tokenHash === 'string' && SHA256_HEX.test(input.tokenHash)
          ? rowsOf(
              await db.execute(sql`
                select c.id, c.organization_id, c.job_id, c.connection_id, c.purpose, c.operation,
                       c.used_at, c.revoked_at, c.expires_at, c.token_expires_at, c.token_mac,
                       c.worker_id, c.attempt, c.secret_version,
                       j.status as job_status, j.worker_id as job_worker,
                       j.attempt_count as job_attempt, j.cancel_requested_at, j.capability_ref,
                       k.status as connection_status, s.status as secret_status,
                       coalesce(v.version, 0) as active_version,
                       statement_timestamp() as database_now
                from vault_access_capabilities as c
                left join execution_jobs as j on j.id = c.job_id
                left join connections as k on k.id = c.connection_id
                left join vault_secrets as s on s.id = c.secret_id
                left join vault_secret_versions as v on v.id = s.active_version_id
                where c.token_hash = ${input.tokenHash}`),
            )[0]
          : undefined;

      if (found === undefined) {
        // Unknown token: attribute it to the presented job's organization, if there is one.
        let organizationId: string | null = null;
        let jobId: string | null = null;
        let connectionId: string | null = null;
        if (presentedJob !== null) {
          const [job] = rowsOf(
            await db.execute(
              sql`select organization_id, connection_id from execution_jobs where id = ${presentedJob}::uuid`,
            ),
          );
          if (job !== undefined) {
            organizationId = String(job.organization_id);
            jobId = presentedJob;
            connectionId =
              presentedConnection !== null && String(job.connection_id) === presentedConnection
                ? presentedConnection
                : null;
          }
        }
        return {
          reason: 'unknown_token',
          organizationId,
          capabilityId: null,
          jobId,
          connectionId,
          purpose: input.purpose,
        };
      }

      const reject = (reason: CapabilityRejectionReason): Rejection => ({
        reason,
        organizationId: String(found.organization_id),
        capabilityId: String(found.id),
        jobId: String(found.job_id),
        connectionId: String(found.connection_id),
        purpose: found.purpose as CapabilityPurpose,
      });
      const purpose = found.purpose as CapabilityPurpose;
      if (
        purpose !== input.purpose ||
        String(found.job_id) !== input.jobId ||
        String(found.connection_id) !== input.connectionId ||
        (found.operation === null ? null : String(found.operation)) !== input.operation
      ) {
        return reject('binding_mismatch');
      }
      if (found.token_mac === null) return reject('integrity');
      if (found.revoked_at !== null) return reject('revoked');
      if (found.used_at !== null) return reject('used');
      // Expired by the caller's clock or by the database's, whichever is later: the consume
      // statement refuses on either.
      const clock = Math.max(now.getTime(), new Date(iso(found.database_now)!).getTime());
      if (
        new Date(iso(found.token_expires_at)!).getTime() <= clock ||
        new Date(iso(found.expires_at)!).getTime() <= clock
      ) {
        return reject('expired');
      }
      if (found.job_status !== 'running' || found.cancel_requested_at !== null) {
        return reject('job_not_running');
      }
      if (
        found.capability_ref === null ||
        String(found.capability_ref) !== String(found.id) ||
        found.job_worker !== found.worker_id ||
        Number(found.job_attempt) !== Number(found.attempt)
      ) {
        return reject('binding_mismatch');
      }
      if (found.connection_status !== (purpose === 'read' ? 'active' : 'authenticating')) {
        return reject('connection_not_active');
      }
      if (
        (purpose === 'read'
          ? found.secret_status !== 'active'
          : found.secret_status === 'revoked') ||
        Number(found.active_version) !== Number(found.secret_version)
      ) {
        return reject('secret_not_active');
      }
      // Every condition holds now: the state changed after the refusal (a concurrent writer).
      return reject('integrity');
    },

    /**
     * Appends `vault.capability_rejected` for a refusal (the theft signal, ADR-014 section 10).
     * Returns null, and writes nothing, when the rejection resolves to no organization: the
     * caller logs and counts it. Inside `repositories.transaction` it commits with the consume
     * that preceded it; on its own it is the "nothing was consumed" case.
     */
    async recordRejection(
      rejection: Rejection,
      context: { role: string; now: Date },
    ): Promise<string | null> {
      requireNow(context.now);
      if (rejection.organizationId === null) return null;
      const event = await createAuditRepository(db).append({
        organizationId: rejection.organizationId,
        actorType: 'system',
        actorId: null,
        connectionId: rejection.connectionId,
        eventType: AuditEventType.parse('vault.capability_rejected'),
        decision: 'deny',
        timestamp: context.now,
        metadata: {
          reason: rejection.reason,
          purpose: rejection.purpose,
          role: context.role,
          capabilityId: rejection.capabilityId,
          jobId: rejection.jobId,
        },
      });
      return event.id;
    },

    /**
     * Retention (ADR-014 section 6): deletes capabilities of finished jobs whose `expires_at` is
     * more than seven days before `now`, clearing the job's `capability_ref` in the same
     * statement. Returns how many rows were deleted. Writes no audit event: it removes expired
     * metadata, not authority.
     */
    async purge(now: Date): Promise<number> {
      const cutoff = new Date(requireNow(now).getTime() - CAPABILITY_RETENTION_MS);
      const rows = rowsOf(
        await db.execute(sql`
          with doomed as (
            select c.id from vault_access_capabilities as c
            join execution_jobs as j on j.id = c.job_id
            where c.expires_at < ${sqlTime(cutoff)} and j.status not in ('queued', 'running')
            for update of c
          ),
          unlinked as (
            update execution_jobs set capability_ref = null
            where capability_ref in (select id from doomed)
            returning id
          )
          delete from vault_access_capabilities where id in (select id from doomed)
          returning id`),
      );
      return rows.length;
    },

    /**
     * Dashboard (B5): counts for one connection since `since`, in the caller's scope. Counts only,
     * never an id, a hash or a MAC. NotFoundError for a connection outside the scope (another
     * owner, another organization or unknown: the same error).
     */
    async summarizeForConnection(
      scope: Scope,
      connectionId: string,
      since: Date,
    ): Promise<CapabilitySummary> {
      requireNow(since);
      return summarize(db, scope, connectionId, sqlTime(since));
    },

    /**
     * Dashboard (B5): the same counts over the last 24 hours by the DATABASE clock
     * (`statement_timestamp()`), so the window does not depend on a caller's clock.
     */
    async summarizeLast24Hours(scope: Scope, connectionId: string): Promise<CapabilitySummary> {
      return summarize(db, scope, connectionId, sql`statement_timestamp() - interval '24 hours'`);
    },
  };
}
