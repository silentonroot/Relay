import { CreateGrantRequest, OperationName } from '@aab/contracts';
import type { AgentGrant } from '@aab/contracts';
import { and, asc, desc, eq, isNull } from 'drizzle-orm';
import type { Db } from '../client.js';
import { ConflictError, NotFoundError, translateDbErrors, ValidationError } from '../errors.js';
import { agentGrants, agents, connections } from '../schema.js';
import {
  afterTimeCursor,
  decodeTimeCursor,
  encodeTimeCursor,
  isUuid,
  isValidScope,
  pageSize,
  toGrant,
  toPage,
} from '../support.js';
import type { Page, PageRequest, Scope } from '../support.js';
import { parseInput } from './resources.js';

/** Like the contracts request, except that fields with defaults may be omitted. */
export type CreateGrantInput = Pick<CreateGrantRequest, 'connectionId' | 'operation'> &
  Partial<Omit<CreateGrantRequest, 'connectionId' | 'operation'>>;

export interface GrantEvaluationKey {
  agentId: string;
  connectionId: string;
  operation: string;
}

export interface GrantRevocation {
  grant: AgentGrant;
  /** False when the grant was already revoked and this call changed nothing. */
  changed: boolean;
}

export function createGrantRepository(db: Db) {
  const agentInScope = (scope: Scope, agentId: string) =>
    and(
      eq(agents.id, agentId),
      eq(agents.organizationId, scope.organizationId),
      eq(agents.ownerUserId, scope.userId),
    );

  return {
    /**
     * Binds an agent to one operation on one connection. Both the agent and the connection
     * must be owned by the caller, which is checked inside the transaction that inserts the
     * grant; either one being out of scope is a NotFoundError. Constraints are validated with
     * the strict contracts schema, so an unknown constraint key is rejected, never stored.
     */
    async create(
      scope: Scope,
      agentId: string,
      input: CreateGrantInput,
      now: Date = new Date(),
    ): Promise<AgentGrant> {
      if (!isValidScope(scope) || !isUuid(agentId)) throw new NotFoundError('agent');
      const data = parseInput(CreateGrantRequest, input, 'grant');
      const expiresAt = data.expiresAt === undefined ? null : new Date(data.expiresAt);
      if (expiresAt !== null && expiresAt.getTime() <= now.getTime()) {
        throw new ValidationError('invalid grant', [
          { path: 'expiresAt', message: 'must be in the future' },
        ]);
      }

      return translateDbErrors('grant', () =>
        db.transaction(async (tx) => {
          const [agent] = await tx
            .select({ status: agents.status })
            .from(agents)
            .where(agentInScope(scope, agentId))
            .limit(1)
            .for('share');
          if (agent === undefined) throw new NotFoundError('agent');

          const [connection] = await tx
            .select({ status: connections.status })
            .from(connections)
            .where(
              and(
                eq(connections.id, data.connectionId),
                eq(connections.organizationId, scope.organizationId),
                eq(connections.ownerUserId, scope.userId),
              ),
            )
            .limit(1)
            .for('share');
          if (connection === undefined) throw new NotFoundError('connection');

          if (agent.status !== 'active') throw new ConflictError('agent is disabled');
          if (connection.status === 'revoked') throw new ConflictError('connection is revoked');

          const [row] = await tx
            .insert(agentGrants)
            .values({
              agentId,
              connectionId: data.connectionId,
              operation: data.operation,
              effect: data.effect,
              constraints: data.constraints,
              approvalMode: data.approvalMode,
              expiresAt,
            })
            .returning();
          return toGrant(row!);
        }),
      );
    },

    /** Every grant of the agent, including revoked and expired ones, newest first. */
    async listForAgent(
      scope: Scope,
      agentId: string,
      page?: PageRequest,
    ): Promise<Page<AgentGrant>> {
      if (!isValidScope(scope) || !isUuid(agentId)) throw new NotFoundError('agent');
      const limit = pageSize(page);
      const cursor = decodeTimeCursor(page?.cursor);
      const [agent] = await db
        .select({ id: agents.id })
        .from(agents)
        .where(agentInScope(scope, agentId))
        .limit(1);
      if (agent === undefined) throw new NotFoundError('agent');

      const rows = await db
        .select()
        .from(agentGrants)
        .where(
          and(
            eq(agentGrants.agentId, agentId),
            afterTimeCursor(agentGrants.createdAt, agentGrants.id, cursor),
          ),
        )
        .orderBy(desc(agentGrants.createdAt), desc(agentGrants.id))
        .limit(limit + 1);
      return toPage(rows, limit, toGrant, encodeTimeCursor);
    },

    /**
     * Sets revoked_at; the row is kept for the audit trail. Revoking an already revoked grant
     * leaves it unchanged and returns `changed: false`, so callers can tell a repeated
     * revocation apart without comparing timestamps.
     */
    async revoke(
      scope: Scope,
      agentId: string,
      grantId: string,
      now: Date = new Date(),
    ): Promise<GrantRevocation> {
      if (!isValidScope(scope) || !isUuid(agentId) || !isUuid(grantId)) {
        throw new NotFoundError('grant');
      }
      return db.transaction(async (tx) => {
        const [current] = await tx
          .select({ grant: agentGrants })
          .from(agentGrants)
          .innerJoin(agents, eq(agents.id, agentGrants.agentId))
          .where(and(eq(agentGrants.id, grantId), agentInScope(scope, agentId)))
          .limit(1)
          .for('update', { of: agentGrants });
        if (current === undefined) throw new NotFoundError('grant');
        if (current.grant.revokedAt !== null) {
          return { grant: toGrant(current.grant), changed: false };
        }

        const [row] = await tx
          .update(agentGrants)
          .set({ revokedAt: now, updatedAt: now })
          .where(eq(agentGrants.id, grantId))
          .returning();
        return { grant: toGrant(row!), changed: true };
      });
    },

    /**
     * For the policy engine: every non-revoked grant for exactly this agent, connection and
     * operation, allow and deny alike, oldest first. Expired grants are included; expiry is
     * the engine's decision because it owns the clock used for the evaluation.
     *
     * Not scoped: the caller is the broker, which has already resolved and authorized the
     * agent and connection. Never expose this through a user-facing route.
     */
    async listForEvaluation(key: GrantEvaluationKey): Promise<AgentGrant[]> {
      if (
        !isUuid(key.agentId) ||
        !isUuid(key.connectionId) ||
        !OperationName.safeParse(key.operation).success
      ) {
        return [];
      }
      const rows = await db
        .select()
        .from(agentGrants)
        .where(
          and(
            eq(agentGrants.agentId, key.agentId),
            eq(agentGrants.connectionId, key.connectionId),
            eq(agentGrants.operation, key.operation),
            isNull(agentGrants.revokedAt),
          ),
        )
        .orderBy(asc(agentGrants.createdAt), asc(agentGrants.id));
      return rows.map(toGrant);
    },
  };
}
