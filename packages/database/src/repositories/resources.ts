import {
  canTransitionConnection,
  CreateAgentRequest,
  CreateConnectionRequest,
  RegisterApplicationRequest,
} from '@aab/contracts';
import type {
  ActorType,
  Agent,
  ApplicationDefinition,
  Connection,
  ConnectionStatus,
} from '@aab/contracts';
import { and, asc, desc, eq } from 'drizzle-orm';
import type { Db } from '../client.js';
import {
  ConflictError,
  InvalidTransitionError,
  NotFoundError,
  translateDbErrors,
  ValidationError,
} from '../errors.js';
import { agents, applicationDefinitions, connections, connectionStatusEvents } from '../schema.js';
import {
  afterTimeCursor,
  decodeTimeCursor,
  encodeTimeCursor,
  isUuid,
  isValidScope,
  pageSize,
  toAgent,
  toApplication,
  toConnection,
  toPage,
} from '../support.js';
import type { Page, PageRequest, Scope } from '../support.js';

/**
 * The slice of a Zod schema this package uses. Declared structurally because zod is not a
 * dependency here; the schemas themselves come from @aab/contracts.
 */
interface SafeParser<Output> {
  safeParse(input: unknown):
    | { success: true; data: Output }
    | {
        success: false;
        error: { issues: readonly { path: readonly PropertyKey[]; message: string }[] };
      };
}

/** Re-validates input at the repository boundary; the API layer validates first. */
export function parseInput<Output>(
  schema: SafeParser<Output>,
  input: unknown,
  entity: string,
): Output {
  const result = schema.safeParse(input);
  if (result.success) return result.data;
  throw new ValidationError(
    `invalid ${entity}`,
    result.error.issues.map((issue) => ({
      path: issue.path.map(String).join('.'),
      message: issue.message,
    })),
  );
}

/* ---------------------------------------------------------------- applications */

/** Application definitions are shared by the whole organization. */
export function createApplicationRepository(db: Db) {
  const inScope = (scope: Scope) => eq(applicationDefinitions.organizationId, scope.organizationId);

  return {
    async register(
      scope: Scope,
      input: RegisterApplicationRequest,
    ): Promise<ApplicationDefinition> {
      if (!isValidScope(scope)) throw new NotFoundError('organization');
      const data = parseInput(RegisterApplicationRequest, input, 'application');
      return translateDbErrors('application', async () => {
        const [row] = await db
          .insert(applicationDefinitions)
          .values({ organizationId: scope.organizationId, ...data })
          .returning();
        return toApplication(row!);
      });
    },

    async list(scope: Scope, page?: PageRequest): Promise<Page<ApplicationDefinition>> {
      if (!isValidScope(scope)) return { items: [], nextCursor: null };
      const limit = pageSize(page);
      const cursor = decodeTimeCursor(page?.cursor);
      const rows = await db
        .select()
        .from(applicationDefinitions)
        .where(
          and(
            inScope(scope),
            afterTimeCursor(applicationDefinitions.createdAt, applicationDefinitions.id, cursor),
          ),
        )
        .orderBy(desc(applicationDefinitions.createdAt), desc(applicationDefinitions.id))
        .limit(limit + 1);
      return toPage(rows, limit, toApplication, encodeTimeCursor);
    },

    async get(scope: Scope, id: string): Promise<ApplicationDefinition | null> {
      if (!isValidScope(scope) || !isUuid(id)) return null;
      const [row] = await db
        .select()
        .from(applicationDefinitions)
        .where(and(inScope(scope), eq(applicationDefinitions.id, id)))
        .limit(1);
      return row === undefined ? null : toApplication(row);
    },
  };
}

/* ---------------------------------------------------------------- connections */

export interface StatusActor {
  type: ActorType;
  id: string | null;
}

export interface TransitionConnectionInput {
  to: ConnectionStatus;
  reason?: string | undefined;
  /** Defaults to the user in the scope. */
  actor?: StatusActor | undefined;
}

export interface RecordSessionInput {
  externalAccountHint: string | null;
  sessionExpiresAt: Date | null;
  lastVerifiedAt: Date;
}

export interface ConnectionStatusEvent {
  id: string;
  connectionId: string;
  fromStatus: ConnectionStatus | null;
  toStatus: ConnectionStatus;
  reason: string | null;
  actorType: ActorType;
  actorId: string | null;
  createdAt: string;
}

/** Connections belong to one user. Other members of the organization cannot see them. */
export function createConnectionRepository(db: Db) {
  const inScope = (scope: Scope) =>
    and(
      eq(connections.organizationId, scope.organizationId),
      eq(connections.ownerUserId, scope.userId),
    );

  /** Shared by the owner-scoped and the broker-internal transition. */
  async function applyTransition(
    scope: Scope | null,
    id: string,
    input: TransitionConnectionInput,
    defaultActor: StatusActor,
  ): Promise<Connection> {
    if (!isUuid(id)) throw new NotFoundError('connection');
    const actor = input.actor ?? defaultActor;
    const reason = input.reason?.trim() ? input.reason.trim().slice(0, 500) : null;

    return translateDbErrors('connection', () =>
      db.transaction(async (tx) => {
        // The row lock makes concurrent transitions queue: the second one re-reads the status
        // the first one wrote, so both cannot succeed from the same starting state.
        const [current] = await tx
          .select()
          .from(connections)
          .where(and(scope === null ? undefined : inScope(scope), eq(connections.id, id)))
          .limit(1)
          .for('update');
        if (current === undefined) throw new NotFoundError('connection');
        if (!canTransitionConnection(current.status, input.to)) {
          throw new InvalidTransitionError(current.status, input.to);
        }

        const now = new Date();
        const [updated] = await tx
          .update(connections)
          .set({
            status: input.to,
            statusReason: reason,
            lastVerifiedAt: input.to === 'active' ? now : current.lastVerifiedAt,
            updatedAt: now,
          })
          .where(eq(connections.id, current.id))
          .returning();
        await tx.insert(connectionStatusEvents).values({
          connectionId: current.id,
          fromStatus: current.status,
          toStatus: input.to,
          reason,
          actorType: actor.type,
          actorId: actor.id,
          createdAt: now,
        });
        return toConnection(updated!);
      }),
    );
  }

  async function transitionStatus(
    scope: Scope,
    id: string,
    input: TransitionConnectionInput,
  ): Promise<Connection> {
    if (!isValidScope(scope)) throw new NotFoundError('connection');
    return applyTransition(scope, id, input, { type: 'user', id: scope.userId });
  }

  return {
    /**
     * Creates a connection in status `created` and records the creation in the status history.
     * The application must belong to the caller's organization and be active.
     */
    async create(scope: Scope, input: CreateConnectionRequest): Promise<Connection> {
      if (!isValidScope(scope)) throw new NotFoundError('application');
      const data = parseInput(CreateConnectionRequest, input, 'connection');
      return translateDbErrors('connection', () =>
        db.transaction(async (tx) => {
          const [application] = await tx
            .select({ status: applicationDefinitions.status })
            .from(applicationDefinitions)
            .where(
              and(
                eq(applicationDefinitions.id, data.applicationId),
                eq(applicationDefinitions.organizationId, scope.organizationId),
              ),
            )
            .limit(1);
          if (application === undefined) throw new NotFoundError('application');
          if (application.status !== 'active') {
            throw new ConflictError('application is disabled');
          }

          const [row] = await tx
            .insert(connections)
            .values({
              ownerUserId: scope.userId,
              organizationId: scope.organizationId,
              applicationId: data.applicationId,
              displayName: data.displayName,
              externalAccountHint: data.externalAccountHint ? data.externalAccountHint : null,
              status: 'created',
            })
            .returning();
          await tx.insert(connectionStatusEvents).values({
            connectionId: row!.id,
            fromStatus: null,
            toStatus: 'created',
            reason: null,
            actorType: 'user',
            actorId: scope.userId,
            createdAt: row!.createdAt,
          });
          return toConnection(row!);
        }),
      );
    },

    async list(scope: Scope, page?: PageRequest): Promise<Page<Connection>> {
      if (!isValidScope(scope)) return { items: [], nextCursor: null };
      const limit = pageSize(page);
      const cursor = decodeTimeCursor(page?.cursor);
      const rows = await db
        .select()
        .from(connections)
        .where(and(inScope(scope), afterTimeCursor(connections.createdAt, connections.id, cursor)))
        .orderBy(desc(connections.createdAt), desc(connections.id))
        .limit(limit + 1);
      return toPage(rows, limit, toConnection, encodeTimeCursor);
    },

    async get(scope: Scope, id: string): Promise<Connection | null> {
      if (!isValidScope(scope) || !isUuid(id)) return null;
      const [row] = await db
        .select()
        .from(connections)
        .where(and(inScope(scope), eq(connections.id, id)))
        .limit(1);
      return row === undefined ? null : toConnection(row);
    },

    /**
     * Moves the connection along the lifecycle in @aab/contracts and records the transition,
     * atomically. Throws NotFoundError outside the scope, InvalidTransitionError otherwise.
     */
    transitionStatus,

    /**
     * Broker-internal variant for the worker: no owner scope, so only call it with an ID the
     * broker itself obtained (a job's connection), never one from a request. It enforces the
     * same transition table and writes the same status event; the actor defaults to
     * `{ type: 'worker', id: null }`. NotFoundError when the connection does not exist.
     */
    transitionStatusInternal(id: string, input: TransitionConnectionInput): Promise<Connection> {
      return applyTransition(null, id, input, { type: 'worker', id: null });
    },

    /** Unscoped read for the worker: the connection and its application definition. */
    async getForExecution(
      connectionId: string,
    ): Promise<{ connection: Connection; application: ApplicationDefinition } | null> {
      if (!isUuid(connectionId)) return null;
      const [row] = await db
        .select({ connection: connections, application: applicationDefinitions })
        .from(connections)
        .innerJoin(applicationDefinitions, eq(applicationDefinitions.id, connections.applicationId))
        .where(eq(connections.id, connectionId))
        .limit(1);
      return row === undefined
        ? null
        : { connection: toConnection(row.connection), application: toApplication(row.application) };
    },

    /** Records what a verified session looked like. Unscoped, for the worker. */
    async recordSession(connectionId: string, input: RecordSessionInput): Promise<Connection> {
      if (!isUuid(connectionId)) throw new NotFoundError('connection');
      const hint = input.externalAccountHint?.trim().slice(0, 120);
      const [row] = await db
        .update(connections)
        .set({
          externalAccountHint: hint ? hint : null,
          sessionExpiresAt: input.sessionExpiresAt,
          lastVerifiedAt: input.lastVerifiedAt,
          updatedAt: new Date(),
        })
        .where(eq(connections.id, connectionId))
        .returning();
      if (row === undefined) throw new NotFoundError('connection');
      return toConnection(row);
    },

    /** Terminal. Revoking an already revoked connection is an InvalidTransitionError. */
    revoke(
      scope: Scope,
      id: string,
      input: { reason?: string | undefined; actor?: StatusActor | undefined } = {},
    ): Promise<Connection> {
      return transitionStatus(scope, id, {
        to: 'revoked',
        reason: input.reason,
        actor: input.actor,
      });
    },

    /** Status history, oldest first. Null when the connection is outside the scope. */
    async listStatusEvents(scope: Scope, id: string): Promise<ConnectionStatusEvent[] | null> {
      if (!isValidScope(scope) || !isUuid(id)) return null;
      const [owned] = await db
        .select({ id: connections.id })
        .from(connections)
        .where(and(inScope(scope), eq(connections.id, id)))
        .limit(1);
      if (owned === undefined) return null;
      const rows = await db
        .select()
        .from(connectionStatusEvents)
        .where(eq(connectionStatusEvents.connectionId, id))
        .orderBy(asc(connectionStatusEvents.createdAt), asc(connectionStatusEvents.id));
      return rows.map((row) => ({
        id: row.id,
        connectionId: row.connectionId,
        fromStatus: row.fromStatus,
        toStatus: row.toStatus,
        reason: row.reason,
        actorType: row.actorType,
        actorId: row.actorId,
        createdAt: row.createdAt.toISOString(),
      }));
    },
  };
}

/* ---------------------------------------------------------------- agents */

/** Agents belong to one user, like connections. */
export function createAgentRepository(db: Db) {
  const inScope = (scope: Scope) =>
    and(eq(agents.organizationId, scope.organizationId), eq(agents.ownerUserId, scope.userId));

  return {
    async create(scope: Scope, input: CreateAgentRequest): Promise<Agent> {
      if (!isValidScope(scope)) throw new NotFoundError('organization');
      const data = parseInput(CreateAgentRequest, input, 'agent');
      return translateDbErrors('agent', async () => {
        const [row] = await db
          .insert(agents)
          .values({
            organizationId: scope.organizationId,
            ownerUserId: scope.userId,
            name: data.name,
            clientIdentity: data.clientIdentity,
          })
          .returning();
        return toAgent(row!);
      });
    },

    async list(scope: Scope, page?: PageRequest): Promise<Page<Agent>> {
      if (!isValidScope(scope)) return { items: [], nextCursor: null };
      const limit = pageSize(page);
      const cursor = decodeTimeCursor(page?.cursor);
      const rows = await db
        .select()
        .from(agents)
        .where(and(inScope(scope), afterTimeCursor(agents.createdAt, agents.id, cursor)))
        .orderBy(desc(agents.createdAt), desc(agents.id))
        .limit(limit + 1);
      return toPage(rows, limit, toAgent, encodeTimeCursor);
    },

    async get(scope: Scope, id: string): Promise<Agent | null> {
      if (!isValidScope(scope) || !isUuid(id)) return null;
      const [row] = await db
        .select()
        .from(agents)
        .where(and(inScope(scope), eq(agents.id, id)))
        .limit(1);
      return row === undefined ? null : toAgent(row);
    },

    /** Unscoped read for the worker, which re-evaluates policy for the job's agent. */
    async getInternal(agentId: string): Promise<Agent | null> {
      if (!isUuid(agentId)) return null;
      const [row] = await db.select().from(agents).where(eq(agents.id, agentId)).limit(1);
      return row === undefined ? null : toAgent(row);
    },

    /** Idempotent. A disabled agent keeps its grants but the policy engine denies it. */
    async disable(scope: Scope, id: string): Promise<Agent> {
      if (!isValidScope(scope) || !isUuid(id)) throw new NotFoundError('agent');
      const [row] = await db
        .update(agents)
        .set({ status: 'disabled', updatedAt: new Date() })
        .where(and(inScope(scope), eq(agents.id, id)))
        .returning();
      if (row === undefined) throw new NotFoundError('agent');
      return toAgent(row);
    },
  };
}
