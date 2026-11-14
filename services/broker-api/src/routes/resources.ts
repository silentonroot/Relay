import {
  Agent,
  AgentGrant,
  AgentGrantList,
  AgentList,
  ApplicationDefinition,
  ApplicationList,
  AuditEventList,
  AuditEventsQuery,
  Connection,
  ConnectionList,
  CreateAgentRequest,
  CreateConnectionRequest,
  CreateGrantRequest,
  GrantParams,
  IdParams,
  ListQuery,
  RegisterApplicationRequest,
  RevokeConnectionRequest,
  Routes,
} from '@aab/contracts';
import { auditAsUser } from '../audit.js';
import { authOf } from '../auth/session.js';
import type { AppContext } from '../context.js';
import { AppError, conflict, notFound } from '../errors.js';
import type { ZodApp } from '../types.js';

/**
 * Phase 1 CRUD. Every repository call takes the scope of the session (never anything from
 * the request), so another owner's ID behaves exactly like an ID that does not exist.
 * Each change and its audit event commit in one transaction.
 */
export function registerResourceRoutes(app: ZodApp, ctx: AppContext) {
  /* ------------------------------------------------------------ applications */

  app.get(
    Routes.applications,
    { schema: { querystring: ListQuery, response: { 200: ApplicationList } } },
    (request) => ctx.repos.applications.list(authOf(request).scope, request.query),
  );

  app.post(
    Routes.applicationsRegister,
    { schema: { body: RegisterApplicationRequest, response: { 201: ApplicationDefinition } } },
    async (request, reply) => {
      const auth = authOf(request);
      // Registering an application defines what every member may connect to (spec §12.1:
      // admin/developer). Members can use applications but not add them.
      if (auth.session.role !== 'owner' && auth.session.role !== 'admin') {
        throw new AppError(403, 'forbidden', 'Only owners and admins can register applications.');
      }
      const now = ctx.clock();
      const application = await ctx.repos.transaction(async (tx) => {
        const created = await tx.applications.register(auth.scope, request.body);
        await auditAsUser(tx, auth.scope, now, {
          eventType: 'application.registered',
          metadata: {
            applicationId: created.id,
            name: created.name,
            adapterId: created.adapterId,
            adapterVersion: created.adapterVersion,
            allowedOrigins: created.allowedOrigins,
          },
        });
        return created;
      });
      return reply.code(201).send(application);
    },
  );

  /* ------------------------------------------------------------ connections */

  app.get(
    Routes.connections,
    { schema: { querystring: ListQuery, response: { 200: ConnectionList } } },
    (request) => ctx.repos.connections.list(authOf(request).scope, request.query),
  );

  app.post(
    Routes.connections,
    { schema: { body: CreateConnectionRequest, response: { 201: Connection } } },
    async (request, reply) => {
      const auth = authOf(request);
      const now = ctx.clock();
      const connection = await ctx.repos.transaction(async (tx) => {
        const created = await tx.connections.create(auth.scope, request.body);
        await auditAsUser(tx, auth.scope, now, {
          eventType: 'connection.created',
          connectionId: created.id,
          metadata: {
            connectionId: created.id,
            applicationId: created.applicationId,
            displayName: created.displayName,
            status: created.status,
          },
        });
        return created;
      });
      return reply.code(201).send(connection);
    },
  );

  app.get(
    Routes.connection,
    { schema: { params: IdParams, response: { 200: Connection } } },
    async (request) => {
      const connection = await ctx.repos.connections.get(authOf(request).scope, request.params.id);
      if (connection === null) throw notFound();
      return connection;
    },
  );

  app.post(
    Routes.connectionRevoke,
    {
      schema: {
        params: IdParams,
        // The body is optional: `{}` and no body (null to Fastify) both mean "no reason".
        body: RevokeConnectionRequest.nullish(),
        response: { 200: Connection },
      },
    },
    async (request) => {
      const auth = authOf(request);
      const now = ctx.clock();
      return ctx.repos.transaction(async (tx) => {
        // Revoked is terminal: a second revoke is an invalid transition, answered with 409.
        const revoked = await tx.connections.revoke(auth.scope, request.params.id, {
          reason: request.body?.reason,
        });
        // Queued jobs end as cancelled, running ones are flagged for the worker, and every
        // ciphertext row of the connection goes with the same commit (spec §8.1).
        const cancelled = await tx.jobs.cancelForConnection(revoked.id, now);
        const secretsBefore = await tx.vault.describeForConnection(revoked.id);
        const versionsDeleted = await tx.vault.deleteForConnection(revoked.id, now);
        await auditAsUser(tx, auth.scope, now, {
          eventType: 'connection.revoked',
          connectionId: revoked.id,
          metadata: {
            connectionId: revoked.id,
            displayName: revoked.displayName,
            hasReason: revoked.statusReason !== null,
            jobsCancelled: cancelled.length,
          },
        });
        if (versionsDeleted > 0) {
          await auditAsUser(tx, auth.scope, now, {
            eventType: 'vault.secret_deleted',
            connectionId: revoked.id,
            metadata: {
              connectionId: revoked.id,
              vaultEntryIds: secretsBefore
                .filter((secret) => secret.activeVersion !== null)
                .map((secret) => secret.id),
              versionsDeleted,
            },
          });
        }
        return revoked;
      });
    },
  );

  /* ------------------------------------------------------------ agents */

  app.get(
    Routes.agents,
    { schema: { querystring: ListQuery, response: { 200: AgentList } } },
    (request) => ctx.repos.agents.list(authOf(request).scope, request.query),
  );

  app.post(
    Routes.agents,
    { schema: { body: CreateAgentRequest, response: { 201: Agent } } },
    async (request, reply) => {
      const auth = authOf(request);
      const now = ctx.clock();
      const agent = await ctx.repos.transaction(async (tx) => {
        const created = await tx.agents.create(auth.scope, request.body);
        await auditAsUser(tx, auth.scope, now, {
          eventType: 'agent.created',
          agentId: created.id,
          metadata: {
            agentId: created.id,
            name: created.name,
            clientIdentity: created.clientIdentity,
          },
        });
        return created;
      });
      return reply.code(201).send(agent);
    },
  );

  app.get(
    Routes.agent,
    { schema: { params: IdParams, response: { 200: Agent } } },
    async (request) => {
      const agent = await ctx.repos.agents.get(authOf(request).scope, request.params.id);
      if (agent === null) throw notFound();
      return agent;
    },
  );

  app.post(
    Routes.agentDisable,
    { schema: { params: IdParams, response: { 200: Agent } } },
    async (request) => {
      const auth = authOf(request);
      const now = ctx.clock();
      return ctx.repos.transaction(async (tx) => {
        const current = await tx.agents.get(auth.scope, request.params.id);
        if (current === null) throw notFound();
        // Like revocation, disabling is a one-way state change; repeating it is a conflict
        // rather than a second audit event.
        if (current.status === 'disabled') throw conflict('agent is already disabled');
        const disabled = await tx.agents.disable(auth.scope, current.id);
        await auditAsUser(tx, auth.scope, now, {
          eventType: 'agent.disabled',
          agentId: disabled.id,
          metadata: { agentId: disabled.id, name: disabled.name },
        });
        return disabled;
      });
    },
  );

  /* ------------------------------------------------------------ grants */

  app.get(
    Routes.agentGrants,
    { schema: { params: IdParams, querystring: ListQuery, response: { 200: AgentGrantList } } },
    (request) =>
      ctx.repos.grants.listForAgent(authOf(request).scope, request.params.id, request.query),
  );

  app.post(
    Routes.agentGrants,
    { schema: { params: IdParams, body: CreateGrantRequest, response: { 201: AgentGrant } } },
    async (request, reply) => {
      const auth = authOf(request);
      const now = ctx.clock();
      // Both ids must be the caller's before anything about them is revealed.
      const agent = await ctx.repos.agents.get(auth.scope, request.params.id);
      const owned = await ctx.repos.connections.get(auth.scope, request.body.connectionId);
      if (agent === null || owned === null) throw notFound();
      // A grant can only name an operation that the connection's adapter declares. Deny grants
      // are held to the same rule so that a typo cannot silently fail to deny anything.
      const target = await ctx.repos.connections.getForExecution(owned.id);
      if (target === null) throw notFound();
      const adapter = ctx.adapters.get(
        target.application.adapterId,
        target.application.adapterVersion,
      );
      if (adapter === undefined) {
        throw new AppError(400, 'validation_failed', 'The request is invalid.', [
          {
            path: 'connectionId',
            message: "no adapter is registered for the connection's application",
          },
        ]);
      }
      if (!Object.hasOwn(adapter.operations, request.body.operation)) {
        throw new AppError(400, 'validation_failed', 'The request is invalid.', [
          { path: 'operation', message: "is not an operation of the connection's adapter" },
        ]);
      }
      const grant = await ctx.repos.transaction(async (tx) => {
        const created = await tx.grants.create(auth.scope, request.params.id, request.body, now);
        await auditAsUser(tx, auth.scope, now, {
          eventType: 'grant.created',
          agentId: created.agentId,
          connectionId: created.connectionId,
          metadata: {
            grantId: created.id,
            operation: created.operation,
            effect: created.effect,
            approvalMode: created.approvalMode,
            constraintKeys: Object.keys(created.constraints),
            expiresAt: created.expiresAt,
          },
        });
        return created;
      });
      return reply.code(201).send(grant);
    },
  );

  app.delete(
    Routes.agentGrant,
    { schema: { params: GrantParams, response: { 200: AgentGrant } } },
    async (request) => {
      const auth = authOf(request);
      const now = ctx.clock();
      return ctx.repos.transaction(async (tx) => {
        // Revokes (sets revoked_at); the row stays for the audit trail.
        const { grant, changed } = await tx.grants.revoke(
          auth.scope,
          request.params.id,
          request.params.grantId,
          now,
        );
        // The repository reports that it changed nothing when the grant was already revoked.
        // That is a repeated revocation: 409, and no second event.
        if (!changed) throw conflict('grant is already revoked');
        await auditAsUser(tx, auth.scope, now, {
          eventType: 'grant.revoked',
          agentId: grant.agentId,
          connectionId: grant.connectionId,
          metadata: { grantId: grant.id, operation: grant.operation },
        });
        return grant;
      });
    },
  );

  /* ------------------------------------------------------------ audit */

  app.get(
    Routes.auditEvents,
    { schema: { querystring: AuditEventsQuery, response: { 200: AuditEventList } } },
    (request) => ctx.repos.audit.list(authOf(request).scope, request.query),
  );
}
