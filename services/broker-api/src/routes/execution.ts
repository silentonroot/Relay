import { createHash } from 'node:crypto';
import { toOperationDescriptors, validateOperationInput } from '@aab/adapter-sdk';
import type { ApplicationAdapter } from '@aab/adapter-sdk';
import {
  canonicalJson,
  canTransitionConnection,
  checkPlainJson,
  ConnectionAuthResponse,
  ExecuteOperationRequest,
  IdParams,
  isTerminalJobStatus,
  JobParams,
  LOGIN_HANDOFF_TIMEOUT_MS,
  OperationJob,
  Routes,
} from '@aab/contracts';
import type { AuditDecision, JsonObject, PolicyDecision } from '@aab/contracts';
import { ConflictError, NotFoundError } from '@aab/database';
import type { ExecutionJob, OwnerScope, Repositories } from '@aab/database';
import { evaluate } from '@aab/policy-engine';
import type { EvaluateInput } from '@aab/policy-engine';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { auditAsUser } from '../audit.js';
import { authOf } from '../auth/session.js';
import type { AppContext, RateLimitSettings } from '../context.js';
import { DEFAULT_RATE_LIMITS } from '../context.js';
import { AppError, conflict, notFound } from '../errors.js';
import type { ZodApp } from '../types.js';

/** How often a waiting request looks at its job. */
export const JOB_POLL_INTERVAL_MS = 100;

const sha256Hex = (text: string) => createHash('sha256').update(text, 'utf8').digest('hex');
const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

/** The caller's scope in the shape the job repository takes. */
function ownerScope(request: FastifyRequest): OwnerScope {
  const { scope } = authOf(request);
  return { organizationId: scope.organizationId, ownerUserId: scope.userId };
}

/**
 * Polls `jobId` until it is terminal, the wait budget runs out, or the client goes away,
 * and returns the latest state of the job. Waiting uses the real clock: the budget is about
 * the caller's patience, not about audit time.
 */
async function waitForTerminal(
  ctx: AppContext,
  reply: FastifyReply,
  jobId: string,
): Promise<ExecutionJob> {
  let disconnected = false;
  const onClose = () => {
    if (!reply.raw.writableEnded) disconnected = true;
  };
  reply.raw.once('close', onClose);
  try {
    const deadline = Date.now() + ctx.config.jobWaitMs;
    for (;;) {
      const job = await ctx.repos.jobs.getInternal(jobId);
      if (job === null) throw notFound();
      const remaining = deadline - Date.now();
      if (isTerminalJobStatus(job.status) || disconnected || remaining <= 0) return job;
      await sleep(Math.min(JOB_POLL_INTERVAL_MS, remaining));
    }
  } finally {
    reply.raw.off('close', onClose);
  }
}

function toOperationJob(job: ExecutionJob): OperationJob {
  if (job.agentId === null || job.operation === null) throw new Error('not an operation job');
  return {
    jobId: job.id,
    status: job.status,
    operation: job.operation,
    agentId: job.agentId,
    connectionId: job.connectionId,
    runId: job.runId,
    result: job.status === 'succeeded' ? job.result : null,
    error: job.error,
    auditEventId: job.auditEventId ?? job.policyDecisionId,
    createdAt: job.createdAt,
    finishedAt: job.finishedAt,
  };
}

function denied(reasonCode?: string): AppError {
  return new AppError(
    403,
    'denied',
    'The request was denied by policy.',
    reasonCode === undefined ? undefined : [{ path: 'policy', message: reasonCode }],
  );
}

function invalidArguments(error: { issues: readonly { path: string; message: string }[] }) {
  // Field paths and fixed wording only; the adapter SDK never includes submitted values.
  return new AppError(
    400,
    'validation_failed',
    'The operation arguments are invalid.',
    error.issues.map((issue) => ({ path: `arguments.${issue.path}`, message: issue.message })),
  );
}

function adapterFor(
  ctx: AppContext,
  application: { adapterId: string; adapterVersion: string },
): ApplicationAdapter | undefined {
  return ctx.adapters.get(application.adapterId, application.adapterVersion);
}

/**
 * Phase 2: operation execution and the login handoff. The API authorizes and creates jobs;
 * the browser worker runs them. Nothing here opens a browser, reads a session snapshot or
 * touches a key, and adapters are only read as data.
 */
export function registerExecutionRoutes(
  app: ZodApp,
  ctx: AppContext,
  limits: RateLimitSettings = DEFAULT_RATE_LIMITS,
) {
  /* ------------------------------------------------------------ execute */

  app.post(
    Routes.operationsExecute,
    {
      // Each call can queue browser work, so the limit is tighter than the global one.
      config: { rateLimit: { max: limits.executeMax, timeWindow: 60_000 } },
      schema: {
        body: ExecuteOperationRequest,
        response: { 200: OperationJob, 202: OperationJob },
      },
    },
    async (request, reply) => {
      const auth = authOf(request);
      const body = request.body;

      // 1. Arguments must be plain JSON before anything else looks at them.
      if (checkPlainJson(body.arguments) !== null) {
        throw new AppError(400, 'validation_failed', 'The operation arguments are invalid.', [
          { path: 'arguments', message: 'must be plain JSON without forbidden keys' },
        ]);
      }

      // 2. Both ids must be the caller's. Missing and foreign look identical, and nothing is
      // audited, so the audit log cannot reveal another owner's ids.
      const [agent, connection] = await Promise.all([
        ctx.repos.agents.get(auth.scope, body.agentId),
        ctx.repos.connections.get(auth.scope, body.connectionId),
      ]);
      if (agent === null || connection === null) throw notFound();

      // 3. Idempotency.
      const requestHash = sha256Hex(
        canonicalJson({
          agentId: body.agentId,
          connectionId: body.connectionId,
          operation: body.operation,
          arguments: body.arguments,
          runId: body.runId ?? null,
        }),
      );
      const existing = await ctx.repos.operationRequests.find(body.agentId, body.idempotencyKey);
      let jobId: string;
      if (existing !== null) {
        if (existing.requestHash !== requestHash) {
          throw conflict('This idempotency key was already used for a different request.');
        }
        jobId = existing.jobId;
      } else {
        jobId = await createJob();
      }

      // 8. Wait for the worker, within the budget.
      const job = await waitForTerminal(ctx, reply, jobId);
      return reply.code(isTerminalJobStatus(job.status) ? 200 : 202).send(toOperationJob(job));

      /** Steps 4 to 7. Returns the id of the new job, or of the one a concurrent twin made. */
      async function createJob(): Promise<string> {
        // 4. The adapter is resolved from the connection's application. An unknown adapter or
        // operation is not rejected here: the policy engine denies it as `operation_unknown`.
        const target = await ctx.repos.connections.getForExecution(connection!.id);
        if (target === null) throw notFound();
        const adapter = adapterFor(ctx, target.application);
        const definition =
          adapter !== undefined && Object.hasOwn(adapter.operations, body.operation)
            ? adapter.operations[body.operation]
            : undefined;
        if (adapter !== undefined && definition !== undefined) {
          const validation = validateOperationInput(adapter, body.operation, body.arguments);
          if (!validation.ok) throw invalidArguments(validation.error);
        }

        // 5. Policy.
        const now = ctx.clock();
        const grants = await ctx.repos.grants.listForEvaluation({
          agentId: body.agentId,
          connectionId: body.connectionId,
          operation: body.operation,
        });
        const descriptor =
          adapter === undefined
            ? undefined
            : toOperationDescriptors(adapter).find((entry) => entry.name === body.operation);
        const policyInput: EvaluateInput = {
          request: {
            agentId: body.agentId,
            connectionId: body.connectionId,
            operation: body.operation,
            arguments: body.arguments,
          },
          operation: descriptor,
          grants,
          agent: {
            id: agent!.id,
            status: agent!.status,
            ownerUserId: agent!.ownerUserId,
            organizationId: agent!.organizationId,
          },
          connection: {
            id: connection!.id,
            status: connection!.status,
            ownerUserId: connection!.ownerUserId,
            organizationId: connection!.organizationId,
          },
          now,
        };
        const decision = evaluate(policyInput);

        /** Every decision is recorded. Metadata holds argument key names, never values. */
        const decisionMetadata = (
          effective: { outcome: string; reasonCode: string },
          extra: JsonObject = {},
        ): JsonObject => ({
          operation: body.operation,
          outcome: effective.outcome,
          reasonCode: effective.reasonCode,
          matchedGrantIds: decision.matchedGrantIds,
          argumentKeys: Object.keys(body.arguments).sort(),
          ...extra,
        });
        const recordDecision = (
          repos: Repositories,
          auditDecision: AuditDecision,
          metadata: JsonObject,
        ) =>
          auditAsUser(repos, auth.scope, now, {
            eventType: 'policy.evaluated',
            decision: auditDecision,
            agentId: body.agentId,
            connectionId: body.connectionId,
            runId: body.runId ?? null,
            metadata,
          });

        if (decision.outcome === 'deny') {
          await recordDecision(ctx.repos, 'deny', decisionMetadata(decision));
          if (isReauthCase(decision, policyInput)) {
            throw new AppError(
              409,
              'reauth_required',
              'The connection needs the owner to sign in again before operations can run.',
            );
          }
          // The reason code for a connection that is not executable is withheld: an agent
          // without a grant must not learn the connection's state.
          throw denied(
            decision.reasonCode === 'connection_not_active' ? undefined : decision.reasonCode,
          );
        }
        if (decision.outcome === 'approval_required') {
          await recordDecision(ctx.repos, 'approval_required', decisionMetadata(decision));
          throw new AppError(
            403,
            'approval_required',
            'This operation needs approval. Approvals arrive in a later phase, so it cannot run yet.',
          );
        }

        // Phase 2 runs reads only, even when policy allows something else.
        if (
          descriptor === undefined ||
          definition === undefined ||
          descriptor.sensitivity !== 'read'
        ) {
          await recordDecision(
            ctx.repos,
            'deny',
            decisionMetadata(
              { outcome: 'deny', reasonCode: 'operation_not_executable' },
              { policyOutcome: decision.outcome },
            ),
          );
          throw new AppError(
            403,
            'denied',
            'Only read operations can be executed in this version of the broker.',
          );
        }

        // 6. Obligations override same-named arguments; the result must still validate.
        const finalArguments: JsonObject = { ...body.arguments, ...decision.obligations };
        const revalidation = validateOperationInput(adapter!, body.operation, finalArguments);
        if (!revalidation.ok) {
          throw new Error('policy obligations produced invalid operation arguments');
        }

        // 7. The decision, the job and the idempotency record commit together.
        try {
          return await ctx.repos.transaction(async (tx) => {
            const event = await recordDecision(
              tx,
              'allow',
              decisionMetadata(decision, {
                obligationKeys: Object.keys(decision.obligations).sort(),
              }),
            );
            const created = await tx.jobs.createOperation({
              organizationId: auth.scope.organizationId,
              requestedByUserId: auth.scope.userId,
              agentId: body.agentId,
              connectionId: body.connectionId,
              runId: body.runId ?? null,
              operation: body.operation,
              arguments: finalArguments,
              retrySafe: definition.idempotent && definition.sensitivity === 'read',
              policyDecisionId: event.id,
              timeoutMs: definition.timeoutMs,
            });
            await tx.operationRequests.create({
              agentId: body.agentId,
              idempotencyKey: body.idempotencyKey,
              requestHash,
              jobId: created.id,
            });
            return created.id;
          });
        } catch (error) {
          if (!(error instanceof ConflictError)) throw error;
          // A concurrent identical request won; this transaction rolled back whole.
          const winner = await ctx.repos.operationRequests.find(body.agentId, body.idempotencyKey);
          if (winner === null) throw error;
          if (winner.requestHash !== requestHash) {
            throw conflict('This idempotency key was already used for a different request.');
          }
          return winner.jobId;
        }
      }
    },
  );

  app.get(
    Routes.operation,
    { schema: { params: JobParams, response: { 200: OperationJob } } },
    async (request) => {
      const job = await ctx.repos.jobs.getForOwner(ownerScope(request), request.params.jobId);
      // A login handoff is not an operation; its id looks like any other missing job.
      if (job.kind !== 'operation') throw notFound();
      return toOperationJob(job);
    },
  );

  /* ------------------------------------------------------------ login handoff */

  app.post(
    Routes.connectionAuthStart,
    { schema: { params: IdParams, response: { 200: ConnectionAuthResponse } } },
    async (request) => {
      const auth = authOf(request);
      const current = await ctx.repos.connections.get(auth.scope, request.params.id);
      if (current === null) throw notFound();

      if (current.status === 'authenticating') {
        throw conflict('A login handoff is already in progress for this connection.');
      }
      // A new connection has to pass through authentication_required first; the lifecycle
      // table has no direct edge from `created`.
      const startable =
        current.status === 'created' || canTransitionConnection(current.status, 'authenticating');
      if (!startable) {
        throw conflict(`A connection that is ${current.status} cannot start a login.`);
      }

      const target = await ctx.repos.connections.getForExecution(current.id);
      if (target === null) throw notFound();
      const adapter = adapterFor(ctx, target.application);
      if (adapter === undefined) {
        throw conflict("No adapter is registered for this connection's application.");
      }
      if (adapter.loginPath === undefined) {
        throw conflict("This connection's adapter does not support an interactive login.");
      }

      const now = ctx.clock();
      return ctx.repos.transaction(async (tx) => {
        if (current.status === 'created') {
          await tx.connections.transitionStatus(auth.scope, current.id, {
            to: 'authentication_required',
          });
        }
        const connection = await tx.connections.transitionStatus(auth.scope, current.id, {
          to: 'authenticating',
        });
        const job = await tx.jobs.createLogin({
          organizationId: auth.scope.organizationId,
          requestedByUserId: auth.scope.userId,
          connectionId: current.id,
          timeoutMs: LOGIN_HANDOFF_TIMEOUT_MS,
        });
        await auditAsUser(tx, auth.scope, now, {
          eventType: 'connection.auth_started',
          connectionId: current.id,
          metadata: {
            connectionId: current.id,
            jobId: job.id,
            adapterId: adapter.id,
            adapterVersion: adapter.version,
            previousStatus: current.status,
            timeoutMs: LOGIN_HANDOFF_TIMEOUT_MS,
          },
        });
        return { connection, jobId: job.id, jobStatus: job.status, error: null };
      });
    },
  );

  app.post(
    Routes.connectionAuthComplete,
    {
      schema: {
        params: IdParams,
        response: { 200: ConnectionAuthResponse, 202: ConnectionAuthResponse },
      },
    },
    async (request, reply) => {
      const auth = authOf(request);
      const connection = await ctx.repos.connections.get(auth.scope, request.params.id);
      if (connection === null) throw notFound();

      const active = await ctx.repos.jobs.findActiveLogin(connection.id);
      if (active === null) throw conflict('No login handoff is in progress for this connection.');
      try {
        await ctx.repos.jobs.requestLoginCompletion(ownerScope(request), active.id, ctx.clock());
      } catch (error) {
        // The job ended between the lookup and the request.
        if (error instanceof NotFoundError) throw conflict('The login handoff has already ended.');
        throw error;
      }

      // The worker, not the API, moves the connection and writes the outcome event.
      const job = await waitForTerminal(ctx, reply, active.id);
      const latest = await ctx.repos.connections.get(auth.scope, connection.id);
      if (latest === null) throw notFound();
      return reply.code(isTerminalJobStatus(job.status) ? 200 : 202).send({
        connection: latest,
        jobId: job.id,
        jobStatus: job.status,
        error: job.error,
      });
    },
  );
}

/**
 * True when the only thing wrong is the connection's status: it is not revoked, and the same
 * request would be allowed if the connection were active. The owner can fix that by signing
 * in again. An agent without a grant gets false, so it cannot tell the connection's state.
 */
function isReauthCase(decision: PolicyDecision, input: EvaluateInput): boolean {
  if (decision.reasonCode !== 'connection_not_active') return false;
  if (input.connection.status === 'revoked') return false;
  const again = evaluate({ ...input, connection: { ...input.connection, status: 'active' } });
  return again.outcome === 'allow';
}
