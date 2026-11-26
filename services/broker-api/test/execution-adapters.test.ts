import { AdapterRegistry, defineAdapter, defineOperation } from '@aab/adapter-sdk';
import { OperationJob, Routes } from '@aab/contracts';
import { schema } from '@aab/database';
import { z } from 'zod';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Harness, SignedIn } from './helpers.js';
import {
  createHarness,
  expectError,
  expectNoSecretLeaks,
  login,
  path,
  seedOwner,
} from './helpers.js';

const owner = { email: 'owner@example.test', password: 'adapter variety test password' };

const item = z.object({ id: z.string().max(20) });
const common = {
  input: z.object({ id: z.string().max(20) }),
  output: z.object({ items: z.array(item).max(10) }),
  timeoutMs: 9_000,
  allowedPaths: ['/items'],
};

/** A made-up adapter with the operation shapes Northstar does not have yet. */
const fakeshop = defineAdapter({
  id: 'fakeshop',
  version: '1.0.0',
  displayName: 'Fakeshop (test only)',
  allowedOrigins: ['https://fakeshop.example.test'],
  authMode: 'browser_session',
  // No loginPath: this adapter cannot do an interactive login handoff.
  operations: {
    'items.read': defineOperation({
      ...common,
      name: 'items.read',
      description: 'Reads items.',
      sensitivity: 'read',
      requiresApproval: false,
      idempotent: false,
      sideEffects: [],
    }),
    'items.rename': defineOperation({
      ...common,
      name: 'items.rename',
      description: 'Renames an item.',
      // A write always requires approval (defineOperation refuses one that does not), so policy
      // can only answer approval_required for it, never allow.
      input: z.object({ id: z.string().min(1).max(20), version: z.number().int().min(0) }),
      sensitivity: 'write',
      requiresApproval: true,
      idempotent: false,
      sideEffects: ['renames an item'],
      resourceArgument: 'id',
      versionArgument: 'version',
    }),
    'items.audit': defineOperation({
      ...common,
      name: 'items.audit',
      description: 'A read that always needs approval.',
      sensitivity: 'read',
      requiresApproval: true,
      idempotent: true,
      sideEffects: [],
    }),
  },
});

describe('operations the adapter declares but Phase 2 does not run', () => {
  let h: Harness;
  let session: SignedIn;
  let agentId: string;
  let connectionId: string;

  const post = (url: string, payload?: object) =>
    h.inject({
      method: 'POST',
      url,
      headers: session.headers,
      ...(payload === undefined ? {} : { payload }),
    });
  const execute = (
    operation: string,
    key: string,
    args: Record<string, unknown> = { id: 'item-1' },
  ) =>
    post(path(Routes.operationsExecute), {
      agentId,
      connectionId,
      operation,
      arguments: args,
      idempotencyKey: key,
    });
  const jobCount = async () => (await h.database.db.select().from(schema.executionJobs)).length;

  beforeAll(async () => {
    const adapters = new AdapterRegistry();
    adapters.register(fakeshop);
    h = await createHarness({ adapters });
    await seedOwner(h, owner);
    session = await login(h, owner);
    const applicationId = (
      await post(path(Routes.applicationsRegister), {
        adapterId: 'fakeshop',
        adapterVersion: '1.0.0',
        name: 'Fakeshop',
        allowedOrigins: ['https://fakeshop.example.test'],
        authModes: ['browser_session'],
      })
    ).json<{ id: string }>().id;
    connectionId = (
      await post(path(Routes.connections), { applicationId, displayName: 'Shop' })
    ).json<{ id: string }>().id;
    const scope = { organizationId: session.organizationId, userId: session.userId };
    for (const to of ['authentication_required', 'authenticating', 'active'] as const) {
      await h.repos.connections.transitionStatus(scope, connectionId, { to });
    }
    agentId = (
      await post(path(Routes.agents), { name: 'Shopper', clientIdentity: 'shopper' })
    ).json<{ id: string }>().id;
    for (const operation of ['items.read', 'items.rename', 'items.audit']) {
      const grant = await post(path(Routes.agentGrants, { id: agentId }), {
        connectionId,
        operation,
      });
      expect(grant.statusCode, grant.body).toBe(201);
    }
  });

  afterAll(async () => {
    await expectNoSecretLeaks(h);
    await h.close();
  });

  it('answers 403 approval_required for a write, never allow, with no job (phase 2 runs no writes)', async () => {
    // Positive control: the same connection and agent run a read through the same route.
    expect((await execute('items.read', 'write-control-1')).statusCode).toBe(202);
    const jobsBefore = await jobCount();
    const body = expectError(
      await execute('items.rename', 'write-key-1', { id: 'item-1', version: 1 }),
      403,
      'approval_required',
    );
    expect(body.error.message).toMatch(/later phase/);
    expect(await jobCount()).toBe(jobsBefore);
    const decision = (
      await h.repos.audit.list(
        { organizationId: session.organizationId, userId: session.userId },
        { limit: 50, eventType: 'policy.evaluated' },
      )
    ).items[0]!;
    expect(decision).toMatchObject({
      decision: 'approval_required',
      metadata: { operation: 'items.rename', reasonCode: 'approval_required' },
    });
  });

  it('answers 403 approval_required for an operation that needs approval, with no job', async () => {
    const jobsBefore = await jobCount();
    const body = expectError(
      await execute('items.audit', 'approval-key-1'),
      403,
      'approval_required',
    );
    expect(body.error.message).toMatch(/later phase/);
    expect(await jobCount()).toBe(jobsBefore);
    const decision = (
      await h.repos.audit.list(
        { organizationId: session.organizationId, userId: session.userId },
        { limit: 50, eventType: 'policy.evaluated' },
      )
    ).items[0]!;
    expect(decision.decision).toBe('approval_required');
  });

  it('marks a read that is not declared idempotent as not retry-safe', async () => {
    const response = await execute('items.read', 'read-key-1');
    expect(response.statusCode, response.body).toBe(202);
    const job = OperationJob.parse(response.json());
    const [row] = (await h.database.db.select().from(schema.executionJobs)).filter(
      (entry) => entry.id === job.jobId,
    );
    expect(row).toMatchObject({ retrySafe: false, timeoutMs: 9_000 });
  });

  it('answers 409 to auth/start when the adapter declares no login path', async () => {
    const created = await post(path(Routes.connections), {
      applicationId: (await h.repos.connections.getForExecution(connectionId))!.application.id,
      displayName: 'Second shop connection',
    });
    const id = created.json<{ id: string }>().id;
    const body = expectError(await post(path(Routes.connectionAuthStart, { id })), 409, 'conflict');
    expect(body.error.message).toMatch(/login/);
    const after = (await h.repos.connections.getForExecution(id))!.connection;
    expect(after.status).toBe('created');
  });

  it('rate limits execute more tightly than the global limit (last: it uses up the budget)', async () => {
    const statuses: number[] = [];
    for (let attempt = 0; attempt < 61; attempt += 1) {
      const response = await post(path(Routes.operationsExecute), {
        agentId: '00000000-0000-4000-8000-000000000000',
        connectionId,
        operation: 'items.read',
        arguments: {},
        idempotencyKey: `limit-key-${attempt}`,
      });
      statuses.push(response.statusCode);
    }
    // 60 per minute by default, and the earlier tests in this file already spent a few.
    expect(statuses.at(-1)).toBe(429);
    expect(statuses[0]).toBe(404);
  });
});
