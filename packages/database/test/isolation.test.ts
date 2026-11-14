import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  ConflictError,
  createRepositories,
  InvalidTransitionError,
  NotFoundError,
} from '../src/index.js';
import type { DatabaseHandle, Repositories, Scope } from '../src/index.js';
import { openTestDb, seedApplication, seedTenant, SYNTHETIC_PASSWORD_HASH } from './helpers.js';
import type { Tenant } from './helpers.js';

/*
 * Two organizations, A and B, each with one owner, plus a second member inside A.
 * Nothing A owns may be read, listed, changed or referenced through B's scope, and a row
 * outside the scope must look exactly like a row that does not exist.
 */

let handle: DatabaseHandle;
let repositories: Repositories;
let a: Tenant;
let b: Tenant;
/** A second user in organization A: same organization, different owner. */
let colleague: Scope;

async function seedResources(tenant: Tenant, label: string) {
  const application = await seedApplication(repositories, tenant.scope);
  const connection = await repositories.connections.create(tenant.scope, {
    applicationId: application.id,
    displayName: `${label} connection`,
  });
  const agent = await repositories.agents.create(tenant.scope, {
    name: `${label} agent`,
    clientIdentity: `${label}-agent`,
  });
  const grant = await repositories.grants.create(tenant.scope, agent.id, {
    connectionId: connection.id,
    operation: 'orders.list',
  });
  const event = await repositories.audit.append({
    organizationId: tenant.organization.id,
    actorType: 'user',
    actorId: tenant.user.id,
    connectionId: connection.id,
    eventType: 'connection.created',
    metadata: { label },
  });
  return { application, connection, agent, grant, event };
}

let ownedByA: Awaited<ReturnType<typeof seedResources>>;
let ownedByB: Awaited<ReturnType<typeof seedResources>>;

beforeAll(async () => {
  handle = await openTestDb();
  repositories = createRepositories(handle.db);
  a = await seedTenant(repositories, 'tenant-a');
  b = await seedTenant(repositories, 'tenant-b');
  ownedByA = await seedResources(a, 'a');
  ownedByB = await seedResources(b, 'b');

  const second = await repositories.users.create({
    email: 'colleague@synthetic.test',
    passwordHash: SYNTHETIC_PASSWORD_HASH,
  });
  await repositories.organizations.addMember({
    organizationId: a.organization.id,
    userId: second.id,
    role: 'member',
  });
  colleague = { organizationId: a.organization.id, userId: second.id };
});

afterAll(async () => {
  await handle.close();
});

describe('cross-organization isolation', () => {
  it('B cannot read A’s rows by id', async () => {
    expect(await repositories.applications.get(b.scope, ownedByA.application.id)).toBeNull();
    expect(await repositories.connections.get(b.scope, ownedByA.connection.id)).toBeNull();
    expect(await repositories.agents.get(b.scope, ownedByA.agent.id)).toBeNull();
    expect(
      await repositories.connections.listStatusEvents(b.scope, ownedByA.connection.id),
    ).toBeNull();
  });

  it('B’s lists contain only B’s rows', async () => {
    const applications = await repositories.applications.list(b.scope, { limit: 200 });
    const connections = await repositories.connections.list(b.scope, { limit: 200 });
    const agents = await repositories.agents.list(b.scope, { limit: 200 });
    const events = await repositories.audit.list(b.scope, { limit: 200 });

    expect(applications.items.map((item) => item.id)).toEqual([ownedByB.application.id]);
    expect(connections.items.map((item) => item.id)).toEqual([ownedByB.connection.id]);
    expect(agents.items.map((item) => item.id)).toEqual([ownedByB.agent.id]);
    expect(events.items.map((item) => item.id)).toEqual([ownedByB.event.id]);
    expect(events.items.every((item) => item.organizationId === b.organization.id)).toBe(true);
  });

  it('B cannot filter its way into A’s audit events', async () => {
    const byConnection = await repositories.audit.list(b.scope, {
      connectionId: ownedByA.connection.id,
    });
    expect(byConnection.items).toEqual([]);
    const verification = await repositories.audit.verify(b.scope);
    expect(verification).toMatchObject({ ok: true, count: 1 });
  });

  it('B cannot change A’s connection, and A’s connection is untouched', async () => {
    await expect(
      repositories.connections.revoke(b.scope, ownedByA.connection.id),
    ).rejects.toBeInstanceOf(NotFoundError);
    await expect(
      repositories.connections.transitionStatus(b.scope, ownedByA.connection.id, {
        to: 'authentication_required',
      }),
    ).rejects.toBeInstanceOf(NotFoundError);
    expect((await repositories.connections.get(a.scope, ownedByA.connection.id))!.status).toBe(
      'created',
    );
    expect(
      await repositories.connections.listStatusEvents(a.scope, ownedByA.connection.id),
    ).toHaveLength(1);
  });

  it('B cannot disable A’s agent', async () => {
    await expect(repositories.agents.disable(b.scope, ownedByA.agent.id)).rejects.toBeInstanceOf(
      NotFoundError,
    );
    expect((await repositories.agents.get(a.scope, ownedByA.agent.id))!.status).toBe('active');
  });

  it('B cannot list or revoke A’s grants', async () => {
    await expect(
      repositories.grants.listForAgent(b.scope, ownedByA.agent.id),
    ).rejects.toBeInstanceOf(NotFoundError);
    await expect(
      repositories.grants.revoke(b.scope, ownedByA.agent.id, ownedByA.grant.id),
    ).rejects.toBeInstanceOf(NotFoundError);
    // Pairing B's own agent with A's grant id must not reach it either.
    await expect(
      repositories.grants.revoke(b.scope, ownedByB.agent.id, ownedByA.grant.id),
    ).rejects.toBeInstanceOf(NotFoundError);

    const grants = await repositories.grants.listForAgent(a.scope, ownedByA.agent.id);
    expect(grants.items).toHaveLength(1);
    expect(grants.items[0]!.revokedAt).toBeNull();
  });

  it('no grant can span two owners, in either direction', async () => {
    const attempts = [
      // B's scope, A's agent, B's connection
      repositories.grants.create(b.scope, ownedByA.agent.id, {
        connectionId: ownedByB.connection.id,
        operation: 'orders.list',
      }),
      // B's scope, B's agent, A's connection
      repositories.grants.create(b.scope, ownedByB.agent.id, {
        connectionId: ownedByA.connection.id,
        operation: 'orders.list',
      }),
      // A's scope, A's agent, B's connection
      repositories.grants.create(a.scope, ownedByA.agent.id, {
        connectionId: ownedByB.connection.id,
        operation: 'orders.list',
      }),
      // B's scope, A's agent, A's connection
      repositories.grants.create(b.scope, ownedByA.agent.id, {
        connectionId: ownedByA.connection.id,
        operation: 'orders.list',
      }),
    ];
    // Settle all of them first: with a real pool the later ones reject while an earlier
    // one is still awaited, which would otherwise surface as an unhandled rejection.
    const outcomes = await Promise.allSettled(attempts);
    for (const outcome of outcomes) {
      expect(outcome.status).toBe('rejected');
      expect((outcome as PromiseRejectedResult).reason).toBeInstanceOf(NotFoundError);
    }
    for (const [agentId, connectionId] of [
      [ownedByA.agent.id, ownedByB.connection.id],
      [ownedByB.agent.id, ownedByA.connection.id],
    ] as const) {
      expect(
        await repositories.grants.listForEvaluation({
          agentId,
          connectionId,
          operation: 'orders.list',
        }),
      ).toEqual([]);
    }
  });

  it('B cannot create a connection on A’s application', async () => {
    await expect(
      repositories.connections.create(b.scope, {
        applicationId: ownedByA.application.id,
        displayName: 'Hijack',
      }),
    ).rejects.toBeInstanceOf(NotFoundError);
  });

  it('a foreign row and a missing row are indistinguishable', async () => {
    const missing = '99999999-9999-4999-8999-999999999999';
    const outcome = async (run: () => Promise<unknown>) => {
      try {
        return { value: await run() };
      } catch (error) {
        return { error: (error as Error).constructor.name, message: (error as Error).message };
      }
    };
    for (const probe of [
      (id: string) => repositories.connections.get(b.scope, id),
      (id: string) => repositories.agents.get(b.scope, id),
      (id: string) => repositories.applications.get(b.scope, id),
      (id: string) => repositories.connections.revoke(b.scope, id),
      (id: string) => repositories.agents.disable(b.scope, id),
      (id: string) => repositories.grants.listForAgent(b.scope, id),
    ]) {
      const foreignId = [ownedByA.connection.id, ownedByA.agent.id, ownedByA.application.id];
      const results = await Promise.all(foreignId.map((id) => outcome(() => probe(id))));
      const baseline = await outcome(() => probe(missing));
      for (const result of results) expect(result).toEqual(baseline);
    }
  });

  it('A’s own access still works, so the denials above are not vacuous', async () => {
    expect(await repositories.connections.get(a.scope, ownedByA.connection.id)).not.toBeNull();
    expect(await repositories.agents.get(a.scope, ownedByA.agent.id)).not.toBeNull();
    await expect(
      repositories.connections.transitionStatus(a.scope, ownedByA.connection.id, { to: 'active' }),
    ).rejects.toBeInstanceOf(InvalidTransitionError);
  });
});

describe('isolation between users of the same organization', () => {
  it('a colleague sees the shared applications but not the owner’s connections or agents', async () => {
    expect(await repositories.applications.get(colleague, ownedByA.application.id)).not.toBeNull();
    expect(await repositories.connections.get(colleague, ownedByA.connection.id)).toBeNull();
    expect(await repositories.agents.get(colleague, ownedByA.agent.id)).toBeNull();
    expect((await repositories.connections.list(colleague)).items).toEqual([]);
    expect((await repositories.agents.list(colleague)).items).toEqual([]);
  });

  it('a colleague cannot change them or grant across owners', async () => {
    await expect(
      repositories.connections.revoke(colleague, ownedByA.connection.id),
    ).rejects.toBeInstanceOf(NotFoundError);
    await expect(repositories.agents.disable(colleague, ownedByA.agent.id)).rejects.toBeInstanceOf(
      NotFoundError,
    );
    await expect(
      repositories.grants.revoke(colleague, ownedByA.agent.id, ownedByA.grant.id),
    ).rejects.toBeInstanceOf(NotFoundError);

    const ownAgent = await repositories.agents.create(colleague, {
      name: 'Colleague agent',
      clientIdentity: 'colleague-agent',
    });
    await expect(
      repositories.grants.create(colleague, ownAgent.id, {
        connectionId: ownedByA.connection.id,
        operation: 'orders.list',
      }),
    ).rejects.toBeInstanceOf(NotFoundError);
  });

  it('a colleague may reuse the owner’s client identity, so a 409 reveals nothing', async () => {
    // agents is unique on (owner_user_id, client_identity), not per organization.
    const reused = await repositories.agents.create(colleague, {
      name: 'Colleague copy',
      clientIdentity: ownedByA.agent.clientIdentity,
    });
    expect(reused.clientIdentity).toBe(ownedByA.agent.clientIdentity);
    expect(reused.ownerUserId).toBe(colleague.userId);
    // The same owner still cannot register it twice.
    await expect(
      repositories.agents.create(colleague, {
        name: 'Colleague copy again',
        clientIdentity: ownedByA.agent.clientIdentity,
      }),
    ).rejects.toBeInstanceOf(ConflictError);
    await expect(
      repositories.agents.create(a.scope, {
        name: 'Owner duplicate',
        clientIdentity: ownedByA.agent.clientIdentity,
      }),
    ).rejects.toBeInstanceOf(ConflictError);
  });

  it('a scope that mixes one organization with another organization’s user matches nothing', async () => {
    const mixed: Scope = { organizationId: a.organization.id, userId: b.user.id };
    expect(await repositories.connections.get(mixed, ownedByA.connection.id)).toBeNull();
    expect(await repositories.connections.get(mixed, ownedByB.connection.id)).toBeNull();
    expect(await repositories.agents.get(mixed, ownedByB.agent.id)).toBeNull();
    const malformed: Scope = { organizationId: 'not-a-uuid', userId: a.user.id };
    expect(await repositories.connections.get(malformed, ownedByA.connection.id)).toBeNull();
    expect((await repositories.connections.list(malformed)).items).toEqual([]);
  });
});
