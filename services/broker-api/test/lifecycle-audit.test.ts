import { AgentGrant, AuditEventList, Connection, Routes } from '@aab/contracts';
import type { AuditEvent } from '@aab/contracts';
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

const owner = { email: 'owner@example.test', password: 'lifecycle test password' };

describe('lifecycle and audit', () => {
  let h: Harness;
  let session: SignedIn;
  let applicationId: string;
  let connectionId: string;
  let agentId: string;
  let grantId: string;

  const post = (url: string, payload?: object) =>
    h.inject({
      method: 'POST',
      url,
      headers: session.headers,
      ...(payload === undefined ? {} : { payload }),
    });
  const get = (url: string) =>
    h.inject({ method: 'GET', url, headers: { cookie: session.cookie } });

  async function allEvents(query = ''): Promise<AuditEvent[]> {
    const events: AuditEvent[] = [];
    let cursor: string | null = null;
    do {
      const separator = query === '' ? '?' : `?${query}&`;
      const response = await get(
        `${path(Routes.auditEvents)}${separator}limit=2${cursor === null ? '' : `&cursor=${cursor}`}`,
      );
      const page = AuditEventList.parse(response.json());
      events.push(...page.items);
      cursor = page.nextCursor;
    } while (cursor !== null);
    return events;
  }

  beforeAll(async () => {
    h = await createHarness();
    await seedOwner(h, owner);
    session = await login(h, owner);
    applicationId = (
      await post(path(Routes.applicationsRegister), {
        adapterId: 'northstar',
        adapterVersion: '0.1.0',
        name: 'Northstar',
        allowedOrigins: ['https://northstar.example.test'],
        authModes: ['browser_session'],
      })
    ).json<{ id: string }>().id;
    connectionId = (
      await post(path(Routes.connections), { applicationId, displayName: 'Main' })
    ).json<{ id: string }>().id;
    agentId = (await post(path(Routes.agents), { name: 'Agent', clientIdentity: 'agent-1' })).json<{
      id: string;
    }>().id;
    const grant = await post(path(Routes.agentGrants, { id: agentId }), {
      connectionId,
      operation: 'orders.list',
      constraints: { maxResults: 25 },
    });
    expect(grant.statusCode, grant.body).toBe(201);
    const parsed = AgentGrant.parse(grant.json());
    expect(parsed).toMatchObject({ effect: 'allow', approvalMode: 'none', revokedAt: null });
    grantId = parsed.id;
  });

  afterAll(async () => {
    await expectNoSecretLeaks(h);
    await h.close();
  });

  it('revoking a grant keeps the row with revokedAt set, and a second revoke is 409', async () => {
    const url = path(Routes.agentGrant, { id: agentId, grantId });
    const first = await h.inject({ method: 'DELETE', url, headers: session.headers });
    expect(first.statusCode).toBe(200);
    expect(AgentGrant.parse(first.json()).revokedAt).not.toBeNull();
    expectError(
      await h.inject({ method: 'DELETE', url, headers: session.headers }),
      409,
      'conflict',
    );

    const list = await get(path(Routes.agentGrants, { id: agentId }));
    const items = list.json<{ items: { id: string; revokedAt: string | null }[] }>().items;
    expect(items).toHaveLength(1);
    expect(items[0]!.revokedAt).not.toBeNull();
  });

  it('revoking a connection twice gives 409 and it stays revoked', async () => {
    const url = path(Routes.connectionRevoke, { id: connectionId });
    const first = await post(url, { reason: 'no longer needed' });
    expect(first.statusCode).toBe(200);
    expect(Connection.parse(first.json())).toMatchObject({
      status: 'revoked',
      statusReason: 'no longer needed',
    });
    expectError(await post(url, {}), 409, 'conflict');
    // Without any body, as a script might send it.
    expectError(await post(url), 409, 'conflict');

    const after = Connection.parse(
      (await get(path(Routes.connection, { id: connectionId }))).json(),
    );
    expect(after.status).toBe('revoked');
    expect(after.statusReason).toBe('no longer needed');

    // A revoked connection cannot receive new grants.
    expectError(
      await post(path(Routes.agentGrants, { id: agentId }), {
        connectionId,
        operation: 'orders.list',
      }),
      409,
      'conflict',
    );
  });

  it('disabling an agent twice gives 409; a disabled agent gets no grants', async () => {
    const url = path(Routes.agentDisable, { id: agentId });
    const first = await post(url);
    expect(first.statusCode).toBe(200);
    expect(first.json<{ status: string }>().status).toBe('disabled');
    expectError(await post(url), 409, 'conflict');

    const other = (
      await post(path(Routes.connections), { applicationId, displayName: 'Second' })
    ).json<{
      id: string;
    }>().id;
    expectError(
      await post(path(Routes.agentGrants, { id: agentId }), {
        connectionId: other,
        operation: 'orders.list',
      }),
      409,
      'conflict',
    );
  });

  it('records an audit event for every mutation, with redacted summaries', async () => {
    const events = await allEvents();
    const types = events.map((event) => event.eventType);
    for (const type of [
      'auth.login_succeeded',
      'application.registered',
      'connection.created',
      'agent.created',
      'grant.created',
      'grant.revoked',
      'connection.revoked',
      'agent.disabled',
    ]) {
      expect(types, type).toContain(type);
    }
    // Refused mutations (409s) leave no events behind.
    expect(types.filter((type) => type === 'grant.revoked')).toHaveLength(1);
    expect(types.filter((type) => type === 'connection.revoked')).toHaveLength(1);
    expect(types.filter((type) => type === 'agent.disabled')).toHaveLength(1);

    for (const event of events) {
      expect(event.actorType).toBe('user');
      expect(event.actorId).toBe(session.userId);
      expect(JSON.stringify(event.metadata)).not.toContain(owner.password);
    }
    const created = events.find(
      (event) => event.eventType === 'connection.created' && event.connectionId === connectionId,
    )!;
    expect(created.metadata).toMatchObject({ connectionId, applicationId, displayName: 'Main' });
    const grant = events.find((event) => event.eventType === 'grant.created')!;
    expect(grant).toMatchObject({ agentId, connectionId });
    expect(grant.metadata).toMatchObject({
      grantId,
      operation: 'orders.list',
      constraintKeys: ['maxResults'],
    });
  });

  it('paginates newest first and filters by event type, agent and connection', async () => {
    const events = await allEvents();
    const sequences = events.map((event) => event.sequence);
    expect(sequences).toEqual([...sequences].sort((a, b) => b - a));
    expect(new Set(sequences).size).toBe(sequences.length);

    const byType = await allEvents('eventType=grant.created');
    expect(byType.map((event) => event.eventType)).toEqual(['grant.created']);

    const byAgent = await allEvents(`agentId=${agentId}`);
    expect(new Set(byAgent.map((event) => event.eventType))).toEqual(
      new Set(['agent.created', 'grant.created', 'grant.revoked', 'agent.disabled']),
    );

    const byConnection = await allEvents(`connectionId=${connectionId}`);
    expect(byConnection.every((event) => event.connectionId === connectionId)).toBe(true);
    expect(byConnection.map((event) => event.eventType)).toContain('connection.revoked');

    expectError(
      await get(`${path(Routes.auditEvents)}?eventType=made.up`),
      400,
      'validation_failed',
    );
  });

  it("the organization's hash chain verifies", async () => {
    const result = await h.repos.audit.verify({
      organizationId: session.organizationId,
      userId: session.userId,
    });
    expect(result.ok).toBe(true);
    expect(result.ok && result.count).toBe((await allEvents()).length);
  });

  it('logout is audited', async () => {
    const response = await h.inject({
      method: 'POST',
      url: path(Routes.authLogout),
      headers: session.headers,
    });
    expect(response.statusCode).toBe(204);
    session = await login(h, owner);
    const events = await allEvents('eventType=auth.logout');
    expect(events).toHaveLength(1);
  });
});

describe('grant revocation with a fixed clock', () => {
  it('still detects a repeated revocation when both requests read the same instant', async () => {
    const fixed = new Date('2026-03-01T09:00:00.000Z');
    const h = await createHarness({ clock: () => fixed });
    try {
      await seedOwner(h, owner);
      const session = await login(h, owner);
      const post = (url: string, payload: object) =>
        h.inject({ method: 'POST', url, headers: session.headers, payload });
      const applicationId = (
        await post(path(Routes.applicationsRegister), {
          adapterId: 'northstar',
          adapterVersion: '0.1.0',
          name: 'Northstar',
          allowedOrigins: ['https://northstar.example.test'],
          authModes: ['browser_session'],
        })
      ).json<{ id: string }>().id;
      const connectionId = (
        await post(path(Routes.connections), { applicationId, displayName: 'Main' })
      ).json<{ id: string }>().id;
      const agentId = (
        await post(path(Routes.agents), { name: 'Agent', clientIdentity: 'fixed-clock-agent' })
      ).json<{ id: string }>().id;
      const grant = await post(path(Routes.agentGrants, { id: agentId }), {
        connectionId,
        operation: 'orders.list',
      });
      expect(grant.statusCode, grant.body).toBe(201);
      const url = path(Routes.agentGrant, {
        id: agentId,
        grantId: AgentGrant.parse(grant.json()).id,
      });

      const first = await h.inject({ method: 'DELETE', url, headers: session.headers });
      expect(first.statusCode, first.body).toBe(200);
      expect(AgentGrant.parse(first.json()).revokedAt).toBe(fixed.toISOString());
      // Same clock reading as the first revocation: the old revokedAt comparison would have
      // treated this as a fresh revoke and written a second event.
      expectError(
        await h.inject({ method: 'DELETE', url, headers: session.headers }),
        409,
        'conflict',
      );
      const events = AuditEventList.parse(
        (
          await h.inject({
            method: 'GET',
            url: `${path(Routes.auditEvents)}?limit=100`,
            headers: { cookie: session.cookie },
          })
        ).json(),
      ).items;
      expect(events.filter((event) => event.eventType === 'grant.revoked')).toHaveLength(1);
    } finally {
      await h.close();
    }
  });
});
