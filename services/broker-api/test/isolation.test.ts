import { AuditEventList, Routes } from '@aab/contracts';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Harness, SignedIn } from './helpers.js';
import {
  createHarness,
  expectError,
  expectNoSecretLeaks,
  login,
  path,
  seedOwner,
  seedTenant,
} from './helpers.js';

const alice = { email: 'alice@example.test', password: 'alice synthetic password' };
const mallory = { email: 'mallory@example.test', password: 'mallory synthetic password' };
const bob = { email: 'bob@example.test', password: 'bob synthetic password' };

interface Owned {
  applicationId: string;
  connectionId: string;
  agentId: string;
  grantId: string;
}

async function createResources(h: Harness, session: SignedIn, label: string): Promise<Owned> {
  const post = async (url: string, payload: object) => {
    const response = await h.inject({ method: 'POST', url, headers: session.headers, payload });
    expect(response.statusCode, response.body).toBe(201);
    return response.json<{ id: string }>().id;
  };
  // The organization's one Northstar application may already exist (colleagues share it).
  const registered = await h.inject({
    method: 'POST',
    url: path(Routes.applicationsRegister),
    headers: session.headers,
    payload: {
      adapterId: 'northstar',
      adapterVersion: '0.1.0',
      name: `${label} app`,
      allowedOrigins: ['https://northstar.example.test'],
      authModes: ['browser_session'],
    },
  });
  const applicationId =
    registered.statusCode === 201
      ? registered.json<{ id: string }>().id
      : (
          await h.inject({
            method: 'GET',
            url: path(Routes.applications),
            headers: { cookie: session.cookie },
          })
        ).json<{ items: { id: string }[] }>().items[0]!.id;
  const connectionId = await post(path(Routes.connections), {
    applicationId,
    displayName: `${label} connection`,
  });
  const agentId = await post(path(Routes.agents), {
    name: `${label} agent`,
    clientIdentity: `${label}-client`,
  });
  const grantId = await post(path(Routes.agentGrants, { id: agentId }), {
    connectionId,
    operation: 'orders.list',
  });
  return { applicationId, connectionId, agentId, grantId };
}

describe('isolation between organizations and owners', () => {
  let h: Harness;
  let aliceSession: SignedIn;
  let mallorySession: SignedIn;
  let bobSession: SignedIn;
  let victim: Owned;
  let attacker: Owned;
  let colleague: Owned;

  beforeAll(async () => {
    h = await createHarness();
    const seeded = await seedOwner(h, alice, 'Victim Org');
    await seedTenant(h, mallory, 'Attacker Org');
    // Bob is an admin in Alice's organization: he shares applications, not connections or agents.
    await seedTenant(h, bob, 'unused', 'admin', seeded.organization.id);
    aliceSession = await login(h, alice);
    mallorySession = await login(h, mallory);
    bobSession = await login(h, bob);
    victim = await createResources(h, aliceSession, 'alice');
    attacker = await createResources(h, mallorySession, 'mallory');
    colleague = await createResources(h, bobSession, 'bob');
  });

  afterAll(async () => {
    await expectNoSecretLeaks(h);
    await h.close();
  });

  for (const [who, sessionOf] of [
    ['another organization', () => mallorySession],
    ['another owner in the same organization', () => bobSession],
  ] as const) {
    describe(`from ${who}`, () => {
      it('cannot read connections or agents', async () => {
        const headers = { cookie: sessionOf().cookie };
        for (const url of [
          path(Routes.connection, { id: victim.connectionId }),
          path(Routes.agent, { id: victim.agentId }),
          path(Routes.agentGrants, { id: victim.agentId }),
        ]) {
          expectError(await h.inject({ method: 'GET', url, headers }), 404, 'not_found');
        }
      });

      it('sees none of them in lists', async () => {
        const headers = { cookie: sessionOf().cookie };
        for (const url of [path(Routes.connections), path(Routes.agents)]) {
          const response = await h.inject({ method: 'GET', url, headers });
          const ids = response.json<{ items: { id: string }[] }>().items.map((item) => item.id);
          expect(ids).not.toContain(victim.connectionId);
          expect(ids).not.toContain(victim.agentId);
          expect(ids).toHaveLength(1);
        }
      });

      it('cannot revoke, disable or change grants', async () => {
        const headers = sessionOf().headers;
        const attempts = [
          {
            method: 'POST',
            url: path(Routes.connectionRevoke, { id: victim.connectionId }),
            payload: {},
          },
          { method: 'POST', url: path(Routes.agentDisable, { id: victim.agentId }) },
          {
            method: 'POST',
            url: path(Routes.agentGrants, { id: victim.agentId }),
            payload: { connectionId: victim.connectionId, operation: 'orders.list' },
          },
          {
            method: 'DELETE',
            url: path(Routes.agentGrant, { id: victim.agentId, grantId: victim.grantId }),
          },
        ] as const;
        for (const attempt of attempts) {
          expectError(await h.inject({ ...attempt, headers }), 404, 'not_found');
        }
      });

      it('cannot join its own agent to the victim connection', async () => {
        const own = sessionOf() === mallorySession ? attacker : colleague;
        const response = await h.inject({
          method: 'POST',
          url: path(Routes.agentGrants, { id: own.agentId }),
          headers: sessionOf().headers,
          payload: { connectionId: victim.connectionId, operation: 'orders.list' },
        });
        expectError(response, 404, 'not_found');
      });

      it("cannot use the victim's grant id under its own agent", async () => {
        const own = sessionOf() === mallorySession ? attacker : colleague;
        const response = await h.inject({
          method: 'DELETE',
          url: path(Routes.agentGrant, { id: own.agentId, grantId: victim.grantId }),
          headers: sessionOf().headers,
        });
        expectError(response, 404, 'not_found');
      });
    });
  }

  it('another organization cannot see or use the applications of the first', async () => {
    const listed = await h.inject({
      method: 'GET',
      url: path(Routes.applications),
      headers: { cookie: mallorySession.cookie },
    });
    const ids = listed.json<{ items: { id: string }[] }>().items.map((item) => item.id);
    expect(ids).toEqual([attacker.applicationId]);

    const response = await h.inject({
      method: 'POST',
      url: path(Routes.connections),
      headers: mallorySession.headers,
      payload: { applicationId: victim.applicationId, displayName: 'Stolen' },
    });
    expectError(response, 404, 'not_found');
  });

  it('another organization sees none of the first organization audit events', async () => {
    const response = await h.inject({
      method: 'GET',
      url: path(Routes.auditEvents),
      headers: { cookie: mallorySession.cookie },
    });
    const list = AuditEventList.parse(response.json());
    expect(list.items.length).toBeGreaterThan(0);
    expect(
      list.items.every((event) => event.organizationId === mallorySession.organizationId),
    ).toBe(true);
    const filtered = await h.inject({
      method: 'GET',
      url: `${path(Routes.auditEvents)}?connectionId=${victim.connectionId}`,
      headers: { cookie: mallorySession.cookie },
    });
    expect(AuditEventList.parse(filtered.json()).items).toEqual([]);
  });

  it('a missing id and a foreign id get byte-identical bodies apart from the request id', async () => {
    const strip = (body: string) => body.replace(/"requestId":"[^"]+"/, '');
    const foreign = await h.inject({
      method: 'GET',
      url: path(Routes.connection, { id: victim.connectionId }),
      headers: { cookie: mallorySession.cookie },
    });
    const missing = await h.inject({
      method: 'GET',
      url: path(Routes.connection, { id: '00000000-0000-4000-8000-000000000000' }),
      headers: { cookie: mallorySession.cookie },
    });
    expect(foreign.statusCode).toBe(missing.statusCode);
    expect(strip(foreign.body)).toBe(strip(missing.body));
  });

  it("the victim's resources are untouched", async () => {
    const connection = await h.inject({
      method: 'GET',
      url: path(Routes.connection, { id: victim.connectionId }),
      headers: { cookie: aliceSession.cookie },
    });
    expect(connection.json<{ status: string }>().status).toBe('created');
    const agent = await h.inject({
      method: 'GET',
      url: path(Routes.agent, { id: victim.agentId }),
      headers: { cookie: aliceSession.cookie },
    });
    expect(agent.json<{ status: string }>().status).toBe('active');
    const grants = await h.inject({
      method: 'GET',
      url: path(Routes.agentGrants, { id: victim.agentId }),
      headers: { cookie: aliceSession.cookie },
    });
    const items = grants.json<{ items: { id: string; revokedAt: string | null }[] }>().items;
    expect(items).toEqual([expect.objectContaining({ id: victim.grantId, revokedAt: null })]);
  });

  it('members (not owners or admins) cannot register applications', async () => {
    const carol = { email: 'carol@example.test', password: 'carol synthetic password' };
    await seedTenant(h, carol, 'unused', 'member', aliceSession.organizationId);
    const session = await login(h, carol);
    const response = await h.inject({
      method: 'POST',
      url: path(Routes.applicationsRegister),
      headers: session.headers,
      payload: {
        adapterId: 'northstar',
        adapterVersion: '0.1.0',
        name: 'Member app',
        allowedOrigins: ['https://northstar.example.test'],
        authModes: ['browser_session'],
      },
    });
    expectError(response, 403, 'forbidden');
  });
});
