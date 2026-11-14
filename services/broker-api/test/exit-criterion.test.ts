import { AgentList, ApplicationList, ConnectionList, Routes } from '@aab/contracts';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Harness, SignedIn } from './helpers.js';
import { createHarness, expectNoSecretLeaks, login, path, seedOwner } from './helpers.js';

const owner = { email: 'owner@example.test', password: 'correct horse battery staple' };

describe('Phase 1 exit criterion', () => {
  let h: Harness;
  let session: SignedIn;

  beforeAll(async () => {
    h = await createHarness();
    await seedOwner(h, owner);
    session = await login(h, owner);
  });

  afterAll(async () => {
    await expectNoSecretLeaks(h);
    await h.close();
  });

  it('one owner registers two applications, creates three connections and two agents, and lists them', async () => {
    const applicationIds: string[] = [];
    for (const [adapterId, origin] of [
      ['northstar', 'https://northstar.example.test'],
      ['ledgerly', 'http://127.0.0.1:5101'],
    ] as const) {
      const response = await h.inject({
        method: 'POST',
        url: path(Routes.applicationsRegister),
        headers: session.headers,
        payload: {
          adapterId,
          adapterVersion: '1.0.0',
          name: `Synthetic ${adapterId}`,
          allowedOrigins: [origin],
          authModes: ['browser_session'],
        },
      });
      expect(response.statusCode, response.body).toBe(201);
      applicationIds.push(response.json<{ id: string }>().id);
    }

    for (const [index, applicationId] of [
      applicationIds[0]!,
      applicationIds[0]!,
      applicationIds[1]!,
    ].entries()) {
      const response = await h.inject({
        method: 'POST',
        url: path(Routes.connections),
        headers: session.headers,
        payload: { applicationId, displayName: `Connection ${index + 1}` },
      });
      expect(response.statusCode, response.body).toBe(201);
      expect(response.json<{ status: string }>().status).toBe('created');
    }

    for (const name of ['Research agent', 'Ops agent']) {
      const response = await h.inject({
        method: 'POST',
        url: path(Routes.agents),
        headers: session.headers,
        payload: { name, clientIdentity: `client-${name.split(' ')[0]!.toLowerCase()}` },
      });
      expect(response.statusCode, response.body).toBe(201);
    }

    const headers = { cookie: session.cookie };
    const applications = ApplicationList.parse(
      (await h.inject({ method: 'GET', url: path(Routes.applications), headers })).json(),
    );
    const connections = ConnectionList.parse(
      (await h.inject({ method: 'GET', url: path(Routes.connections), headers })).json(),
    );
    const agents = AgentList.parse(
      (await h.inject({ method: 'GET', url: path(Routes.agents), headers })).json(),
    );

    expect(applications.items).toHaveLength(2);
    expect(connections.items).toHaveLength(3);
    expect(agents.items).toHaveLength(2);
    expect(connections.items.every((item) => item.ownerUserId === session.userId)).toBe(true);
    expect(new Set(connections.items.map((item) => item.applicationId))).toEqual(
      new Set(applicationIds),
    );
  });
});
