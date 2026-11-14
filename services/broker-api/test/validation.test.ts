import { Routes } from '@aab/contracts';
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

const owner = { email: 'owner@example.test', password: 'validation test password' };
/** A recognizable value that must never be echoed back. */
const CANARY = 'canary-value-7f3e9b';

const application = (allowedOrigins: string[]) => ({
  adapterId: 'northstar',
  adapterVersion: '0.1.0',
  name: 'Northstar',
  allowedOrigins,
  authModes: ['browser_session'],
});

describe('request validation', () => {
  let h: Harness;
  let session: SignedIn;
  let agentId: string;
  let connectionId: string;

  beforeAll(async () => {
    h = await createHarness();
    await seedOwner(h, owner);
    session = await login(h, owner);
    h.forbiddenInResponses.add(CANARY);
    const app = await h.inject({
      method: 'POST',
      url: path(Routes.applicationsRegister),
      headers: session.headers,
      payload: application(['https://northstar.example.test']),
    });
    const connection = await h.inject({
      method: 'POST',
      url: path(Routes.connections),
      headers: session.headers,
      payload: { applicationId: app.json<{ id: string }>().id, displayName: 'Main' },
    });
    connectionId = connection.json<{ id: string }>().id;
    const agent = await h.inject({
      method: 'POST',
      url: path(Routes.agents),
      headers: session.headers,
      payload: { name: 'Agent', clientIdentity: 'agent-1' },
    });
    agentId = agent.json<{ id: string }>().id;
  });

  afterAll(async () => {
    await expectNoSecretLeaks(h);
    await h.close();
  });

  it.each([
    ['a wildcard host', 'https://*.example.test'],
    ['a bare wildcard', '*'],
    ['a lookalike with a path', 'https://northstar.example.test/login'],
    ['a lookalike with credentials', 'https://user@northstar.example.test'],
    ['a trailing dot', 'https://northstar.example.test.'],
    ['plain http to a public host', 'http://northstar.example.test'],
    ['a non-http scheme', 'javascript://northstar.example.test'],
    ['an uppercase host', 'https://NorthStar.example.test'],
    ['a trailing slash', 'https://northstar.example.test/'],
    ['a punycode-normalized unicode host', 'https://nörthstar.example.test'],
  ])('rejects %s as an allowed origin', async (_label, origin) => {
    const response = await h.inject({
      method: 'POST',
      url: path(Routes.applicationsRegister),
      headers: session.headers,
      payload: application([origin]),
    });
    const body = expectError(response, 400, 'validation_failed');
    expect(body.error.details?.map((detail) => detail.path)).toEqual(['allowedOrigins.0']);
    expect(response.body).not.toContain(origin);
  });

  it('rejects a grant with an unknown constraint key', async () => {
    const response = await h.inject({
      method: 'POST',
      url: path(Routes.agentGrants, { id: agentId }),
      headers: session.headers,
      payload: {
        connectionId,
        operation: 'orders.list',
        constraints: { maxResults: 10, allowEverything: CANARY },
      },
    });
    const body = expectError(response, 400, 'validation_failed');
    expect(body.error.details?.[0]?.path).toBe('constraints');
    // Zod names the unknown key; the submitted value is never echoed.
    expect(body.error.details?.[0]?.message).toContain('allowEverything');
    expect(response.body).not.toContain(CANARY);
    const grants = await h.inject({
      method: 'GET',
      url: path(Routes.agentGrants, { id: agentId }),
      headers: { cookie: session.cookie },
    });
    expect(grants.json<{ items: unknown[] }>().items).toEqual([]);
  });

  it('reports paths and never the submitted values', async () => {
    const secretish = `${CANARY}-password`;
    const response = await h.inject({
      method: 'POST',
      url: path(Routes.agents),
      headers: session.headers,
      payload: { name: 'x'.repeat(121) + secretish, clientIdentity: 42 },
    });
    const body = expectError(response, 400, 'validation_failed');
    expect(body.error.details?.map((detail) => detail.path).sort()).toEqual([
      'clientIdentity',
      'name',
    ]);
    expect(response.body).not.toContain(secretish);
    expect(response.body).not.toContain('xxxxxxxx');

    const login = await h.inject({
      method: 'POST',
      url: '/v1/auth/login',
      payload: { email: `not-an-email-${CANARY}`, password: secretish },
    });
    expectError(login, 400, 'validation_failed');
    expect(login.body).not.toContain(CANARY);
  });

  it('reports query and params paths with a prefix', async () => {
    const query = await h.inject({
      method: 'GET',
      url: `${path(Routes.connections)}?limit=1000`,
      headers: { cookie: session.cookie },
    });
    expect(expectError(query, 400, 'validation_failed').error.details?.[0]?.path).toBe(
      'query.limit',
    );

    const params = await h.inject({
      method: 'GET',
      url: path(Routes.connection, { id: CANARY }),
      headers: { cookie: session.cookie },
    });
    expect(expectError(params, 400, 'validation_failed').error.details?.[0]?.path).toBe(
      'params.id',
    );
  });

  it('rejects a forged cursor and a malformed JSON body without echoing them', async () => {
    const cursor = await h.inject({
      method: 'GET',
      url: `${path(Routes.agents)}?cursor=${CANARY}`,
      headers: { cookie: session.cookie },
    });
    expect(expectError(cursor, 400, 'validation_failed').error.details?.[0]?.path).toBe('cursor');

    const malformed = await h.inject({
      method: 'POST',
      url: path(Routes.agents),
      headers: { ...session.headers, 'content-type': 'application/json' },
      payload: `{"name": "${CANARY}`,
    });
    expectError(malformed, 400, 'validation_failed');
    expect(malformed.body).not.toContain(CANARY);
  });

  it('rejects unknown body fields', async () => {
    const response = await h.inject({
      method: 'POST',
      url: path(Routes.agents),
      headers: session.headers,
      payload: { name: 'Agent', clientIdentity: 'agent-2', ownerUserId: session.userId },
    });
    expectError(response, 400, 'validation_failed');
  });

  it('rejects bodies over the size limit', async () => {
    const response = await h.inject({
      method: 'POST',
      url: path(Routes.agents),
      headers: session.headers,
      payload: { name: 'Agent', clientIdentity: 'a'.repeat(70 * 1024) },
    });
    expectError(response, 413, 'validation_failed');
  });

  it('rejects a grant that expires in the past', async () => {
    const response = await h.inject({
      method: 'POST',
      url: path(Routes.agentGrants, { id: agentId }),
      headers: session.headers,
      payload: { connectionId, operation: 'orders.list', expiresAt: '2020-01-01T00:00:00.000Z' },
    });
    expect(expectError(response, 400, 'validation_failed').error.details?.[0]?.path).toBe(
      'expiresAt',
    );
  });
});
