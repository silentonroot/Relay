import { randomUUID } from 'node:crypto';
import { API_PREFIX, CSRF_HEADER, Routes } from '@aab/contracts';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Harness, SignedIn } from './helpers.js';
import { createHarness, expectError, expectNoSecretLeaks, login, seedOwner } from './helpers.js';

const owner = { email: 'owner@example.test', password: 'route guard test password' };
const SAFE = new Set(['GET', 'HEAD', 'OPTIONS']);

/** Fills `:param` segments with fresh UUIDs. */
function concrete(url: string): string {
  return url.replace(/:[A-Za-z]+/g, () => randomUUID());
}

describe('route guards, driven by the route table', () => {
  let h: Harness;
  let session: SignedIn;
  let routes: { method: string; url: string; public: boolean }[];

  beforeAll(async () => {
    h = await createHarness();
    await seedOwner(h, owner);
    session = await login(h, owner);
    routes = h.app.routeTable.filter((route) => route.url.startsWith(`${API_PREFIX}/`));
  });

  afterAll(async () => {
    await expectNoSecretLeaks(h);
    await h.close();
  });

  it('implements every route in the contracts route table', () => {
    for (const template of Object.values(Routes)) {
      expect(
        routes.some((route) => route.url === `${API_PREFIX}${template}`),
        `${template} is not implemented`,
      ).toBe(true);
    }
  });

  it('marks only health and login as public', () => {
    const publicRoutes = routes
      .filter((route) => route.public)
      .map((route) => `${route.method} ${route.url}`)
      .sort();
    expect(publicRoutes).toEqual(
      [
        `GET ${API_PREFIX}${Routes.health}`,
        `HEAD ${API_PREFIX}${Routes.health}`,
        `POST ${API_PREFIX}${Routes.authLogin}`,
      ].sort(),
    );
  });

  it('answers 401 on every non-public route without a session', async () => {
    const guarded = routes.filter((route) => !route.public);
    expect(guarded.length).toBeGreaterThan(15);
    for (const route of guarded) {
      const response = await h.inject({
        method: route.method as 'GET',
        url: concrete(route.url),
        ...(SAFE.has(route.method) ? {} : { payload: {} }),
      });
      if (route.method === 'HEAD') {
        expect(response.statusCode, `${route.method} ${route.url}`).toBe(401);
        continue;
      }
      expectError(response, 401, 'unauthenticated');
    }
  });

  const mutating = () => routes.filter((route) => !route.public && !SAFE.has(route.method));

  it('answers 403 csrf_failed on every mutating route without a CSRF token', async () => {
    expect(mutating().length).toBeGreaterThanOrEqual(8);
    for (const route of mutating()) {
      const response = await h.inject({
        method: route.method as 'POST',
        url: concrete(route.url),
        headers: { cookie: session.cookie },
        payload: {},
      });
      expectError(response, 403, 'csrf_failed');
    }
  });

  it('answers 403 csrf_failed on every mutating route with a wrong CSRF token', async () => {
    const other = await login(h, owner);
    for (const route of mutating()) {
      for (const token of [other.csrfToken, `${session.csrfToken}x`, session.csrfToken.slice(1)]) {
        const response = await h.inject({
          method: route.method as 'POST',
          url: concrete(route.url),
          headers: { cookie: session.cookie, [CSRF_HEADER]: token },
          payload: {},
        });
        expectError(response, 403, 'csrf_failed');
      }
    }
  });

  it('rejects non-JSON bodies on every mutating route', async () => {
    for (const route of [...mutating(), ...routes.filter((r) => r.public && r.method === 'POST')]) {
      for (const contentType of ['text/plain', 'application/x-www-form-urlencoded']) {
        const response = await h.inject({
          method: route.method as 'POST',
          url: concrete(route.url),
          headers: { ...session.headers, 'content-type': contentType },
          payload: 'a=b',
        });
        expectError(response, 415, 'validation_failed');
      }
    }
  });

  it('accepts a bodiless mutation without a content type (as the dashboard sends it)', async () => {
    const response = await h.inject({
      method: 'POST',
      url: `${API_PREFIX}/agents/${randomUUID()}/disable`,
      headers: session.headers,
    });
    expectError(response, 404, 'not_found');
  });

  it('serves the OpenAPI document to signed-in callers only', async () => {
    expectError(await h.inject({ method: 'GET', url: '/v1/openapi.json' }), 401, 'unauthenticated');
    const response = await h.inject({
      method: 'GET',
      url: '/v1/openapi.json',
      headers: { cookie: session.cookie },
    });
    expect(response.statusCode).toBe(200);
    const document = response.json<{ openapi: string; paths: Record<string, unknown> }>();
    expect(document.openapi).toMatch(/^3\./);
    expect(Object.keys(document.paths)).toEqual(
      expect.arrayContaining(['/v1/connections/{id}/revoke', '/v1/agents/{id}/grants/{grantId}']),
    );
    expect(Object.keys(document.paths)).not.toContain('/v1/openapi.json');
  });
});
