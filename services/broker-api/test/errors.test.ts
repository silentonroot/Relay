import { ErrorResponse, HealthResponse, REQUEST_ID_HEADER, Routes } from '@aab/contracts';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { requestIdFor } from '../src/app.js';
import { mapError } from '../src/errors.js';
import type { Harness, SignedIn } from './helpers.js';
import {
  createHarness,
  expectError,
  expectNoSecretLeaks,
  login,
  path,
  seedOwner,
} from './helpers.js';

const owner = { email: 'owner@example.test', password: 'error path test password' };
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

describe('request ids, error bodies and health', () => {
  let h: Harness;
  let session: SignedIn;

  beforeAll(async () => {
    h = await createHarness();
    await seedOwner(h, owner);
    session = await login(h, owner);
  });

  afterAll(async () => {
    // Every non-2xx response recorded in this file parses as ErrorResponse with the header id.
    for (const response of h.responses.filter((r) => r.statusCode >= 300)) {
      const body = ErrorResponse.parse(response.json());
      expect(body.error.requestId).toBe(response.headers[REQUEST_ID_HEADER]);
    }
    await expectNoSecretLeaks(h);
    await h.close();
  });

  it('assigns a fresh UUID to every request', async () => {
    const first = await h.inject({ method: 'GET', url: path(Routes.health) });
    const second = await h.inject({ method: 'GET', url: path(Routes.health) });
    expect(first.headers[REQUEST_ID_HEADER]).toMatch(UUID);
    expect(second.headers[REQUEST_ID_HEADER]).toMatch(UUID);
    expect(first.headers[REQUEST_ID_HEADER]).not.toBe(second.headers[REQUEST_ID_HEADER]);
  });

  it('keeps a safe inbound request id and replaces an unsafe one', async () => {
    const kept = await h.inject({
      method: 'GET',
      url: path(Routes.health),
      headers: { [REQUEST_ID_HEADER]: 'trace-01.abc:42' },
    });
    expect(kept.headers[REQUEST_ID_HEADER]).toBe('trace-01.abc:42');

    for (const unsafe of ['has space', 'x'.repeat(65), '<script>', 'a"b', '-leading-dash', '']) {
      expect(requestIdFor(unsafe)).toMatch(UUID);
    }
    expect(requestIdFor(['a', 'b'])).toMatch(UUID);
    const replaced = await h.inject({
      method: 'GET',
      url: path(Routes.health),
      headers: { [REQUEST_ID_HEADER]: '{"injected":true}' },
    });
    expect(replaced.headers[REQUEST_ID_HEADER]).toMatch(UUID);
  });

  it('answers unknown routes with 404 not_found', async () => {
    for (const url of ['/v1/nope', '/v1/connections/x/y/z', '/', '/admin']) {
      const response = await h.inject({ method: 'GET', url, headers: { cookie: session.cookie } });
      expectError(response, 404, 'not_found');
    }
    expectError(await h.inject({ method: 'PUT', url: path(Routes.agents) }), 404, 'not_found');
  });

  it('puts the request id in every error body', async () => {
    const response = await h.inject({
      method: 'GET',
      url: path(Routes.connections),
      headers: { [REQUEST_ID_HEADER]: 'client-chosen-id' },
    });
    expect(expectError(response, 401, 'unauthenticated').error.requestId).toBe('client-chosen-id');
  });

  it('reports database reachability without authentication', async () => {
    const response = await h.inject({ method: 'GET', url: path(Routes.health) });
    expect(response.statusCode).toBe(200);
    expect(HealthResponse.parse(response.json())).toEqual({
      status: 'ok',
      version: expect.any(String),
      checks: { database: 'ok' },
    });
  });

  it('sets security headers and forbids caching', async () => {
    const response = await h.inject({
      method: 'GET',
      url: path(Routes.authSession),
      headers: { cookie: session.cookie },
    });
    expect(response.headers['x-content-type-options']).toBe('nosniff');
    expect(response.headers['content-security-policy']).toBeDefined();
    expect(response.headers['cache-control']).toBe('no-store');
    expect(response.headers['access-control-allow-origin']).toBeUndefined();
  });

  it('maps unexpected errors to 500 internal_error without detail', () => {
    const mapped = mapError(new Error('relation "users" does not exist at /srv/db.ts:12'));
    expect(mapped).toEqual({
      statusCode: 500,
      code: 'internal_error',
      message: 'An unexpected error occurred.',
    });
  });
});

describe('when the database is gone', () => {
  let h: Harness;
  let session: SignedIn;

  beforeAll(async () => {
    h = await createHarness();
    await seedOwner(h, owner);
    session = await login(h, owner);
    await h.database.close();
  });

  afterAll(async () => {
    await expectNoSecretLeaks(h, { databaseOpen: false });
    await h.app.close();
  });

  it('returns 500 internal_error with no internal detail', async () => {
    const response = await h.inject({
      method: 'GET',
      url: path(Routes.connections),
      headers: { cookie: session.cookie },
    });
    const body = expectError(response, 500, 'internal_error');
    expect(body.error.message).toBe('An unexpected error occurred.');
    expect(body.error.details).toBeUndefined();
    expect(response.body).not.toMatch(/pglite|closed|stack|at /i);
    // The cause is in the server log instead.
    const errorLines = h.logs.filter((line) => line.includes('"level":50'));
    expect(errorLines.length).toBeGreaterThan(0);
    // Driver errors quote bound parameters (here the session token hash); they are scrubbed.
    expect(errorLines.join('')).toContain('params: [REDACTED]');
    expect(errorLines.join('')).toContain('PGlite is closed');
  });

  it('health reports the database as unavailable', async () => {
    const response = await h.inject({ method: 'GET', url: path(Routes.health) });
    expect(response.statusCode).toBe(200);
    expect(HealthResponse.parse(response.json())).toMatchObject({
      status: 'degraded',
      checks: { database: 'unavailable' },
    });
  });
});
