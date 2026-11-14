import { ConnectionList } from '@aab/contracts';
import { describe, expect, it, vi } from 'vitest';
import { z } from 'zod';
import { ApiError, createApiClient } from '../src/api/client.js';
import { createEndpoints } from '../src/api/endpoints.js';
import { apiError, CSRF_TOKEN, json, makeConnection, mockApi, page, uuid } from './helpers.js';

function setup(token: string | null = CSRF_TOKEN) {
  const onUnauthenticated = vi.fn();
  const client = createApiClient({ getCsrfToken: () => token, onUnauthenticated });
  return { client, onUnauthenticated };
}

const Thing = z.object({ ok: z.literal(true) });

describe('API client: CSRF header', () => {
  it('sends x-csrf-token on POST and DELETE but not on GET', async () => {
    const log = mockApi({
      'GET /v1/thing': () => json({ ok: true }),
      'POST /v1/thing': () => json({ ok: true }),
      'DELETE /v1/thing': () => new Response(null, { status: 204 }),
    });
    const { client } = setup();

    await client.request({ path: '/thing', schema: Thing });
    await client.request({ method: 'POST', path: '/thing', body: { a: 1 }, schema: Thing });
    await client.request({ method: 'DELETE', path: '/thing', schema: null });

    const [get, post, del] = log;
    expect(get?.method).toBe('GET');
    expect(get?.headers.has('x-csrf-token')).toBe(false);
    expect(post?.method).toBe('POST');
    expect(post?.headers.get('x-csrf-token')).toBe(CSRF_TOKEN);
    expect(del?.method).toBe('DELETE');
    expect(del?.headers.get('x-csrf-token')).toBe(CSRF_TOKEN);
  });

  it('declares a JSON content type only when there is a body, and never sends cookies cross-origin', async () => {
    const log = mockApi({
      'POST /v1/thing': () => json({ ok: true }),
    });
    const { client } = setup();
    await client.request({ method: 'POST', path: '/thing', schema: Thing });
    await client.request({ method: 'POST', path: '/thing', body: {}, schema: Thing });
    expect(log[0]?.headers.has('content-type')).toBe(false);
    expect(log[1]?.headers.get('content-type')).toBe('application/json');
    const init = vi.mocked(globalThis.fetch).mock.calls[0]?.[1];
    expect(init?.credentials).toBe('same-origin');
  });
});

describe('API client: responses', () => {
  it('rejects a success body that fails schema validation', async () => {
    mockApi({
      // Valid JSON, wrong shape: the connection status is not one of the eight.
      'GET /v1/connections': () => json(page([{ ...makeConnection(1), status: 'mystery' }])),
    });
    const { client } = setup();
    const error = await client
      .request({ path: '/connections', schema: ConnectionList })
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({ code: 'invalid_response', status: 200 });
  });

  it('rejects a success body that is not JSON', async () => {
    mockApi({ 'GET /v1/thing': () => new Response('<html>', { status: 200 }) });
    const { client } = setup();
    await expect(client.request({ path: '/thing', schema: Thing })).rejects.toMatchObject({
      code: 'invalid_response',
    });
  });

  it('turns an error body into an ApiError with code, request id and details', async () => {
    mockApi({
      'POST /v1/thing': () =>
        apiError(400, 'validation_failed', 'The request was not valid.', 'req_abc123', [
          { path: 'name', message: 'Required' },
        ]),
    });
    const { client, onUnauthenticated } = setup();
    const error = await client
      .request({ method: 'POST', path: '/thing', body: {}, schema: Thing })
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({
      code: 'validation_failed',
      message: 'The request was not valid.',
      status: 400,
      requestId: 'req_abc123',
      details: [{ path: 'name', message: 'Required' }],
    });
    expect(onUnauthenticated).not.toHaveBeenCalled();
  });

  it('falls back to the x-request-id header when an error body is not the contract shape', async () => {
    mockApi({
      'GET /v1/thing': () =>
        new Response('Bad gateway', {
          status: 502,
          headers: { 'x-request-id': 'req_from_header' },
        }),
    });
    const { client } = setup();
    await expect(client.request({ path: '/thing', schema: Thing })).rejects.toMatchObject({
      code: 'invalid_response',
      status: 502,
      requestId: 'req_from_header',
    });
  });

  it('reports an unreachable API as network_error', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() => Promise.reject(new TypeError('Failed to fetch'))),
    );
    const { client } = setup();
    await expect(client.request({ path: '/thing', schema: Thing })).rejects.toMatchObject({
      code: 'network_error',
      status: null,
    });
  });

  it('reports a request that never answers as timeout', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(
        (_url: string, init?: RequestInit) =>
          new Promise<Response>((_resolve, reject) => {
            init?.signal?.addEventListener('abort', () =>
              reject(new DOMException('', 'AbortError')),
            );
          }),
      ),
    );
    const client = createApiClient({
      getCsrfToken: () => null,
      onUnauthenticated: () => undefined,
      timeoutMs: 20,
    });
    await expect(client.request({ path: '/thing', schema: Thing })).rejects.toMatchObject({
      code: 'timeout',
    });
  });
});

describe('API client: 401 handling', () => {
  it('signs out on a 401 from an established session', async () => {
    mockApi({
      'GET /v1/thing': () => apiError(401, 'unauthenticated', 'Sign in required.', 'req_401'),
    });
    const { client, onUnauthenticated } = setup();
    await expect(client.request({ path: '/thing', schema: Thing })).rejects.toMatchObject({
      code: 'unauthenticated',
      requestId: 'req_401',
    });
    expect(onUnauthenticated).toHaveBeenCalledTimes(1);
  });

  it('signs out on a bare 401 with no contract body', async () => {
    mockApi({ 'GET /v1/thing': () => new Response('', { status: 401 }) });
    const { client, onUnauthenticated } = setup();
    await expect(client.request({ path: '/thing', schema: Thing })).rejects.toMatchObject({
      code: 'unauthenticated',
    });
    expect(onUnauthenticated).toHaveBeenCalledTimes(1);
  });

  it('does not sign out when a 401 is the expected answer (session probe, login)', async () => {
    mockApi({
      'GET /v1/thing': () => apiError(401, 'unauthenticated', 'Invalid email or password.'),
    });
    const { client, onUnauthenticated } = setup();
    await expect(
      client.request({ path: '/thing', schema: Thing, unauthenticatedIsExpected: true }),
    ).rejects.toMatchObject({ code: 'unauthenticated' });
    expect(onUnauthenticated).not.toHaveBeenCalled();
  });

  it('does not sign out for a 403 csrf failure', async () => {
    mockApi({ 'POST /v1/thing': () => apiError(403, 'csrf_failed', 'CSRF check failed.') });
    const { client, onUnauthenticated } = setup();
    await expect(
      client.request({ method: 'POST', path: '/thing', schema: Thing }),
    ).rejects.toMatchObject({ code: 'csrf_failed' });
    expect(onUnauthenticated).not.toHaveBeenCalled();
  });
});

describe('endpoints', () => {
  it('omits empty query values and encodes path parameters', async () => {
    const log = mockApi({
      'GET /v1/audit-events': () => json(page([])),
      'POST /v1/agents/a%2Fb/disable': () => apiError(404, 'not_found', 'No such agent.'),
    });
    const { client } = setup();
    const api = createEndpoints(client);
    await api.listAuditEvents({ agentId: undefined }, { limit: 50 });
    expect(log[0]?.url).toBe('/v1/audit-events?limit=50');
    await expect(api.disableAgent('a/b')).rejects.toMatchObject({ code: 'not_found' });
    expect(log[1]?.path).toBe('/v1/agents/a%2Fb/disable');
  });

  it('follows nextCursor until the collection is complete', async () => {
    const log = mockApi({
      'GET /v1/agents': (request) =>
        request.query.get('cursor') === null ? json(page([], 'c2')) : json(page([], null)),
    });
    const { client } = setup();
    expect(await createEndpoints(client).listAgents()).toEqual([]);
    expect(log.map((request) => request.query.get('cursor'))).toEqual([null, 'c2']);
    expect(log.every((request) => request.query.get('limit') === '200')).toBe(true);
    expect(uuid(1)).toHaveLength(36);
  });
});
