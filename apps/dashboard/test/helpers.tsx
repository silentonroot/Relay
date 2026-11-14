import type {
  Agent,
  AgentGrant,
  ApplicationDefinition,
  AuditEvent,
  Connection,
  ConnectionAuthResponse,
  ConnectionStatus,
  JobError,
  OperationJob,
  SessionResponse,
} from '@aab/contracts';
import { render } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, expect, vi } from 'vitest';
import { AppProviders, AppRoutes, createQueryClient } from '../src/App.js';

/* Synthetic data only. */

export const CSRF_TOKEN = 'csrf-test-token';
const NOW = '2026-03-02T10:00:00.000Z';

/** A well-formed v4 UUID for each small integer, so schema validation passes. */
export function uuid(n: number): string {
  return `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
}

export const ORG_ID = uuid(900);
export const USER_ID = uuid(901);

export function makeSession(): SessionResponse {
  return {
    user: {
      id: USER_ID,
      email: 'owner@example.test',
      status: 'active',
      createdAt: NOW,
      updatedAt: NOW,
    },
    organization: {
      id: ORG_ID,
      name: 'Test Organization',
      status: 'active',
      createdAt: NOW,
      updatedAt: NOW,
    },
    csrfToken: CSRF_TOKEN,
    expiresAt: '2026-03-02T22:00:00.000Z',
  };
}

export function makeApplication(
  n: number,
  overrides: Partial<ApplicationDefinition> = {},
): ApplicationDefinition {
  return {
    id: uuid(100 + n),
    organizationId: ORG_ID,
    adapterId: 'northstar',
    adapterVersion: '1.0.0',
    name: `Northstar ${n}`,
    allowedOrigins: ['https://app.example.test'],
    authModes: ['browser_session'],
    status: 'active',
    createdAt: NOW,
    updatedAt: NOW,
    ...overrides,
  };
}

export function makeConnection(n: number, overrides: Partial<Connection> = {}): Connection {
  return {
    id: uuid(200 + n),
    ownerUserId: USER_ID,
    organizationId: ORG_ID,
    applicationId: uuid(101),
    displayName: `Connection ${n}`,
    externalAccountHint: null,
    status: 'active',
    statusReason: null,
    lastVerifiedAt: null,
    sessionExpiresAt: null,
    createdAt: NOW,
    updatedAt: NOW,
    ...overrides,
  };
}

export function makeAuthResponse(
  connection: Connection,
  overrides: Partial<ConnectionAuthResponse> = {},
): ConnectionAuthResponse {
  return {
    connection,
    jobId: uuid(700),
    jobStatus: connection.status === 'authenticating' ? 'running' : 'succeeded',
    error: null,
    ...overrides,
  };
}

export function makeJob(n: number, overrides: Partial<OperationJob> = {}): OperationJob {
  return {
    jobId: uuid(800 + n),
    status: 'succeeded',
    operation: 'orders.list',
    agentId: uuid(301),
    connectionId: uuid(201),
    runId: null,
    result: { orders: [] },
    error: null,
    auditEventId: null,
    createdAt: NOW,
    finishedAt: NOW,
    ...overrides,
  };
}

export function jobError(code: JobError['code'], message = 'Fixed broker text.'): JobError {
  return { code, message };
}

export function makeAgent(n: number, overrides: Partial<Agent> = {}): Agent {
  return {
    id: uuid(300 + n),
    organizationId: ORG_ID,
    ownerUserId: USER_ID,
    name: `Agent ${n}`,
    clientIdentity: `client-${n}`,
    status: 'active',
    createdAt: NOW,
    updatedAt: NOW,
    ...overrides,
  };
}

export function makeGrant(n: number, overrides: Partial<AgentGrant> = {}): AgentGrant {
  return {
    id: uuid(400 + n),
    agentId: uuid(301),
    connectionId: uuid(201),
    operation: 'orders.list',
    effect: 'allow',
    constraints: {},
    approvalMode: 'none',
    expiresAt: null,
    revokedAt: null,
    createdAt: NOW,
    updatedAt: NOW,
    ...overrides,
  };
}

export function makeAuditEvent(n: number, overrides: Partial<AuditEvent> = {}): AuditEvent {
  return {
    id: uuid(500 + n),
    sequence: n,
    timestamp: NOW,
    organizationId: ORG_ID,
    actorType: 'user',
    actorId: USER_ID,
    agentId: null,
    runId: null,
    connectionId: null,
    eventType: 'connection.created',
    decision: 'not_applicable',
    metadata: {},
    previousHash: null,
    eventHash: `hash${String(n).padStart(8, '0')}abcdef0123456789`,
    ...overrides,
  };
}

export const ALL_CONNECTION_STATUSES: readonly ConnectionStatus[] = [
  'created',
  'authentication_required',
  'authenticating',
  'active',
  'degraded',
  'expired',
  'reconnect_required',
  'revoked',
];

export function page<T>(items: T[], nextCursor: string | null = null) {
  return { items, nextCursor };
}

export function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });
}

export function apiError(
  status: number,
  code: string,
  message: string,
  requestId = 'req_test_0001',
  details?: { path: string; message: string }[],
): Response {
  return json(
    { error: { code, message, requestId, ...(details === undefined ? {} : { details }) } },
    status,
  );
}

export interface RecordedRequest {
  method: string;
  /** Path and query, as sent. */
  url: string;
  path: string;
  query: URLSearchParams;
  headers: Headers;
  body: unknown;
}

export type Handler = (request: RecordedRequest) => Response | Promise<Response>;

/** Keys look like `GET /v1/connections`. */
export type Handlers = Record<string, Handler>;

const unhandled: string[] = [];

afterEach(() => {
  // A request nobody planned for is a test bug, not a silent 404.
  const missed = unhandled.splice(0);
  expect(missed).toEqual([]);
});

/**
 * Replaces global fetch with a fake broker. Everything the app does still goes through its
 * real API client; only the network is faked. Returns the log of requests it received.
 */
export function mockApi(overrides: Handlers = {}): RecordedRequest[] {
  const defaults: Handlers = {
    'GET /v1/auth/session': () => json(makeSession()),
    'GET /v1/health': () =>
      json({ status: 'ok', version: '0.0.0-test', checks: { database: 'ok' } }),
    'GET /v1/applications': () => json(page([])),
    'GET /v1/connections': () => json(page([])),
    'GET /v1/agents': () => json(page([])),
    'GET /v1/audit-events': () => json(page([])),
  };
  const handlers = { ...defaults, ...overrides };
  const log: RecordedRequest[] = [];

  const fake = vi.fn(async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const raw = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    const url = new URL(raw, 'http://localhost');
    const method = (init?.method ?? 'GET').toUpperCase();
    const text = typeof init?.body === 'string' ? init.body : undefined;
    const request: RecordedRequest = {
      method,
      url: `${url.pathname}${url.search}`,
      path: url.pathname,
      query: url.searchParams,
      headers: new Headers(init?.headers),
      body: text === undefined ? undefined : (JSON.parse(text) as unknown),
    };
    log.push(request);
    const handler = handlers[`${method} ${url.pathname}`];
    if (handler === undefined) {
      unhandled.push(`${method} ${url.pathname}`);
      return apiError(404, 'not_found', 'No such route in the test server.');
    }
    return handler(request);
  });
  vi.stubGlobal('fetch', fake);
  return log;
}

export function requestsTo(log: RecordedRequest[], method: string, path: string) {
  return log.filter((request) => request.method === method && request.path === path);
}

/** Renders the whole app (session, guard, routes) at an address. */
export function renderApp(path = '/') {
  const queryClient = createQueryClient();
  queryClient.setDefaultOptions({
    queries: { retry: false, staleTime: 0, refetchOnWindowFocus: false },
    mutations: { retry: false },
  });
  const view = render(
    <AppProviders queryClient={queryClient}>
      <MemoryRouter initialEntries={[path]}>
        <AppRoutes />
      </MemoryRouter>
    </AppProviders>,
  );
  return { ...view, queryClient };
}
