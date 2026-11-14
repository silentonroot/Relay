import { CSRF_HEADER, ErrorResponse, REQUEST_ID_HEADER, SESSION_COOKIE } from '@aab/contracts';
import { hashPassword, hashToken } from '@aab/crypto';
import type { ScryptParams } from '@aab/crypto';
import { createRepositories } from '@aab/database';
import type { DatabaseHandle, Repositories } from '@aab/database';
import { createTestDatabase } from '@aab/database/testing';
import type { FastifyInstance, InjectOptions, LightMyRequestResponse } from 'fastify';
import { expect } from 'vitest';
import { buildApp } from '../src/app.js';
import type { BuildAppDeps } from '../src/app.js';
import type { AppConfig } from '../src/config.js';
import type { RateLimitSettings } from '../src/context.js';
import { createOwner } from '../src/owner.js';

/** The cheapest parameters @aab/crypto accepts. Production uses the defaults. */
export const TEST_SCRYPT: ScryptParams = { logN: 10, r: 8, p: 1 };

export const BASE_TIME = Date.parse('2026-03-01T09:00:00.000Z');

export function testConfig(overrides: Partial<AppConfig> = {}): AppConfig {
  return {
    databaseUrl: 'postgres://unused.invalid/aab',
    host: '127.0.0.1',
    port: 0,
    kekDir: undefined,
    sessionTtlMinutes: 60,
    cookieSecure: true,
    logLevel: 'info',
    trustProxy: false,
    passwordConcurrency: 2,
    passwordQueueLimit: 8,
    jobWaitMs: 25,
    ...overrides,
  };
}

/** Strictly increasing: every read advances one millisecond, `advance` jumps ahead. */
export class TestClock {
  private current = BASE_TIME;
  readonly now = (): Date => {
    this.current += 1;
    return new Date(this.current);
  };
  advance(ms: number): void {
    this.current += ms;
  }
}

export interface Credentials {
  email: string;
  password: string;
}

export interface SignedIn {
  token: string;
  csrfToken: string;
  cookie: string;
  userId: string;
  organizationId: string;
  /** Headers for an authenticated mutation: cookie and CSRF token. */
  headers: Record<string, string>;
}

export interface Harness {
  app: FastifyInstance;
  database: DatabaseHandle;
  repos: Repositories;
  clock: TestClock;
  logs: string[];
  responses: LightMyRequestResponse[];
  /** Values that must never appear in any response. */
  forbiddenInResponses: Set<string>;
  /** Values that must never appear in the logs. */
  forbiddenInLogs: Set<string>;
  /** Seeded accounts, so their current password hashes can be checked too. */
  emails: string[];
  inject(options: InjectOptions): Promise<LightMyRequestResponse>;
  close(): Promise<void>;
}

export async function createHarness(
  options: {
    config?: Partial<AppConfig>;
    rateLimits?: Partial<RateLimitSettings>;
    /** Overrides the strictly increasing test clock, for example with a fixed one. */
    clock?: () => Date;
    passwordVerifier?: BuildAppDeps['passwordVerifier'];
    /** Replaces the default adapter registry (which holds Northstar). */
    adapters?: BuildAppDeps['adapters'];
  } = {},
): Promise<Harness> {
  const database = await createTestDatabase();
  const clock = new TestClock();
  const logs: string[] = [];
  const app = await buildApp({
    database,
    config: testConfig(options.config),
    clock: options.clock ?? clock.now,
    ...(options.passwordVerifier === undefined
      ? {}
      : { passwordVerifier: options.passwordVerifier }),
    ...(options.adapters === undefined ? {} : { adapters: options.adapters }),
    logDestination: { write: (line) => void logs.push(line) },
    passwordParams: TEST_SCRYPT,
    rateLimits: { globalMax: 10_000, ...options.rateLimits },
  });
  const responses: LightMyRequestResponse[] = [];
  const harness: Harness = {
    app,
    database,
    repos: createRepositories(database.db),
    clock,
    logs,
    responses,
    forbiddenInResponses: new Set(),
    forbiddenInLogs: new Set(),
    emails: [],
    async inject(injectOptions) {
      const response = await app.inject(injectOptions);
      responses.push(response);
      return response;
    },
    async close() {
      await app.close();
      await database.close();
    },
  };
  return harness;
}

function remember(harness: Harness, credentials: Credentials, passwordHash: string) {
  harness.forbiddenInResponses.add(credentials.password);
  harness.forbiddenInResponses.add(passwordHash);
  harness.forbiddenInLogs.add(credentials.password);
  harness.emails.push(credentials.email);
}

/** The first owner, created the way create-owner does it. */
export async function seedOwner(
  harness: Harness,
  credentials: Credentials,
  organizationName = 'Synthetic Org One',
) {
  const result = await createOwner(harness.database.db, {
    ...credentials,
    organizationName,
    hashOptions: { params: TEST_SCRYPT },
  });
  const record = await harness.repos.users.findForLogin(credentials.email);
  remember(harness, credentials, record!.passwordHash);
  return result;
}

/** Another organization with its own owner (bootstrap only works once per database). */
export async function seedTenant(
  harness: Harness,
  credentials: Credentials,
  organizationName: string,
  role: 'owner' | 'admin' | 'member' = 'owner',
  existingOrganizationId?: string,
) {
  const passwordHash = await hashPassword(credentials.password, { params: TEST_SCRYPT });
  const organization =
    existingOrganizationId === undefined
      ? await harness.repos.organizations.create({ name: organizationName })
      : { id: existingOrganizationId };
  const user = await harness.repos.users.create({ email: credentials.email, passwordHash });
  await harness.repos.organizations.addMember({
    organizationId: organization.id,
    userId: user.id,
    role,
  });
  remember(harness, credentials, passwordHash);
  return { organizationId: organization.id, userId: user.id };
}

export function sessionTokenFrom(response: LightMyRequestResponse): string | undefined {
  const cookie = response.cookies.find((entry) => entry.name === SESSION_COOKIE);
  return cookie?.value;
}

export async function login(harness: Harness, credentials: Credentials): Promise<SignedIn> {
  const response = await harness.inject({
    method: 'POST',
    url: '/v1/auth/login',
    payload: credentials,
  });
  expect(response.statusCode, response.body).toBe(200);
  const body = response.json<{
    csrfToken: string;
    user: { id: string };
    organization: { id: string };
  }>();
  const token = sessionTokenFrom(response)!;
  harness.forbiddenInResponses.add(hashToken(token));
  harness.forbiddenInResponses.add(hashToken(body.csrfToken));
  harness.forbiddenInLogs.add(token);
  harness.forbiddenInLogs.add(hashToken(token));
  harness.forbiddenInLogs.add(body.csrfToken);
  const cookie = `${SESSION_COOKIE}=${token}`;
  return {
    token,
    csrfToken: body.csrfToken,
    cookie,
    userId: body.user.id,
    organizationId: body.organization.id,
    headers: { cookie, [CSRF_HEADER]: body.csrfToken },
  };
}

/** Builds a URL from a contracts route template. */
export function path(template: string, params: Record<string, string> = {}): string {
  return `/v1${template.replace(/:([A-Za-z]+)/g, (_match, name: string) => params[name] ?? '')}`;
}

export function expectError(
  response: LightMyRequestResponse,
  statusCode: number,
  code: string,
): ErrorResponse {
  expect(response.statusCode, response.body).toBe(statusCode);
  const parsed = ErrorResponse.parse(response.json());
  expect(parsed.error.code).toBe(code);
  expect(parsed.error.requestId).toBe(response.headers[REQUEST_ID_HEADER]);
  return parsed;
}

/** Every recorded response and log line is free of every remembered secret. */
export async function expectNoSecretLeaks(
  harness: Harness,
  options: { databaseOpen?: boolean } = {},
): Promise<void> {
  // Hashes may have been replaced by a rehash on login; the current ones count too.
  for (const email of options.databaseOpen === false ? [] : harness.emails) {
    const record = await harness.repos.users.findForLogin(email);
    if (record !== null) harness.forbiddenInResponses.add(record.passwordHash);
  }
  const serialized = harness.responses.map(
    (response) => `${JSON.stringify(response.headers)}\n${response.body}`,
  );
  expect(serialized.length).toBeGreaterThan(0);
  for (const secret of harness.forbiddenInResponses) {
    for (const text of serialized)
      expect(text.includes(secret), 'secret in a response').toBe(false);
  }
  const logText = harness.logs.join('');
  expect(logText.length).toBeGreaterThan(0);
  for (const secret of harness.forbiddenInLogs) {
    expect(logText.includes(secret), 'secret in the logs').toBe(false);
  }
}

/** Retries an assertion while background work (a failed-login audit event) completes. */
export async function eventually<T>(check: () => Promise<T>, attempts = 50): Promise<T> {
  let lastError: unknown;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      return await check();
    } catch (error) {
      lastError = error;
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
  }
  throw lastError;
}
