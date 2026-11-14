import { Writable } from 'node:stream';
import { AdapterRegistry, defineAdapter, defineOperation } from '@aab/adapter-sdk';
import type { SanitizedResult } from '@aab/adapter-sdk';
import type { Connection, JsonObject } from '@aab/contracts';
import { InMemoryKekProvider } from '@aab/crypto';
import { createRepositories, schema } from '@aab/database';
import type { DatabaseHandle, Repositories } from '@aab/database';
import { createTestDatabase } from '@aab/database/testing';
import { randomBytes } from 'node:crypto';
import { pino } from 'pino';
import type { Logger } from 'pino';
import { z } from 'zod';
import { storeSnapshot } from '../../src/session-store/index.js';
import type {
  JobRunner,
  LoginHandle,
  LoginJobSpec,
  LoginOutcome,
  OperationJobOutcome,
  OperationJobSpec,
  StorageCookie,
  StorageState,
} from '../../src/types.js';

export const APP_ORIGIN = 'https://app.example.test';
export const CDN_ORIGIN = 'https://cdn.example.test';
export const OTHER_ORIGIN = 'https://tracker.other.test';

function operation(name: string, sensitivity: 'read' | 'write') {
  return defineOperation({
    name,
    description: `test operation ${name}`,
    input: z.object({ limit: z.number().int().min(1).max(100).optional() }),
    output: z.object({ items: z.array(z.string()), note: z.string().optional() }),
    sensitivity,
    requiresApproval: false,
    idempotent: sensitivity === 'read',
    sideEffects: sensitivity === 'read' ? [] : ['changes orders'],
    timeoutMs: 30_000,
    allowedPaths: ['/orders'],
  });
}

const unreachable = async (): Promise<SanitizedResult> => {
  throw new Error('the supervisor never runs adapter code');
};

/** A browser-session adapter with a read and a write operation. */
export const testAdapter = defineAdapter({
  id: 'test-app',
  version: '1.0.0',
  displayName: 'Test App',
  allowedOrigins: [APP_ORIGIN, CDN_ORIGIN],
  authMode: 'browser_session',
  loginPath: '/login',
  sessionCheckPaths: ['/account'],
  checkSession: async () => ({ state: 'active' }),
  execute: unreachable,
  operations: {
    'orders.list': operation('orders.list', 'read'),
    'orders.cancel': operation('orders.cancel', 'write'),
  },
});

/** Registered but cannot run anything. */
export const manifestOnlyAdapter = defineAdapter({
  id: 'manifest-only',
  version: '1.0.0',
  displayName: 'Manifest Only',
  allowedOrigins: [APP_ORIGIN],
  authMode: 'browser_session',
  operations: { 'orders.list': operation('orders.list', 'read') },
});

export function testRegistry(): AdapterRegistry {
  const registry = new AdapterRegistry();
  registry.register(testAdapter);
  registry.register(manifestOnlyAdapter);
  return registry;
}

export function testKek(): InMemoryKekProvider {
  return new InMemoryKekProvider([[1, randomBytes(32)]]);
}

/** Captures every log line so tests can assert nothing secret was written. */
export function captureLogger(level: pino.Level = 'debug'): { logger: Logger; lines: string[] } {
  const lines: string[] = [];
  const stream = new Writable({
    write(chunk: Buffer, _encoding, callback) {
      lines.push(chunk.toString('utf8'));
      callback();
    },
  });
  return { logger: pino({ level }, stream), lines };
}

export function cookie(name: string, value: string, domain: string, expires = -1): StorageCookie {
  return {
    name,
    value,
    domain,
    path: '/',
    expires,
    httpOnly: true,
    secure: true,
    sameSite: 'Lax',
  };
}

export function stateWith(value: string): StorageState {
  return {
    cookies: [cookie('sid', value, 'app.example.test', 2_000_000_000)],
    origins: [{ origin: APP_ORIGIN, localStorage: [{ name: 'pref', value: `ls-${value}` }] }],
  };
}

export interface World {
  handle: DatabaseHandle;
  repos: Repositories;
  scope: { organizationId: string; userId: string };
  applicationId: string;
  agentId: string;
  close(): Promise<void>;
}

export async function createWorld(
  application: { adapterId?: string; allowedOrigins?: string[] } = {},
): Promise<World> {
  const handle = await createTestDatabase();
  const repos = createRepositories(handle.db);
  const owner = await repos.organizations.bootstrapLocalOwner({
    email: 'owner@example.test',
    passwordHash: 'synthetic-hash-not-used',
    organizationName: 'Test Org',
  });
  const scope = { organizationId: owner.organization.id, userId: owner.user.id };
  const app = await repos.applications.register(scope, {
    adapterId: application.adapterId ?? 'test-app',
    adapterVersion: '1.0.0',
    name: 'Test App',
    allowedOrigins: application.allowedOrigins ?? [APP_ORIGIN, CDN_ORIGIN],
    authModes: ['browser_session'],
  });
  const agent = await repos.agents.create(scope, { name: 'Agent', clientIdentity: 'agent-1' });
  return {
    handle,
    repos,
    scope,
    applicationId: app.id,
    agentId: agent.id,
    close: () => handle.close(),
  };
}

export async function registerApplication(
  world: World,
  input: { adapterId: string; allowedOrigins: string[] },
): Promise<string> {
  const app = await world.repos.applications.register(world.scope, {
    adapterId: input.adapterId,
    adapterVersion: '1.0.0',
    name: `App ${input.adapterId}`,
    allowedOrigins: input.allowedOrigins,
    authModes: ['browser_session'],
  });
  return app.id;
}

let connectionCounter = 0;

/** A connection in `authenticating` with a queued login job. */
export async function loginConnection(
  world: World,
  applicationId = world.applicationId,
): Promise<{ connection: Connection; jobId: string }> {
  const created = await world.repos.connections.create(world.scope, {
    applicationId,
    displayName: `Connection ${(connectionCounter += 1)}`,
  });
  await world.repos.connections.transitionStatus(world.scope, created.id, {
    to: 'authentication_required',
  });
  const connection = await world.repos.connections.transitionStatus(world.scope, created.id, {
    to: 'authenticating',
  });
  const job = await world.repos.jobs.createLogin({
    organizationId: world.scope.organizationId,
    requestedByUserId: world.scope.userId,
    connectionId: created.id,
    timeoutMs: 600_000,
  });
  return { connection, jobId: job.id };
}

/** An `active` connection with a stored snapshot, a hint and an allow grant. */
export async function activeConnection(
  world: World,
  kek: InMemoryKekProvider,
  options: {
    state?: StorageState | null;
    hint?: string | null;
    applicationId?: string;
    grant?: boolean;
    operation?: string;
  } = {},
): Promise<Connection> {
  const { connection } = await loginConnection(world, options.applicationId);
  // The login job is not needed: end it as the API would never leave it.
  await world.repos.jobs.cancelForConnection(connection.id, new Date());
  await world.repos.connections.transitionStatus(world.scope, connection.id, { to: 'active' });
  const state = options.state === undefined ? stateWith('default') : options.state;
  if (state !== null) {
    await storeSnapshot(world.repos, { connection, storageState: state, kek, now: new Date() });
  }
  await world.repos.connections.recordSession(connection.id, {
    externalAccountHint: options.hint === undefined ? 'user@example.test' : options.hint,
    sessionExpiresAt: null,
    lastVerifiedAt: new Date(),
  });
  if (options.grant !== false) {
    await world.repos.grants.create(world.scope, world.agentId, {
      connectionId: connection.id,
      operation: options.operation ?? 'orders.list',
    });
  }
  const fresh = await world.repos.connections.get(world.scope, connection.id);
  return fresh!;
}

export async function queueOperation(
  world: World,
  connectionId: string,
  options: { operation?: string; arguments?: JsonObject; retrySafe?: boolean } = {},
): Promise<string> {
  const job = await world.repos.jobs.createOperation({
    organizationId: world.scope.organizationId,
    requestedByUserId: world.scope.userId,
    agentId: world.agentId,
    connectionId,
    runId: null,
    operation: options.operation ?? 'orders.list',
    arguments: options.arguments ?? { limit: 5 },
    retrySafe: options.retrySafe ?? true,
    policyDecisionId: null,
    timeoutMs: 30_000,
  });
  return job.id;
}

/** Every row of every table that could hold a secret, as one searchable string. */
export async function dumpTables(world: World): Promise<string> {
  const db = world.handle.db;
  const tables = [
    schema.vaultSecrets,
    schema.vaultSecretVersions,
    schema.executionJobs,
    schema.auditEvents,
    schema.connections,
    schema.connectionStatusEvents,
  ];
  const parts: string[] = [];
  for (const table of tables) {
    const rows = await db.select().from(table);
    parts.push(
      JSON.stringify(rows, (_key, value: unknown) => {
        if (
          typeof value === 'object' &&
          value !== null &&
          (value as { type?: unknown }).type === 'Buffer'
        ) {
          return Buffer.from((value as { data: number[] }).data).toString('latin1');
        }
        return value;
      }),
    );
  }
  return parts.join('\n');
}

export async function auditEvents(world: World) {
  const page = await world.repos.audit.list(world.scope, { limit: 200 });
  return [...page.items].reverse();
}

export function deferred<T>(): {
  promise: Promise<T>;
  resolve(value: T): void;
  reject(error: unknown): void;
} {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

export interface FakeLoginHandle extends LoginHandle {
  closeWindow(): void;
  cancelled: boolean;
  completed: boolean;
}

export function fakeLoginHandle(outcome: () => Promise<LoginOutcome>): FakeLoginHandle {
  const closed = deferred<void>();
  const handle: FakeLoginHandle = {
    closed: closed.promise,
    cancelled: false,
    completed: false,
    closeWindow: () => closed.resolve(),
    async complete() {
      handle.completed = true;
      try {
        return await outcome();
      } finally {
        closed.resolve();
      }
    },
    async cancel() {
      handle.cancelled = true;
      closed.resolve();
    },
  };
  return handle;
}

/** A JobRunner that never starts a sandbox. Records deep copies of what it is given. */
export class FakeRunner implements JobRunner {
  readonly sandbox = 'unsafe-process' as const;
  operationCalls: OperationJobSpec[] = [];
  loginCalls: LoginJobSpec[] = [];
  handles: FakeLoginHandle[] = [];
  selfCheckError: Error | null = null;
  operation: (spec: OperationJobSpec, signal: AbortSignal) => Promise<OperationJobOutcome> =
    async () => ({ status: 'succeeded', data: { items: ['a'] } });
  login: (spec: LoginJobSpec, signal: AbortSignal) => Promise<LoginHandle> = async () => {
    const handle = fakeLoginHandle(async () => ({
      status: 'succeeded',
      storageState: stateWith('login'),
      externalAccountHint: 'user@example.test',
    }));
    this.handles.push(handle);
    return handle;
  };

  async runOperation(spec: OperationJobSpec, signal: AbortSignal): Promise<OperationJobOutcome> {
    this.operationCalls.push(structuredClone(spec));
    return this.operation(spec, signal);
  }

  async startLogin(spec: LoginJobSpec, signal: AbortSignal): Promise<LoginHandle> {
    this.loginCalls.push(structuredClone(spec));
    return this.login(spec, signal);
  }

  async selfCheck(): Promise<void> {
    if (this.selfCheckError !== null) throw this.selfCheckError;
  }
}

/** Resolves when `check` returns true, polling every 10 ms, or rejects after `timeoutMs`. */
export async function waitFor(check: () => Promise<boolean> | boolean, timeoutMs = 5_000) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (await check()) return;
    if (Date.now() > deadline) throw new Error('condition not met in time');
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}
