import { randomBytes, randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { generateLocalKek, openSecret, sealSecret } from '@aab/crypto';
import { createRepositories } from '@aab/database';
import type { DatabaseHandle, Db, Repositories } from '@aab/database';
import { createTestDatabase, sql } from '@aab/database/testing';
import type { VaultRole } from '@aab/contracts';
import {
  addOperationJob,
  markRunning,
  resetClock,
  setConnectionStatus,
} from '../../../packages/database/test/capability-fixtures.js';
import type { CapabilityFixture } from '../../../packages/database/test/capability-fixtures.js';
import {
  openTestDb,
  seedConnectionAndAgent,
  seedTenant,
} from '../../../packages/database/test/helpers.js';
import type { Tenant } from '../../../packages/database/test/helpers.js';
import { rowsOf } from '../../../packages/database/src/client.js';
import { createLogger } from '../src/logging.js';
import { startVault } from '../src/vault.js';
import type { RunningVault, StartVaultOptions } from '../src/vault.js';
import { call, LogCapture, makeKekDir, makeSocketDir, removeDir, testConfig } from './helpers.js';

export const SECRET_TYPE = 'session_snapshot';

export { markRunning, resetClock, sql, seedTenant };
export type { CapabilityFixture, Tenant };

/** A database whose every call can be made to fail, to simulate "the database is down". */
export function switchableDatabase(handle: DatabaseHandle): {
  handle: DatabaseHandle;
  setDown(down: boolean): void;
} {
  let down = false;
  const proxy = new Proxy(handle.db, {
    get(target, property) {
      const value: unknown = Reflect.get(target, property, target);
      if (typeof value !== 'function') return value;
      return (...args: unknown[]) => {
        if (down) throw Object.assign(new Error('connection terminated'), { code: 'ECONNRESET' });
        return (value as (...a: unknown[]) => unknown).apply(target, args);
      };
    },
  }) as Db;
  return { handle: { db: proxy, close: handle.close }, setDown: (value) => (down = value) };
}

export interface Service {
  vault: RunningVault;
  db: Db;
  repos: Repositories;
  dbHandle: DatabaseHandle;
  kekDir: string;
  socketDir: string;
  log: LogCapture;
  /** Every response line the helpers received, for the secrets scan. */
  responses: string[];
  setDatabaseDown(down: boolean): void;
  rpc(
    role: VaultRole,
    operation: string,
    params: Record<string, unknown>,
  ): Promise<Record<string, unknown>>;
  stop(): Promise<void>;
  cleanup(): Promise<void>;
}

export interface ServiceOptions {
  /** Reuse a database, a key directory and a socket directory (restart tests). */
  reuse?: Pick<Service, 'dbHandle' | 'kekDir' | 'socketDir'>;
  kekVersions?: number[];
  operations?: StartVaultOptions['operations'];
  /** Per-role limit overrides (timeouts, caps). */
  limits?: StartVaultOptions['limits'];
  /**
   * Use the PostgreSQL server of AAB_TEST_DATABASE_URL (a throwaway database) instead of PGlite:
   * for tests that need real lock waits and real statement timeouts. Callers skip without it.
   */
  postgres?: boolean;
}

/** True when a PostgreSQL server is configured for the PostgreSQL-only tests. */
export const hasPostgres = (): boolean => (process.env['AAB_TEST_DATABASE_URL'] ?? '') !== '';

/** Starts a real vault (the real operations) on temporary sockets, a temporary KEK directory and PGlite. */
export async function startService(options: ServiceOptions = {}): Promise<Service> {
  resetClock();
  const owned = options.reuse === undefined;
  const base =
    options.reuse?.dbHandle ??
    (options.postgres === true ? await openTestDb() : await createTestDatabase());
  const switchable = switchableDatabase(base);
  const socketDir = options.reuse?.socketDir ?? (await makeSocketDir());
  const kekDir = options.reuse?.kekDir ?? (await makeKekDir(options.kekVersions ?? [1]));
  const log = new LogCapture();
  const vault = await startVault(testConfig(socketDir, kekDir), {
    logger: createLogger('debug', log),
    database: switchable.handle,
    ...(options.operations === undefined ? {} : { operations: options.operations }),
    ...(options.limits === undefined ? {} : { limits: options.limits }),
  });
  const responses: string[] = [];
  const service: Service = {
    vault,
    db: base.db,
    repos: createRepositories(base.db),
    dbHandle: base,
    kekDir,
    socketDir,
    log,
    responses,
    setDatabaseDown: switchable.setDown,
    async rpc(role, operation, params) {
      const response = await call(vault.sockets[role], {
        id: `t${responses.length + 1}`,
        operation,
        params,
      });
      responses.push(JSON.stringify(response));
      return response;
    },
    stop: () => vault.stop(),
    async cleanup() {
      await vault.stop().catch(() => undefined);
      if (owned) {
        await removeDir(socketDir);
        await removeDir(join(kekDir, '..'));
        await base.close().catch(() => undefined);
      }
    },
  };
  return service;
}

export async function addKek(kekDir: string, version: number): Promise<void> {
  await generateLocalKek(kekDir, version);
}

export const TOKEN_TTL = 30;
export const AUTH_TTL = 600;

export const CANARY = 'CANARY-COOKIE-VALUE-5f3a9c71-do-not-leak';
export const storageStateJson = (extra = CANARY): string =>
  JSON.stringify({
    cookies: [
      {
        name: 'sid',
        value: extra,
        domain: 'localhost',
        path: '/',
        expires: -1,
        httpOnly: true,
        secure: false,
        sameSite: 'Lax',
      },
    ],
    origins: [],
  });
export const b64url = (text: string): string => Buffer.from(text, 'utf8').toString('base64url');

export interface SealedOperation extends CapabilityFixture {
  plaintext: string;
  ownerUserId: string;
}

/**
 * An active connection holding a really sealed version 1 (under the service's KEK), an agent
 * with an allow grant, and a queued operation job.
 */
export async function seedSealedOperation(
  service: Service,
  tenant: Tenant,
  plaintext = storageStateJson(),
): Promise<SealedOperation> {
  const { connection, agent } = await seedConnectionAndAgent(service.repos, tenant);
  await setConnectionStatus(service.db, connection.id, 'active');
  const ensured = await service.repos.vault.ensureSecret({
    connectionId: connection.id,
    secretType: SECRET_TYPE,
    now: new Date(),
  });
  const grant = await service.repos.grants.create(tenant.scope, agent.id, {
    connectionId: connection.id,
    operation: 'orders.list',
    effect: 'allow',
  });
  const fixture = await addOperationJob(
    service.repos,
    {
      tenant,
      connectionId: connection.id,
      agentId: agent.id,
      secretId: ensured.secretId,
      jobId: '',
      operation: 'orders.list',
      argumentsHash: null,
      purpose: 'read',
      policyEventId: null,
      grantId: grant.id,
    },
    { operation: 'orders.list' },
  );
  await putSealed(
    service,
    tenant,
    fixture.connectionId,
    ensured.secretId,
    ensured.nextVersion,
    plaintext,
  );
  return { ...fixture, plaintext, ownerUserId: tenant.user.id };
}

export async function putSealed(
  service: Service,
  tenant: Tenant,
  connectionId: string,
  secretId: string,
  version: number,
  plaintext: string,
): Promise<void> {
  const sealed = await sealSecret({
    plaintext: Buffer.from(plaintext, 'utf8'),
    aad: {
      organizationId: tenant.organization.id,
      userId: tenant.user.id,
      connectionId,
      secretId,
      secretType: SECRET_TYPE,
      secretVersion: version,
    },
    kek: service.vault.keys.kekProvider,
  });
  await service.repos.vault.putVersion({ secretId, version, sealed, now: new Date() });
}

/** Opens the stored active version directly with the service's keys (a test-side check). */
export async function openStored(
  service: Service,
  tenant: Tenant,
  connectionId: string,
): Promise<string | null> {
  const active = await service.repos.vault.getActive(connectionId, SECRET_TYPE);
  if (active === null) return null;
  const plaintext = await openSecret({
    sealed: active.sealed,
    aad: {
      organizationId: tenant.organization.id,
      userId: tenant.user.id,
      connectionId,
      secretId: active.secretId,
      secretType: SECRET_TYPE,
      secretVersion: active.version,
    },
    kek: service.vault.keys.kekProvider,
  });
  return plaintext.toString('utf8');
}

/** An `authenticating` connection, a pending secret and a queued login job. */
export async function seedLoginJob(service: Service, tenant: Tenant): Promise<CapabilityFixture> {
  const { connection, agent } = await seedConnectionAndAgent(service.repos, tenant);
  await setConnectionStatus(service.db, connection.id, 'authenticating');
  const ensured = await service.repos.vault.ensureSecret({
    connectionId: connection.id,
    secretType: SECRET_TYPE,
    now: new Date(),
  });
  const job = await service.repos.jobs.createLogin({
    organizationId: tenant.organization.id,
    requestedByUserId: tenant.user.id,
    connectionId: connection.id,
    timeoutMs: 600_000,
  });
  return {
    tenant,
    connectionId: connection.id,
    agentId: agent.id,
    secretId: ensured.secretId,
    jobId: job.id,
    operation: null,
    argumentsHash: null,
    purpose: 'seal',
    policyEventId: null,
    grantId: null,
  };
}

export function ok(response: Record<string, unknown>): Record<string, unknown> {
  if (response['ok'] !== true) throw new Error(`expected ok, got ${JSON.stringify(response)}`);
  return response['result'] as Record<string, unknown>;
}

export function errorCode(response: Record<string, unknown>): string {
  if (response['ok'] !== false) throw new Error('expected an error response');
  return (response['error'] as { code: string }).code;
}

export interface Prepared {
  fixture: CapabilityFixture;
  capabilityId: string;
  token: string;
  tokenExpiresAt: string;
  secretVersion: number;
  workerId: string;
}

/** authorize (api) -> job running under a worker -> issue (supervisor). */
export async function prepare(
  service: Service,
  fixture: CapabilityFixture,
  options: { workerId?: string; attempt?: number; tokenTtl?: number } = {},
): Promise<Prepared> {
  const authorized = ok(
    await service.rpc('api', 'authorizeJobAccess', { jobId: fixture.jobId, ttlSeconds: AUTH_TTL }),
  );
  const workerId = options.workerId ?? 'worker-1';
  await markRunning(service.db, fixture.jobId, workerId, options.attempt ?? 1);
  const issueResponse = await service.rpc('supervisor', 'issueAccessCapability', {
    capabilityId: authorized['capabilityId'],
    jobId: fixture.jobId,
    workerId,
    attempt: options.attempt ?? 1,
    ttlSeconds: options.tokenTtl ?? TOKEN_TTL,
  });
  const issued = ok(issueResponse);
  return {
    fixture,
    capabilityId: authorized['capabilityId'] as string,
    token: issued['token'] as string,
    tokenExpiresAt: issued['tokenExpiresAt'] as string,
    secretVersion: issued['secretVersion'] as number,
    workerId,
  };
}

export function readParams(prepared: Prepared, overrides: Record<string, unknown> = {}) {
  return {
    token: prepared.token,
    jobId: prepared.fixture.jobId,
    connectionId: prepared.fixture.connectionId,
    operation: prepared.fixture.operation,
    ...overrides,
  };
}

export function completeParams(
  prepared: Prepared,
  plaintext: string,
  overrides: Record<string, unknown> = {},
) {
  return {
    token: prepared.token,
    jobId: prepared.fixture.jobId,
    connectionId: prepared.fixture.connectionId,
    plaintext: b64url(plaintext),
    externalAccountHint: 'synthetic-account',
    sessionExpiresAt: null,
    ...overrides,
  };
}

export async function auditEvents(
  service: Service,
  organizationId: string,
  type?: string,
): Promise<Array<Record<string, unknown>>> {
  const rows = rowsOf(
    await service.db.execute(
      sql`select event_type, decision, metadata, actor_type, actor_id, connection_id from audit_events where organization_id = ${organizationId}::uuid order by sequence`,
    ),
  );
  return type === undefined ? rows : rows.filter((row) => row['event_type'] === type);
}

export async function capabilityRowOf(service: Service, capabilityId: string) {
  return rowsOf(
    await service.db.execute(
      sql`select * from vault_access_capabilities where id = ${capabilityId}::uuid`,
    ),
  )[0]!;
}

export async function execSql(service: Service, text: ReturnType<typeof sql>): Promise<void> {
  await service.db.execute(text);
}

/** Every row of every table as text, for the "nothing leaked" scans. */
export async function dumpAllTables(service: Service): Promise<Map<string, string[]>> {
  const tables = rowsOf(
    await service.db.execute(sql`select tablename from pg_tables where schemaname = 'public'`),
  ).map((row) => String(row['tablename']));
  const dump = new Map<string, string[]>();
  for (const table of tables) {
    const rows = rowsOf(
      await service.db.execute(sql.raw(`select row_to_json(t)::text as j from "${table}" as t`)),
    );
    dump.set(
      table,
      rows.map((row) => String(row['j'])),
    );
  }
  return dump;
}

export const randomCanaryToken = (): string => randomBytes(32).toString('base64url');
export const newUuid = (): string => randomUUID();

export async function rejectedReasons(service: Service, organizationId: string): Promise<string[]> {
  return (await auditEvents(service, organizationId, 'vault.capability_rejected')).map(
    (event) => (event['metadata'] as { reason: string }).reason,
  );
}

/** The exact shape of every refused capability: a code and nothing else. */
export function isPlainForbidden(response: Record<string, unknown>): boolean {
  const keys = Object.keys(response).sort().join(',');
  const error = response['error'] as Record<string, unknown> | undefined;
  return (
    keys === 'error,id,ok' &&
    response['ok'] === false &&
    error !== undefined &&
    Object.keys(error).join(',') === 'code' &&
    error['code'] === 'forbidden'
  );
}

export const sleep = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));
