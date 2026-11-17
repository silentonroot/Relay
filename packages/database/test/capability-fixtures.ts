import { createHash, randomBytes, randomUUID } from 'node:crypto';
import type { JsonObject } from '@aab/contracts';
import { sql } from 'drizzle-orm';
import { rowsOf } from '../src/client.js';
import type { CapabilityRecord, Db, Repositories } from '../src/index.js';
import { fakeSealed, jobArgumentsHash, seedConnectionAndAgent } from './helpers.js';
import type { Tenant } from './helpers.js';

/*
 * Fixtures for the capability tests. The MACs are fixed hex strings: computing them is the
 * vault's job (step B2), and this package only stores and compares them.
 */

/*
 * The capability statements compare the caller's clock with the database's: an authorization or
 * a token is refused when `now` is more than five seconds away from `statement_timestamp()`, and
 * a consume refuses an expired capability whatever `now` says. So the tests' clock starts at the
 * real time. `T0` is a live binding that every test file resets in `beforeEach` (`resetClock`),
 * so a slow suite never drifts past the skew limit; inside one test the offsets from `at()` stay
 * a few seconds.
 */
const wallClock = (): Date => new Date(Math.floor(Date.now() / 10) * 10);
export let T0: Date = wallClock();
export function resetClock(): void {
  T0 = wallClock();
}
export const at = (ms: number): Date => new Date(T0.getTime() + ms);

export const AUTH_MAC = 'a'.repeat(64);
export const TOKEN_MAC = 'b'.repeat(64);
export const SECRET_TYPE = 'browser_session';
export const AUTHORIZATION_TTL = 600;
export const TOKEN_TTL = 30;

export const sha256Hex = (value: string): string =>
  createHash('sha256').update(value, 'utf8').digest('hex');

export function newToken(): { token: string; hash: string } {
  const token = randomBytes(32).toString('base64url');
  return { token, hash: sha256Hex(token) };
}

export interface CapabilityFixture {
  tenant: Tenant;
  connectionId: string;
  agentId: string;
  secretId: string;
  jobId: string;
  operation: string | null;
  argumentsHash: string | null;
  purpose: 'read' | 'seal';
  policyEventId: string | null;
  /** The allow grant the policy decision matched (operation jobs only). */
  grantId: string | null;
}

export interface Authorized extends CapabilityFixture {
  capabilityId: string;
}

export interface Issued extends Authorized {
  token: string;
  tokenHash: string;
  workerId: string;
  record: CapabilityRecord;
}

export async function setConnectionStatus(db: Db, connectionId: string, status: string) {
  await db.execute(sql`update connections set status = ${status} where id = ${connectionId}::uuid`);
}

export async function markRunning(db: Db, jobId: string, workerId = 'worker-1', attempt = 1) {
  await db.execute(
    sql`update execution_jobs set status = 'running', worker_id = ${workerId}, attempt_count = ${attempt}, lease_expires_at = ${at(60_000).toISOString()}::timestamptz where id = ${jobId}::uuid`,
  );
}

/**
 * A policy decision (an allowed `policy.evaluated` event naming `grantId`) and a queued
 * operation job that points at it, for an agent and connection that already exist.
 */
export async function addOperationJob(
  repositories: Repositories,
  base: CapabilityFixture,
  options: { operation?: string; decisionTimestamp?: Date } = {},
): Promise<CapabilityFixture> {
  const operation = options.operation ?? base.operation ?? 'orders.list';
  const policyEvent = await repositories.audit.append({
    organizationId: base.tenant.organization.id,
    actorType: 'system',
    agentId: base.agentId,
    connectionId: base.connectionId,
    eventType: 'policy.evaluated',
    decision: 'allow',
    metadata: { operation, outcome: 'allow', matchedGrantIds: [base.grantId] },
    timestamp: options.decisionTimestamp ?? T0,
  });
  const args = { limit: 5 } as JsonObject;
  const binding = {
    organizationId: base.tenant.organization.id,
    agentId: base.agentId,
    connectionId: base.connectionId,
    operation,
    policyDecisionId: policyEvent.id,
    retrySafe: true,
    timeoutMs: 30_000,
    arguments: args,
  };
  const job = await repositories.jobs.createOperation({
    organizationId: base.tenant.organization.id,
    requestedByUserId: base.tenant.user.id,
    agentId: base.agentId,
    connectionId: base.connectionId,
    runId: null,
    operation,
    arguments: args,
    argumentsHash: jobArgumentsHash(binding),
    retrySafe: true,
    policyDecisionId: policyEvent.id,
    timeoutMs: 30_000,
  });
  return {
    ...base,
    jobId: job.id,
    operation,
    argumentsHash: job.argumentsHash,
    policyEventId: policyEvent.id,
  };
}

/**
 * An `active` connection with a stored version 1, an agent with an allow grant, an allowed
 * `policy.evaluated` event that matched the grant and a queued operation job that points at it.
 */
export async function seedOperation(
  db: Db,
  repositories: Repositories,
  tenant: Tenant,
  options: { operation?: string; withSecret?: boolean } = {},
): Promise<CapabilityFixture> {
  const { connection, agent } = await seedConnectionAndAgent(repositories, tenant);
  await setConnectionStatus(db, connection.id, 'active');
  const operation = options.operation ?? 'orders.list';
  const ensured = await repositories.vault.ensureSecret({
    connectionId: connection.id,
    secretType: SECRET_TYPE,
    now: T0,
  });
  if (options.withSecret !== false) {
    await repositories.vault.putVersion({
      secretId: ensured.secretId,
      version: ensured.nextVersion,
      sealed: fakeSealed('v1'),
      now: T0,
    });
  }
  const grant = await repositories.grants.create(tenant.scope, agent.id, {
    connectionId: connection.id,
    operation,
    effect: 'allow',
  });
  return addOperationJob(
    repositories,
    {
      tenant,
      connectionId: connection.id,
      agentId: agent.id,
      secretId: ensured.secretId,
      jobId: '',
      operation,
      argumentsHash: null,
      purpose: 'read',
      policyEventId: null,
      grantId: grant.id,
    },
    { operation },
  );
}

/** An `authenticating` connection, a pending secret and a queued login job. */
export async function seedLogin(
  db: Db,
  repositories: Repositories,
  tenant: Tenant,
): Promise<CapabilityFixture> {
  const { connection, agent } = await seedConnectionAndAgent(repositories, tenant);
  await setConnectionStatus(db, connection.id, 'authenticating');
  const ensured = await repositories.vault.ensureSecret({
    connectionId: connection.id,
    secretType: SECRET_TYPE,
    now: T0,
  });
  const job = await repositories.jobs.createLogin({
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

export async function authorize(
  repositories: Repositories,
  fixture: CapabilityFixture,
  options: { now?: Date; ttlSeconds?: number; capabilityId?: string } = {},
): Promise<Authorized> {
  const capabilityId = options.capabilityId ?? randomUUID();
  await repositories.capabilities.insertAuthorization({
    capabilityId,
    jobId: fixture.jobId,
    secretId: fixture.secretId,
    purpose: fixture.purpose,
    organizationId: fixture.tenant.organization.id,
    agentId: fixture.purpose === 'read' ? fixture.agentId : null,
    connectionId: fixture.connectionId,
    operation: fixture.operation,
    argumentsHash: fixture.argumentsHash,
    now: options.now ?? T0,
    ttlSeconds: options.ttlSeconds ?? AUTHORIZATION_TTL,
    authorizationMac: AUTH_MAC,
    macKekVersion: 1,
  });
  return { ...fixture, capabilityId };
}

/** Authorizes, runs the job under `workerId` and issues a token. */
export async function issue(
  db: Db,
  repositories: Repositories,
  fixture: CapabilityFixture,
  options: { workerId?: string; attempt?: number; now?: Date; ttlSeconds?: number } = {},
): Promise<Issued> {
  const authorized = await authorize(repositories, fixture);
  const workerId = options.workerId ?? 'worker-1';
  const attempt = options.attempt ?? 1;
  await markRunning(db, fixture.jobId, workerId, attempt);
  const { token, hash } = newToken();
  const record = await repositories.capabilities.issueToken({
    capabilityId: authorized.capabilityId,
    jobId: fixture.jobId,
    workerId,
    attempt,
    tokenHash: hash,
    tokenTtlSeconds: options.ttlSeconds ?? TOKEN_TTL,
    now: options.now ?? at(1000),
    authorizationMac: AUTH_MAC,
    computeTokenMac: () => TOKEN_MAC,
  });
  if (record === null) throw new Error('fixture: the token was not issued');
  return { ...authorized, token, tokenHash: hash, workerId, record };
}

export function consumeInput(issued: Issued, overrides: Record<string, unknown> = {}) {
  return {
    tokenHash: issued.tokenHash,
    jobId: issued.jobId,
    connectionId: issued.connectionId,
    operation: issued.operation,
    now: at(2000),
    ...overrides,
  };
}

/** The whole capability row, to prove a refused statement changed nothing. */
export async function capabilityRow(
  db: Db,
  capabilityId: string,
): Promise<Record<string, unknown>> {
  const rows = rowsOf(
    await db.execute(sql`select * from vault_access_capabilities where id = ${capabilityId}::uuid`),
  );
  return rows[0]!;
}

export async function jobRow(db: Db, jobId: string): Promise<Record<string, unknown>> {
  return rowsOf(await db.execute(sql`select * from execution_jobs where id = ${jobId}::uuid`))[0]!;
}

export async function secretRow(db: Db, secretId: string): Promise<Record<string, unknown>> {
  return rowsOf(
    await db.execute(sql`select * from vault_secrets where id = ${secretId}::uuid`),
  )[0]!;
}

export async function auditTypes(db: Db, organizationId: string): Promise<string[]> {
  return rowsOf(
    await db.execute(
      sql`select event_type from audit_events where organization_id = ${organizationId}::uuid order by sequence`,
    ),
  ).map((row) => String(row.event_type));
}

export const isPostgres = (): boolean => (process.env.AAB_TEST_DATABASE_URL ?? '') !== '';

export const sleep = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));
