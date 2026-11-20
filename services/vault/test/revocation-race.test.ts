import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { AuditEventType } from '@aab/contracts';
import type { JsonObject } from '@aab/contracts';
import { createRepositories } from '@aab/database';
import type { Repositories } from '@aab/database';
import { ConflictError } from '@aab/database';
import { rowsOf } from '../../../packages/database/src/client.js';
import {
  addKek,
  auditEvents,
  capabilityRowOf,
  completeParams,
  execSql,
  hasPostgres,
  isPlainForbidden,
  ok,
  openStored,
  prepare,
  putSealed,
  readParams,
  seedLoginJob,
  seedSealedOperation,
  seedTenant,
  sleep,
  sql,
  startService,
  storageStateJson,
} from './service-helpers.js';
import type { CapabilityFixture, Service, Tenant } from './service-helpers.js';

/*
 * P3-8 and P3-9 through the vault, on two real connections (PostgreSQL only: PGlite has one
 * connection, so its transactions cannot interleave). Revocation is a copy of the transaction of the
 * connection-revoke route (`services/broker-api/src/routes/resources.ts`): connection revoked, jobs
 * cancelled, versions deleted and the `connection.revoked`, `vault.secret_revoked` and
 * `vault.secret_deleted` events appended, all on one connection. It is a copy, not that code,
 * because this step may not touch `services/broker-api/src` (so the route's transaction could not
 * be extracted into a function both import); the last test of this file reads the route's source and
 * fails when the calls the copy makes are no longer made there in this order.
 *
 * Interleaving is controlled, not timed: a test holds the revocation transaction open, or holds
 * an advisory lock that a trigger makes the vault's own transaction wait for just before its
 * audit event (the last statement of read, login completion and rewrap), and reads pg_locks to
 * know the vault has reached that point.
 */

const GATE_KEY = 7001;
const cleanups: Array<() => Promise<void>> = [];
afterAll(async () => {
  for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
});

function gate() {
  let release!: () => void;
  const opened = new Promise<void>((resolve) => {
    release = resolve;
  });
  return { opened, release };
}

/** True while `promise` is still pending after `ms`. */
async function stillPending(promise: Promise<unknown>, ms = 500): Promise<boolean> {
  let settled = false;
  void promise.then(
    () => (settled = true),
    () => (settled = true),
  );
  await sleep(ms);
  return !settled;
}

async function withRace() {
  const service = await startService({ postgres: true, kekVersions: [1] });
  cleanups.push(() => service.cleanup());
  await installGate(service);
  return service;
}

/** Makes a vault transaction wait on an advisory lock right before it appends these events. */
async function installGate(service: Service): Promise<void> {
  await execSql(
    service,
    sql.raw(`create function aab_race_gate() returns trigger language plpgsql as $$
      begin perform pg_advisory_xact_lock(${GATE_KEY}); return new; end $$`),
  );
  await execSql(
    service,
    sql.raw(`create trigger aab_race_gate before insert on audit_events for each row
      when (new.event_type in ('vault.secret_read', 'vault.secret_stored', 'vault.secret_rewrapped'))
      execute function aab_race_gate()`),
  );
}

/** Holds the advisory lock until `release()`; vault transactions that reach the gate wait. */
async function holdGate(service: Service) {
  const held = gate();
  const release = gate();
  const done = service.db.transaction(async (tx) => {
    await tx.execute(sql.raw(`select pg_advisory_xact_lock(${GATE_KEY})`));
    held.release();
    await release.opened;
  });
  await Promise.race([held.opened, done]);
  return {
    release: async () => {
      release.release();
      await done;
    },
  };
}

/** Waits until some transaction is blocked on the gate, i.e. the vault operation is in flight. */
async function waitUntilVaultIsAtGate(service: Service): Promise<void> {
  for (let i = 0; i < 200; i += 1) {
    const waiting = rowsOf(
      await service.db.execute(
        sql`select count(*)::int as n from pg_locks where locktype = 'advisory' and not granted`,
      ),
    )[0]!;
    if (Number(waiting['n']) > 0) return;
    await sleep(25);
  }
  throw new Error('the vault operation never reached the gate');
}

async function revokeIn(repos: Repositories, tenant: Tenant, connectionId: string): Promise<void> {
  const now = new Date();
  const revoked = await repos.connections.revoke(tenant.scope, connectionId, {});
  const cancelled = await repos.jobs.cancelForConnection(revoked.id, now);
  const secretsBefore = await repos.vault.describeForConnection(revoked.id);
  const versionsDeleted = await repos.vault.deleteForConnection(revoked.id, now);
  const audit = (eventType: string, metadata: Record<string, unknown>) =>
    repos.audit.append({
      organizationId: tenant.organization.id,
      actorType: 'user',
      actorId: tenant.user.id,
      connectionId: revoked.id,
      eventType: AuditEventType.parse(eventType),
      decision: 'not_applicable',
      metadata: metadata as JsonObject,
      timestamp: now,
    });
  await audit('connection.revoked', {
    connectionId: revoked.id,
    displayName: revoked.displayName,
    hasReason: revoked.statusReason !== null,
    jobsCancelled: cancelled.length,
  });
  if (secretsBefore.length > 0) {
    await audit('vault.secret_revoked', {
      connectionId: revoked.id,
      vaultEntryIds: secretsBefore.map((secret) => secret.id),
      versionsDeleted,
    });
  }
  if (versionsDeleted > 0) {
    await audit('vault.secret_deleted', {
      connectionId: revoked.id,
      vaultEntryIds: secretsBefore
        .filter((secret) => secret.activeVersion !== null)
        .map((secret) => secret.id),
      versionsDeleted,
    });
  }
}

/** A revocation transaction that has made its changes and waits, uncommitted, for `commit()`. */
async function holdRevocation(service: Service, tenant: Tenant, connectionId: string) {
  const locked = gate();
  const commit = gate();
  const done = service.db.transaction(async (tx) => {
    await revokeIn(createRepositories(tx), tenant, connectionId);
    locked.release();
    await commit.opened;
  });
  await Promise.race([locked.opened, done]);
  return {
    commit: async () => {
      commit.release();
      await done;
    },
  };
}

/** The revocation as one transaction that waits for locks like any other writer. */
function revokeNow(service: Service, tenant: Tenant, connectionId: string): Promise<void> {
  return service.db.transaction((tx) => revokeIn(createRepositories(tx), tenant, connectionId));
}

async function versions(service: Service, secretId: string) {
  return rowsOf(
    await service.db.execute(
      sql`select version, kek_version from vault_secret_versions where secret_id = ${secretId}::uuid order by version`,
    ),
  ).map((row) => ({ version: Number(row['version']), kek: Number(row['kek_version']) }));
}

async function secretStatus(service: Service, secretId: string): Promise<string> {
  return String(
    rowsOf(
      await service.db.execute(sql`select status from vault_secrets where id = ${secretId}::uuid`),
    )[0]!['status'],
  );
}

/** Sealed sessions under KEK v1, the service restarted with v1 and v2 (v2 is current). */
async function rotated<T>(seed: (first: Service) => Promise<T>) {
  const first = await startService({ postgres: true, kekVersions: [1] });
  cleanups.push(() => first.cleanup());
  const seeded = await seed(first);
  await first.stop();
  await addKek(first.kekDir, 2);
  const second = await startService({ reuse: first, postgres: true });
  cleanups.push(() => second.cleanup());
  await installGate(second);
  return { first, second, seeded };
}

const REWRAP = { batchSize: 10, maxBatches: 5 };

describe.runIf(hasPostgres())('P3-8: a revocation that commits first (PostgreSQL)', () => {
  it('makes a concurrent readForWorker change nothing', async () => {
    const service = await withRace();
    const tenant = await seedTenant(service.repos, 'race-read-1');
    const op = await seedSealedOperation(service, tenant);
    const prepared = await prepare(service, op);

    const revocation = await holdRevocation(service, tenant, op.connectionId);
    const read = service.rpc('supervisor', 'readForWorker', readParams(prepared));
    expect(await stillPending(read)).toBe(true); // the consume waits for the connection row, locked by the revocation
    await revocation.commit();

    expect(isPlainForbidden(await read)).toBe(true);
    expect((await capabilityRowOf(service, prepared.capabilityId))['used_at']).toBeNull();
    expect(await auditEvents(service, tenant.organization.id, 'vault.secret_read')).toHaveLength(0);
    expect(await versions(service, op.secretId)).toEqual([]);
    expect(await secretStatus(service, op.secretId)).toBe('revoked');
  });

  it('makes a concurrent completeLogin change nothing', async () => {
    const service = await withRace();
    const tenant = await seedTenant(service.repos, 'race-login-1');
    const login = await seedLoginJob(service, tenant);
    const prepared = await prepare(service, login);

    const revocation = await holdRevocation(service, tenant, login.connectionId);
    const completion = service.rpc(
      'supervisor',
      'completeLogin',
      completeParams(prepared, storageStateJson('raced')),
    );
    expect(await stillPending(completion)).toBe(true);
    await revocation.commit();

    expect(isPlainForbidden(await completion)).toBe(true);
    expect((await capabilityRowOf(service, prepared.capabilityId))['used_at']).toBeNull();
    expect(await versions(service, login.secretId)).toEqual([]);
    expect(await secretStatus(service, login.secretId)).toBe('revoked');
    expect(await auditEvents(service, tenant.organization.id, 'vault.secret_stored')).toHaveLength(
      0,
    );
  });

  it('makes a concurrent rewrap skip the row and change nothing', async () => {
    const { second, seeded } = await rotated(async (first) => {
      const tenant = await seedTenant(first.repos, 'race-rewrap-1');
      return { tenant, op: await seedSealedOperation(first, tenant) };
    });
    const { tenant, op } = seeded;

    const revocation = await holdRevocation(second, tenant, op.connectionId);
    const rewrap = second.rpc('admin', 'rewrap', REWRAP);
    expect(await stillPending(rewrap)).toBe(true);
    await revocation.commit();

    expect(ok(await rewrap)).toMatchObject({ rewrapped: 0, skipped: 1, failed: 0, remaining: 0 });
    expect(await versions(second, op.secretId)).toEqual([]);
    expect(
      await auditEvents(second, tenant.organization.id, 'vault.secret_rewrapped'),
    ).toHaveLength(0);
    expect(await secretStatus(second, op.secretId)).toBe('revoked');
  });
});

describe.runIf(hasPostgres())('P3-8: a revocation that commits second (PostgreSQL)', () => {
  it('removes what a readForWorker in flight delivered', async () => {
    const service = await withRace();
    const tenant = await seedTenant(service.repos, 'race-read-2');
    const op = await seedSealedOperation(service, tenant);
    const prepared = await prepare(service, op);

    const hold = await holdGate(service);
    const read = service.rpc('supervisor', 'readForWorker', readParams(prepared));
    await waitUntilVaultIsAtGate(service);
    const revocation = revokeNow(service, tenant, op.connectionId);
    // The revocation's update of the connection row waits for the read's FOR SHARE lock on it.
    expect(await stillPending(revocation)).toBe(true);
    await hold.release();

    expect(ok(await read)).toMatchObject({ secretVersion: 1 });
    await revocation;
    expect((await capabilityRowOf(service, prepared.capabilityId))['used_at']).not.toBeNull();
    expect(await versions(service, op.secretId)).toEqual([]);
    expect(await secretStatus(service, op.secretId)).toBe('revoked');
  });

  it('removes what a completeLogin in flight stored', async () => {
    const service = await withRace();
    const tenant = await seedTenant(service.repos, 'race-login-2');
    const login = await seedLoginJob(service, tenant);
    const prepared = await prepare(service, login);

    const hold = await holdGate(service);
    const completion = service.rpc(
      'supervisor',
      'completeLogin',
      completeParams(prepared, storageStateJson('stored')),
    );
    await waitUntilVaultIsAtGate(service);
    const revocation = revokeNow(service, tenant, login.connectionId);
    // consumeSeal holds the connection row FOR UPDATE; the revocation's update waits for it.
    expect(await stillPending(revocation)).toBe(true);
    await hold.release();

    expect(ok(await completion)).toMatchObject({ secretVersion: 1 });
    await revocation;
    expect(await versions(service, login.secretId)).toEqual([]);
    expect(await secretStatus(service, login.secretId)).toBe('revoked');
    expect(await openStored(service, tenant, login.connectionId)).toBeNull();
  });

  it('removes what a rewrap in flight wrote', async () => {
    const { second, seeded } = await rotated(async (first) => {
      const tenant = await seedTenant(first.repos, 'race-rewrap-2');
      return { tenant, op: await seedSealedOperation(first, tenant) };
    });
    const { tenant, op } = seeded;

    const hold = await holdGate(second);
    const rewrap = second.rpc('admin', 'rewrap', REWRAP);
    await waitUntilVaultIsAtGate(second);
    const revocation = revokeNow(second, tenant, op.connectionId);
    // rewrapVersion holds the connection row FOR SHARE; the revocation's update waits for it.
    expect(await stillPending(revocation)).toBe(true);
    await hold.release();

    expect(ok(await rewrap)).toMatchObject({ rewrapped: 1, skipped: 0, failed: 0 });
    await revocation;
    expect(await versions(second, op.secretId)).toEqual([]);
    expect(await secretStatus(second, op.secretId)).toBe('revoked');
  });
});

describe.runIf(hasPostgres())(
  'P3-9: a rewrap racing a completeLogin that replaces the same version (PostgreSQL)',
  () => {
    /** Version 1 sealed under KEK v1 by a first login; a second login is ready to replace it. */
    async function replacementSetup(label: string) {
      return rotated(async (first) => {
        const tenant = await seedTenant(first.repos, label);
        const login = await seedLoginJob(first, tenant);
        const p1 = await prepare(first, login);
        ok(
          await first.rpc(
            'supervisor',
            'completeLogin',
            completeParams(p1, storageStateJson('one')),
          ),
        );
        return { tenant, login };
      }).then(async (world) => {
        const { second, seeded } = world;
        const { tenant, login } = seeded;
        await execSql(
          second,
          sql`update connections set status = 'authenticating' where id = ${login.connectionId}::uuid`,
        );
        const job = await second.repos.jobs.createLogin({
          organizationId: tenant.organization.id,
          requestedByUserId: tenant.user.id,
          connectionId: login.connectionId,
          timeoutMs: 600_000,
        });
        const replacement: CapabilityFixture = { ...login, jobId: job.id };
        const prepared = await prepare(second, replacement, { workerId: 'worker-2' });
        expect(prepared.secretVersion).toBe(1);
        return { second, tenant, login, prepared };
      });
    }

    it('the replacement commits first: the replaced version is skipped and the new one reads', async () => {
      const { second, tenant, login, prepared } = await replacementSetup('race-replace-1');
      const hold = await holdGate(second);
      const completion = second.rpc(
        'supervisor',
        'completeLogin',
        completeParams(prepared, storageStateJson('two')),
      );
      await waitUntilVaultIsAtGate(second); // version 2 inserted, version 1 deleted, uncommitted
      const rewrap = second.rpc('admin', 'rewrap', REWRAP);
      expect(await stillPending(rewrap)).toBe(true); // it listed version 1 and waits for its row
      await hold.release();

      expect(ok(await completion)).toMatchObject({ secretVersion: 2, kekVersion: 2 });
      expect(ok(await rewrap)).toMatchObject({ rewrapped: 0, skipped: 1, failed: 0, remaining: 0 });
      expect(await versions(second, login.secretId)).toEqual([{ version: 2, kek: 2 }]);
      expect(await openStored(second, tenant, login.connectionId)).toBe(storageStateJson('two'));
      expect(
        await auditEvents(second, tenant.organization.id, 'vault.secret_rewrapped'),
      ).toHaveLength(0);
    });

    it('the rewrap commits first: the replacement then removes the rewrapped version, and the new one reads', async () => {
      const { second, tenant, login, prepared } = await replacementSetup('race-replace-2');
      const hold = await holdGate(second);
      const rewrap = second.rpc('admin', 'rewrap', REWRAP);
      await waitUntilVaultIsAtGate(second); // version 1 rewrapped, uncommitted
      const completion = second.rpc(
        'supervisor',
        'completeLogin',
        completeParams(prepared, storageStateJson('two')),
      );
      expect(await stillPending(completion)).toBe(true); // it waits for version 1's row
      await hold.release();

      expect(ok(await rewrap)).toMatchObject({ rewrapped: 1, skipped: 0, failed: 0 });
      expect(ok(await completion)).toMatchObject({ secretVersion: 2 });
      expect(await versions(second, login.secretId)).toEqual([{ version: 2, kek: 2 }]);
      expect(await openStored(second, tenant, login.connectionId)).toBe(storageStateJson('two'));
      expect(
        await auditEvents(second, tenant.organization.id, 'vault.secret_rewrapped'),
      ).toHaveLength(1);
    });
  },
);

describe.runIf(hasPostgres())(
  'P3-8: a revoked secret never becomes active again (PostgreSQL)',
  () => {
    it('refuses every way back: a write, a new login, a read, a rewrap and the status itself', async () => {
      const { second, seeded } = await rotated(async (first) => {
        const tenant = await seedTenant(first.repos, 'race-never');
        const op = await seedSealedOperation(first, tenant);
        return { tenant, op };
      });
      const { tenant, op } = seeded;
      const prepared = await prepare(second, op); // authorized and issued before the revocation
      const lateLogin = await seedLoginJob(second, tenant); // a second connection of the tenant, untouched
      await revokeNow(second, tenant, op.connectionId);

      // The secret row is terminal: a trigger refuses any move out of `revoked`.
      for (const status of ['active', 'pending']) {
        await expect(
          execSql(
            second,
            sql.raw(`update vault_secrets set status = '${status}' where id = '${op.secretId}'`),
          ),
        ).rejects.toThrow();
      }
      // A write, an `ensureSecret`, a read with the old token, and a rewrap all change nothing.
      await expect(
        putSealed(second, tenant, op.connectionId, op.secretId, 9, 'resurrect'),
      ).rejects.toBeInstanceOf(ConflictError);
      await expect(
        second.repos.vault.ensureSecret({
          connectionId: op.connectionId,
          secretType: 'session_snapshot',
          now: new Date(),
        }),
      ).rejects.toBeInstanceOf(ConflictError);
      expect(
        isPlainForbidden(await second.rpc('supervisor', 'readForWorker', readParams(prepared))),
      ).toBe(true);
      expect(ok(await second.rpc('admin', 'rewrap', REWRAP))).toMatchObject({
        rewrapped: 0,
        remaining: 0,
      });
      // A new authorization for the revoked connection's job is refused too.
      const again = await second.rpc('api', 'authorizeJobAccess', {
        jobId: op.jobId,
        ttlSeconds: 600,
      });
      expect(again['ok']).toBe(false);

      expect(await versions(second, op.secretId)).toEqual([]);
      expect(await secretStatus(second, op.secretId)).toBe('revoked');
      // Another connection of the same tenant is unaffected.
      expect(await secretStatus(second, lateLogin.secretId)).toBe('pending');
    });
  },
);

describe('the revocation copy follows the route', () => {
  it('the connection-revoke route makes the same calls in the same order', async () => {
    const route = readFileSync(
      join(import.meta.dirname, '..', '..', 'broker-api', 'src', 'routes', 'resources.ts'),
      'utf8',
    );
    const calls = [
      'tx.connections.revoke(',
      'tx.jobs.cancelForConnection(',
      'tx.vault.describeForConnection(',
      'tx.vault.deleteForConnection(',
      "eventType: 'connection.revoked'",
      "eventType: 'vault.secret_revoked'",
      "eventType: 'vault.secret_deleted'",
    ];
    const positions = calls.map((call) => route.indexOf(call));
    expect(positions.every((position) => position !== -1)).toBe(true);
    expect([...positions].sort((a, b) => a - b)).toEqual(positions);
  });
});
