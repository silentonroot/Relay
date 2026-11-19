import { afterAll, describe, expect, it } from 'vitest';
import { rowsOf } from '../../../packages/database/src/client.js';
import {
  auditEvents,
  capabilityRowOf,
  errorCode,
  execSql,
  hasPostgres,
  markRunning,
  ok,
  prepare,
  readParams,
  seedLoginJob,
  seedSealedOperation,
  seedTenant,
  sleep,
  sql,
  startService,
  completeParams,
  storageStateJson,
  addKek,
} from './service-helpers.js';
import type { Service } from './service-helpers.js';

/*
 * B2 review fix 3: a request that is answered as failed because of time has rolled back.
 * Every vault transaction runs under SET LOCAL statement_timeout and lock_timeout below the
 * role's request timeout, so PostgreSQL ends the work first and the answer comes from the handler.
 *
 * PGlite cannot enforce a timeout (one connection, no signals): the first block proves the limits
 * are SET in every transaction by recording them from a trigger. The second block, PostgreSQL
 * only (AAB_TEST_DATABASE_URL), proves their effect with a real lock wait.
 */

const cleanups: Array<() => Promise<void>> = [];
afterAll(async () => {
  for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
});

describe('every vault transaction carries the role limits (PGlite and PostgreSQL)', () => {
  it('sets statement_timeout 80% and lock_timeout 50% of the role request timeout', async () => {
    const service = await startService();
    cleanups.push(() => service.cleanup());
    // Records the limits in force whenever an audit event is appended.
    await execSql(
      service,
      sql`create table tmo_probe (event_type text, statement_timeout text, lock_timeout text)`,
    );
    await execSql(
      service,
      sql`create function tmo_probe_fn() returns trigger language plpgsql as $$
          begin
            insert into tmo_probe values (new.event_type, current_setting('statement_timeout'), current_setting('lock_timeout'));
            return new;
          end $$`,
    );
    await execSql(
      service,
      sql`create trigger tmo_probe_t before insert on audit_events for each row execute function tmo_probe_fn()`,
    );

    // api: authorizeJobAccess appends vault.capability_authorized inside its transaction.
    const tenant = await seedTenant(service.repos, 'tmo');
    const op = await seedSealedOperation(service, tenant);
    await execSql(service, sql`truncate tmo_probe`);
    ok(await service.rpc('api', 'authorizeJobAccess', { jobId: op.jobId, ttlSeconds: 600 }));
    const probed = async (eventType: string) =>
      rowsOf(
        await service.db.execute(
          sql`select statement_timeout, lock_timeout from tmo_probe where event_type = ${eventType}`,
        ),
      );
    expect(await probed('vault.capability_authorized')).toEqual([
      { statement_timeout: '8s', lock_timeout: '5s' },
    ]);

    // supervisor: the same request timeout as the api by default.
    const second = await seedSealedOperation(service, await seedTenant(service.repos, 'tmo2'));
    const prepared = await prepare(service, second);
    ok(await service.rpc('supervisor', 'readForWorker', readParams(prepared)));
    expect(await probed('vault.capability_issued')).toEqual([
      { statement_timeout: '8s', lock_timeout: '5s' },
    ]);
    expect(await probed('vault.secret_read')).toEqual([
      { statement_timeout: '8s', lock_timeout: '5s' },
    ]);
  });

  it('gives the admin role its own, longer limits (rewrap row transactions)', async () => {
    const first = await startService();
    cleanups.push(() => first.cleanup());
    const op = await seedSealedOperation(first, await seedTenant(first.repos, 'tmo-admin'));
    void op;
    await first.stop();
    await addKek(first.kekDir, 2);
    const second = await startService({ reuse: first });
    cleanups.push(() => second.cleanup());
    await execSql(
      second,
      sql`create table tmo_probe (event_type text, statement_timeout text, lock_timeout text)`,
    );
    await execSql(
      second,
      sql`create function tmo_probe_fn() returns trigger language plpgsql as $$
          begin
            insert into tmo_probe values (new.event_type, current_setting('statement_timeout'), current_setting('lock_timeout'));
            return new;
          end $$`,
    );
    await execSql(
      second,
      sql`create trigger tmo_probe_t before insert on audit_events for each row execute function tmo_probe_fn()`,
    );
    expect(ok(await second.rpc('admin', 'rewrap', { batchSize: 10, maxBatches: 1 }))).toMatchObject(
      { rewrapped: 1 },
    );
    // Default admin timeout 120 s: 96 s and 60 s.
    expect(
      rowsOf(
        await second.db.execute(
          sql`select statement_timeout, lock_timeout from tmo_probe where event_type = 'vault.secret_rewrapped'`,
        ),
      ),
    ).toEqual([{ statement_timeout: '96s', lock_timeout: '1min' }]);
  });
});

/** Holds a row lock in another transaction until released. */
async function holdLock(service: Service, text: ReturnType<typeof sql>) {
  let release!: () => void;
  const released = new Promise<void>((resolve) => {
    release = resolve;
  });
  let locked!: () => void;
  const hasLock = new Promise<void>((resolve) => {
    locked = resolve;
  });
  const done = service.db.transaction(async (tx) => {
    await tx.execute(text);
    locked();
    await released;
  });
  await hasLock;
  return {
    async release() {
      release();
      await done;
    },
  };
}

describe.skipIf(!hasPostgres())(
  'a request answered as timed out has rolled back (PostgreSQL only)',
  () => {
    // 2 s request timeout: lock_timeout 1 s, statement_timeout 1.6 s.
    const limits = { supervisor: { requestTimeoutMs: 2_000 } };

    it('a consume blocked on a held connection lock ends service_unavailable and consumes nothing', async () => {
      const service = await startService({ postgres: true, limits });
      cleanups.push(() => service.cleanup());
      const tenant = await seedTenant(service.repos, 'tmo-read');
      const op = await seedSealedOperation(service, tenant);
      const prepared = await prepare(service, op);

      const held = await holdLock(
        service,
        sql`select id from connections where id = ${op.connectionId}::uuid for update`,
      );
      const started = Date.now();
      const response = await service.rpc('supervisor', 'readForWorker', readParams(prepared));
      const took = Date.now() - started;
      expect(errorCode(response)).toBe('service_unavailable');
      // The database ended it (lock_timeout 1 s), before the 2 s request timer.
      expect(took).toBeLessThan(1_900);
      // Release the lock: nothing may still be waiting to commit the consume.
      await held.release();
      await sleep(500);
      expect((await capabilityRowOf(service, prepared.capabilityId))['used_at']).toBeNull();
      expect(await auditEvents(service, tenant.organization.id, 'vault.secret_read')).toHaveLength(
        0,
      );
      // And the capability still redeems.
      ok(await service.rpc('supervisor', 'readForWorker', readParams(prepared)));
      expect(await auditEvents(service, tenant.organization.id, 'vault.secret_read')).toHaveLength(
        1,
      );
    }, 30_000);

    it('an issue blocked on a held capability row ends service_unavailable and sets no token', async () => {
      const service = await startService({ postgres: true, limits });
      cleanups.push(() => service.cleanup());
      const tenant = await seedTenant(service.repos, 'tmo-issue');
      const op = await seedSealedOperation(service, tenant);
      const authorized = ok(
        await service.rpc('api', 'authorizeJobAccess', { jobId: op.jobId, ttlSeconds: 600 }),
      );
      const capabilityId = authorized['capabilityId'] as string;
      await markRunning(service.db, op.jobId, 'worker-1', 1);
      const issueParams = {
        capabilityId,
        jobId: op.jobId,
        workerId: 'worker-1',
        attempt: 1,
        ttlSeconds: 30,
      };
      const held = await holdLock(
        service,
        sql`select id from vault_access_capabilities where id = ${capabilityId}::uuid for update`,
      );
      const response = await service.rpc('supervisor', 'issueAccessCapability', issueParams);
      expect(errorCode(response)).toBe('service_unavailable');
      await held.release();
      await sleep(500);
      expect((await capabilityRowOf(service, capabilityId))['token_hash']).toBeNull();
      expect(await auditEvents(service, tenant.organization.id, 'vault.capability_issued')).toEqual(
        [],
      );
      // Issuing works once the lock is gone.
      ok(await service.rpc('supervisor', 'issueAccessCapability', issueParams));
    }, 30_000);

    it('a login completion blocked on a held lock stores nothing', async () => {
      const service = await startService({ postgres: true, limits });
      cleanups.push(() => service.cleanup());
      const tenant = await seedTenant(service.repos, 'tmo-login');
      const login = await seedLoginJob(service, tenant);
      const prepared = await prepare(service, login);
      const held = await holdLock(
        service,
        sql`select id from connections where id = ${login.connectionId}::uuid for update`,
      );
      const response = await service.rpc(
        'supervisor',
        'completeLogin',
        completeParams(prepared, storageStateJson()),
      );
      expect(errorCode(response)).toBe('service_unavailable');
      await held.release();
      await sleep(500);
      expect(
        rowsOf(
          await service.db.execute(
            sql`select count(*)::int as n from vault_secret_versions where secret_id = ${login.secretId}::uuid`,
          ),
        )[0],
      ).toEqual({ n: 0 });
      expect((await capabilityRowOf(service, prepared.capabilityId))['used_at']).toBeNull();
    }, 30_000);
  },
);
