import { randomUUID } from 'node:crypto';
import { sql } from 'drizzle-orm';
import { readMigrationFiles } from 'drizzle-orm/migrator';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { rowsOf } from '../src/client.js';
import type { Db } from '../src/client.js';
import { createRepositories, migrate, MIGRATIONS_FOLDER } from '../src/index.js';
import type { DatabaseHandle } from '../src/index.js';
import {
  fakeSealed,
  jobArgumentsHash,
  openEmptyTestDb,
  seedConnectionAndAgent,
  seedTenant,
} from './helpers.js';

/*
 * Migration 0005_phase3_vault (ADR-014 section 11, P3-19) on an empty database and on a
 * database that holds Phase 2 rows: sealed secrets, a revoked connection and jobs.
 */

// Each test builds and migrates its own database; under a loaded machine that takes a while.
vi.setConfig({ testTimeout: 90_000 });

/** 0000 to 0004: the schema as Phase 2 and step B0.5 left it. */
const BEFORE_0005 = 5;

async function migrateFirst(db: Db, count: number): Promise<void> {
  const migrations = readMigrationFiles({ migrationsFolder: MIGRATIONS_FOLDER }).slice(0, count);
  await db.transaction(async (tx) => {
    await tx.execute(sql`create schema if not exists drizzle`);
    await tx.execute(
      sql`create table if not exists drizzle.__drizzle_migrations (id serial primary key, hash text not null, created_at bigint)`,
    );
    for (const migration of migrations) {
      for (const statement of migration.sql) {
        if (statement.trim() === '') continue;
        await tx.execute(sql.raw(statement));
      }
      await tx.execute(
        sql`insert into drizzle.__drizzle_migrations (hash, created_at) values (${migration.hash}, ${migration.folderMillis})`,
      );
    }
  });
}

const handles: DatabaseHandle[] = [];
afterEach(async () => {
  while (handles.length > 0) await handles.pop()!.close();
});

async function emptyDatabase(): Promise<DatabaseHandle> {
  const handle = await openEmptyTestDb();
  handles.push(handle);
  return handle;
}

const one = async (db: Db, statement: ReturnType<typeof sql>) =>
  rowsOf(await db.execute(statement))[0]!;

interface Phase2Database {
  handle: DatabaseHandle;
  secrets: { active: string; revoked: string; reconnect: string; pending: string };
  connections: { active: string; revoked: string; reconnect: string; pending: string };
  jobIds: string[];
}

/** A database as Phase 2 left it, built with the Phase 2 schema only. */
async function phase2Database(): Promise<Phase2Database> {
  const handle = await emptyDatabase();
  await migrateFirst(handle.db, BEFORE_0005);
  const repositories = createRepositories(handle.db);
  const tenant = await seedTenant(repositories, 'migration-0005');

  const make = async (status: string) => {
    const fixture = await seedConnectionAndAgent(repositories, tenant);
    await handle.db.execute(
      sql`update connections set status = ${status} where id = ${fixture.connection.id}::uuid`,
    );
    const ensured = await repositories.vault.ensureSecret({
      connectionId: fixture.connection.id,
      secretType: 'browser_session',
      now: new Date('2030-01-01T00:00:00Z'),
    });
    return { fixture, secretId: ensured.secretId, nextVersion: ensured.nextVersion };
  };

  const active = await make('active');
  await repositories.vault.putVersion({
    secretId: active.secretId,
    version: active.nextVersion,
    sealed: fakeSealed('phase2-snapshot'),
    now: new Date('2030-01-01T00:00:00Z'),
  });

  // What Phase 2 revocation did: versions deleted, secret `deleted`, connection `revoked`.
  const revoked = await make('active');
  await repositories.vault.putVersion({
    secretId: revoked.secretId,
    version: revoked.nextVersion,
    sealed: fakeSealed('revoked-snapshot'),
    now: new Date('2030-01-01T00:00:00Z'),
  });
  await handle.db.execute(
    sql`delete from vault_secret_versions where secret_id = ${revoked.secretId}::uuid`,
  );
  await handle.db.execute(
    sql`update vault_secrets set status = 'deleted', active_version_id = null where id = ${revoked.secretId}::uuid`,
  );
  await handle.db.execute(
    sql`update connections set status = 'revoked' where id = ${revoked.fixture.connection.id}::uuid`,
  );

  // A deleted secret of a connection that is not revoked (reconnect after reauth_required).
  const reconnect = await make('reconnect_required');
  await handle.db.execute(
    sql`update vault_secrets set status = 'deleted' where id = ${reconnect.secretId}::uuid`,
  );
  const pending = await make('authenticating');

  const args = { limit: 5 };
  const binding = {
    organizationId: tenant.organization.id,
    agentId: active.fixture.agent.id,
    connectionId: active.fixture.connection.id,
    operation: 'orders.list',
    policyDecisionId: null,
    retrySafe: true,
    timeoutMs: 30_000,
    arguments: args,
  };
  const operation = await repositories.jobs.createOperation({
    organizationId: tenant.organization.id,
    requestedByUserId: tenant.user.id,
    agentId: active.fixture.agent.id,
    connectionId: active.fixture.connection.id,
    runId: null,
    operation: 'orders.list',
    arguments: args,
    argumentsHash: jobArgumentsHash(binding),
    retrySafe: true,
    policyDecisionId: null,
    timeoutMs: 30_000,
  });
  const login = await repositories.jobs.createLogin({
    organizationId: tenant.organization.id,
    requestedByUserId: tenant.user.id,
    connectionId: pending.fixture.connection.id,
    timeoutMs: 600_000,
  });

  return {
    handle,
    secrets: {
      active: active.secretId,
      revoked: revoked.secretId,
      reconnect: reconnect.secretId,
      pending: pending.secretId,
    },
    connections: {
      active: active.fixture.connection.id,
      revoked: revoked.fixture.connection.id,
      reconnect: reconnect.fixture.connection.id,
      pending: pending.fixture.connection.id,
    },
    jobIds: [operation.id, login.id],
  };
}

describe('migration 0005_phase3_vault on an empty database', () => {
  it('migrates an empty database and creates the capability table, its constraints and triggers', async () => {
    const handle = await emptyDatabase();
    const journal = readMigrationFiles({ migrationsFolder: MIGRATIONS_FOLDER });
    expect(await migrate(handle.db)).toEqual({ applied: journal.length });
    expect(await migrate(handle.db)).toEqual({ applied: 0 });

    const columns = rowsOf(
      await handle.db.execute(
        sql`select column_name from information_schema.columns where table_name = 'vault_access_capabilities' order by ordinal_position`,
      ),
    ).map((row) => row.column_name);
    expect(columns).toEqual([
      'id',
      'organization_id',
      'job_id',
      'agent_id',
      'connection_id',
      'secret_id',
      'purpose',
      'operation',
      'arguments_hash',
      'issued_at',
      'expires_at',
      'authorization_mac',
      'mac_kek_version',
      'worker_id',
      'attempt',
      'secret_version',
      'token_hash',
      'token_issued_at',
      'token_expires_at',
      'token_mac',
      'used_at',
      'revoked_at',
      'revoked_reason',
      'created_at',
    ]);
    expect(
      await one(
        handle.db,
        sql`select data_type from information_schema.columns where table_name = 'execution_jobs' and column_name = 'capability_ref'`,
      ),
    ).toEqual({ data_type: 'uuid' });
    const foreignKeys = rowsOf(
      await handle.db.execute(
        sql`select conname from pg_constraint where contype = 'f' and conrelid in ('vault_access_capabilities'::regclass, 'execution_jobs'::regclass) and conname like '%capab%' order by conname`,
      ),
    ).map((row) => row.conname);
    expect(foreignKeys).toEqual([
      'execution_jobs_capability_ref_vault_access_capabilities_id_fk',
      'vault_access_capabilities_connection_id_connections_id_fk',
      'vault_access_capabilities_job_id_execution_jobs_id_fk',
      'vault_access_capabilities_organization_id_organizations_id_fk',
      'vault_access_capabilities_secret_id_vault_secrets_id_fk',
    ]);
    const indexes = rowsOf(
      await handle.db.execute(
        sql`select indexname from pg_indexes where tablename = 'vault_access_capabilities' order by indexname`,
      ),
    ).map((row) => row.indexname);
    expect(indexes).toContain('vault_access_capabilities_job_open_unique');
    expect(indexes).toContain('vault_access_capabilities_token_hash_unique');
    expect(
      rowsOf(
        await handle.db.execute(
          sql`select indexdef from pg_indexes where indexname = 'execution_jobs_policy_decision_unique'`,
        ),
      ).map((row) => String(row.indexdef)),
    ).toEqual([expect.stringMatching(/UNIQUE INDEX .*\(policy_decision_id\) WHERE .*IS NOT NULL/)]);
    const triggers = rowsOf(
      await handle.db.execute(
        sql`select tgname from pg_trigger where not tgisinternal and tgrelid in ('vault_secrets'::regclass, 'vault_secret_versions'::regclass) order by tgname`,
      ),
    ).map((row) => row.tgname);
    expect(triggers).toEqual([
      'vault_secret_versions_refuse_revoked_secret',
      'vault_secrets_revoked_is_terminal',
    ]);
  });

  it('accepts the two new job error codes and the revoked secret status, and nothing else', async () => {
    const handle = await emptyDatabase();
    await migrate(handle.db);
    const repositories = createRepositories(handle.db);
    const tenant = await seedTenant(repositories, 'codes');
    const { connection } = await seedConnectionAndAgent(repositories, tenant);
    const job = await repositories.jobs.createLogin({
      organizationId: tenant.organization.id,
      requestedByUserId: tenant.user.id,
      connectionId: connection.id,
      timeoutMs: 1000,
    });
    for (const code of ['vault_unavailable', 'vault_denied']) {
      await handle.db.execute(
        sql`update execution_jobs set error_code = ${code} where id = ${job.id}::uuid`,
      );
    }
    await expect(
      handle.db.execute(
        sql`update execution_jobs set error_code = 'vault_broken' where id = ${job.id}::uuid`,
      ),
    ).rejects.toThrow();
    const ensured = await repositories.vault.ensureSecret({
      connectionId: connection.id,
      secretType: 'browser_session',
      now: new Date(),
    });
    await handle.db.execute(
      sql`update vault_secrets set status = 'revoked' where id = ${ensured.secretId}::uuid`,
    );
    await expect(
      handle.db.execute(
        sql`insert into vault_secrets (connection_id, secret_type, status) values (${connection.id}::uuid, 'other', 'frozen')`,
      ),
    ).rejects.toThrow();
  });
});

describe('migration 0005_phase3_vault on a database with Phase 2 rows', () => {
  it('moves the secrets of revoked connections to revoked and leaves every other row alone', async () => {
    const database = await phase2Database();
    const { handle, secrets } = database;
    const before = rowsOf(
      await handle.db.execute(
        sql`select id, status, active_version_id, last_version, connection_id, secret_type from vault_secrets order by id`,
      ),
    );
    const versionsBefore = rowsOf(
      await handle.db.execute(sql`select * from vault_secret_versions order by id`),
    );
    const jobsBefore = rowsOf(
      await handle.db.execute(sql`select * from execution_jobs order by id`),
    );
    expect(before.find((row) => row.id === secrets.revoked)?.status).toBe('deleted');

    expect(await migrate(handle.db)).toEqual({ applied: 1 });

    const after = rowsOf(
      await handle.db.execute(
        sql`select id, status, active_version_id, last_version, connection_id, secret_type from vault_secrets order by id`,
      ),
    );
    const byId = (rows: Record<string, unknown>[], id: string) =>
      rows.find((row) => row.id === id)!;
    expect(byId(after, secrets.revoked).status).toBe('revoked');
    expect(byId(after, secrets.active).status).toBe('active');
    expect(byId(after, secrets.reconnect).status).toBe('deleted');
    expect(byId(after, secrets.pending).status).toBe('pending');
    // Apart from that one status, every secret row is what it was.
    for (const row of before) {
      const next = byId(after, String(row.id));
      expect({ ...next, status: row.id === secrets.revoked ? 'deleted' : next.status }).toEqual(
        row,
      );
    }

    // The sealed snapshot is byte-for-byte what Phase 2 wrote and the repository still returns it.
    expect(
      rowsOf(await handle.db.execute(sql`select * from vault_secret_versions order by id`)),
    ).toEqual(versionsBefore);
    const repositories = createRepositories(handle.db);
    const snapshot = await repositories.vault.getActive(
      database.connections.active,
      'browser_session',
    );
    expect(snapshot?.version).toBe(1);
    expect(snapshot?.sealed.ciphertext.toString()).toBe('synthetic-ciphertext-phase2-snapshot');
    expect(snapshot?.sealed.wrappedDek.toString()).toBe('synthetic-wrapped-dek-phase2-snapshot');
    expect(
      await repositories.vault.getActive(database.connections.revoked, 'browser_session'),
    ).toBeNull();

    // capability_ref is a uuid column now, still null on every row, and the jobs are unchanged.
    expect(
      await one(
        handle.db,
        sql`select data_type from information_schema.columns where table_name = 'execution_jobs' and column_name = 'capability_ref'`,
      ),
    ).toEqual({ data_type: 'uuid' });
    const jobsAfter = rowsOf(
      await handle.db.execute(sql`select * from execution_jobs order by id`),
    );
    expect(jobsAfter).toEqual(jobsBefore);
    expect(jobsAfter.every((row) => row.capability_ref === null)).toBe(true);
    expect(jobsAfter.map((row) => row.id).sort()).toEqual([...database.jobIds].sort());

    // The trigger now guards the migrated revoked secret.
    await expect(
      handle.db.execute(
        sql`update vault_secrets set status = 'active' where id = ${secrets.revoked}::uuid`,
      ),
    ).rejects.toThrow();
    await expect(
      repositories.vault.putVersion({
        secretId: secrets.revoked,
        version: 5,
        sealed: fakeSealed('late'),
        now: new Date(),
      }),
    ).rejects.toThrow();
  });

  it('a Phase 2 snapshot is still readable from the repository after migration', async () => {
    // The vault (step B2) opens it with the AAD rebuilt from the connection row; the AAD and the
    // envelope are unchanged by 0005, so this database part checks the stored record is intact.
    const database = await phase2Database();
    await migrate(database.handle.db);
    const repositories = createRepositories(database.handle.db);
    const snapshot = await repositories.vault.getVersion(database.secrets.active, 1);
    expect(snapshot).not.toBeNull();
    expect(snapshot!.sealed).toMatchObject({
      algorithm: 'aab-envelope-v1/aes-256-gcm',
      kekVersion: 1,
      aadVersion: 1,
    });
  });

  it.each([
    ['a value that is not a uuid', 'not-a-uuid'],
    ['a value that is a well-formed uuid', randomUUID()],
    ['an empty string', ''],
  ])(
    'refuses to migrate when capability_ref holds %s, and changes nothing',
    async (_name, value) => {
      const database = await phase2Database();
      const { handle } = database;
      await handle.db.execute(
        sql`update execution_jobs set capability_ref = ${value} where id = ${database.jobIds[0]!}::uuid`,
      );
      const secretsBefore = rowsOf(
        await handle.db.execute(sql`select id, status from vault_secrets order by id`),
      );

      await expect(migrate(handle.db)).rejects.toThrow();
      let message = '';
      try {
        await migrate(handle.db);
      } catch (error) {
        for (let current: unknown = error; current instanceof Error; current = current.cause) {
          message += `${current.message} | `;
        }
      }
      expect(message).toContain('capability_ref holds values');

      // One transaction: nothing was applied.
      expect(
        await one(handle.db, sql`select count(*)::int as n from drizzle.__drizzle_migrations`),
      ).toEqual({ n: BEFORE_0005 });
      expect(
        await one(
          handle.db,
          sql`select data_type from information_schema.columns where table_name = 'execution_jobs' and column_name = 'capability_ref'`,
        ),
      ).toEqual({ data_type: 'text' });
      expect(
        rowsOf(
          await handle.db.execute(
            sql`select 1 from information_schema.tables where table_name = 'vault_access_capabilities'`,
          ),
        ),
      ).toHaveLength(0);
      expect(
        rowsOf(await handle.db.execute(sql`select id, status from vault_secrets order by id`)),
      ).toEqual(secretsBefore);

      // Once a person has cleared the value the migration runs.
      await handle.db.execute(sql`update execution_jobs set capability_ref = null`);
      expect(await migrate(handle.db)).toEqual({ applied: 1 });
    },
  );
  /** The message of a failed migration, whatever the driver wraps it in. */
  async function migrationFailure(handle: DatabaseHandle): Promise<string> {
    let message = '';
    try {
      await migrate(handle.db);
    } catch (error) {
      for (let current: unknown = error; current instanceof Error; current = current.cause) {
        message += `${current.message} | `;
      }
    }
    return message;
  }

  it('refuses to migrate when two jobs share one policy decision, and runs once they do not', async () => {
    const database = await phase2Database();
    const { handle } = database;
    const decision = randomUUID();
    await handle.db.execute(
      sql`update execution_jobs set policy_decision_id = ${decision}::uuid where id = ${database.jobIds[0]!}::uuid`,
    );
    // The second row needs the operation shape; copy the first one under a new id.
    await handle.db.execute(
      sql`insert into execution_jobs (organization_id, requested_by_user_id, kind, agent_id, connection_id, operation, arguments, arguments_hash, retry_safe, policy_decision_id, timeout_ms)
          select organization_id, requested_by_user_id, kind, agent_id, connection_id, operation, arguments, arguments_hash, retry_safe, policy_decision_id, timeout_ms
          from execution_jobs where id = ${database.jobIds[0]!}::uuid`,
    );

    expect(await migrationFailure(handle)).toContain('share one policy_decision_id');
    expect(
      await one(handle.db, sql`select count(*)::int as n from drizzle.__drizzle_migrations`),
    ).toEqual({ n: BEFORE_0005 });

    await handle.db.execute(
      sql`update execution_jobs set policy_decision_id = null where id <> ${database.jobIds[0]!}::uuid and policy_decision_id is not null`,
    );
    expect(await migrate(handle.db)).toEqual({ applied: 1 });
    // And from now on a second job on one decision is refused by the index.
    await expect(
      handle.db.execute(
        sql`insert into execution_jobs (organization_id, requested_by_user_id, kind, agent_id, connection_id, operation, arguments, arguments_hash, retry_safe, policy_decision_id, timeout_ms)
            select organization_id, requested_by_user_id, kind, agent_id, connection_id, operation, arguments, arguments_hash, retry_safe, policy_decision_id, timeout_ms
            from execution_jobs where id = ${database.jobIds[0]!}::uuid`,
      ),
    ).rejects.toThrow();
  });

  it.each([
    [
      'a stored version row',
      async (db: Db, secretId: string) => {
        await db.execute(
          sql`insert into vault_secret_versions (secret_id, version, algorithm, ciphertext, nonce, auth_tag, wrapped_dek, kek_version, aad_version)
              values (${secretId}::uuid, 7, 'aab-envelope-v1/aes-256-gcm', 'c', 'n', 't', 'w', 1, 1)`,
        );
      },
    ],
    [
      'an active version pointer',
      async (db: Db, secretId: string) => {
        await db.execute(
          sql`update vault_secrets set active_version_id = ${randomUUID()}::uuid where id = ${secretId}::uuid`,
        );
      },
    ],
  ])(
    "refuses to migrate when a revoked connection's secret still has %s, and changes nothing",
    async (_name, leftover) => {
      const database = await phase2Database();
      const { handle } = database;
      await leftover(handle.db, database.secrets.revoked);
      const before = rowsOf(
        await handle.db.execute(sql`select id, status from vault_secrets order by id`),
      );

      expect(await migrationFailure(handle)).toContain(
        'a revoked connection still has a vault secret with an active version or stored version rows',
      );
      expect(
        await one(handle.db, sql`select count(*)::int as n from drizzle.__drizzle_migrations`),
      ).toEqual({ n: BEFORE_0005 });
      expect(
        rowsOf(await handle.db.execute(sql`select id, status from vault_secrets order by id`)),
      ).toEqual(before);

      // Once a person has removed the leftovers the migration runs and the secret is terminal.
      await handle.db.execute(
        sql`delete from vault_secret_versions where secret_id = ${database.secrets.revoked}::uuid`,
      );
      await handle.db.execute(
        sql`update vault_secrets set active_version_id = null where id = ${database.secrets.revoked}::uuid`,
      );
      expect(await migrate(handle.db)).toEqual({ applied: 1 });
      expect(
        await one(
          handle.db,
          sql`select status from vault_secrets where id = ${database.secrets.revoked}::uuid`,
        ),
      ).toEqual({ status: 'revoked' });
    },
  );
});
