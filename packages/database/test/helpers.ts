import { randomBytes } from 'node:crypto';
import type { Organization, User } from '@aab/contracts';
import { PGlite } from '@electric-sql/pglite';
import { sql } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/pglite';
import { readMigrationFiles } from 'drizzle-orm/migrator';
import pg from 'pg';
import { createDatabase, migrate, MIGRATIONS_FOLDER } from '../src/index.js';
import type { DatabaseHandle, Db, Repositories, Scope } from '../src/index.js';
import { createTestDatabase } from '../src/testing.js';

/**
 * Opens an isolated, migrated database for one test file.
 *
 * Default: in-process PGlite. Set AAB_TEST_DATABASE_URL to a PostgreSQL server where the role
 * may create databases to run the very same suite on node-postgres with real concurrency;
 * each call then creates a throwaway database and drops it on close.
 */
export async function openTestDb(): Promise<DatabaseHandle> {
  const serverUrl = process.env.AAB_TEST_DATABASE_URL;
  if (serverUrl === undefined || serverUrl === '') return createTestDatabase();
  const handle = await openEmptyTestDb();
  await migrate(handle.db);
  return handle;
}

/**
 * Like openTestDb, but no migration has been applied: for tests that migrate step by step.
 */
export async function openEmptyTestDb(): Promise<DatabaseHandle> {
  const serverUrl = process.env.AAB_TEST_DATABASE_URL;
  if (serverUrl === undefined || serverUrl === '') {
    const client = await PGlite.create();
    return { db: drizzle(client), close: () => client.close() };
  }

  const name = `aab_test_${randomBytes(6).toString('hex')}`;
  const runAdmin = async (statement: string): Promise<void> => {
    const admin = new pg.Client({ connectionString: serverUrl });
    await admin.connect();
    try {
      await admin.query(statement);
    } finally {
      await admin.end();
    }
  };
  await runAdmin(`create database ${name}`);

  const target = new URL(serverUrl);
  target.pathname = `/${name}`;
  const handle = createDatabase({ connectionString: target.toString(), maxConnections: 30 });
  return {
    db: handle.db,
    close: async () => {
      await handle.close();
      await runAdmin(`drop database if exists ${name} with (force)`);
    },
  };
}

/** The job arguments hash, as the execute route computes it. */
/**
 * Applies only the first `count` migrations, with the same bookkeeping as `migrate`, so a later
 * `migrate(db)` applies the rest: a database as an earlier phase left it.
 */
export async function migrateFirst(db: Db, count: number): Promise<void> {
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

export { hashJobArguments as jobArgumentsHash } from '../src/index.js';

/** Placeholder that only has the shape of a hash. No real password was ever involved. */
export const SYNTHETIC_PASSWORD_HASH = 'scrypt$synthetic$not-a-real-hash';

export interface Tenant {
  organization: Organization;
  user: User;
  scope: Scope;
}

let counter = 0;

/** An organization with one owner, entirely synthetic. */
export async function seedTenant(repositories: Repositories, label: string): Promise<Tenant> {
  counter += 1;
  const organization = await repositories.organizations.create({ name: `${label} org` });
  const user = await repositories.users.create({
    email: `${label}-${counter}@synthetic.test`,
    passwordHash: SYNTHETIC_PASSWORD_HASH,
  });
  await repositories.organizations.addMember({
    organizationId: organization.id,
    userId: user.id,
    role: 'owner',
  });
  return { organization, user, scope: { organizationId: organization.id, userId: user.id } };
}

export async function seedApplication(repositories: Repositories, scope: Scope, version = '1.0.0') {
  return repositories.applications.register(scope, {
    adapterId: 'northstar',
    adapterVersion: version,
    name: 'Northstar (synthetic)',
    allowedOrigins: ['http://localhost:4100'],
    authModes: ['browser_session'],
  });
}

export const UNKNOWN_ID = '99999999-9999-4999-8999-999999999999';

let nameCounter = 0;

/** A fresh connection (status `created`) and an agent for the tenant, both synthetic. */
export async function seedConnectionAndAgent(
  repositories: Repositories,
  tenant: Tenant,
  application?: { id: string },
) {
  nameCounter += 1;
  const app =
    application ?? (await seedApplication(repositories, tenant.scope, `2.${nameCounter}.0`));
  const connection = await repositories.connections.create(tenant.scope, {
    applicationId: app.id,
    displayName: `synthetic connection ${nameCounter}`,
  });
  const agent = await repositories.agents.create(tenant.scope, {
    name: `synthetic agent ${nameCounter}`,
    clientIdentity: `synthetic-agent-${nameCounter}`,
  });
  return { application: app, connection, agent };
}

/** Fake ciphertext with the shape of a SealedSecret. Not produced by any real key. */
export function fakeSealed(tag = 'a', kekVersion = 1) {
  return {
    algorithm: 'aab-envelope-v1/aes-256-gcm',
    ciphertext: Buffer.from(`synthetic-ciphertext-${tag}`),
    nonce: Buffer.alloc(12, 1),
    authTag: Buffer.alloc(16, 2),
    wrappedDek: Buffer.from(`synthetic-wrapped-dek-${tag}`),
    kekVersion,
    aadVersion: 1,
  };
}
