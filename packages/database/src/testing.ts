import { PGlite } from '@electric-sql/pglite';
import { drizzle } from 'drizzle-orm/pglite';
import type { DatabaseHandle } from './client.js';
import { migrate } from './migrate.js';

/**
 * A fresh, fully migrated, in-memory PostgreSQL (PGlite) for tests. Each call returns an
 * isolated database; close it when the test file is done.
 *
 * PGlite runs one connection, so transactions execute one after another. Code paths that
 * depend on real lock contention behave correctly here but are not stress-tested by it.
 */
export async function createTestDatabase(): Promise<DatabaseHandle> {
  const client = await PGlite.create();
  const db = drizzle(client);
  await migrate(db);
  return {
    db,
    close: () => client.close(),
  };
}
