/*
 * Applies pending database migrations: `npm run migrate` (reads DATABASE_URL).
 */
import process from 'node:process';
import { createDatabase, migrate } from '@aab/database';
import { DatabaseUrl } from '../config.js';

async function main(): Promise<number> {
  const url = DatabaseUrl.safeParse(process.env.DATABASE_URL?.trim() || undefined);
  if (!url.success) {
    console.error(`migrate: DATABASE_URL ${url.error.issues[0]?.message ?? 'is invalid'}`);
    return 1;
  }
  const database = createDatabase({ connectionString: url.data, maxConnections: 1 });
  try {
    const result = await migrate(database.db);
    console.log(
      result.applied === 0
        ? 'migrate: database is up to date'
        : `migrate: applied ${result.applied} migration(s)`,
    );
    return 0;
  } catch (error) {
    // The driver's message, not the error object: the latter can carry connection details.
    console.error(`migrate: failed: ${error instanceof Error ? error.message : 'unknown error'}`);
    return 1;
  } finally {
    await database.close();
  }
}

process.exitCode = await main();
