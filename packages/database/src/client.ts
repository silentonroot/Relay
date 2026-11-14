import { drizzle } from 'drizzle-orm/node-postgres';
import type { PgDatabase, PgQueryResultHKT } from 'drizzle-orm/pg-core';
import pg from 'pg';

/**
 * Driver-independent database type. node-postgres (deployment) and PGlite (tests) both
 * satisfy it, and so does a transaction, which is how repositories compose atomically.
 */
export type Db = PgDatabase<PgQueryResultHKT>;

export interface DatabaseHandle {
  db: Db;
  /** Releases the pool or the in-process engine. The handle is unusable afterwards. */
  close(): Promise<void>;
}

export interface CreateDatabaseOptions {
  /** PostgreSQL connection string. Comes from configuration; never log it. */
  connectionString: string;
  maxConnections?: number;
  /**
   * Called when an idle pooled connection fails. Without a listener node-postgres would
   * crash the process; the caller decides how to log it (the message, not the config).
   */
  onPoolError?: (error: Error) => void;
}

/** Opens a node-postgres pool. Run `migrate(handle.db)` before first use. */
export function createDatabase(options: CreateDatabaseOptions): DatabaseHandle {
  const pool = new pg.Pool({
    connectionString: options.connectionString,
    max: options.maxConnections ?? 10,
  });
  pool.on('error', (error) => options.onPoolError?.(error));
  return {
    db: drizzle(pool),
    close: () => pool.end(),
  };
}

/**
 * Normalizes the driver-specific result of `db.execute()` into rows. node-postgres and PGlite
 * return `{ rows }`; some other drivers return the array itself.
 */
export function rowsOf(result: unknown): Record<string, unknown>[] {
  if (Array.isArray(result)) return result as Record<string, unknown>[];
  if (typeof result === 'object' && result !== null && 'rows' in result) {
    const rows = (result as { rows: unknown }).rows;
    if (Array.isArray(rows)) return rows as Record<string, unknown>[];
  }
  return [];
}
