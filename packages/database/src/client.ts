import { sql } from 'drizzle-orm';
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

/** Per-transaction limits applied with `SET LOCAL` (milliseconds, whole numbers of at least 1). */
export interface TransactionTimeouts {
  /** `statement_timeout`: PostgreSQL cancels a statement that runs longer. */
  statementTimeoutMs: number;
  /** `lock_timeout`: PostgreSQL cancels a statement that waits longer for a lock. */
  lockTimeoutMs: number;
}

function timeoutLiteral(name: string, value: number): string {
  // 0 would DISABLE the timeout in PostgreSQL: refuse it along with anything not a whole number.
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new RangeError(`${name} must be a whole number of milliseconds, at least 1`);
  }
  return String(value);
}

/**
 * Returns a `Db` whose top-level `transaction()` first runs `SET LOCAL statement_timeout` and
 * `SET LOCAL lock_timeout` with the limits `resolve()` returns at the moment the transaction is
 * opened (nothing is set when it returns undefined). `SET LOCAL` ends with the transaction, so a
 * pooled connection never carries the limit into another use, and a timeout error aborts the
 * transaction: everything in it rolls back. Repositories that call `db.transaction` themselves get
 * the limits without knowing. Statements outside a transaction are not covered, and a nested
 * `tx.transaction` (a savepoint) runs inside the limits of the outer one.
 */
export function withTransactionTimeouts(
  db: Db,
  resolve: () => TransactionTimeouts | undefined,
): Db {
  return new Proxy(db, {
    get(target, property) {
      const value: unknown = Reflect.get(target, property, target);
      if (property !== 'transaction' || typeof value !== 'function') return value;
      return (work: (tx: Db) => Promise<unknown>, config?: unknown) => {
        const timeouts = resolve();
        const transaction = value as (w: unknown, c?: unknown) => Promise<unknown>;
        if (timeouts === undefined) return transaction.call(target, work, config);
        let statement: string;
        let lock: string;
        try {
          statement = timeoutLiteral('statementTimeoutMs', timeouts.statementTimeoutMs);
          lock = timeoutLiteral('lockTimeoutMs', timeouts.lockTimeoutMs);
        } catch (error) {
          return Promise.reject(error);
        }
        return transaction.call(
          target,
          async (tx: Db) => {
            await tx.execute(sql.raw(`SET LOCAL statement_timeout = ${statement}`));
            await tx.execute(sql.raw(`SET LOCAL lock_timeout = ${lock}`));
            return work(tx);
          },
          config,
        );
      };
    },
  }) as Db;
}
