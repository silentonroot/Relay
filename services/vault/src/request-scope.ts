import { AsyncLocalStorage } from 'node:async_hooks';
import type { TransactionTimeouts } from '@aab/database';

/*
 * The database limits of the request being handled. The server runs a handler inside `run`; the
 * database handle (`withTransactionTimeouts`, see vault.ts) reads them when a transaction opens, so
 * every vault transaction, including the ones repositories open themselves, gets `SET LOCAL
 * statement_timeout` and `SET LOCAL lock_timeout` below the role's request timeout. A request that
 * is answered as failed because of the database therefore rolled back; the server's own timer is
 * only a last resort that closes the connection without claiming an outcome (ADR-014 "As built" in
 * B2 review fixes).
 */

const scope = new AsyncLocalStorage<TransactionTimeouts>();

/** Statement limit as a share of the request timeout; the lock limit is tighter still. */
export const STATEMENT_TIMEOUT_SHARE = 0.8;
export const LOCK_TIMEOUT_SHARE = 0.5;

export function timeoutsFor(requestTimeoutMs: number): TransactionTimeouts {
  return {
    statementTimeoutMs: Math.max(1, Math.floor(requestTimeoutMs * STATEMENT_TIMEOUT_SHARE)),
    lockTimeoutMs: Math.max(1, Math.floor(requestTimeoutMs * LOCK_TIMEOUT_SHARE)),
  };
}

export function runWithTimeouts<T>(timeouts: TransactionTimeouts, work: () => T): T {
  return scope.run(timeouts, work);
}

export function currentTimeouts(): TransactionTimeouts | undefined {
  return scope.getStore();
}
