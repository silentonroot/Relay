import { sql } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { rowsOf } from '../src/client.js';
import { withTransactionTimeouts } from '../src/index.js';
import type { DatabaseHandle } from '../src/index.js';
import { openTestDb } from './helpers.js';

/*
 * `withTransactionTimeouts` is what makes a vault request that is answered as timed out one that
 * rolled back: PostgreSQL cancels the statement first, so the transaction aborts.
 */

let handle: DatabaseHandle;
beforeAll(async () => {
  handle = await openTestDb();
});
afterAll(async () => {
  await handle.close();
});

const show = async (db: DatabaseHandle['db'], name: string) =>
  String(rowsOf(await db.execute(sql.raw(`show ${name}`)))[0]![name]);

describe('withTransactionTimeouts', () => {
  it('sets statement_timeout and lock_timeout for the transaction only', async () => {
    const db = withTransactionTimeouts(handle.db, () => ({
      statementTimeoutMs: 8_000,
      lockTimeoutMs: 5_000,
    }));
    const inside = await db.transaction(async (tx) => ({
      statement: await show(tx, 'statement_timeout'),
      lock: await show(tx, 'lock_timeout'),
    }));
    expect(inside).toEqual({ statement: '8s', lock: '5s' });
    // SET LOCAL ended with the transaction: nothing leaks to the next use of a connection.
    expect(await show(handle.db, 'statement_timeout')).toBe('0');
    expect(await show(handle.db, 'lock_timeout')).toBe('0');
  });

  it('resolves the limits when the transaction opens, and sets nothing when there are none', async () => {
    const state: { current?: { statementTimeoutMs: number; lockTimeoutMs: number } } = {};
    const db = withTransactionTimeouts(handle.db, () => state.current);
    expect(await db.transaction((tx) => show(tx, 'statement_timeout'))).toBe('0');
    state.current = { statementTimeoutMs: 1_500, lockTimeoutMs: 700 };
    expect(await db.transaction((tx) => show(tx, 'statement_timeout'))).toBe('1500ms');
    expect(await db.transaction((tx) => show(tx, 'lock_timeout'))).toBe('700ms');
  });

  it('refuses a limit that would disable the timeout or is not a whole number', async () => {
    for (const bad of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
      const db = withTransactionTimeouts(handle.db, () => ({
        statementTimeoutMs: bad,
        lockTimeoutMs: 1_000,
      }));
      await expect(db.transaction(() => Promise.resolve(1))).rejects.toThrow(RangeError);
    }
  });

  it('keeps the return value and rolls back when the work throws', async () => {
    const db = withTransactionTimeouts(handle.db, () => ({
      statementTimeoutMs: 5_000,
      lockTimeoutMs: 5_000,
    }));
    expect(await db.transaction(() => Promise.resolve(42))).toBe(42);
    await expect(
      db.transaction(async (tx) => {
        await tx.execute(sql`select 1`);
        throw new Error('boom');
      }),
    ).rejects.toThrow('boom');
  });

  // PGlite has one connection and ignores real waiting; the timeout itself is proved on PostgreSQL.
  it.skipIf((process.env.AAB_TEST_DATABASE_URL ?? '') === '')(
    'PostgreSQL cancels a statement that outlives statement_timeout, and rolls the transaction back',
    async () => {
      await handle.db.execute(sql`create table tt_rollback (n int)`);
      const db = withTransactionTimeouts(handle.db, () => ({
        statementTimeoutMs: 200,
        lockTimeoutMs: 100,
      }));
      await expect(
        db.transaction(async (tx) => {
          await tx.execute(sql`insert into tt_rollback values (1)`);
          await tx.execute(sql`select pg_sleep(5)`);
        }),
      ).rejects.toMatchObject({ cause: { code: '57014' } });
      expect(
        rowsOf(await handle.db.execute(sql`select count(*)::int as n from tt_rollback`))[0],
      ).toEqual({
        n: 0,
      });
    },
  );
});
