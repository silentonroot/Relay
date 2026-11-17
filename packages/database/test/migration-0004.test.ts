import { randomUUID } from 'node:crypto';
import type { JobArgumentsBinding, JsonObject, JsonValue } from '@aab/contracts';
import { sql } from 'drizzle-orm';
import { readMigrationFiles } from 'drizzle-orm/migrator';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { rowsOf } from '../src/client.js';
import type { Db } from '../src/client.js';
import { createRepositories, migrate, MIGRATIONS_FOLDER } from '../src/index.js';
import type { DatabaseHandle, Repositories } from '../src/index.js';
import {
  jobArgumentsHash,
  openEmptyTestDb,
  seedConnectionAndAgent,
  seedTenant,
} from './helpers.js';
import type { Tenant } from './helpers.js';

/*
 * Migration 0004 backfills `execution_jobs.arguments_hash` for rows written by Phase 2. The SQL
 * reproduces the canonical JSON of `@aab/contracts` itself, so this test writes Phase 2 rows
 * with awkward arguments (key order that differs between UTF-16 and code point order, escapes,
 * numbers in every ECMAScript format range) and checks each backfilled hash against the hash
 * the worker computes from the same row.
 */

const PHASE_2_MIGRATIONS = 4;

/** Applies the first `count` migrations with the same bookkeeping as `migrate`. */
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

/** Deterministic PRNG (mulberry32), so a failure reproduces. */
function prng(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// prettier-ignore
const CHARACTERS = [
  'a', 'Z', '0', ' ', '"', '\\', '/', "'", '<', '&', '\b', '\f', '\n', '\r', '\t', '\u0001',
  '\u001f', '\u007f', '\u0080', 'é', 'ß', '中', ' ', ' ', '퟿', '', '�',
  '￿', '\u{10000}', '😀', '\u{10ffff}',
];

// prettier-ignore
const NUMBERS = [
  0, -0, 1, -1, 5, 100, 4.35, 0.1, 0.5, 1 / 3, Math.PI, -Math.E, 123.456, 0.000123, 1e-6, -1e-6,
  1e-7, 1.5e-10, 5e-324, -5e-324, 1e20, 1e21, 9.999999999999999e20, 123456789012345680000,
  1.7976931348623157e308, -1e300, 2 ** 53, 2 ** 53 + 2, -(2 ** 31), 1e300, 2.5e-300,
];

function randomString(next: () => number, maxLength = 6): string {
  const length = Math.floor(next() * (maxLength + 1));
  let text = '';
  for (let index = 0; index < length; index += 1) {
    text += CHARACTERS[Math.floor(next() * CHARACTERS.length)]!;
  }
  return text;
}

function randomNumber(next: () => number): number {
  const pick = next();
  if (pick < 0.5) return NUMBERS[Math.floor(next() * NUMBERS.length)]!;
  if (pick < 0.7) return Math.floor((next() - 0.5) * 2 ** 40);
  return (next() - 0.5) * 10 ** Math.floor(next() * 50 - 25);
}

function randomValue(next: () => number, depth: number): JsonValue {
  const pick = next();
  if (depth <= 0 || pick < 0.45) {
    const scalar = next();
    if (scalar < 0.35) return randomString(next);
    if (scalar < 0.75) return randomNumber(next);
    if (scalar < 0.85) return true;
    if (scalar < 0.92) return false;
    return null;
  }
  if (pick < 0.7) {
    return Array.from({ length: Math.floor(next() * 4) }, () => randomValue(next, depth - 1));
  }
  return randomObject(next, depth - 1);
}

function randomObject(next: () => number, depth: number): JsonObject {
  const object: JsonObject = {};
  const size = Math.floor(next() * 5);
  for (let index = 0; index < size; index += 1) {
    object[randomString(next, 4)] = randomValue(next, depth);
  }
  return object;
}

/** Hand-picked arguments for the cases most likely to differ between SQL and JavaScript. */
const HAND_PICKED: JsonObject[] = [
  {},
  { limit: 5 },
  { status: 'open', page: 2 },
  // UTF-16 order puts U+1F600 (D83D DE00) before U+E000; code point order puts it after.
  { '': 1, '😀': 2, '￿': 3, '\u{10000}': 4, é: 5, '': 6, a: 7, A: 8, aa: 9, b: 10 },
  { text: 'quote " backslash \\ slash / tab \t newline \n bell \u0007 del \u007f ls  ' },
  { numbers: NUMBERS },
  { nested: { b: [{ d: 1, c: 2 }, [], {}], a: null }, flag: false },
  { orderId: 'NS-100042', resourceIds: ['NS-1', 'NS-2'] },
];

describe('migration 0004_job_arguments_hash on a database with Phase 2 rows', () => {
  let handle: DatabaseHandle;
  let repositories: Repositories;
  let tenant: Tenant;
  const operationJobIds: string[] = [];
  /** What each row was written with: job id to operation, connection and arguments. */
  const written = new Map<string, JobArgumentsBinding>();
  let loginJobId: string;

  beforeAll(async () => {
    handle = await openEmptyTestDb();
    await migrateFirst(handle.db, PHASE_2_MIGRATIONS);
    repositories = createRepositories(handle.db);
    tenant = await seedTenant(repositories, 'migration-0004');
    const first = await seedConnectionAndAgent(repositories, tenant);
    const second = await seedConnectionAndAgent(repositories, tenant);

    const next = prng(0x0004);
    const generated = Array.from({ length: 150 }, () => randomObject(next, 4));
    const statuses = ['queued', 'running', 'succeeded', 'failed', 'denied', 'cancelled'];
    const all = [...HAND_PICKED, ...generated];
    for (const [index, args] of all.entries()) {
      const fixture = index % 2 === 0 ? first : second;
      const operation = index % 3 === 0 ? 'orders.get' : 'orders.list';
      // Every other row has no decision id (the column is nullable); the flag and the timeout vary.
      const policyDecisionId = index % 2 === 0 ? null : randomUUID();
      const retrySafe = index % 4 < 2;
      const timeoutMs = [30_000, 1, 600_000, 2_147_483_647][index % 4]!;
      // The column does not exist yet; this is a Phase 2 insert. JSON.stringify is what the
      // driver sends for a jsonb value.
      const rows = rowsOf(
        await handle.db.execute(
          sql`insert into execution_jobs (organization_id, requested_by_user_id, kind, agent_id, connection_id, operation, arguments, policy_decision_id, retry_safe, timeout_ms, status)
              values (${tenant.organization.id}, ${tenant.user.id}, 'operation', ${fixture.agent.id}, ${fixture.connection.id}, ${operation}, ${JSON.stringify(args)}::jsonb, ${policyDecisionId}, ${retrySafe}, ${timeoutMs}, ${statuses[index % statuses.length]!})
              returning id`,
        ),
      );
      operationJobIds.push(String(rows[0]!.id));
      written.set(String(rows[0]!.id), {
        organizationId: tenant.organization.id,
        agentId: fixture.agent.id,
        connectionId: fixture.connection.id,
        operation,
        arguments: args,
        policyDecisionId,
        timeoutMs,
        retrySafe,
      });
    }
    const login = rowsOf(
      await handle.db.execute(
        sql`insert into execution_jobs (organization_id, requested_by_user_id, kind, connection_id, timeout_ms)
            values (${tenant.organization.id}, ${tenant.user.id}, 'login', ${first.connection.id}, 600000)
            returning id`,
      ),
    );
    loginJobId = String(login[0]!.id);

    // 0004 and every migration after it (0005 and later) are pending on this database.
    const pending =
      readMigrationFiles({ migrationsFolder: MIGRATIONS_FOLDER }).length - PHASE_2_MIGRATIONS;
    expect(pending).toBeGreaterThanOrEqual(1);
    expect(await migrate(handle.db)).toEqual({ applied: pending });
  }, 120_000);

  afterAll(async () => {
    await handle.close();
  });

  it('backfills every operation job with the hash the worker computes from the row', async () => {
    expect(operationJobIds).toHaveLength(HAND_PICKED.length + 150);
    const mismatches: string[] = [];
    for (const id of operationJobIds) {
      const job = (await repositories.jobs.getInternal(id))!;
      expect(job.argumentsHash).toMatch(/^[0-9a-f]{64}$/);
      // The reference is the value that was written, not the value read back: node-postgres
      // decodes jsonb with JSON.parse, which gives back exactly that value for text that
      // JSON.stringify produced. PGlite's in-process decoding was seen to return one generated
      // row with a wrong key byte, in both `arguments` and `arguments::text`, while SQL inside
      // the database saw the right value; reading back would test PGlite, not the migration.
      const source = written.get(id)!;
      const expected = jobArgumentsHash(source);
      if (job.argumentsHash !== expected) mismatches.push(JSON.stringify(source));
    }
    expect(mismatches).toEqual([]);
  });

  it('gives different rows different hashes', async () => {
    const rows = rowsOf(
      await handle.db.execute(
        sql`select count(distinct arguments_hash)::int as n from execution_jobs where kind = 'operation'`,
      ),
    );
    const distinct = rowsOf(
      await handle.db.execute(
        sql`select count(*)::int as n from (select distinct arguments, connection_id, operation, policy_decision_id, retry_safe, timeout_ms from execution_jobs where kind = 'operation') as d`,
      ),
    );
    expect(rows[0]!.n).toBe(distinct[0]!.n);
  });

  it('leaves the login job without a hash', async () => {
    expect((await repositories.jobs.getInternal(loginJobId))?.argumentsHash).toBeNull();
  });

  it('drops its helper functions and keeps the constraint', async () => {
    const functions = rowsOf(
      await handle.db.execute(sql`select proname from pg_proc where proname like 'aab_0004_%'`),
    );
    expect(functions).toEqual([]);
    const constraints = rowsOf(
      await handle.db.execute(
        sql`select conname from pg_constraint where conname = 'execution_jobs_arguments_hash_check'`,
      ),
    );
    expect(constraints).toHaveLength(1);
    await expect(
      handle.db.execute(
        sql`update execution_jobs set arguments_hash = null where id = ${operationJobIds[0]!}`,
      ),
    ).rejects.toThrow();
  });

  it('is applied once', async () => {
    expect(await migrate(handle.db)).toEqual({ applied: 0 });
  });
});
