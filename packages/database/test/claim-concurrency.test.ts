import { sql } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { rowsOf } from '../src/client.js';
import { createRepositories } from '../src/index.js';
import type { DatabaseHandle, ExecutionJob, Repositories } from '../src/index.js';
import { openTestDb, seedConnectionAndAgent, seedTenant } from './helpers.js';
import type { Tenant } from './helpers.js';

/*
 * Needs real lock contention, which single-connection PGlite cannot show. Runs only when
 * AAB_TEST_DATABASE_URL points at a PostgreSQL server (see helpers.ts).
 */
const hasServer = (process.env.AAB_TEST_DATABASE_URL ?? '') !== '';

const CONNECTIONS = 6;
const JOBS_PER_CONNECTION = 5;
const CLAIMERS = 24;

describe.skipIf(!hasServer)('jobs.claimNext under contention', () => {
  let handle: DatabaseHandle;
  let repositories: Repositories;
  let tenant: Tenant;
  let connectionIds: string[];

  beforeAll(async () => {
    handle = await openTestDb();
    repositories = createRepositories(handle.db);
    tenant = await seedTenant(repositories, 'claim');
    connectionIds = [];
    for (let index = 0; index < CONNECTIONS; index += 1) {
      const { connection, agent } = await seedConnectionAndAgent(repositories, tenant);
      connectionIds.push(connection.id);
      for (let job = 0; job < JOBS_PER_CONNECTION; job += 1) {
        await repositories.jobs.createOperation({
          organizationId: tenant.organization.id,
          requestedByUserId: tenant.user.id,
          agentId: agent.id,
          connectionId: connection.id,
          runId: null,
          operation: 'orders.list',
          arguments: {},
          retrySafe: true,
          policyDecisionId: null,
          timeoutMs: 30_000,
        });
      }
    }
  });

  afterAll(async () => {
    await handle.close();
  });

  const runningCount = async (connectionId: string) =>
    Number(
      rowsOf(
        await handle.db.execute(
          sql`select count(*)::int as n from execution_jobs where connection_id = ${connectionId} and status = 'running'`,
        ),
      )[0]!.n,
    );

  it('hands each job to exactly one claimer and runs one job per connection at a time', async () => {
    const claimedIds = new Set<string>();
    let violations = 0;
    let rounds = 0;
    const total = CONNECTIONS * JOBS_PER_CONNECTION;

    // Round one keeps the claimed jobs running: only one per connection may exist.
    const first = await Promise.all(
      Array.from({ length: CLAIMERS }, (_, index) =>
        repositories.jobs.claimNext({ workerId: `w${index}`, leaseMs: 60_000, now: new Date() }),
      ),
    );
    const firstClaims = first.filter((job): job is ExecutionJob => job !== null);
    expect(new Set(firstClaims.map((job) => job.id)).size).toBe(firstClaims.length);
    expect(new Set(firstClaims.map((job) => job.connectionId)).size).toBe(firstClaims.length);
    expect(firstClaims).toHaveLength(CONNECTIONS);
    for (const id of connectionIds) expect(await runningCount(id)).toBe(1);

    for (const job of firstClaims) {
      claimedIds.add(job.id);
      await repositories.jobs.complete(job.id, job.workerId!, {
        status: 'succeeded',
        now: new Date(),
      });
    }

    // Then drain the queue with claimers that complete what they claim.
    while (claimedIds.size < total && rounds < 50) {
      rounds += 1;
      const batch = await Promise.all(
        Array.from({ length: CLAIMERS }, async (_, index) => {
          const workerId = `w${index}`;
          const job = await repositories.jobs.claimNext({
            workerId,
            leaseMs: 60_000,
            now: new Date(),
          });
          if (job === null) return null;
          if ((await runningCount(job.connectionId)) !== 1) violations += 1;
          await repositories.jobs.complete(job.id, workerId, {
            status: 'succeeded',
            now: new Date(),
          });
          return job;
        }),
      );
      for (const job of batch) {
        if (job === null) continue;
        expect(claimedIds.has(job.id)).toBe(false);
        claimedIds.add(job.id);
      }
    }

    expect(violations).toBe(0);
    expect(claimedIds.size).toBe(total);
    const rows = rowsOf(
      await handle.db.execute(
        sql`select status, count(*)::int as n, max(attempt_count)::int as attempts from execution_jobs group by status`,
      ),
    );
    expect(rows).toEqual([{ status: 'succeeded', n: total, attempts: 1 }]);
  });
});
