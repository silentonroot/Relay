import { sql } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createRepositories } from '../src/index.js';
import type { DatabaseHandle, Repositories } from '../src/index.js';
import { authorize, jobRow, resetClock, seedOperation } from './capability-fixtures.js';
import { openTestDb, seedTenant } from './helpers.js';
import type { Tenant } from './helpers.js';

/* B3a: failQueuedWithoutCapability and listQueuedWithoutCapability (ADR-014 sections 5 and 9). */

let handle: DatabaseHandle;
let repositories: Repositories;
let tenant: Tenant;

beforeAll(async () => {
  handle = await openTestDb();
  repositories = createRepositories(handle.db);
  tenant = await seedTenant(repositories, 'job-vault-failure');
});
afterAll(async () => {
  await handle.close();
});
beforeEach(async () => {
  resetClock();
  await handle.db.execute(
    sql`update execution_jobs set status = 'cancelled' where status in ('queued', 'running')`,
  );
});

const unavailable = {
  code: 'vault_unavailable',
  message: 'The vault could not be reached.',
} as const;
const queuedJob = async () => (await seedOperation(handle.db, repositories, tenant)).jobId;
const row = (jobId: string) => jobRow(handle.db, jobId);
const now = () => new Date();

describe('jobs.failQueuedWithoutCapability', () => {
  it('fails a queued job with no capability, with the error and finish time', async () => {
    const jobId = await queuedJob();
    const at = now();
    const failed = await repositories.jobs.failQueuedWithoutCapability(jobId, {
      error: unavailable,
      now: at,
    });
    expect(failed).toMatchObject({
      id: jobId,
      status: 'failed',
      error: { code: 'vault_unavailable', message: unavailable.message },
    });
    expect(await row(jobId)).toMatchObject({ status: 'failed', error_code: 'vault_unavailable' });
  });

  it('does NOT fail a job that got a capability in between', async () => {
    const f = await seedOperation(handle.db, repositories, tenant);
    await authorize(repositories, f);
    expect((await row(f.jobId))['capability_ref']).not.toBeNull();
    expect(
      await repositories.jobs.failQueuedWithoutCapability(f.jobId, {
        error: { code: 'vault_denied', message: 'x' },
        now: now(),
      }),
    ).toBeNull();
    expect(await row(f.jobId)).toMatchObject({ status: 'queued', error_code: null });
  });

  it('leaves a claimed, finished or unknown job alone', async () => {
    const running = await queuedJob();
    await handle.db.execute(
      sql`update execution_jobs set status = 'running', worker_id = 'w', attempt_count = 1 where id = ${running}::uuid`,
    );
    const cancelled = await queuedJob();
    await handle.db.execute(
      sql`update execution_jobs set status = 'cancelled' where id = ${cancelled}::uuid`,
    );
    for (const id of [running, cancelled, '00000000-0000-4000-8000-000000000000', 'nope']) {
      expect(
        await repositories.jobs.failQueuedWithoutCapability(id, { error: unavailable, now: now() }),
      ).toBeNull();
    }
    expect(await row(running)).toMatchObject({ status: 'running' });
    expect(await row(cancelled)).toMatchObject({ status: 'cancelled' });
  });

  it('is a single winner when two callers race', async () => {
    const jobId = await queuedJob();
    const results = await Promise.all(
      [1, 2, 3].map(() =>
        repositories.jobs.failQueuedWithoutCapability(jobId, { error: unavailable, now: now() }),
      ),
    );
    expect(results.filter((result) => result !== null)).toHaveLength(1);
  });
});

describe('jobs.listQueuedWithoutCapability', () => {
  it('lists old queued jobs without a capability, oldest first, bounded by the limit', async () => {
    const first = await queuedJob();
    const second = await queuedJob();
    const third = await queuedJob();
    const authorized = await seedOperation(handle.db, repositories, tenant);
    await authorize(repositories, authorized);
    await handle.db.execute(
      sql`update execution_jobs set created_at = now() - interval '10 minutes' where id = ${first}::uuid`,
    );
    await handle.db.execute(
      sql`update execution_jobs set created_at = now() - interval '5 minutes' where id = ${second}::uuid`,
    );
    // Age in seconds, judged on the database's clock (statement_timestamp()), not the caller's.
    const cutoff = 60;
    const all = await repositories.jobs.listQueuedWithoutCapability(cutoff, 10);
    // `third` is newer than the cutoff, the authorized job has a capability.
    expect(all.map((job) => job.id)).toEqual([first, second]);
    expect(all.map((job) => job.id)).not.toContain(third);
    expect(all.map((job) => job.id)).not.toContain(authorized.jobId);
    expect(
      (await repositories.jobs.listQueuedWithoutCapability(cutoff, 1)).map((j) => j.id),
    ).toEqual([first]);
    await expect(repositories.jobs.listQueuedWithoutCapability(cutoff, 0)).rejects.toThrow();
    await expect(repositories.jobs.listQueuedWithoutCapability(-1, 5)).rejects.toThrow();
  });
});
