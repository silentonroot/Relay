import { randomUUID } from 'node:crypto';
import { sql } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { rowsOf } from '../src/client.js';
import { ConflictError, createRepositories } from '../src/index.js';
import type { DatabaseHandle, Repositories } from '../src/index.js';
import {
  addOperationJob,
  at,
  AUTH_MAC,
  authorize,
  capabilityRow,
  consumeInput,
  isPostgres,
  issue,
  jobRow,
  markRunning,
  newToken,
  resetClock,
  seedLogin,
  seedOperation,
  sleep,
  T0,
  TOKEN_MAC,
  TOKEN_TTL,
} from './capability-fixtures.js';
import { fakeSealed, openTestDb, seedTenant } from './helpers.js';
import type { Tenant } from './helpers.js';

/*
 * P3-4 (check and consume are one atomic step) and P3-8 (revocation wins over in-flight work).
 *
 * Every test runs on PGlite and on PostgreSQL. PGlite has one connection, so transactions run
 * one after another: those runs prove the statement outcomes, not lock contention. The
 * "interleaved" tests need two real connections, so they run only when AAB_TEST_DATABASE_URL
 * points at a PostgreSQL server; they hold one transaction open while a second one starts and
 * check that the second one waits for the first and then sees what it committed.
 */

const CONCURRENCY = 20;

let handle: DatabaseHandle;
let repositories: Repositories;
let tenant: Tenant;

beforeAll(async () => {
  handle = await openTestDb();
  repositories = createRepositories(handle.db);
  tenant = await seedTenant(repositories, 'caps-race');
});

afterAll(async () => {
  await handle.close();
});

// The statements compare `now` with the database clock (see capability-fixtures.ts).
beforeEach(resetClock);

const op = () => seedOperation(handle.db, repositories, tenant);
const login = () => seedLogin(handle.db, repositories, tenant);

/** The production revocation transaction (routes/resources.ts), without the HTTP layer. */
function revokeConnection(repos: Repositories, connectionId: string) {
  return (async () => {
    await repos.connections.revoke(tenant.scope, connectionId, {});
    await repos.jobs.cancelForConnection(connectionId, at(5000));
    await repos.vault.deleteForConnection(connectionId, at(5000));
  })();
}

/** A promise that settles when `release` is called, to hold a transaction open. */
function gate() {
  let release!: () => void;
  const opened = new Promise<void>((resolve) => {
    release = resolve;
  });
  return { opened, release };
}

/** True while `promise` is still pending after `ms`. */
async function stillPending(promise: Promise<unknown>, ms = 400): Promise<boolean> {
  let settled = false;
  void promise.then(
    () => {
      settled = true;
    },
    () => {
      settled = true;
    },
  );
  await sleep(ms);
  return !settled;
}

async function versionCount(secretId: string): Promise<number> {
  return rowsOf(
    await handle.db.execute(
      sql`select 1 from vault_secret_versions where secret_id = ${secretId}::uuid`,
    ),
  ).length;
}

async function secretStatus(secretId: string): Promise<string> {
  return String(
    rowsOf(
      await handle.db.execute(sql`select status from vault_secrets where id = ${secretId}::uuid`),
    )[0]!.status,
  );
}

describe('P3-4: one conditional statement per consume', () => {
  it(`redeems a capability exactly once under ${CONCURRENCY} concurrent redemptions`, async () => {
    const f = await op();
    const issued = await issue(handle.db, repositories, f);
    const results = await Promise.all(
      Array.from({ length: CONCURRENCY }, () =>
        repositories.capabilities.consumeRead(consumeInput(issued)),
      ),
    );
    expect(results.filter((result) => result !== null)).toHaveLength(1);
    expect((await capabilityRow(handle.db, issued.capabilityId)).used_at).not.toBeNull();
  });

  it(`redeems a seal capability exactly once under ${CONCURRENCY} concurrent redemptions`, async () => {
    const l = await login();
    const issued = await issue(handle.db, repositories, l);
    const results = await Promise.all(
      Array.from({ length: CONCURRENCY }, () =>
        repositories.capabilities.consumeSeal(consumeInput(issued, { operation: null })),
      ),
    );
    expect(results.filter((result) => result !== null)).toHaveLength(1);
  });

  it('redeems exactly once when the redemptions run in separate transactions that also read the secret', async () => {
    const f = await op();
    const issued = await issue(handle.db, repositories, f);
    const results = await Promise.all(
      Array.from({ length: CONCURRENCY }, () =>
        repositories.transaction(async (tx) => {
          const consumed = await tx.capabilities.consumeRead(consumeInput(issued));
          if (consumed === null) return null;
          return tx.vault.getVersion(consumed.secretId, consumed.secretVersion!);
        }),
      ),
    );
    expect(results.filter((result) => result !== null)).toHaveLength(1);
  });

  it(`issues one token under ${CONCURRENCY} concurrent issues, and the winner is the stored hash`, async () => {
    const f = await op();
    const authorized = await authorize(repositories, f);
    await markRunning(handle.db, f.jobId);
    const attempts = Array.from({ length: CONCURRENCY }, () => newToken().hash);
    const results = await Promise.all(
      attempts.map((tokenHash) =>
        repositories.capabilities.issueToken({
          capabilityId: authorized.capabilityId,
          jobId: f.jobId,
          workerId: 'worker-1',
          attempt: 1,
          tokenHash,
          tokenTtlSeconds: TOKEN_TTL,
          now: at(1000),
          authorizationMac: AUTH_MAC,
          computeTokenMac: () => TOKEN_MAC,
        }),
      ),
    );
    const winners = results.filter((result) => result !== null);
    expect(winners).toHaveLength(1);
    expect((await capabilityRow(handle.db, authorized.capabilityId)).token_hash).toBe(
      winners[0]!.tokenHash,
    );
  });

  it(`authorizes a job once under ${CONCURRENCY} concurrent authorizations`, async () => {
    const f = await op();
    const results = await Promise.allSettled(
      Array.from({ length: CONCURRENCY }, () =>
        repositories.capabilities.insertAuthorization({
          capabilityId: randomUUID(),
          jobId: f.jobId,
          secretId: f.secretId,
          purpose: 'read',
          organizationId: tenant.organization.id,
          agentId: f.agentId,
          connectionId: f.connectionId,
          operation: f.operation,
          argumentsHash: f.argumentsHash,
          now: T0,
          ttlSeconds: 600,
          authorizationMac: AUTH_MAC,
          macKekVersion: 1,
        }),
      ),
    );
    expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
    for (const result of results) {
      if (result.status === 'rejected') expect(result.reason).toBeInstanceOf(ConflictError);
    }
    expect(
      rowsOf(
        await handle.db.execute(
          sql`select 1 from vault_access_capabilities where job_id = ${f.jobId}::uuid`,
        ),
      ),
    ).toHaveLength(1);
  });

  it('moves the active pointer for exactly one of several concurrent logins that expected the same version (P3-9)', async () => {
    const f = await op();
    const results = await Promise.allSettled(
      Array.from({ length: 10 }, (_, index) =>
        repositories.vault.putVersion({
          secretId: f.secretId,
          version: index + 2,
          sealed: fakeSealed(`race-${index}`),
          now: at(10),
          expectedActiveVersion: 1,
        }),
      ),
    );
    expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
    expect(await versionCount(f.secretId)).toBe(1);
  });
});

describe('P3-8: revocation and in-flight work, one commit order after the other', () => {
  it('a revocation that committed first makes the consume change nothing', async () => {
    const f = await op();
    const issued = await issue(handle.db, repositories, f);
    await repositories.transaction((tx) => revokeConnection(tx, f.connectionId));
    const before = await capabilityRow(handle.db, issued.capabilityId);
    expect(await repositories.capabilities.consumeRead(consumeInput(issued))).toBeNull();
    expect(await capabilityRow(handle.db, issued.capabilityId)).toEqual(before);
    expect(before.used_at).toBeNull();
    expect(before.revoked_reason).toBe('connection_revoked');
    expect(await secretStatus(f.secretId)).toBe('revoked');
    expect(await versionCount(f.secretId)).toBe(0);
    expect(
      (
        await repositories.capabilities.describeForRejection({
          ...consumeInput(issued),
          purpose: 'read',
        })
      ).reason,
    ).toBe('revoked');
  });

  it('a revocation that commits second leaves the capability used, the ciphertext gone and the secret revoked', async () => {
    const f = await op();
    const issued = await issue(handle.db, repositories, f);
    expect(await repositories.capabilities.consumeRead(consumeInput(issued))).not.toBeNull();
    await repositories.transaction((tx) => revokeConnection(tx, f.connectionId));
    const row = await capabilityRow(handle.db, issued.capabilityId);
    expect(row.used_at).not.toBeNull();
    expect(await versionCount(f.secretId)).toBe(0);
    expect(await secretStatus(f.secretId)).toBe('revoked');
    expect((await jobRow(handle.db, f.jobId)).cancel_requested_at).not.toBeNull();
    // Nothing can be consumed again, and the secret can never be written again.
    expect(await repositories.capabilities.consumeRead(consumeInput(issued))).toBeNull();
    await expect(
      repositories.vault.putVersion({
        secretId: f.secretId,
        version: 9,
        sealed: fakeSealed('late'),
        now: at(6000),
      }),
    ).rejects.toBeInstanceOf(ConflictError);
  });

  it('a login completion after a committed revocation stores nothing', async () => {
    const l = await login();
    const issued = await issue(handle.db, repositories, l);
    await repositories.transaction((tx) => revokeConnection(tx, l.connectionId));
    expect(
      await repositories.capabilities.consumeSeal(consumeInput(issued, { operation: null })),
    ).toBeNull();
    await expect(
      repositories.vault.putVersion({
        secretId: l.secretId,
        version: 1,
        sealed: fakeSealed('login'),
        now: at(6000),
        expectedActiveVersion: 0,
      }),
    ).rejects.toBeInstanceOf(ConflictError);
    expect(await versionCount(l.secretId)).toBe(0);
    expect(await secretStatus(l.secretId)).toBe('revoked');
  });

  it('a revocation after a committed login completion deletes what was written', async () => {
    const l = await login();
    const issued = await issue(handle.db, repositories, l);
    await repositories.transaction(async (tx) => {
      const consumed = await tx.capabilities.consumeSeal(consumeInput(issued, { operation: null }));
      expect(consumed).not.toBeNull();
      await tx.vault.putVersion({
        secretId: l.secretId,
        version: 1,
        sealed: fakeSealed('login'),
        now: at(3000),
        expectedActiveVersion: consumed!.secretVersion!,
      });
    });
    expect(await versionCount(l.secretId)).toBe(1);
    await repositories.transaction((tx) => revokeConnection(tx, l.connectionId));
    expect(await versionCount(l.secretId)).toBe(0);
    expect(await secretStatus(l.secretId)).toBe('revoked');
  });
});

describe.runIf(isPostgres())(
  'P3-8: interleaved transactions on two connections (PostgreSQL)',
  () => {
    it('a consume that starts while a revocation is uncommitted waits for it and then changes nothing', async () => {
      const f = await op();
      const issued = await issue(handle.db, repositories, f);
      const locked = gate();
      const commit = gate();
      const revoker = handle.db.transaction(async (tx) => {
        await revokeConnection(createRepositories(tx), f.connectionId);
        locked.release();
        await commit.opened;
      });
      await locked.opened;

      const consumer = repositories.capabilities.consumeRead(consumeInput(issued));
      expect(await stillPending(consumer)).toBe(true); // blocked on the connection lock
      commit.release();
      await revoker;
      expect(await consumer).toBeNull();

      const row = await capabilityRow(handle.db, issued.capabilityId);
      expect(row.used_at).toBeNull();
      expect(row.revoked_reason).toBe('connection_revoked');
      expect(await secretStatus(f.secretId)).toBe('revoked');
      expect(await versionCount(f.secretId)).toBe(0);
    });

    it('a revocation that starts while a consume is uncommitted waits for it and then deletes the secret', async () => {
      const f = await op();
      const issued = await issue(handle.db, repositories, f);
      const consumed = gate();
      const commit = gate();
      let record: unknown = null;
      const reader = handle.db.transaction(async (tx) => {
        const repos = createRepositories(tx);
        record = await repos.capabilities.consumeRead(consumeInput(issued));
        if (record !== null) {
          await repos.vault.getVersion(f.secretId, 1);
        }
        consumed.release();
        await commit.opened;
      });
      await consumed.opened;
      expect(record).not.toBeNull();

      const revoker = handle.db.transaction((tx) =>
        revokeConnection(createRepositories(tx), f.connectionId),
      );
      expect(await stillPending(revoker)).toBe(true); // blocked on the connection lock
      commit.release();
      await reader;
      await revoker;

      const row = await capabilityRow(handle.db, issued.capabilityId);
      expect(row.used_at).not.toBeNull();
      expect(await secretStatus(f.secretId)).toBe('revoked');
      expect(await versionCount(f.secretId)).toBe(0);
      expect((await jobRow(handle.db, f.jobId)).cancel_requested_at).not.toBeNull();
    });

    it('a login completion in flight blocks the revocation, which then deletes the stored session', async () => {
      const l = await login();
      const issued = await issue(handle.db, repositories, l);
      const sealed = gate();
      const commit = gate();
      const completion = handle.db.transaction(async (tx) => {
        const repos = createRepositories(tx);
        const consumed = await repos.capabilities.consumeSeal(
          consumeInput(issued, { operation: null }),
        );
        expect(consumed).not.toBeNull();
        await repos.vault.putVersion({
          secretId: l.secretId,
          version: 1,
          sealed: fakeSealed('login'),
          now: at(3000),
          expectedActiveVersion: consumed!.secretVersion!,
        });
        sealed.release();
        await commit.opened;
      });
      await sealed.opened;
      const revoker = handle.db.transaction((tx) =>
        revokeConnection(createRepositories(tx), l.connectionId),
      );
      expect(await stillPending(revoker)).toBe(true);
      commit.release();
      await completion;
      await revoker;
      expect(await versionCount(l.secretId)).toBe(0);
      expect(await secretStatus(l.secretId)).toBe('revoked');
    });

    it('a revocation in flight makes a login completion that starts after it store nothing', async () => {
      const l = await login();
      const issued = await issue(handle.db, repositories, l);
      const locked = gate();
      const commit = gate();
      const revoker = handle.db.transaction(async (tx) => {
        await revokeConnection(createRepositories(tx), l.connectionId);
        locked.release();
        await commit.opened;
      });
      await locked.opened;
      const completion = repositories.transaction(async (tx) => {
        const consumed = await tx.capabilities.consumeSeal(
          consumeInput(issued, { operation: null }),
        );
        if (consumed === null) return 'refused';
        await tx.vault.putVersion({
          secretId: l.secretId,
          version: 1,
          sealed: fakeSealed('login'),
          now: at(3000),
          expectedActiveVersion: consumed.secretVersion!,
        });
        return 'stored';
      });
      expect(await stillPending(completion)).toBe(true);
      commit.release();
      await revoker;
      expect(await completion).toBe('refused');
      expect(await versionCount(l.secretId)).toBe(0);
    });

    it('a rewrap in flight blocks a revocation, which then removes the version; a rewrap after it changes nothing', async () => {
      const f = await op();
      const row = rowsOf(
        await handle.db.execute(
          sql`select id, wrapped_dek, kek_version from vault_secret_versions where secret_id = ${f.secretId}::uuid`,
        ),
      )[0]!;
      const rewrapInput = {
        versionId: String(row.id),
        fromKekVersion: 1,
        expectedWrappedDek: Buffer.from(row.wrapped_dek as Uint8Array),
        toKekVersion: 2,
        newWrappedDek: Buffer.from('rewrapped'),
        now: at(100),
      };
      const rewrapped = gate();
      const commit = gate();
      const rewrap = handle.db.transaction(async (tx) => {
        expect(await createRepositories(tx).vault.rewrapVersion(rewrapInput)).toBe(true);
        rewrapped.release();
        await commit.opened;
      });
      await rewrapped.opened;
      const revoker = handle.db.transaction((tx) =>
        revokeConnection(createRepositories(tx), f.connectionId),
      );
      expect(await stillPending(revoker)).toBe(true);
      commit.release();
      await rewrap;
      await revoker;
      expect(await versionCount(f.secretId)).toBe(0);

      // The other order: revocation first, rewrap second.
      const g = await op();
      const gRow = rowsOf(
        await handle.db.execute(
          sql`select id, wrapped_dek from vault_secret_versions where secret_id = ${g.secretId}::uuid`,
        ),
      )[0]!;
      const locked = gate();
      const hold = gate();
      const revoker2 = handle.db.transaction(async (tx) => {
        await revokeConnection(createRepositories(tx), g.connectionId);
        locked.release();
        await hold.opened;
      });
      await locked.opened;
      const late = repositories.vault.rewrapVersion({
        ...rewrapInput,
        versionId: String(gRow.id),
        expectedWrappedDek: Buffer.from(gRow.wrapped_dek as Uint8Array),
      });
      expect(await stillPending(late)).toBe(true);
      hold.release();
      await revoker2;
      expect(await late).toBe(false);
      expect(await versionCount(g.secretId)).toBe(0);
    });

    it('a grant revoked while a consume is uncommitted does not undo the consume, and one that commits first blocks it', async () => {
      // Revocation first: the consume statement waits on the capability row and sees revoked_at.
      const f = await op();
      const issued = await issue(handle.db, repositories, f);
      const revoked = gate();
      const commit = gate();
      const revoker = handle.db.transaction(async (tx) => {
        await createRepositories(tx).capabilities.revokeForAgentConnection({
          agentId: f.agentId,
          connectionId: f.connectionId,
          reason: 'grant_revoked',
          now: at(1500),
        });
        revoked.release();
        await commit.opened;
      });
      await revoked.opened;
      const consumer = repositories.capabilities.consumeRead(consumeInput(issued));
      expect(await stillPending(consumer)).toBe(true);
      commit.release();
      await revoker;
      expect(await consumer).toBeNull();
      expect((await capabilityRow(handle.db, issued.capabilityId)).used_at).toBeNull();

      // Consume first: the revocation skips the used capability.
      const g = await op();
      const gIssued = await issue(handle.db, repositories, g);
      const used = gate();
      const hold = gate();
      const reader = handle.db.transaction(async (tx) => {
        expect(
          await createRepositories(tx).capabilities.consumeRead(consumeInput(gIssued)),
        ).not.toBeNull();
        used.release();
        await hold.opened;
      });
      await used.opened;
      const late = repositories.capabilities.revokeForAgentConnection({
        agentId: g.agentId,
        connectionId: g.connectionId,
        reason: 'grant_revoked',
        now: at(2500),
      });
      expect(await stillPending(late)).toBe(true);
      hold.release();
      await reader;
      expect((await late).revoked).toBe(0);
      const row = await capabilityRow(handle.db, gIssued.capabilityId);
      expect(row.used_at).not.toBeNull();
      expect(row.revoked_at).toBeNull();
    });
  },
);

describe.runIf(isPostgres())(
  'review fixes: authorization, lease recovery and revocation order (PostgreSQL)',
  () => {
    const sqlStatus = async (jobId: string) => String((await jobRow(handle.db, jobId)).status);

    /** An authorization that waits for `locker`'s uncommitted revocation, then is refused. */
    async function authorizationWaitsFor(
      name: string,
      revoke: (tx: Repositories, f: Awaited<ReturnType<typeof op>>) => Promise<unknown>,
    ) {
      const f = await op();
      const locked = gate();
      const commit = gate();
      const revoker = handle.db.transaction(async (tx) => {
        await revoke(createRepositories(tx), f);
        locked.release();
        await commit.opened;
      });
      await locked.opened;
      const authorizing = authorize(repositories, f).then(
        () => 'authorized' as const,
        (error: unknown) => error,
      );
      expect(await stillPending(authorizing), `${name}: authorization did not wait`).toBe(true);
      commit.release();
      await revoker;
      expect(await authorizing).toBeInstanceOf(ConflictError);
      expect((await jobRow(handle.db, f.jobId)).capability_ref).toBeNull();
      expect(
        rowsOf(
          await handle.db.execute(
            sql`select 1 from vault_access_capabilities where job_id = ${f.jobId}::uuid`,
          ),
        ),
      ).toHaveLength(0);
    }

    it('an authorization that starts while a grant revocation is uncommitted waits for it and is refused (M1)', async () => {
      await authorizationWaitsFor('grants.revoke', (repos, f) =>
        repos.grants.revoke(tenant.scope, f.agentId, f.grantId!, at(500)),
      );
    });

    it('an authorization that starts while an agent disable is uncommitted waits for it and is refused (M1)', async () => {
      await authorizationWaitsFor('agents.disable', (repos, f) =>
        repos.agents.disable(tenant.scope, f.agentId),
      );
    });

    it('an authorization that committed first is revoked by the grant revocation that waited for it (M1)', async () => {
      const f = await op();
      const authorizing = gate();
      const commit = gate();
      let capabilityId = '';
      const authorizer = handle.db.transaction(async (tx) => {
        capabilityId = (await authorize(createRepositories(tx), f)).capabilityId;
        authorizing.release();
        await commit.opened;
      });
      await authorizing.opened;
      const revoking = repositories.grants.revoke(tenant.scope, f.agentId, f.grantId!, at(500));
      expect(await stillPending(revoking)).toBe(true); // the agent row is held FOR SHARE
      commit.release();
      await authorizer;
      await revoking;
      expect((await capabilityRow(handle.db, capabilityId)).revoked_reason).toBe('grant_revoked');
    });

    it('a lease recovery that decided to requeue, then an issueToken, then the recovery commit: no token, a consistent job (M3)', async () => {
      const f = await op();
      const authorized = await authorize(repositories, f);
      await markRunning(handle.db, f.jobId);
      const decided = gate();
      const commit = gate();
      const recovery = handle.db.transaction(async (tx) => {
        const changed = await createRepositories(tx).jobs.recoverExpiredLeases({
          now: at(61_000),
          maxAttempts: 3,
          capabilityAware: true,
        });
        expect(changed.map((job) => [job.id, job.status])).toContainEqual([f.jobId, 'queued']);
        decided.release();
        await commit.opened;
      });
      await decided.opened;

      const issuing = repositories.capabilities.issueToken({
        capabilityId: authorized.capabilityId,
        jobId: f.jobId,
        workerId: 'worker-1',
        attempt: 1,
        tokenHash: newToken().hash,
        tokenTtlSeconds: TOKEN_TTL,
        now: at(1000),
        authorizationMac: AUTH_MAC,
        computeTokenMac: () => TOKEN_MAC,
      });
      expect(await stillPending(issuing)).toBe(true); // waits for the recovery's job lock
      commit.release();
      await recovery;
      expect(await issuing).toBeNull();

      const row = await capabilityRow(handle.db, authorized.capabilityId);
      expect(row.token_hash).toBeNull();
      expect(row.token_mac).toBeNull();
      expect(await sqlStatus(f.jobId)).toBe('queued');
      expect(String((await jobRow(handle.db, f.jobId)).capability_ref)).toBe(
        authorized.capabilityId,
      );
      expect(row.revoked_at).toBeNull(); // the retry may still be issued a token
    });

    it('an issueToken in flight hides the job from a lease recovery, which then fails the job and revokes the capability (M3)', async () => {
      const f = await op();
      const authorized = await authorize(repositories, f);
      await markRunning(handle.db, f.jobId);
      const issued = gate();
      const commit = gate();
      const issuer = handle.db.transaction(async (tx) => {
        const record = await createRepositories(tx).capabilities.issueToken({
          capabilityId: authorized.capabilityId,
          jobId: f.jobId,
          workerId: 'worker-1',
          attempt: 1,
          tokenHash: newToken().hash,
          tokenTtlSeconds: TOKEN_TTL,
          now: at(1000),
          authorizationMac: AUTH_MAC,
          computeTokenMac: () => TOKEN_MAC,
        });
        expect(record).not.toBeNull();
        issued.release();
        await commit.opened;
      });
      await issued.opened;
      const recoverInput = { now: at(61_000), maxAttempts: 3, capabilityAware: true } as const;
      // The job row is locked by the issuer: the recovery skips it this round.
      expect(await repositories.jobs.recoverExpiredLeases(recoverInput)).toEqual([]);
      commit.release();
      await issuer;

      const [job] = await repositories.jobs.recoverExpiredLeases(recoverInput);
      expect(job).toMatchObject({
        id: f.jobId,
        status: 'failed',
        error: { code: 'worker_failure' },
      });
      expect((await capabilityRow(handle.db, authorized.capabilityId)).revoked_reason).toBe(
        'lease_recovery',
      );
      const row = await capabilityRow(handle.db, authorized.capabilityId);
      expect(
        await repositories.capabilities.consumeRead({
          tokenHash: String(row.token_hash),
          jobId: f.jobId,
          connectionId: f.connectionId,
          operation: f.operation,
          now: at(2000),
        }),
      ).toBeNull();
    });

    it('disabling an agent while its connection is revoked completes, repeatedly, without a deadlock (L3)', async () => {
      for (let run = 0; run < 6; run += 1) {
        const f = await op();
        const jobs = [f];
        for (let index = 0; index < 5; index += 1)
          jobs.push(await addOperationJob(repositories, f));
        const capabilityIds = [];
        for (const job of jobs)
          capabilityIds.push((await authorize(repositories, job)).capabilityId);

        const outcomes = await Promise.allSettled([
          repositories.agents.disable(tenant.scope, f.agentId),
          repositories.connections.revoke(tenant.scope, f.connectionId, {}),
          repositories.grants.revoke(tenant.scope, f.agentId, f.grantId!, at(500)),
          repositories.agents.disable(tenant.scope, f.agentId),
        ]);
        for (const outcome of outcomes) {
          if (outcome.status === 'rejected') throw outcome.reason;
        }
        const rows = rowsOf(
          await handle.db.execute(
            sql`select revoked_at, revoked_reason from vault_access_capabilities where job_id in (${sql.join(
              jobs.map((job) => sql`${job.jobId}::uuid`),
              sql`, `,
            )})`,
          ),
        );
        expect(rows).toHaveLength(6);
        expect(rows.every((row) => row.revoked_at !== null)).toBe(true);
      }
    });
  },
);
