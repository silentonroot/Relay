import { readdir } from 'node:fs/promises';
import { afterAll, describe, expect, it } from 'vitest';
import { rowsOf } from '../../../packages/database/src/client.js';
import {
  addKek,
  auditEvents,
  errorCode,
  execSql,
  ok,
  openStored,
  prepare,
  readParams,
  seedSealedOperation,
  seedTenant,
  sql,
  startService,
} from './service-helpers.js';
import type { SealedOperation, Service, Tenant } from './service-helpers.js';

const cleanups: Array<() => Promise<void>> = [];
afterAll(async () => {
  for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
});

/** A vault with KEK v1 and `count` sealed sessions, restarted with KEK v1 and v2 loaded. */
async function rotated(count: number, operations?: Parameters<typeof startService>[0]) {
  const first = await startService();
  cleanups.push(() => first.cleanup());
  const sealed: Array<{ tenant: Tenant; op: SealedOperation }> = [];
  for (let i = 0; i < count; i += 1) {
    const tenant = await seedTenant(first.repos, `rw-${i}`);
    sealed.push({ tenant, op: await seedSealedOperation(first, tenant, `session-${i}`) });
  }
  await first.stop();
  await addKek(first.kekDir, 2);
  const second = await startService({ reuse: first, ...operations });
  cleanups.push(() => second.cleanup());
  return { first, second, sealed };
}

const versionsByKek = async (service: Service) =>
  ok(await service.rpc('admin', 'status', {}))['versionsByKek'] as Record<string, number>;

const cipherColumns = async (service: Service) =>
  rowsOf(
    await service.db.execute(
      sql`select id, encode(ciphertext,'hex') as c, encode(nonce,'hex') as n, encode(auth_tag,'hex') as t
          from vault_secret_versions order by id`,
    ),
  );

describe('rewrap from KEK v1 to v2 (P3-9)', () => {
  it('moves every wrapped key to the active KEK, keeps the ciphertext, and reads still work', async () => {
    const { second, sealed, first } = await rotated(5);
    expect(await versionsByKek(second)).toEqual({ '1': 5 });
    expect(ok(await second.rpc('admin', 'kekRetirementCheck', { kekVersion: 1 }))).toEqual({
      referencingVersions: 5,
      safeToRemove: false,
    });
    const before = await cipherColumns(second);

    const result = ok(await second.rpc('admin', 'rewrap', { batchSize: 2, maxBatches: 10 }));
    expect(result).toEqual({ rewrapped: 5, skipped: 0, failed: 0, remaining: 0 });
    expect(await versionsByKek(second)).toEqual({ '2': 5 });
    // Only wrapped_dek and kek_version change; the ciphertext, nonce and tag are untouched.
    expect(await cipherColumns(second)).toEqual(before);
    expect(ok(await second.rpc('admin', 'kekRetirementCheck', { kekVersion: 1 }))).toEqual({
      referencingVersions: 0,
      safeToRemove: true,
    });
    // The current KEK is never reported safe to remove.
    expect(ok(await second.rpc('admin', 'kekRetirementCheck', { kekVersion: 2 }))).toMatchObject({
      safeToRemove: false,
    });

    for (const { tenant, op } of sealed) {
      expect(await openStored(second, tenant, op.connectionId)).toBe(op.plaintext);
    }
    // And through the vault, with the capability flow: the read reports the new KEK version.
    const { tenant, op } = sealed[0]!;
    const fresh = await seedTenant(second.repos, 'rw-after');
    void tenant;
    void op;
    const another = await seedSealedOperation(second, fresh);
    const prepared = await prepare(second, another);
    expect(ok(await second.rpc('supervisor', 'readForWorker', readParams(prepared)))).toMatchObject(
      {
        kekVersion: 2,
      },
    );
    // One audit event per row, naming both versions and no key bytes.
    const events = await Promise.all(
      sealed.map(({ tenant }) =>
        auditEvents(second, tenant.organization.id, 'vault.secret_rewrapped'),
      ),
    );
    for (const list of events) {
      expect(list).toHaveLength(1);
      expect(list[0]!['metadata']).toMatchObject({ keyVersionFrom: 1, keyVersionTo: 2 });
    }

    // Re-running is a no-op: nothing to do, no new events.
    expect(ok(await second.rpc('admin', 'rewrap', { batchSize: 2, maxBatches: 10 }))).toEqual({
      rewrapped: 0,
      skipped: 0,
      failed: 0,
      remaining: 0,
    });
    const eventsAfter = await Promise.all(
      sealed.map(({ tenant }) =>
        auditEvents(second, tenant.organization.id, 'vault.secret_rewrapped'),
      ),
    );
    expect(eventsAfter.map((list) => list.length)).toEqual([1, 1, 1, 1, 1]);
    // The vault never deletes a key file (P3-20).
    expect((await readdir(first.kekDir)).sort()).toEqual(['kek-v1.key', 'kek-v2.key']);
  });

  it('a crash after N rows leaves every row openable, and re-running continues where it stopped', async () => {
    let crashAt: number | null = 3;
    const { second, sealed } = await rotated(6, {
      operations: {
        afterRewrapRow: (count) => {
          if (crashAt !== null && count === crashAt) throw new Error('simulated crash');
        },
      },
    });
    const crashed = await second.rpc('admin', 'rewrap', { batchSize: 2, maxBatches: 10 });
    expect(errorCode(crashed)).toBe('service_unavailable');
    expect(await versionsByKek(second)).toEqual({ '1': 3, '2': 3 });
    // Every row, rewrapped or not, still opens with the loaded keys.
    for (const { tenant, op } of sealed) {
      expect(await openStored(second, tenant, op.connectionId)).toBe(op.plaintext);
    }
    // A concurrent-looking second call is allowed again (the crashed run released its lock).
    crashAt = null;
    expect(ok(await second.rpc('admin', 'rewrap', { batchSize: 2, maxBatches: 10 }))).toEqual({
      rewrapped: 3,
      skipped: 0,
      failed: 0,
      remaining: 0,
    });
    expect(await versionsByKek(second)).toEqual({ '2': 6 });
    for (const { tenant, op } of sealed) {
      expect(await openStored(second, tenant, op.connectionId)).toBe(op.plaintext);
    }
  });

  it('skips versions that were replaced while the batch was being rewrapped', async () => {
    const holder: { service?: Service } = {};
    let changed = false;
    const { second, sealed } = await rotated(4, {
      operations: {
        afterRewrapRow: async () => {
          if (changed || holder.service === undefined) return;
          changed = true;
          // Another writer replaces the wrapped key of every row that is still on KEK v1, after
          // the batch was listed: the compare-and-set on (kek_version, wrapped_dek) cannot match.
          await execSql(
            holder.service,
            sql`update vault_secret_versions
                set wrapped_dek = set_byte(wrapped_dek, 0, get_byte(wrapped_dek, 0) # 255)
                where kek_version = 1`,
          );
        },
      },
    });
    holder.service = second;
    const result = ok(await second.rpc('admin', 'rewrap', { batchSize: 10, maxBatches: 1 }));
    expect(result).toEqual({ rewrapped: 1, skipped: 3, failed: 0, remaining: 3 });
    // The skipped rows were not rewrapped and were not resurrected or deleted; a later run
    // counts them as failed (they no longer unwrap), it never changes them.
    expect(await versionsByKek(second)).toEqual({ '1': 3, '2': 1 });
    expect(ok(await second.rpc('admin', 'rewrap', { batchSize: 10, maxBatches: 1 }))).toEqual({
      rewrapped: 0,
      skipped: 0,
      failed: 3,
      remaining: 3,
    });
    expect(sealed).toHaveLength(4);
  });

  it('a failing audit append rolls the row back: nothing is rewrapped', async () => {
    const { second } = await rotated(2);
    await execSql(
      second,
      sql.raw(`create function aab_test_fail_rewrap() returns trigger as $$
        begin
          if new.event_type = 'vault.secret_rewrapped' then raise exception 'simulated'; end if;
          return new;
        end $$ language plpgsql`),
    );
    await execSql(
      second,
      sql.raw(
        'create trigger aab_test_fail_rewrap before insert on audit_events for each row execute function aab_test_fail_rewrap()',
      ),
    );
    expect(errorCode(await second.rpc('admin', 'rewrap', { batchSize: 10, maxBatches: 1 }))).toBe(
      'service_unavailable',
    );
    expect(await versionsByKek(second)).toEqual({ '1': 2 });
  });
});
