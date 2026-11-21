import { randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  auditEvents,
  capabilityRowOf,
  CANARY,
  execSql,
  isPlainForbidden,
  ok,
  prepare,
  readParams,
  rejectedReasons,
  seedSealedOperation,
  seedTenant,
  sql,
  startService,
} from './service-helpers.js';
import type { Service } from './service-helpers.js';

let service: Service;
beforeAll(async () => {
  service = await startService();
});
afterAll(async () => {
  await service.cleanup();
});

const FORGED = 'c'.repeat(64);

describe('P3-6: freshness and uniqueness are inside the MACs', () => {
  it('a job the API did not authorize yields no token (a row inserted by a database writer)', async () => {
    const tenant = await seedTenant(service.repos, 'forged-insert');
    const op = await seedSealedOperation(service, tenant);
    const capabilityId = '5a5a5a5a-5a5a-45a5-85a5-5a5a5a5a5a5a';
    // A writer with database access inserts a capability and points the job at it, MAC and all.
    await execSql(
      service,
      sql`insert into vault_access_capabilities
            (id, organization_id, job_id, agent_id, connection_id, secret_id, purpose, operation,
             arguments_hash, issued_at, expires_at, authorization_mac, mac_kek_version)
          select ${capabilityId}::uuid, j.organization_id, j.id, j.agent_id, j.connection_id,
                 ${op.secretId}::uuid, 'read', j.operation, j.arguments_hash,
                 now(), now() + interval '10 minutes', ${FORGED}, 1
          from execution_jobs as j where j.id = ${op.jobId}::uuid`,
    );
    await execSql(
      service,
      sql`update execution_jobs set capability_ref = ${capabilityId}::uuid, status = 'running',
            worker_id = 'worker-1', attempt_count = 1 where id = ${op.jobId}::uuid`,
    );
    const response = await service.rpc('supervisor', 'issueAccessCapability', {
      capabilityId,
      jobId: op.jobId,
      workerId: 'worker-1',
      attempt: 1,
      ttlSeconds: 30,
    });
    expect(isPlainForbidden(response)).toBe(true);
    expect((await capabilityRowOf(service, capabilityId))['token_hash']).toBeNull();
    expect(await rejectedReasons(service, tenant.organization.id)).toEqual(['integrity']);
  });

  it('an authorization edited before issue yields no token', async () => {
    const tenant = await seedTenant(service.repos, 'forged-auth-before');
    const op = await seedSealedOperation(service, tenant);
    const authorized = ok(
      await service.rpc('api', 'authorizeJobAccess', { jobId: op.jobId, ttlSeconds: 600 }),
    );
    // Stretch the window by a database edit: the MAC no longer matches the row.
    await execSql(
      service,
      sql`update vault_access_capabilities set expires_at = expires_at + interval '30 minutes'
          where id = ${authorized['capabilityId'] as string}::uuid`,
    );
    await execSql(
      service,
      sql`update execution_jobs set status = 'running', worker_id = 'worker-1', attempt_count = 1 where id = ${op.jobId}::uuid`,
    );
    const response = await service.rpc('supervisor', 'issueAccessCapability', {
      capabilityId: authorized['capabilityId'],
      jobId: op.jobId,
      workerId: 'worker-1',
      attempt: 1,
      ttlSeconds: 30,
    });
    expect(isPlainForbidden(response)).toBe(true);
    expect(
      (await capabilityRowOf(service, authorized['capabilityId'] as string))['token_hash'],
    ).toBeNull();
    expect(await rejectedReasons(service, tenant.organization.id)).toEqual(['integrity']);
  });

  it('an unknown capability id yields no token', async () => {
    const tenant = await seedTenant(service.repos, 'unknown-capability');
    const op = await seedSealedOperation(service, tenant);
    await execSql(
      service,
      sql`update execution_jobs set status = 'running', worker_id = 'worker-1', attempt_count = 1 where id = ${op.jobId}::uuid`,
    );
    const response = await service.rpc('supervisor', 'issueAccessCapability', {
      capabilityId: '99999999-9999-4999-8999-999999999999',
      jobId: op.jobId,
      workerId: 'worker-1',
      attempt: 1,
      ttlSeconds: 30,
    });
    expect(isPlainForbidden(response)).toBe(true);
    expect(await rejectedReasons(service, tenant.organization.id)).toEqual(['unknown_token']);
  });

  const edits: Array<[string, (id: string) => ReturnType<typeof sql>]> = [
    [
      'authorization MAC',
      (id) =>
        sql`update vault_access_capabilities set authorization_mac = ${FORGED} where id = ${id}::uuid`,
    ],
    [
      'token MAC',
      (id) =>
        sql`update vault_access_capabilities set token_mac = ${FORGED} where id = ${id}::uuid`,
    ],
    [
      'binding (arguments hash)',
      (id) =>
        sql`update vault_access_capabilities set arguments_hash = ${'d'.repeat(64)} where id = ${id}::uuid`,
    ],
    [
      'binding (token expiry stretched)',
      (id) =>
        sql`update vault_access_capabilities set token_expires_at = token_expires_at + interval '1 minute' where id = ${id}::uuid`,
    ],
    [
      'binding (secret version)',
      (id) =>
        sql`update vault_access_capabilities set secret_version = secret_version + 1 where id = ${id}::uuid`,
    ],
  ];
  it.each(edits)(
    'a forged %s after issue is refused as integrity, spends the capability and returns no plaintext',
    async (_name, edit) => {
      const tenant = await seedTenant(service.repos, 'forged-after');
      const op = await seedSealedOperation(service, tenant);
      const prepared = await prepare(service, op);
      await execSql(service, edit(prepared.capabilityId));
      const response = await service.rpc('supervisor', 'readForWorker', readParams(prepared));
      // secret_version edits make the consume itself refuse (the version no longer matches);
      // the others pass the statement and fail the MAC check.
      expect(isPlainForbidden(response)).toBe(true);
      expect(JSON.stringify(response)).not.toContain(CANARY);
      const reasons = await rejectedReasons(service, tenant.organization.id);
      expect(reasons).toHaveLength(1);
      expect(['integrity', 'secret_not_active']).toContain(reasons[0]);
      expect(await auditEvents(service, tenant.organization.id, 'vault.secret_read')).toHaveLength(
        0,
      );
      if (reasons[0] === 'integrity') {
        // Spent with its rejection event, committed together (ADR-014 section 6).
        expect((await capabilityRowOf(service, prepared.capabilityId))['used_at']).not.toBeNull();
        const again = await service.rpc('supervisor', 'readForWorker', readParams(prepared));
        expect(isPlainForbidden(again)).toBe(true);
        expect(await rejectedReasons(service, tenant.organization.id)).toEqual([
          'integrity',
          'used',
        ]);
      }
    },
  );

  it('a cleared token MAC makes the capability unusable (integrity)', async () => {
    const tenant = await seedTenant(service.repos, 'no-token-mac');
    const op = await seedSealedOperation(service, tenant);
    const prepared = await prepare(service, op);
    await execSql(
      service,
      sql`update vault_access_capabilities set token_mac = null where id = ${prepared.capabilityId}::uuid`,
    );
    const response = await service.rpc('supervisor', 'readForWorker', readParams(prepared));
    expect(isPlainForbidden(response)).toBe(true);
    expect(await rejectedReasons(service, tenant.organization.id)).toEqual(['integrity']);
  });

  it('an unknown token is refused as unknown_token and attributed to the presented job', async () => {
    const tenant = await seedTenant(service.repos, 'unknown-token');
    const op = await seedSealedOperation(service, tenant);
    const guess = randomBytes(32).toString('base64url');
    const response = await service.rpc('supervisor', 'readForWorker', {
      token: guess,
      jobId: op.jobId,
      connectionId: op.connectionId,
      operation: op.operation,
    });
    expect(isPlainForbidden(response)).toBe(true);
    expect(await rejectedReasons(service, tenant.organization.id)).toEqual(['unknown_token']);
  });

  it('an unknown token for an unknown job cannot go on a chain: logged and counted, not audited', async () => {
    const before = ok(await service.rpc('admin', 'status', {}))['counters'] as Record<
      string,
      number
    >;
    const response = await service.rpc('supervisor', 'readForWorker', {
      token: randomBytes(32).toString('base64url'),
      jobId: '99999999-9999-4999-8999-999999999998',
      connectionId: '99999999-9999-4999-8999-999999999997',
      operation: 'orders.list',
    });
    expect(isPlainForbidden(response)).toBe(true);
    const after = ok(await service.rpc('admin', 'status', {}))['counters'] as Record<
      string,
      number
    >;
    expect(after['rejectedUnattributed']).toBe(before['rejectedUnattributed']! + 1);
    expect(service.log.text()).toContain('resolved to no organization');
  });
});

/*
 * VS-1 RESIDUAL. These tests DOCUMENT a gap; they do not show that the design is safe.
 *
 * `used_at` and `revoked_at` are not covered by either MAC (services/vault/src/mac.ts), and the
 * consume statement judges them as plain columns (`c.used_at is null and c.revoked_at is null`). So
 * a writer with database access who also holds a spent token can clear `used_at` and redeem it
 * again inside its windows (`token_expires_at`, `expires_at`), and one who clears `revoked_at` of a
 * capability that was revoked while its connection and secret are still active can reopen it (when
 * the connection itself is revoked, its status and the secret's, checked in the same statement, still
 * stop the read: that case is not exercised here). The
 * token hash, the bindings, the windows, the running job and the connection and secret checks of the
 * same statement still apply; what the writer gains is the repeat. Closing it needs the spent and
 * revoked states to be inside the MAC (or an append-only record): not done in Phase 3 (docs/threat-model.md VS-1).
 */
describe('VS-1 residual (documents the gap, proves nothing about safety): used_at and revoked_at are not under the MAC', () => {
  it('a database writer with a spent token clears used_at and redeems it a second time', async () => {
    const tenant = await seedTenant(service.repos, 'residual-rearm-used');
    const op = await seedSealedOperation(service, tenant);
    const prepared = await prepare(service, op);
    ok(await service.rpc('supervisor', 'readForWorker', readParams(prepared)));
    const spent = await service.rpc('supervisor', 'readForWorker', readParams(prepared));
    expect(isPlainForbidden(spent)).toBe(true);
    expect(await rejectedReasons(service, tenant.organization.id)).toEqual(['used']);

    // The re-arm: one column, no MAC to fail (the vault cannot tell the row was edited).
    await execSql(
      service,
      sql`update vault_access_capabilities set used_at = null where id = ${prepared.capabilityId}::uuid`,
    );
    const again = await service.rpc('supervisor', 'readForWorker', readParams(prepared));
    // RESIDUAL: this is accepted. The answer is the same session again, and a second read is audited.
    expect(again['ok']).toBe(true);
    expect(JSON.stringify(again)).toContain('plaintext');
    expect(await auditEvents(service, tenant.organization.id, 'vault.secret_read')).toHaveLength(2);
    // It is spent again after that read.
    const spentAgain = await service.rpc('supervisor', 'readForWorker', readParams(prepared));
    expect(isPlainForbidden(spentAgain)).toBe(true);
  });

  it('a database writer clears revoked_at of a revoked capability (its connection and secret still active) and redeems it', async () => {
    const tenant = await seedTenant(service.repos, 'residual-rearm-revoked');
    const op = await seedSealedOperation(service, tenant);
    const prepared = await prepare(service, op);
    await service.repos.capabilities.revokeForConnection({
      connectionId: op.connectionId,
      reason: 'owner_requested',
      now: new Date(),
    });
    const refused = await service.rpc('supervisor', 'readForWorker', readParams(prepared));
    expect(isPlainForbidden(refused)).toBe(true);
    expect(await rejectedReasons(service, tenant.organization.id)).toEqual(['revoked']);

    await execSql(
      service,
      sql`update vault_access_capabilities set revoked_at = null, revoked_reason = null where id = ${prepared.capabilityId}::uuid`,
    );
    const again = await service.rpc('supervisor', 'readForWorker', readParams(prepared));
    // RESIDUAL: accepted, because nothing but the capability row says it was revoked here.
    expect(again['ok']).toBe(true);
  });
});
