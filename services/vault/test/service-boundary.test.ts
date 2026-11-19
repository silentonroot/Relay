import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { hashToken } from '@aab/crypto';
import {
  auditEvents,
  capabilityRowOf,
  CANARY,
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
import type { Service } from './service-helpers.js';

let service: Service;
beforeAll(async () => {
  service = await startService();
});
afterAll(async () => {
  await service.cleanup();
});

describe('authorize -> issue -> read (the happy path through the sockets)', () => {
  it('returns the plaintext once, with its metadata, and writes the audit trail in order', async () => {
    const tenant = await seedTenant(service.repos, 'happy');
    const op = await seedSealedOperation(service, tenant);
    const prepared = await prepare(service, op);
    expect(prepared.token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(prepared.secretVersion).toBe(1);

    const read = ok(await service.rpc('supervisor', 'readForWorker', readParams(prepared)));
    expect(read).toMatchObject({
      secretType: 'session_snapshot',
      secretVersion: 1,
      kekVersion: 1,
      argumentsHash: op.argumentsHash,
    });
    expect(Buffer.from(read['plaintext'] as string, 'base64url').toString('utf8')).toBe(
      op.plaintext,
    );

    const types = (await auditEvents(service, tenant.organization.id)).map((e) => e['event_type']);
    expect(types.filter((t) => String(t).startsWith('vault.'))).toEqual([
      'vault.capability_authorized',
      'vault.capability_issued',
      'vault.secret_read',
    ]);
    const row = await capabilityRowOf(service, prepared.capabilityId);
    expect(row['used_at']).not.toBeNull();
    expect(row['token_hash']).toBe(hashToken(prepared.token));
    expect(row['token_hash']).not.toBe(prepared.token);
  });

  it('answers only the role that may call each operation (the socket is the identity)', async () => {
    const tenant = await seedTenant(service.repos, 'roles');
    const op = await seedSealedOperation(service, tenant);
    // The supervisor socket cannot authorize; the api socket cannot issue or read.
    expect(
      errorCode(
        await service.rpc('supervisor', 'authorizeJobAccess', { jobId: op.jobId, ttlSeconds: 60 }),
      ),
    ).toBe('forbidden');
    const prepared = await prepare(service, op);
    expect(errorCode(await service.rpc('api', 'readForWorker', readParams(prepared)))).toBe(
      'forbidden',
    );
    expect(errorCode(await service.rpc('admin', 'readForWorker', readParams(prepared)))).toBe(
      'forbidden',
    );
    // Those refusals consumed nothing: the capability still redeems on the supervisor socket.
    ok(await service.rpc('supervisor', 'readForWorker', readParams(prepared)));
  });

  it('refuses to authorize a job twice or a job that is not queued', async () => {
    const tenant = await seedTenant(service.repos, 'twice');
    const op = await seedSealedOperation(service, tenant);
    ok(await service.rpc('api', 'authorizeJobAccess', { jobId: op.jobId, ttlSeconds: 60 }));
    expect(
      errorCode(
        await service.rpc('api', 'authorizeJobAccess', { jobId: op.jobId, ttlSeconds: 60 }),
      ),
    ).toBe('conflict');
    expect(
      errorCode(
        await service.rpc('api', 'authorizeJobAccess', {
          jobId: '99999999-9999-4999-8999-999999999999',
          ttlSeconds: 60,
        }),
      ),
    ).toBe('not_found');
  });
});

describe('P3-10: sealed versions are bound to their owner record', () => {
  async function readAfter(
    mutate: (op: Awaited<ReturnType<typeof seedSealedOperation>>) => Promise<void>,
  ) {
    const tenant = await seedTenant(service.repos, 'bind');
    const op = await seedSealedOperation(service, tenant);
    const prepared = await prepare(service, op);
    await mutate(op);
    const response = await service.rpc('supervisor', 'readForWorker', readParams(prepared));
    return { tenant, op, prepared, response };
  }

  async function flip(
    connectionId: string,
    column: 'ciphertext' | 'auth_tag' | 'nonce' | 'wrapped_dek',
  ) {
    const col = sql.raw(column);
    await execSql(
      service,
      sql`update vault_secret_versions set ${col} = set_byte(${col}, 0, get_byte(${col}, 0) # 255)
          where secret_id in (select id from vault_secrets where connection_id = ${connectionId}::uuid)`,
    );
  }

  it.each(['ciphertext', 'auth_tag', 'nonce', 'wrapped_dek'] as const)(
    'tampered %s fails at the service boundary: forbidden, no plaintext, rejection audited as integrity',
    async (column) => {
      const { tenant, op, response } = await readAfter((o) => flip(o.connectionId, column));
      expect(errorCode(response)).toBe('forbidden');
      expect(JSON.stringify(response)).not.toContain(CANARY);
      const rejected = await auditEvents(
        service,
        tenant.organization.id,
        'vault.capability_rejected',
      );
      expect(rejected).toHaveLength(1);
      expect(rejected[0]!['metadata']).toMatchObject({ reason: 'integrity', purpose: 'read' });
      expect(await auditEvents(service, tenant.organization.id, 'vault.secret_read')).toHaveLength(
        0,
      );
      void op;
    },
  );

  it('a version copied to another connection, secret or organization fails to open', async () => {
    // Victim: connection B (another tenant) holds version 1 sealed for B. The attacker copies
    // B's ciphertext, nonce, tag and wrapped key over connection A's version row.
    const other = await seedTenant(service.repos, 'victim');
    const victim = await seedSealedOperation(service, other, 'VICTIM-SESSION');
    const { tenant, response } = await readAfter(async (attacker) => {
      await execSql(
        service,
        sql`update vault_secret_versions as a
            set ciphertext = b.ciphertext, nonce = b.nonce, auth_tag = b.auth_tag, wrapped_dek = b.wrapped_dek
            from vault_secret_versions as b
            where a.secret_id = (select id from vault_secrets where connection_id = ${attacker.connectionId}::uuid)
              and b.secret_id = ${victim.secretId}::uuid`,
      );
    });
    expect(errorCode(response)).toBe('forbidden');
    expect(JSON.stringify(response)).not.toContain('VICTIM');
    const rejected = await auditEvents(
      service,
      tenant.organization.id,
      'vault.capability_rejected',
    );
    expect(rejected[0]!['metadata']).toMatchObject({ reason: 'integrity' });
  });

  it('a version row renumbered to another version number fails to open', async () => {
    const { response } = await readAfter(async () => {
      // Same secret, same bytes, a different number: the AAD binds the version.
      await execSql(
        service,
        sql`update vault_secret_versions set version = 7 where id in (
              select active_version_id from vault_secrets where connection_id in (
                select connection_id from vault_access_capabilities order by created_at desc limit 1))`,
      );
    });
    expect(errorCode(response)).toBe('forbidden');
  });
});

describe('the vault is not the owner of what it returns', () => {
  it('has no operation that returns plaintext to the api or admin role', async () => {
    const tenant = await seedTenant(service.repos, 'noplain');
    const op = await seedSealedOperation(service, tenant);
    for (const role of ['api', 'admin'] as const) {
      for (const operation of [
        'readForWorker',
        'completeLogin',
        'revoke',
        'describe',
        'rewrapSecret',
      ]) {
        const response = await service.rpc(role, operation, {});
        expect(response['ok']).toBe(false);
        expect(JSON.stringify(response)).not.toContain(CANARY);
      }
    }
    expect(await openStored(service, tenant, op.connectionId)).toBe(op.plaintext);
  });
});
