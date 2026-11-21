import { afterAll, describe, expect, it } from 'vitest';
import { chmod, copyFile, mkdir, mkdtemp, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { migrate } from '@aab/database';
import type { DatabaseHandle } from '@aab/database';
import { addOperationJob } from '../../../packages/database/test/capability-fixtures.js';
import { migrateFirst, openEmptyTestDb } from '../../../packages/database/test/helpers.js';
import type { Tenant } from '../../../packages/database/test/helpers.js';
import { rowsOf } from '../../../packages/database/src/client.js';
import { makeSocketDir, removeDir } from './helpers.js';
import { auditEvents, ok, prepare, readParams, sql, startService } from './service-helpers.js';
import type { Service } from './service-helpers.js';

/*
 * P3-19: "a Phase 2 snapshot opens through the vault after migration".
 *
 * The bytes under test are a golden fixture (test/fixtures/, see its README): one session
 * snapshot sealed by the real Phase 2 code at git 640bd27 (packages/crypto sealSecret with
 * LocalFileKekProvider, from a temporary worktree of that commit) with a synthetic, throwaway
 * KEK. They are inserted raw into a database that has only migrations 0000 to 0004, in the
 * shape Phase 2's vault repository wrote them. Then migration 0005 is applied, the real vault of
 * this repository starts on that database and on that KEK file, and the snapshot is read over the
 * supervisor socket with a real capability. Nothing in this test seals anything: the sealing code
 * of today is not involved, so a later change to it cannot make this pass by accident.
 */

const PHASE2_MIGRATIONS = 5; // 0000 to 0004
const FIXTURES = fileURLToPath(new URL('./fixtures/', import.meta.url));

interface Fixture {
  ids: { organizationId: string; userId: string; connectionId: string; secretId: string };
  secretType: string;
  plaintextUtf8: string;
  row: {
    algorithm: string;
    ciphertext: string;
    nonce: string;
    authTag: string;
    wrappedDek: string;
    kekVersion: number;
    aadVersion: number;
  };
}

const cleanups: Array<() => Promise<void>> = [];
afterAll(async () => {
  while (cleanups.length > 0) await cleanups.pop()!();
});

const rowDigest = async (handle: DatabaseHandle, secretId: string) =>
  rowsOf(
    await handle.db.execute(
      sql`select version, algorithm, encode(ciphertext, 'hex') as ct, encode(nonce, 'hex') as nonce, encode(auth_tag, 'hex') as tag, encode(wrapped_dek, 'hex') as dek, kek_version, aad_version from vault_secret_versions where secret_id = ${secretId}::uuid order by version`,
    ),
  );

/** Flips one bit of one hex-encoded byte. */
const flipHexByte = (hex: string, index: number): string => {
  const bytes = Buffer.from(hex, 'hex');
  bytes[index] = bytes[index]! ^ 0x01;
  return bytes.toString('hex');
};

async function phase2Snapshot(options: { corruptCiphertext?: boolean } = {}) {
  const fixture = JSON.parse(
    await readFile(join(FIXTURES, 'phase2-snapshot.json'), 'utf8'),
  ) as Fixture;
  const handle = await openEmptyTestDb();
  // The fixture KEK, copied into a directory the key loader accepts (0700; the key file 0600).
  const kekDir = join(await mkdtemp(join(tmpdir(), 'aab-kek-')), 'keys');
  await mkdir(kekDir, { mode: 0o700 });
  await chmod(kekDir, 0o700);
  await copyFile(join(FIXTURES, 'phase2-kek-v1.key'), join(kekDir, 'kek-v1.key'));
  await chmod(join(kekDir, 'kek-v1.key'), 0o600);
  const socketDir = await makeSocketDir();
  cleanups.push(async () => {
    await removeDir(socketDir);
    await removeDir(join(kekDir, '..'));
    await handle.close().catch(() => undefined);
  });

  await migrateFirst(handle.db, PHASE2_MIGRATIONS);
  const applied = rowsOf(
    await handle.db.execute(sql`select count(*)::int as n from drizzle.__drizzle_migrations`),
  );
  expect(applied[0]!['n']).toBe(PHASE2_MIGRATIONS);
  expect(
    rowsOf(
      await handle.db.execute(
        sql`select 1 from information_schema.tables where table_name = 'vault_access_capabilities'`,
      ),
    ),
  ).toHaveLength(0);

  // The rows Phase 2 had written, with the identifiers the fixture's associated data names.
  const { ids, row } = fixture;
  const applicationId = '0a11f1c0-5a17-4c0d-8a00-0000000000a1';
  const versionRowId = '0a11f1c0-5a17-4c0d-8a00-0000000000b1';
  const ciphertext =
    options.corruptCiphertext === true ? flipHexByte(row.ciphertext, 3) : row.ciphertext;
  await handle.db.execute(
    sql`insert into organizations (id, name) values (${ids.organizationId}::uuid, 'phase2 golden org')`,
  );
  await handle.db.execute(
    sql`insert into users (id, email, password_hash) values (${ids.userId}::uuid, 'phase2-golden@synthetic.test', 'scrypt$synthetic$not-a-real-hash')`,
  );
  await handle.db.execute(
    sql`insert into memberships (organization_id, user_id, role) values (${ids.organizationId}::uuid, ${ids.userId}::uuid, 'owner')`,
  );
  await handle.db.execute(
    sql`insert into application_definitions (id, organization_id, adapter_id, adapter_version, name, allowed_origins, auth_modes) values (${applicationId}::uuid, ${ids.organizationId}::uuid, 'northstar', '1.0.0', 'Northstar (synthetic)', '["http://localhost:4100"]'::jsonb, '["browser_session"]'::jsonb)`,
  );
  await handle.db.execute(
    sql`insert into connections (id, owner_user_id, organization_id, application_id, display_name, status) values (${ids.connectionId}::uuid, ${ids.userId}::uuid, ${ids.organizationId}::uuid, ${applicationId}::uuid, 'phase2 golden connection', 'active')`,
  );
  await handle.db.execute(
    sql`insert into vault_secrets (id, connection_id, secret_type, status, last_version) values (${ids.secretId}::uuid, ${ids.connectionId}::uuid, ${fixture.secretType}, 'active', 1)`,
  );
  await handle.db.execute(
    sql`insert into vault_secret_versions (id, secret_id, version, algorithm, ciphertext, nonce, auth_tag, wrapped_dek, kek_version, aad_version) values (${versionRowId}::uuid, ${ids.secretId}::uuid, 1, ${row.algorithm}, decode(${ciphertext}, 'hex'), decode(${row.nonce}, 'hex'), decode(${row.authTag}, 'hex'), decode(${row.wrappedDek}, 'hex'), ${row.kekVersion}, ${row.aadVersion})`,
  );
  await handle.db.execute(
    sql`update vault_secrets set active_version_id = ${versionRowId}::uuid where id = ${ids.secretId}::uuid`,
  );
  const stored = await rowDigest(handle, ids.secretId);
  expect(stored).toHaveLength(1);
  expect(stored[0]!['ct']).toBe(ciphertext);
  return {
    handle,
    kekDir,
    socketDir,
    ids,
    connectionId: ids.connectionId,
    secretId: ids.secretId,
    plaintext: fixture.plaintextUtf8,
    stored,
  };
}

async function migrateAndStart(snapshot: Awaited<ReturnType<typeof phase2Snapshot>>) {
  await migrate(snapshot.handle.db);
  const service = await startService({
    reuse: {
      dbHandle: snapshot.handle,
      kekDir: snapshot.kekDir,
      socketDir: snapshot.socketDir,
    },
  });
  cleanups.push(() => service.stop());
  return service;
}

async function queueRead(service: Service, snapshot: Awaited<ReturnType<typeof phase2Snapshot>>) {
  const scope = { organizationId: snapshot.ids.organizationId, userId: snapshot.ids.userId };
  const agent = await service.repos.agents.create(scope, {
    name: 'phase2 golden agent',
    clientIdentity: 'phase2-golden-agent',
  });
  const grant = await service.repos.grants.create(scope, agent.id, {
    connectionId: snapshot.connectionId,
    operation: 'orders.list',
    effect: 'allow',
  });
  // Only the ids are read from the tenant.
  const tenant = {
    organization: { id: scope.organizationId },
    user: { id: scope.userId },
    scope,
  } as unknown as Tenant;
  return addOperationJob(service.repos, {
    tenant,
    connectionId: snapshot.connectionId,
    agentId: agent.id,
    secretId: snapshot.secretId,
    jobId: '',
    operation: 'orders.list',
    argumentsHash: null,
    purpose: 'read',
    policyEventId: null,
    grantId: grant.id,
  });
}

describe('P3-19: a Phase 2 snapshot opens through the vault after migration', () => {
  it('reads, over the supervisor socket, the fixture bytes sealed by the Phase 2 code (git 640bd27), and leaves the stored row untouched', async () => {
    const snapshot = await phase2Snapshot();
    const service = await migrateAndStart(snapshot);
    // The migration kept the ciphertext, the nonce, the tag, the wrapped key and both versions.
    expect(await rowDigest(snapshot.handle, snapshot.secretId)).toEqual(snapshot.stored);

    const job = await queueRead(service, snapshot);
    const prepared = await prepare(service, job);
    expect(prepared.secretVersion).toBe(1);
    const result = ok(await service.rpc('supervisor', 'readForWorker', readParams(prepared)));
    expect(Buffer.from(result['plaintext'] as string, 'base64url').toString('utf8')).toBe(
      snapshot.plaintext,
    );
    expect(result['plaintext']).not.toBe('');

    // One read event, one stored row, unchanged by the read.
    expect(
      await auditEvents(service, snapshot.ids.organizationId, 'vault.secret_read'),
    ).toHaveLength(1);
    expect(await rowDigest(snapshot.handle, snapshot.secretId)).toEqual(snapshot.stored);
  });

  it('refuses the same row with one ciphertext bit flipped (a control: the pass above is not vacuous)', async () => {
    const snapshot = await phase2Snapshot({ corruptCiphertext: true });
    const service = await migrateAndStart(snapshot);
    const job = await queueRead(service, snapshot);
    const prepared = await prepare(service, job);
    const response = await service.rpc('supervisor', 'readForWorker', readParams(prepared));
    expect(response['ok']).toBe(false);
    expect(JSON.stringify(response)).not.toContain('PHASE2-GOLDEN-COOKIE-synthetic');
  });
});
