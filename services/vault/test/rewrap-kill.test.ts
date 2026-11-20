import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { LocalFileKekProvider, openSecret, sealSecret } from '@aab/crypto';
import { afterAll, describe, expect, it } from 'vitest';
import { rowsOf } from '../../../packages/database/src/client.js';
import { seedApplication } from '../../../packages/database/test/helpers.js';
import { call } from './helpers.js';
import {
  addKek,
  hasPostgres,
  isPlainForbidden,
  ok,
  prepare,
  readParams,
  seedSealedOperation,
  seedTenant,
  sleep,
  sql,
  startService,
} from './service-helpers.js';
import type { Service } from './service-helpers.js';

/*
 * P3-9: the real vault process is killed with SIGKILL in the middle of a rewrap, restarted, and
 * the rewrap is run again until nothing remains (PostgreSQL only: the process connects to
 * AAB_TEST_DATABASE_URL). The kill lands inside a row's transaction, not between rows: a trigger
 * makes the vault's transaction for the 31st row wait on an advisory lock that the test holds,
 * after the row was updated and before its audit event was written.
 */

const VAULT_DIR = join(import.meta.dirname, '..');
const SECRET_TYPE = 'session_snapshot';
const GATE_KEY = 7002;
/** Rows rewrapped and committed before the kill. */
const KILL_AFTER = 30;
const BULK_ROWS = 330;
const REAL_OPERATIONS = 6;
const TOTAL = BULK_ROWS + REAL_OPERATIONS;

const cleanups: Array<() => Promise<void>> = [];
afterAll(async () => {
  for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
});

interface Proc {
  child: ReturnType<typeof spawn>;
  exited: Promise<number | null>;
  out(): string;
  err(): string;
}

function run(script: string, args: string[], env: Record<string, string>): Proc {
  const child = spawn(process.execPath, ['--import', 'tsx', script, ...args], {
    cwd: VAULT_DIR,
    env: { PATH: process.env['PATH'] ?? '', ...env },
  });
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', (chunk: Buffer) => (stdout += chunk.toString()));
  child.stderr.on('data', (chunk: Buffer) => (stderr += chunk.toString()));
  const exited = new Promise<number | null>((resolve) =>
    child.once('exit', (code) => resolve(code)),
  );
  return { child, exited, out: () => stdout, err: () => stderr };
}

async function startVaultProcess(env: Record<string, string>): Promise<Proc> {
  const proc = run('src/main.ts', [], { ...env, AAB_VAULT_ISOLATION: 'shared-uid' });
  cleanups.push(async () => {
    proc.child.kill('SIGKILL');
    await proc.exited;
  });
  for (let i = 0; i < 300 && !proc.out().includes('"msg":"vault listening"'); i += 1) {
    await sleep(100);
    if (proc.child.exitCode !== null) throw new Error(`vault exited early: ${proc.err()}`);
  }
  if (!proc.out().includes('"msg":"vault listening"')) throw new Error('vault did not start');
  return proc;
}

const count = async (service: Service, query: ReturnType<typeof sql>): Promise<number> =>
  Number(rowsOf(await service.db.execute(query))[0]!['n']);

/** One hash over every ciphertext, nonce and tag, in a fixed order. */
async function ciphertextDigest(service: Service): Promise<string> {
  const rows = rowsOf(
    await service.db.execute(
      sql`select id, encode(ciphertext,'hex') as c, encode(nonce,'hex') as n, encode(auth_tag,'hex') as t, algorithm, aad_version
          from vault_secret_versions order by id`,
    ),
  );
  return createHash('sha256').update(JSON.stringify(rows)).digest('hex');
}

describe.runIf(hasPostgres())('P3-9: SIGKILL in the middle of a rewrap (PostgreSQL)', () => {
  it('leaves every version readable, rewraps each row exactly once after a restart, and touches no ciphertext', async () => {
    // --- Seed: KEK v1 only, real sealed rows, then add v2 (the rotation) ---------------------
    const first = await startService({ postgres: true, kekVersions: [1] });
    cleanups.push(() => first.cleanup());
    const tenant = await seedTenant(first.repos, 'kill');
    const app = await seedApplication(first.repos, tenant.scope);
    const bulk: Array<{ connectionId: string; secretId: string; plaintext: string }> = [];
    for (let i = 0; i < BULK_ROWS; i += 1) {
      const connection = await first.repos.connections.create(tenant.scope, {
        applicationId: app.id,
        displayName: `kill ${i}`,
      });
      const ensured = await first.repos.vault.ensureSecret({
        connectionId: connection.id,
        secretType: SECRET_TYPE,
        now: new Date(),
      });
      const plaintext = `synthetic-session-${i}`;
      const sealed = await sealSecret({
        plaintext: Buffer.from(plaintext),
        aad: {
          organizationId: tenant.organization.id,
          userId: tenant.user.id,
          connectionId: connection.id,
          secretId: ensured.secretId,
          secretType: SECRET_TYPE,
          secretVersion: ensured.nextVersion,
        },
        kek: first.vault.keys.kekProvider,
      });
      await first.repos.vault.putVersion({
        secretId: ensured.secretId,
        version: ensured.nextVersion,
        sealed,
        now: new Date(),
      });
      bulk.push({ connectionId: connection.id, secretId: ensured.secretId, plaintext });
    }
    const real = [];
    for (let i = 0; i < REAL_OPERATIONS; i += 1) {
      real.push(await seedSealedOperation(first, await seedTenant(first.repos, `kill-real-${i}`)));
    }
    const expected = new Map<string, string>([
      ...bulk.map((row): [string, string] => [row.secretId, row.plaintext]),
      ...real.map((op): [string, string] => [op.secretId, op.plaintext]),
    ]);
    expect(expected.size).toBe(TOTAL);
    await first.stop();
    await addKek(first.kekDir, 2);

    const databaseName = String(
      rowsOf(await first.db.execute(sql`select current_database() as n`))[0]!['n'],
    );
    const url = new URL(process.env['AAB_TEST_DATABASE_URL']!);
    url.pathname = `/${databaseName}`;
    const env = {
      DATABASE_URL: url.toString(),
      AAB_KEK_DIR: first.kekDir,
      AAB_VAULT_SOCKET_DIR: first.socketDir,
    };

    // The independent opener: the key files read directly, no vault in between.
    const keys = await LocalFileKekProvider.load(first.kekDir);
    const openAll = async (): Promise<number> => {
      const rows = rowsOf(
        await first.db.execute(sql`
          select v.version, v.kek_version, v.aad_version, v.algorithm, v.ciphertext, v.nonce, v.auth_tag, v.wrapped_dek,
                 s.id as secret_id, s.secret_type, k.id as connection_id, k.organization_id, k.owner_user_id
          from vault_secret_versions v join vault_secrets s on s.id = v.secret_id
          join connections k on k.id = s.connection_id`),
      );
      for (const row of rows) {
        const plaintext = await openSecret({
          sealed: {
            algorithm: String(row['algorithm']),
            ciphertext: Buffer.from(row['ciphertext'] as Uint8Array),
            nonce: Buffer.from(row['nonce'] as Uint8Array),
            authTag: Buffer.from(row['auth_tag'] as Uint8Array),
            wrappedDek: Buffer.from(row['wrapped_dek'] as Uint8Array),
            kekVersion: Number(row['kek_version']),
            aadVersion: Number(row['aad_version']),
          },
          aad: {
            organizationId: String(row['organization_id']),
            userId: String(row['owner_user_id']),
            connectionId: String(row['connection_id']),
            secretId: String(row['secret_id']),
            secretType: String(row['secret_type']),
            secretVersion: Number(row['version']),
          },
          kek: keys,
        });
        // Not just "it opens": it is what was sealed.
        expect(plaintext.toString('utf8')).toBe(expected.get(String(row['secret_id'])));
      }
      return rows.length;
    };
    expect(await openAll()).toBe(TOTAL);
    const digestBefore = await ciphertextDigest(first);

    // --- Kill inside the 31st row's transaction -----------------------------------------------
    await first.db.execute(
      sql.raw(`create function aab_kill_gate() returns trigger language plpgsql as $$
        begin
          if (select count(*) from audit_events where event_type = 'vault.secret_rewrapped') >= ${KILL_AFTER} then
            perform pg_advisory_xact_lock(${GATE_KEY});
          end if;
          return new;
        end $$`),
    );
    await first.db.execute(
      sql.raw(`create trigger aab_kill_gate before insert on audit_events for each row
        when (new.event_type = 'vault.secret_rewrapped') execute function aab_kill_gate()`),
    );
    let release!: () => void;
    const released = new Promise<void>((resolve) => (release = resolve));
    let held!: () => void;
    const heldLock = new Promise<void>((resolve) => (held = resolve));
    const lockHolder = first.db.transaction(async (tx) => {
      await tx.execute(sql.raw(`select pg_advisory_xact_lock(${GATE_KEY})`));
      held();
      await released;
    });
    await heldLock;

    const firstProcess = await startVaultProcess(env);
    const cli = run('src/scripts/vault-cli.ts', ['rewrap', '--batch-size', '10'], {
      AAB_VAULT_SOCKET_DIR: first.socketDir,
    });
    for (let i = 0; i < 600; i += 1) {
      const waiting = await count(
        first,
        sql`select count(*)::int as n from pg_locks where locktype = 'advisory' and not granted`,
      );
      if (waiting > 0) break;
      if (i === 599) throw new Error(`the rewrap never reached the gate: ${firstProcess.err()}`);
      await sleep(50);
    }
    // The 31st row is updated and uncommitted; 30 are committed with their events.
    firstProcess.child.kill('SIGKILL');
    expect(await firstProcess.exited).toBeNull(); // killed by a signal, no clean exit
    expect(await cli.exited).toBe(1); // the admin command lost its vault
    release();
    await lockHolder;
    await first.db.execute(sql.raw('drop trigger aab_kill_gate on audit_events'));

    // --- After the kill: no half-applied row ----------------------------------------------------
    const rewrappedEvents = sql`select count(*)::int as n from audit_events where event_type = 'vault.secret_rewrapped'`;
    expect(await count(first, rewrappedEvents)).toBe(KILL_AFTER);
    expect(
      await count(
        first,
        sql`select count(*)::int as n from vault_secret_versions where kek_version = 2`,
      ),
    ).toBe(KILL_AFTER);
    expect(
      await count(
        first,
        sql`select count(*)::int as n from vault_secret_versions where kek_version = 1`,
      ),
    ).toBe(TOTAL - KILL_AFTER);
    expect(await ciphertextDigest(first)).toBe(digestBefore);
    expect(await openAll()).toBe(TOTAL); // every version still opens with the key files

    // --- Restart, read through the vault in the mixed state, rewrap to the end ---------------
    const secondProcess = await startVaultProcess(env);
    const viaVault: Service = {
      ...first,
      rpc: async (role, operation, params) =>
        call(join(first.socketDir, role, 'vault.sock'), { id: 'k1', operation, params }),
    };
    const status = ok(await viaVault.rpc('admin', 'status', {}));
    expect(status['versionsByKek']).toEqual({ '1': TOTAL - KILL_AFTER, '2': KILL_AFTER });
    const usedBefore = [];
    for (const op of real.slice(0, 3)) {
      const prepared = await prepare(viaVault, op);
      usedBefore.push(prepared);
      const read = ok(await viaVault.rpc('supervisor', 'readForWorker', readParams(prepared)));
      expect(read['secretVersion']).toBe(1);
      expect(Buffer.from(String(read['plaintext']), 'base64url').toString('utf8')).toBe(
        op.plaintext,
      );
    }

    const finish = run('src/scripts/vault-cli.ts', ['rewrap', '--batch-size', '10'], {
      AAB_VAULT_SOCKET_DIR: first.socketDir,
    });
    expect(await finish.exited).toBe(0);
    const total = JSON.parse(finish.out().trim()) as Record<string, number>;
    // The three reads above consumed their capabilities but did not change any wrapped key.
    expect(total).toEqual({ rewrapped: TOTAL - KILL_AFTER, skipped: 0, failed: 0, remaining: 0 });

    // --- After: every row exactly once, nothing else changed ------------------------------------
    expect(await count(first, rewrappedEvents)).toBe(TOTAL);
    expect(
      await count(
        first,
        sql`select count(*)::int as n from (select metadata->>'vaultEntryId' as id from audit_events
              where event_type = 'vault.secret_rewrapped' group by 1 having count(*) > 1) as dup`,
      ),
    ).toBe(0);
    expect(
      await count(
        first,
        sql`select count(distinct metadata->>'vaultEntryId')::int as n from audit_events where event_type = 'vault.secret_rewrapped'`,
      ),
    ).toBe(TOTAL);
    expect(
      await count(
        first,
        sql`select count(*)::int as n from vault_secret_versions where kek_version = 2`,
      ),
    ).toBe(TOTAL);
    expect(await ciphertextDigest(first)).toBe(digestBefore);
    expect(await openAll()).toBe(TOTAL);
    expect(ok(await viaVault.rpc('admin', 'kekRetirementCheck', { kekVersion: 1 }))).toEqual({
      referencingVersions: 0,
      safeToRemove: true,
    });
    // Through the vault again, the rest of the real operations (now wrapped under v2).
    for (const op of real.slice(3)) {
      const prepared = await prepare(viaVault, op);
      const read = ok(await viaVault.rpc('supervisor', 'readForWorker', readParams(prepared)));
      expect(read['kekVersion']).toBe(2);
      expect(Buffer.from(String(read['plaintext']), 'base64url').toString('utf8')).toBe(
        op.plaintext,
      );
    }
    // A capability used before the kill-and-restart sequence still cannot be replayed.
    const replay = await viaVault.rpc('supervisor', 'readForWorker', readParams(usedBefore[0]!));
    expect(isPlainForbidden(replay)).toBe(true);
    expect(bulk).toHaveLength(BULK_ROWS);
    secondProcess.child.kill('SIGTERM');
    await secondProcess.exited;
  }, 280_000);
});
