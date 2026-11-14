import { sql } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { rowsOf } from '../src/client.js';
import { ConflictError, createRepositories, NotFoundError } from '../src/index.js';
import type { DatabaseHandle, Repositories } from '../src/index.js';
import {
  fakeSealed,
  openTestDb,
  seedConnectionAndAgent,
  seedTenant,
  UNKNOWN_ID,
} from './helpers.js';
import type { Tenant } from './helpers.js';

let handle: DatabaseHandle;
let repositories: Repositories;
let tenant: Tenant;

const TYPE = 'session_snapshot';
const T0 = new Date('2030-01-01T00:00:00.000Z');
const at = (ms: number) => new Date(T0.getTime() + ms);

beforeAll(async () => {
  handle = await openTestDb();
  repositories = createRepositories(handle.db);
  tenant = await seedTenant(repositories, 'vault');
});

afterAll(async () => {
  await handle.close();
});

async function newConnection() {
  return (await seedConnectionAndAgent(repositories, tenant)).connection;
}

async function versionRows(secretId: string) {
  return rowsOf(
    await handle.db.execute(
      sql`select version from vault_secret_versions where secret_id = ${secretId} order by version`,
    ),
  ).map((row) => row.version);
}

describe('vault.ensureSecret', () => {
  it('creates a pending secret once and starts at version 1', async () => {
    const connection = await newConnection();
    const first = await repositories.vault.ensureSecret({
      connectionId: connection.id,
      secretType: TYPE,
      now: T0,
    });
    expect(first.nextVersion).toBe(1);
    const again = await repositories.vault.ensureSecret({
      connectionId: connection.id,
      secretType: TYPE,
      now: at(1),
    });
    expect(again).toEqual(first);

    const [description] = await repositories.vault.describeForConnection(connection.id);
    expect(description).toMatchObject({ id: first.secretId, secretType: TYPE, status: 'pending' });
    expect(await repositories.vault.getActive(connection.id, TYPE)).toBeNull();

    const other = await repositories.vault.ensureSecret({
      connectionId: connection.id,
      secretType: 'other_type',
      now: T0,
    });
    expect(other.secretId).not.toBe(first.secretId);
  });

  it('is NotFound for a malformed connection id and Conflict-free for concurrent callers', async () => {
    await expect(
      repositories.vault.ensureSecret({ connectionId: 'nope', secretType: TYPE, now: T0 }),
    ).rejects.toBeInstanceOf(NotFoundError);
    const connection = await newConnection();
    const results = await Promise.all(
      [1, 2, 3].map(() =>
        repositories.vault.ensureSecret({ connectionId: connection.id, secretType: TYPE, now: T0 }),
      ),
    );
    expect(new Set(results.map((r) => r.secretId)).size).toBe(1);
  });
});

describe('vault.putVersion and getActive', () => {
  it('stores ciphertext round-trip and activates the secret', async () => {
    const connection = await newConnection();
    const { secretId, nextVersion } = await repositories.vault.ensureSecret({
      connectionId: connection.id,
      secretType: TYPE,
      now: T0,
    });
    const sealed = fakeSealed('one', 3);
    await repositories.vault.putVersion({ secretId, version: nextVersion, sealed, now: at(1) });

    const active = await repositories.vault.getActive(connection.id, TYPE);
    expect(active).toEqual({ secretId, version: 1, sealed });
    expect(Buffer.isBuffer(active?.sealed.ciphertext)).toBe(true);
    expect(await repositories.vault.getActive(connection.id, 'missing')).toBeNull();

    expect(await repositories.vault.describeForConnection(connection.id)).toEqual([
      {
        id: secretId,
        secretType: TYPE,
        status: 'active',
        activeVersion: 1,
        kekVersion: 3,
        lastAccessedAt: null,
      },
    ]);
  });

  it('replaces the active version and deletes every older one', async () => {
    const connection = await newConnection();
    const { secretId } = await repositories.vault.ensureSecret({
      connectionId: connection.id,
      secretType: TYPE,
      now: T0,
    });
    await repositories.vault.putVersion({
      secretId,
      version: 1,
      sealed: fakeSealed('v1'),
      now: T0,
    });
    await repositories.vault.putVersion({
      secretId,
      version: 2,
      sealed: fakeSealed('v2'),
      now: at(1),
    });
    await repositories.vault.putVersion({
      secretId,
      version: 3,
      sealed: fakeSealed('v3'),
      now: at(2),
    });

    expect(await versionRows(secretId)).toEqual([3]);
    const active = await repositories.vault.getActive(connection.id, TYPE);
    expect(active?.version).toBe(3);
    expect(active?.sealed.ciphertext.toString()).toBe('synthetic-ciphertext-v3');
    expect(
      (
        await repositories.vault.ensureSecret({
          connectionId: connection.id,
          secretType: TYPE,
          now: T0,
        })
      ).nextVersion,
    ).toBe(4);
  });

  it('raises ConflictError for a duplicate or reused version and keeps the old data', async () => {
    const connection = await newConnection();
    const { secretId } = await repositories.vault.ensureSecret({
      connectionId: connection.id,
      secretType: TYPE,
      now: T0,
    });
    await repositories.vault.putVersion({
      secretId,
      version: 1,
      sealed: fakeSealed('v1'),
      now: T0,
    });
    await expect(
      repositories.vault.putVersion({
        secretId,
        version: 1,
        sealed: fakeSealed('dup'),
        now: at(1),
      }),
    ).rejects.toBeInstanceOf(ConflictError);
    expect(
      (await repositories.vault.getActive(connection.id, TYPE))?.sealed.ciphertext.toString(),
    ).toBe('synthetic-ciphertext-v1');
    await expect(
      repositories.vault.putVersion({
        secretId: UNKNOWN_ID,
        version: 1,
        sealed: fakeSealed(),
        now: T0,
      }),
    ).rejects.toBeInstanceOf(NotFoundError);
  });

  it('rolls back completely when the new version cannot be stored', async () => {
    const connection = await newConnection();
    const { secretId } = await repositories.vault.ensureSecret({
      connectionId: connection.id,
      secretType: TYPE,
      now: T0,
    });
    await repositories.vault.putVersion({
      secretId,
      version: 1,
      sealed: fakeSealed('v1'),
      now: T0,
    });
    // kek_version 0 violates a CHECK constraint after the secret row was locked.
    await expect(
      repositories.vault.putVersion({
        secretId,
        version: 2,
        sealed: fakeSealed('bad', 0),
        now: at(1),
      }),
    ).rejects.toThrow();
    expect(await versionRows(secretId)).toEqual([1]);
    expect((await repositories.vault.getActive(connection.id, TYPE))?.version).toBe(1);
  });
});

describe('vault.touchAccessed', () => {
  it('records the access time', async () => {
    const connection = await newConnection();
    const { secretId } = await repositories.vault.ensureSecret({
      connectionId: connection.id,
      secretType: TYPE,
      now: T0,
    });
    await repositories.vault.touchAccessed(secretId, at(500));
    const [description] = await repositories.vault.describeForConnection(connection.id);
    expect(description?.lastAccessedAt).toBe(at(500).toISOString());
    await repositories.vault.touchAccessed(UNKNOWN_ID, at(600));
  });
});

describe('vault.deleteForConnection', () => {
  it('removes every ciphertext row, keeps metadata and never reuses a version number', async () => {
    const connection = await newConnection();
    const bystander = await newConnection();
    const a = await repositories.vault.ensureSecret({
      connectionId: connection.id,
      secretType: TYPE,
      now: T0,
    });
    const b = await repositories.vault.ensureSecret({
      connectionId: connection.id,
      secretType: 'second',
      now: T0,
    });
    const keep = await repositories.vault.ensureSecret({
      connectionId: bystander.id,
      secretType: TYPE,
      now: T0,
    });
    await repositories.vault.putVersion({
      secretId: a.secretId,
      version: 1,
      sealed: fakeSealed('a1'),
      now: T0,
    });
    await repositories.vault.putVersion({
      secretId: a.secretId,
      version: 2,
      sealed: fakeSealed('a2'),
      now: T0,
    });
    await repositories.vault.putVersion({
      secretId: b.secretId,
      version: 1,
      sealed: fakeSealed('b1'),
      now: T0,
    });
    await repositories.vault.putVersion({
      secretId: keep.secretId,
      version: 1,
      sealed: fakeSealed('k1'),
      now: T0,
    });

    expect(await repositories.vault.deleteForConnection(connection.id, at(10))).toBe(2);

    expect(await versionRows(a.secretId)).toEqual([]);
    expect(await versionRows(b.secretId)).toEqual([]);
    expect(await versionRows(keep.secretId)).toEqual([1]);
    const rows = rowsOf(
      await handle.db.execute(
        sql`select status, active_version_id from vault_secrets where connection_id = ${connection.id}`,
      ),
    );
    expect(rows).toHaveLength(2);
    for (const row of rows) {
      expect(row.status).toBe('deleted');
      expect(row.active_version_id).toBeNull();
    }
    expect(await repositories.vault.getActive(connection.id, TYPE)).toBeNull();
    expect((await repositories.vault.getActive(bystander.id, TYPE))?.version).toBe(1);
    expect(await repositories.vault.deleteForConnection(connection.id, at(20))).toBe(0);

    // The next version continues after the highest one ever used, 2, not after zero rows.
    const again = await repositories.vault.ensureSecret({
      connectionId: connection.id,
      secretType: TYPE,
      now: at(30),
    });
    expect(again).toEqual({ secretId: a.secretId, nextVersion: 3 });
    await expect(
      repositories.vault.putVersion({
        secretId: a.secretId,
        version: 1,
        sealed: fakeSealed('re'),
        now: at(31),
      }),
    ).rejects.toBeInstanceOf(ConflictError);
    await repositories.vault.putVersion({
      secretId: a.secretId,
      version: 3,
      sealed: fakeSealed('a3'),
      now: at(32),
    });
    expect((await repositories.vault.getActive(connection.id, TYPE))?.version).toBe(3);
  });

  it('is a no-op for a connection without secrets or a malformed id', async () => {
    const connection = await newConnection();
    expect(await repositories.vault.deleteForConnection(connection.id, T0)).toBe(0);
    expect(await repositories.vault.deleteForConnection('nope', T0)).toBe(0);
    expect(await repositories.vault.describeForConnection(connection.id)).toEqual([]);
  });
});

describe('vault.describeForConnection', () => {
  it('exposes metadata only', async () => {
    const connection = await newConnection();
    const { secretId } = await repositories.vault.ensureSecret({
      connectionId: connection.id,
      secretType: TYPE,
      now: T0,
    });
    await repositories.vault.putVersion({
      secretId,
      version: 1,
      sealed: fakeSealed('meta'),
      now: T0,
    });
    const [description] = await repositories.vault.describeForConnection(connection.id);
    expect(Object.keys(description!).sort()).toEqual([
      'activeVersion',
      'id',
      'kekVersion',
      'lastAccessedAt',
      'secretType',
      'status',
    ]);
    expect(JSON.stringify(description)).not.toContain('synthetic-ciphertext');
  });
});
