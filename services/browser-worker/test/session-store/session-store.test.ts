import { SESSION_SNAPSHOT_SECRET_TYPE } from '@aab/contracts';
import type { Repositories } from '@aab/database';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  filterStorageState,
  MAX_SNAPSHOT_BYTES,
  openSnapshot,
  sessionExpiry,
  SnapshotOpenError,
  SnapshotTooLargeError,
  storeSnapshot,
} from '../../src/session-store/index.js';
import type { StorageState } from '../../src/types.js';
import {
  APP_ORIGIN,
  CDN_ORIGIN,
  cookie,
  createWorld,
  dumpTables,
  loginConnection,
  OTHER_ORIGIN,
  stateWith,
  testKek,
} from '../supervisor/helpers.js';
import type { World } from '../supervisor/helpers.js';

const CANARY = 'canary-cookie-value-7f3a9c';

describe('session store', () => {
  let world: World;
  beforeEach(async () => {
    world = await createWorld();
  });
  afterEach(async () => {
    await world.close();
  });

  it('stores ciphertext only and opens it again with the same key', async () => {
    const kek = testKek();
    const { connection } = await loginConnection(world);
    const state = stateWith(CANARY);
    const stored = await storeSnapshot(world.repos, {
      connection,
      storageState: state,
      kek,
      now: new Date(),
    });
    expect(stored).toEqual({ vaultEntryId: expect.any(String), version: 1, kekVersion: 1 });
    expect(Object.keys(stored).sort()).toEqual(['kekVersion', 'vaultEntryId', 'version']);

    const dump = await dumpTables(world);
    expect(dump).not.toContain(CANARY);
    expect(dump).not.toContain(Buffer.from(CANARY).toString('base64'));

    const opened = await openSnapshot(world.repos, connection, kek);
    expect(opened).not.toBeNull();
    expect(opened!.storageState).toEqual(state);
    expect(opened!.version).toBe(1);
    opened!.dispose();
    expect(opened!.storageState.cookies).toHaveLength(0);
    opened!.dispose();
  });

  it('works inside a caller transaction and rolls back with it', async () => {
    const kek = testKek();
    const { connection } = await loginConnection(world);
    await expect(
      world.repos.transaction(async (tx) => {
        await storeSnapshot(tx, { connection, storageState: stateWith('x'), kek, now: new Date() });
        throw new Error('roll back');
      }),
    ).rejects.toThrow('roll back');
    expect(await openSnapshot(world.repos, connection, kek)).toBeNull();
  });

  it('returns null when there is no active snapshot', async () => {
    const { connection } = await loginConnection(world);
    expect(await openSnapshot(world.repos, connection, testKek())).toBeNull();
  });

  it('a new snapshot replaces the old one and increments the version', async () => {
    const kek = testKek();
    const { connection } = await loginConnection(world);
    await storeSnapshot(world.repos, {
      connection,
      storageState: stateWith('a'),
      kek,
      now: new Date(),
    });
    const second = await storeSnapshot(world.repos, {
      connection,
      storageState: stateWith('b'),
      kek,
      now: new Date(),
    });
    expect(second.version).toBe(2);
    const opened = await openSnapshot(world.repos, connection, kek);
    expect(opened!.storageState).toEqual(stateWith('b'));
  });

  it('fails to open with a different KEK', async () => {
    const { connection } = await loginConnection(world);
    await storeSnapshot(world.repos, {
      connection,
      storageState: stateWith(CANARY),
      kek: testKek(),
      now: new Date(),
    });
    const error = await openSnapshot(world.repos, connection, testKek()).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(SnapshotOpenError);
    expect((error as SnapshotOpenError).reason).toBe('decrypt');
    expect(String((error as Error).message)).not.toContain(CANARY);
  });

  it('a ciphertext row copied onto another connection does not open (associated data)', async () => {
    const kek = testKek();
    const a = await loginConnection(world);
    const b = await loginConnection(world);
    await storeSnapshot(world.repos, {
      connection: a.connection,
      storageState: stateWith(CANARY),
      kek,
      now: new Date(),
    });
    const source = await world.repos.vault.getActive(a.connection.id, SESSION_SNAPSHOT_SECRET_TYPE);
    const target = await world.repos.vault.ensureSecret({
      connectionId: b.connection.id,
      secretType: SESSION_SNAPSHOT_SECRET_TYPE,
      now: new Date(),
    });
    // Same version number, so only the bound connection and secret ids differ.
    expect(target.nextVersion).toBe(source!.version);
    await world.repos.vault.putVersion({
      secretId: target.secretId,
      version: target.nextVersion,
      sealed: source!.sealed,
      now: new Date(),
    });
    await expect(openSnapshot(world.repos, b.connection, kek)).rejects.toBeInstanceOf(
      SnapshotOpenError,
    );
    // The original still opens.
    expect(await openSnapshot(world.repos, a.connection, kek)).not.toBeNull();
    // And it does not open when presented as belonging to another owner.
    await expect(
      openSnapshot(world.repos, { ...a.connection, ownerUserId: b.connection.id }, kek),
    ).rejects.toBeInstanceOf(SnapshotOpenError);
  });

  it.each(['ciphertext', 'authTag', 'nonce', 'wrappedDek'] as const)(
    'fails to open when %s is tampered with',
    async (field) => {
      const kek = testKek();
      const { connection } = await loginConnection(world);
      await storeSnapshot(world.repos, {
        connection,
        storageState: stateWith(CANARY),
        kek,
        now: new Date(),
      });
      const real = await world.repos.vault.getActive(connection.id, SESSION_SNAPSHOT_SECRET_TYPE);
      const tampered = Buffer.from(real!.sealed[field]);
      tampered[0] = (tampered[0] ?? 0) ^ 0x01;
      const repos: Repositories = {
        ...world.repos,
        vault: {
          ...world.repos.vault,
          getActive: async () => ({ ...real!, sealed: { ...real!.sealed, [field]: tampered } }),
        },
      };
      await expect(openSnapshot(repos, connection, kek)).rejects.toBeInstanceOf(SnapshotOpenError);
    },
  );

  it('refuses a snapshot over the size cap and stores nothing', async () => {
    const kek = testKek();
    const { connection } = await loginConnection(world);
    const big: StorageState = {
      cookies: [],
      origins: Array.from({ length: 10 }, (_, index) => ({
        origin: `https://o${index}.example.test`,
        localStorage: [{ name: 'blob', value: 'x'.repeat(250_000) }],
      })),
    };
    await expect(
      storeSnapshot(world.repos, { connection, storageState: big, kek, now: new Date() }),
    ).rejects.toBeInstanceOf(SnapshotTooLargeError);
    expect(MAX_SNAPSHOT_BYTES).toBeLessThan(2_500_000 + 1);
    expect(await openSnapshot(world.repos, connection, kek)).toBeNull();
  });

  it('rejects an invalid storage state before sealing', async () => {
    const { connection } = await loginConnection(world);
    const invalid = { cookies: [{ name: 'x' }], origins: [] } as unknown as StorageState;
    await expect(
      storeSnapshot(world.repos, {
        connection,
        storageState: invalid,
        kek: testKek(),
        now: new Date(),
      }),
    ).rejects.toBeInstanceOf(SnapshotOpenError);
  });
});

describe('filterStorageState', () => {
  it('keeps cookies whose domain is an allowed host and origin storage that is exactly allowed', () => {
    const state: StorageState = {
      cookies: [
        cookie('a', '1', 'app.example.test'),
        cookie('b', '2', '.app.example.test'),
        cookie('c', '3', 'cdn.example.test'),
        cookie('d', '4', 'example.test'),
        cookie('e', '5', '.example.test'),
        cookie('f', '6', 'tracker.other.test'),
        cookie('g', '7', 'evil-app.example.test'),
        cookie('h', '8', '..app.example.test'),
        cookie('i', '9', 'APP.example.test'),
      ],
      origins: [
        { origin: APP_ORIGIN, localStorage: [{ name: 'k', value: 'v' }] },
        { origin: OTHER_ORIGIN, localStorage: [{ name: 'k', value: 'v' }] },
        { origin: 'http://app.example.test', localStorage: [] },
        { origin: `${APP_ORIGIN}:8443`, localStorage: [] },
      ],
    };
    const filtered = filterStorageState(state, [APP_ORIGIN, CDN_ORIGIN]);
    expect(filtered.cookies.map((c) => c.name)).toEqual(['a', 'b', 'c', 'i']);
    expect(filtered.origins.map((o) => o.origin)).toEqual([APP_ORIGIN]);
    // The input is not modified.
    expect(state.cookies).toHaveLength(9);
  });

  it('returns an empty state for no allowed origins', () => {
    expect(filterStorageState(stateWith('x'), [])).toEqual({ cookies: [], origins: [] });
  });
});

describe('sessionExpiry', () => {
  it('returns the earliest positive expiry', () => {
    const state: StorageState = {
      cookies: [
        cookie('a', '1', 'app.example.test', -1),
        cookie('b', '1', 'app.example.test', 2_000_000_000),
        cookie('c', '1', 'app.example.test', 1_900_000_000.5),
        cookie('d', '1', 'app.example.test', 0),
      ],
      origins: [],
    };
    expect(sessionExpiry(state)).toEqual(new Date(1_900_000_000_500));
  });

  it('returns null for session cookies only', () => {
    expect(
      sessionExpiry({ cookies: [cookie('a', '1', 'app.example.test', -1)], origins: [] }),
    ).toBeNull();
    expect(sessionExpiry({ cookies: [], origins: [] })).toBeNull();
  });
});
