import { randomBytes } from 'node:crypto';
import { chmod, mkdir, mkdtemp, readFile, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { inspect } from 'node:util';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  CryptoInputError,
  generateLocalKek,
  InMemoryKekProvider,
  KekOperationError,
  KekStoreError,
  LOCAL_WRAPPED_DEK_BYTES,
  LocalFileKekProvider,
} from '../src/index.js';
import type { KekContext } from '../src/index.js';

const CONTEXT: KekContext = { secretAad: Buffer.from('{"secretId":"a"}') };
const OTHER_CONTEXT: KekContext = { secretAad: Buffer.from('{"secretId":"b"}') };

/** Writes a key file and sets its mode explicitly, independent of the process umask. */
async function writeKey(path: string, bytes: Buffer, mode: number): Promise<void> {
  await writeFile(path, bytes);
  await chmod(path, mode);
}

describe('InMemoryKekProvider', () => {
  it('wraps and unwraps a data key', async () => {
    const kek = InMemoryKekProvider.random();
    const dek = randomBytes(32);
    const wrapped = await kek.wrap(dek, CONTEXT);

    expect(wrapped.kekVersion).toBe(1);
    expect(wrapped.wrappedDek.byteLength).toBe(LOCAL_WRAPPED_DEK_BYTES);
    expect(wrapped.wrappedDek.includes(dek)).toBe(false);
    expect((await kek.unwrap(wrapped, CONTEXT)).equals(dek)).toBe(true);
  });

  it('wraps the same key differently every time', async () => {
    const kek = InMemoryKekProvider.random();
    const dek = randomBytes(32);
    const a = await kek.wrap(dek, CONTEXT);
    const b = await kek.wrap(dek, CONTEXT);
    expect(a.wrappedDek.equals(b.wrappedDek)).toBe(false);
  });

  it('wraps with the highest version and still unwraps older ones', async () => {
    const v1Key = randomBytes(32);
    const old = new InMemoryKekProvider([[1, v1Key]]);
    const rotated = new InMemoryKekProvider([
      [7, randomBytes(32)],
      [1, v1Key],
    ]);
    expect(rotated.currentVersion).toBe(7);
    expect(rotated.versions).toEqual([1, 7]);

    const dek = randomBytes(32);
    const wrappedOld = await old.wrap(dek, CONTEXT);
    expect((await rotated.unwrap(wrappedOld, CONTEXT)).equals(dek)).toBe(true);
    expect((await rotated.wrap(dek, CONTEXT)).kekVersion).toBe(7);
  });

  it('fails generically for a wrong context, version, key or tampered blob', async () => {
    const kek = InMemoryKekProvider.random(1, 2);
    const wrapped = await kek.wrap(randomBytes(32), CONTEXT);
    const flipped = Buffer.from(wrapped.wrappedDek);
    flipped[30] = (flipped[30] ?? 0) ^ 0xff;

    const attempts = [
      kek.unwrap(wrapped, OTHER_CONTEXT),
      kek.unwrap({ ...wrapped, kekVersion: 1 }, CONTEXT),
      kek.unwrap({ ...wrapped, kekVersion: 3 }, CONTEXT),
      kek.unwrap({ ...wrapped, wrappedDek: flipped }, CONTEXT),
      kek.unwrap({ ...wrapped, wrappedDek: wrapped.wrappedDek.subarray(0, 44) }, CONTEXT),
      kek.unwrap({ ...wrapped, wrappedDek: Buffer.alloc(0) }, CONTEXT),
      InMemoryKekProvider.random(2).unwrap(wrapped, CONTEXT),
    ];
    for (const attempt of attempts) {
      const error: unknown = await attempt.catch((reason: unknown) => reason);
      expect(error).toBeInstanceOf(KekOperationError);
      expect((error as Error).message).toBe('unable to unwrap data key');
    }
  });

  it('rejects malformed keys and data keys', async () => {
    expect(() => new InMemoryKekProvider([])).toThrow(CryptoInputError);
    expect(() => new InMemoryKekProvider([[1, randomBytes(16)]])).toThrow(CryptoInputError);
    expect(() => new InMemoryKekProvider([[0, randomBytes(32)]])).toThrow(CryptoInputError);
    expect(() => new InMemoryKekProvider([[1.5, randomBytes(32)]])).toThrow(CryptoInputError);
    expect(
      () =>
        new InMemoryKekProvider([
          [1, randomBytes(32)],
          [1, randomBytes(32)],
        ]),
    ).toThrow(CryptoInputError);

    const kek = InMemoryKekProvider.random();
    await expect(kek.wrap(randomBytes(16), CONTEXT)).rejects.toBeInstanceOf(CryptoInputError);
    await expect(kek.wrap(randomBytes(33), CONTEXT)).rejects.toBeInstanceOf(CryptoInputError);
  });

  it('does not expose key bytes through inspect, JSON or enumeration', () => {
    const key = randomBytes(32);
    const kek = new InMemoryKekProvider([[1, key]]);
    const output = [
      inspect(kek, { depth: 10, showHidden: true }),
      JSON.stringify(kek),
      JSON.stringify(Object.entries(kek)),
      String(kek),
    ].join('\n');

    expect(output).not.toContain(key.toString('hex'));
    expect(output).not.toContain(key.toString('base64'));
    expect(output).not.toContain(key.toString('base64url'));
    expect(inspect(kek)).toContain('InMemoryKekProvider');
    expect(inspect(kek)).toContain('versions');
  });

  it('keeps its own copy of the key, so the caller can zero theirs', async () => {
    const key = randomBytes(32);
    const kek = new InMemoryKekProvider([[1, key]]);
    const dek = randomBytes(32);
    const wrapped = await kek.wrap(dek, CONTEXT);
    key.fill(0);
    expect((await kek.unwrap(wrapped, CONTEXT)).equals(dek)).toBe(true);
  });
});

describe('LocalFileKekProvider', () => {
  let root: string;
  let dir: string;

  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), 'aab-crypto-test-'));
    dir = join(root, 'keys');
    await mkdir(dir);
    await chmod(dir, 0o700);
  });

  afterEach(async () => {
    await rm(root, { recursive: true, force: true });
  });

  async function expectLoadToFail(directory: string, pattern: RegExp): Promise<Error> {
    const error: unknown = await LocalFileKekProvider.load(directory).catch(
      (reason: unknown) => reason,
    );
    expect(error).toBeInstanceOf(KekStoreError);
    expect((error as Error).message).toMatch(pattern);
    return error as Error;
  }

  it('loads a 0600 key and uses it', async () => {
    const key = randomBytes(32);
    await writeKey(join(dir, 'kek-v1.key'), key, 0o600);

    const kek = await LocalFileKekProvider.load(dir);
    expect(kek.currentVersion).toBe(1);
    expect(kek.directory).toBe(dir);

    // Interoperates with a provider built from the same bytes.
    const dek = randomBytes(32);
    const wrapped = await new InMemoryKekProvider([[1, key]]).wrap(dek, CONTEXT);
    expect((await kek.unwrap(wrapped, CONTEXT)).equals(dek)).toBe(true);
  });

  it('accepts a stricter mode than 0600', async () => {
    await writeKey(join(dir, 'kek-v1.key'), randomBytes(32), 0o400);
    expect((await LocalFileKekProvider.load(dir)).versions).toEqual([1]);
  });

  it.each([0o644, 0o640, 0o604, 0o660, 0o620, 0o602, 0o610, 0o601])(
    'rejects a key file with mode %o',
    async (mode) => {
      await writeKey(join(dir, 'kek-v1.key'), randomBytes(32), mode);
      await expectLoadToFail(dir, /group or other/);
    },
  );

  it.each([0, 16, 31, 33, 64])('rejects a key file of %i bytes', async (length) => {
    await writeKey(join(dir, 'kek-v1.key'), randomBytes(length), 0o600);
    await expectLoadToFail(dir, /exactly 32 bytes/);
  });

  it('rejects a symbolic link, even to a well-formed key', async () => {
    const real = join(root, 'elsewhere.key');
    await writeKey(real, randomBytes(32), 0o600);
    await symlink(real, join(dir, 'kek-v1.key'));
    await expectLoadToFail(dir, /symbolic link/);
  });

  it('rejects a directory named like a key file', async () => {
    await mkdir(join(dir, 'kek-v1.key'), { mode: 0o700 });
    await expectLoadToFail(dir, /not a regular file|cannot be opened/);
  });

  it('fails closed when one of several keys is unsafe', async () => {
    await writeKey(join(dir, 'kek-v1.key'), randomBytes(32), 0o600);
    await writeKey(join(dir, 'kek-v2.key'), randomBytes(32), 0o644);
    await expectLoadToFail(dir, /group or other/);
  });

  it.each([0o770, 0o707, 0o720, 0o702, 0o777, 0o750, 0o755, 0o710, 0o701, 0o740, 0o704])(
    'rejects a key directory with mode %o',
    async (mode) => {
      await writeKey(join(dir, 'kek-v1.key'), randomBytes(32), 0o600);
      await chmod(dir, mode);
      await expectLoadToFail(dir, /accessible by group or other/);
    },
  );

  it.each([0o700, 0o500])('accepts a key directory with mode %o', async (mode) => {
    await writeKey(join(dir, 'kek-v1.key'), randomBytes(32), 0o600);
    await chmod(dir, mode);
    try {
      expect((await LocalFileKekProvider.load(dir)).versions).toEqual([1]);
    } finally {
      await chmod(dir, 0o700);
    }
  });

  it('rejects a missing directory, a file and a symlinked directory', async () => {
    await expectLoadToFail(join(root, 'missing'), /does not exist/);

    const file = join(root, 'a-file');
    await writeFile(file, 'x');
    await expectLoadToFail(file, /not a directory/);

    await writeKey(join(dir, 'kek-v1.key'), randomBytes(32), 0o600);
    const link = join(root, 'link');
    await symlink(dir, link);
    await expectLoadToFail(link, /not a directory/);
  });

  it('rejects a directory with no key files and ignores unrelated names', async () => {
    await expectLoadToFail(dir, /no KEK files/);

    // None of these match kek-v<N>.key, so they are neither loaded nor permission-checked.
    for (const name of ['README.txt', 'kek-v1.key.bak', 'kek-v0.key', 'kek-v01.key', 'kek-1.key']) {
      await writeKey(join(dir, name), randomBytes(32), 0o644);
    }
    await expectLoadToFail(dir, /no KEK files/);

    await writeKey(join(dir, 'kek-v3.key'), randomBytes(32), 0o600);
    expect((await LocalFileKekProvider.load(dir)).versions).toEqual([3]);
  });

  it('makes the highest version current and keeps older ones for unwrap', async () => {
    const v2 = randomBytes(32);
    await writeKey(join(dir, 'kek-v2.key'), v2, 0o600);
    await writeKey(join(dir, 'kek-v10.key'), randomBytes(32), 0o600);
    await writeKey(join(dir, 'kek-v9.key'), randomBytes(32), 0o600);

    const kek = await LocalFileKekProvider.load(dir);
    expect(kek.versions).toEqual([2, 9, 10]);
    expect(kek.currentVersion).toBe(10);

    const dek = randomBytes(32);
    const oldWrap = await new InMemoryKekProvider([[2, v2]]).wrap(dek, CONTEXT);
    expect((await kek.unwrap(oldWrap, CONTEXT)).equals(dek)).toBe(true);
    expect((await kek.wrap(dek, CONTEXT)).kekVersion).toBe(10);
  });

  it('never puts key bytes in error messages or inspect output', async () => {
    const key = randomBytes(32);
    await writeKey(join(dir, 'kek-v1.key'), key, 0o644);
    const error = await expectLoadToFail(dir, /group or other/);
    await chmod(join(dir, 'kek-v1.key'), 0o600);
    const kek = await LocalFileKekProvider.load(dir);

    const output = [
      inspect(error, { depth: 10, showHidden: true }),
      inspect(kek, { depth: 10, showHidden: true }),
      JSON.stringify(kek),
    ].join('\n');
    expect(output).not.toContain(key.toString('hex'));
    expect(output).not.toContain(key.toString('base64'));
    expect(output).not.toContain(key.toString('base64url'));
    expect(inspect(kek)).toContain(dir);
  });

  describe('generateLocalKek', () => {
    it('creates a 0700 directory and a 0600 32-byte key that loads', async () => {
      const fresh = join(root, 'nested', 'fresh-keys');
      const path = await generateLocalKek(fresh, 1);

      expect(path).toBe(join(fresh, 'kek-v1.key'));
      expect((await stat(fresh)).mode & 0o777).toBe(0o700);
      const fileStat = await stat(path);
      expect(fileStat.mode & 0o777).toBe(0o600);
      expect(fileStat.size).toBe(32);

      const kek = await LocalFileKekProvider.load(fresh);
      expect(kek.currentVersion).toBe(1);
    });

    it('generates distinct keys for distinct versions', async () => {
      const a = await readFile(await generateLocalKek(dir, 1));
      const b = await readFile(await generateLocalKek(dir, 2));
      expect(a.equals(b)).toBe(false);
      expect(a.equals(Buffer.alloc(32))).toBe(false);
      expect((await LocalFileKekProvider.load(dir)).versions).toEqual([1, 2]);
    });

    it('refuses to overwrite an existing key and leaves it untouched', async () => {
      const path = await generateLocalKek(dir, 1);
      const original = await readFile(path);

      const error: unknown = await generateLocalKek(dir, 1).catch((reason: unknown) => reason);
      expect(error).toBeInstanceOf(KekStoreError);
      expect((error as Error).message).toMatch(/already exists/);
      expect((await readFile(path)).equals(original)).toBe(true);
    });

    it('refuses to write through a symbolic link', async () => {
      const target = join(root, 'target.key');
      await symlink(target, join(dir, 'kek-v1.key'));
      await expect(generateLocalKek(dir, 1)).rejects.toBeInstanceOf(KekStoreError);
      await expect(stat(target)).rejects.toThrow();
    });

    it.each([0o750, 0o755])(
      'refuses an existing %o directory and writes no key into it',
      async (mode) => {
        await chmod(dir, mode);
        const error: unknown = await generateLocalKek(dir, 1).catch((reason: unknown) => reason);
        await chmod(dir, 0o700);
        expect(error).toBeInstanceOf(KekStoreError);
        expect((error as Error).message).toMatch(/accessible by group or other/);
        await expect(stat(join(dir, 'kek-v1.key'))).rejects.toThrow();
      },
    );

    it('refuses an unsafe existing directory and invalid versions', async () => {
      await chmod(dir, 0o777);
      await expect(generateLocalKek(dir, 1)).rejects.toBeInstanceOf(KekStoreError);
      await chmod(dir, 0o700);

      for (const version of [0, -1, 1.5, Number.NaN, 1e12]) {
        await expect(generateLocalKek(dir, version)).rejects.toBeInstanceOf(CryptoInputError);
      }
    });
  });
});
