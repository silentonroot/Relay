import { createHash, randomBytes } from 'node:crypto';
import { inspect } from 'node:util';
import { describe, expect, it } from 'vitest';
import {
  AAD_VERSION,
  CryptoInputError,
  ENVELOPE_ALGORITHM,
  encodeSecretAad,
  InMemoryKekProvider,
  LOCAL_WRAPPED_DEK_BYTES,
  openSecret,
  rewrapSecret,
  sealSecret,
  SecretOpenError,
} from '../src/index.js';
import type { KekContext, KekProvider, SealedSecret, SecretAad, WrappedDek } from '../src/index.js';

const AAD: SecretAad = {
  organizationId: '0b9f6f0e-2f0b-4c8e-9d43-0d9c1b1f7a11',
  userId: '6a1d1c52-8f1a-4d0e-b0a5-3f1f0a4c2b22',
  connectionId: 'c2f4a6e8-1b3d-4f5a-8c7e-9d0b1a2c3e33',
  secretId: 'd4e6f8a0-2c4e-4a6c-9e8a-0b1c2d3e4f44', // gitleaks:allow (synthetic test value)
  secretType: 'browser_session',
  secretVersion: 1,
};

const OTHER_UUID = 'ffffffff-ffff-4fff-bfff-ffffffffffff';

function clone(sealed: SealedSecret): SealedSecret {
  return {
    ...sealed,
    ciphertext: Buffer.from(sealed.ciphertext),
    nonce: Buffer.from(sealed.nonce),
    authTag: Buffer.from(sealed.authTag),
    wrappedDek: Buffer.from(sealed.wrappedDek),
  };
}

function flipBit(buffer: Buffer, index: number): void {
  buffer[index] = (buffer[index] ?? 0) ^ 0x01;
}

async function expectOpenToFail(
  sealed: SealedSecret,
  aad: SecretAad,
  kek: KekProvider,
): Promise<void> {
  const error: unknown = await openSecret({ sealed, aad, kek }).then(
    () => undefined,
    (reason: unknown) => reason,
  );
  expect(error).toBeInstanceOf(SecretOpenError);
  // Every failure must be indistinguishable from every other.
  expect((error as Error).message).toBe('unable to open sealed secret');
  expect((error as Error).cause).toBeUndefined();
}

/** Wraps a real provider and records what the envelope hands to it. */
class RecordingKekProvider implements KekProvider {
  readonly dekDigests: string[] = [];
  readonly dekBuffers: Uint8Array[] = [];
  readonly #inner = InMemoryKekProvider.random(1);

  get currentVersion(): number {
    return this.#inner.currentVersion;
  }

  wrap(dek: Uint8Array, context: KekContext): Promise<WrappedDek> {
    this.dekDigests.push(createHash('sha256').update(dek).digest('hex'));
    this.dekBuffers.push(dek);
    return this.#inner.wrap(dek, context);
  }

  unwrap(wrapped: WrappedDek, context: KekContext): Promise<Buffer> {
    return this.#inner.unwrap(wrapped, context);
  }
}

describe('sealSecret / openSecret', () => {
  it.each([
    ['empty', Buffer.alloc(0)],
    ['small', Buffer.from('{"cookies":[{"name":"sid","value":"synthetic"}]}', 'utf8')],
    ['1 MB', randomBytes(1024 * 1024)],
  ])('round-trips a %s plaintext', async (_label, plaintext) => {
    const kek = InMemoryKekProvider.random();
    const sealed = await sealSecret({ plaintext, aad: AAD, kek });
    const opened = await openSecret({ sealed, aad: AAD, kek });
    expect(opened.equals(plaintext)).toBe(true);
  });

  it('produces a record with the documented shape and sizes', async () => {
    const kek = InMemoryKekProvider.random(3);
    const plaintext = Buffer.from('synthetic session state');
    const sealed = await sealSecret({ plaintext, aad: AAD, kek });

    expect(sealed.algorithm).toBe(ENVELOPE_ALGORITHM);
    expect(sealed.aadVersion).toBe(AAD_VERSION);
    expect(sealed.kekVersion).toBe(3);
    expect(sealed.nonce.byteLength).toBe(12);
    expect(sealed.authTag.byteLength).toBe(16);
    expect(sealed.ciphertext.byteLength).toBe(plaintext.byteLength);
    expect(sealed.wrappedDek.byteLength).toBe(LOCAL_WRAPPED_DEK_BYTES);
    expect(sealed.ciphertext.includes(plaintext)).toBe(false);
  });

  it('accepts a plain Uint8Array and does not modify the caller plaintext', async () => {
    const kek = InMemoryKekProvider.random();
    const plaintext = new Uint8Array([1, 2, 3, 4, 5]);
    const sealed = await sealSecret({ plaintext, aad: AAD, kek });
    expect([...plaintext]).toEqual([1, 2, 3, 4, 5]);
    expect([...(await openSecret({ sealed, aad: AAD, kek }))]).toEqual([1, 2, 3, 4, 5]);
  });

  it('treats UUID case as insignificant in the bound context', async () => {
    const kek = InMemoryKekProvider.random();
    const upper = { ...AAD, secretId: AAD.secretId.toUpperCase() };
    const sealed = await sealSecret({ plaintext: Buffer.from('x'), aad: upper, kek });
    expect((await openSecret({ sealed, aad: AAD, kek })).toString()).toBe('x');
  });

  it.each([
    ['organizationId', { organizationId: OTHER_UUID }],
    ['userId', { userId: OTHER_UUID }],
    ['connectionId', { connectionId: OTHER_UUID }],
    ['secretId', { secretId: OTHER_UUID }],
    ['secretType', { secretType: 'oauth_refresh_token' }],
    ['secretVersion', { secretVersion: 2 }],
  ] as const)('refuses to open when aad.%s differs', async (_field, change) => {
    const kek = InMemoryKekProvider.random();
    const sealed = await sealSecret({ plaintext: Buffer.from('secret'), aad: AAD, kek });
    await expectOpenToFail(sealed, { ...AAD, ...change }, kek);
  });

  it('refuses to open when the caller AAD is malformed, with the same generic error', async () => {
    const kek = InMemoryKekProvider.random();
    const sealed = await sealSecret({ plaintext: Buffer.from('secret'), aad: AAD, kek });
    await expectOpenToFail(sealed, { ...AAD, connectionId: 'not-a-uuid' }, kek);
    await expectOpenToFail(sealed, { ...AAD, secretVersion: 0 }, kek);
  });

  it.each([
    ['ciphertext', (s: SealedSecret) => flipBit(s.ciphertext, 0)],
    ['last ciphertext byte', (s: SealedSecret) => flipBit(s.ciphertext, s.ciphertext.length - 1)],
    ['nonce', (s: SealedSecret) => flipBit(s.nonce, 5)],
    ['auth tag', (s: SealedSecret) => flipBit(s.authTag, 15)],
    ['wrapped-DEK nonce', (s: SealedSecret) => flipBit(s.wrappedDek, 0)],
    ['wrapped DEK', (s: SealedSecret) => flipBit(s.wrappedDek, 12 + 7)],
    ['wrapped-DEK tag', (s: SealedSecret) => flipBit(s.wrappedDek, LOCAL_WRAPPED_DEK_BYTES - 1)],
  ])('refuses to open after one flipped bit in the %s', async (_label, tamper) => {
    const kek = InMemoryKekProvider.random();
    const sealed = await sealSecret({ plaintext: Buffer.from('secret value'), aad: AAD, kek });
    const tampered = clone(sealed);
    tamper(tampered);
    await expectOpenToFail(tampered, AAD, kek);
    // The untouched original still opens, so the failure is caused by the flipped bit alone.
    expect((await openSecret({ sealed, aad: AAD, kek })).toString()).toBe('secret value');
  });

  it.each([
    ['tag truncated to 8 bytes', (s: SealedSecret) => (s.authTag = s.authTag.subarray(0, 8))],
    ['tag truncated to 4 bytes', (s: SealedSecret) => (s.authTag = s.authTag.subarray(0, 4))],
    ['tag truncated to 15 bytes', (s: SealedSecret) => (s.authTag = s.authTag.subarray(0, 15))],
    ['empty tag', (s: SealedSecret) => (s.authTag = Buffer.alloc(0))],
    [
      'tag with an extra byte',
      (s: SealedSecret) => (s.authTag = Buffer.concat([s.authTag, Buffer.alloc(1)])),
    ],
    ['nonce truncated', (s: SealedSecret) => (s.nonce = s.nonce.subarray(0, 8))],
    [
      'nonce extended to 16 bytes',
      (s: SealedSecret) => (s.nonce = Buffer.concat([s.nonce, Buffer.alloc(4)])),
    ],
    ['ciphertext truncated', (s: SealedSecret) => (s.ciphertext = s.ciphertext.subarray(0, 3))],
    [
      'ciphertext extended',
      (s: SealedSecret) => (s.ciphertext = Buffer.concat([s.ciphertext, Buffer.alloc(1)])),
    ],
    ['wrapped DEK truncated', (s: SealedSecret) => (s.wrappedDek = s.wrappedDek.subarray(0, 59))],
    [
      'wrapped DEK extended',
      (s: SealedSecret) => (s.wrappedDek = Buffer.concat([s.wrappedDek, Buffer.alloc(1)])),
    ],
    ['unknown algorithm', (s: SealedSecret) => (s.algorithm = 'aes-256-cbc')],
    ['unsupported aadVersion', (s: SealedSecret) => (s.aadVersion = 2)],
    ['unknown kekVersion', (s: SealedSecret) => (s.kekVersion = 99)],
  ])('refuses to open a record with %s', async (_label, tamper) => {
    const kek = InMemoryKekProvider.random();
    const tampered = clone(
      await sealSecret({ plaintext: Buffer.from('secret value'), aad: AAD, kek }),
    );
    tamper(tampered);
    await expectOpenToFail(tampered, AAD, kek);
  });

  it('refuses to open with a different KEK of the same version', async () => {
    const sealed = await sealSecret({
      plaintext: Buffer.from('secret'),
      aad: AAD,
      kek: InMemoryKekProvider.random(1),
    });
    await expectOpenToFail(sealed, AAD, InMemoryKekProvider.random(1));
  });

  it('refuses to open when the record claims another known KEK version', async () => {
    const kek = InMemoryKekProvider.random(1, 2);
    const sealed = clone(await sealSecret({ plaintext: Buffer.from('secret'), aad: AAD, kek }));
    expect(sealed.kekVersion).toBe(2);
    sealed.kekVersion = 1;
    await expectOpenToFail(sealed, AAD, kek);
  });

  it('refuses a wrapped DEK transplanted from another secret', async () => {
    const kek = InMemoryKekProvider.random();
    const otherAad = { ...AAD, secretId: OTHER_UUID };
    const a = await sealSecret({ plaintext: Buffer.from('secret A'), aad: AAD, kek });
    const b = await sealSecret({ plaintext: Buffer.from('secret B'), aad: otherAad, kek });

    // B's data key attached to A's row: the wrap is bound to B's context, so it will not unwrap.
    await expectOpenToFail({ ...clone(a), wrappedDek: Buffer.from(b.wrappedDek) }, AAD, kek);
    await expectOpenToFail({ ...clone(b), wrappedDek: Buffer.from(a.wrappedDek) }, otherAad, kek);
  });

  it('refuses a wrapped DEK swapped between two versions sealed under the same context', async () => {
    const kek = InMemoryKekProvider.random();
    const a = await sealSecret({ plaintext: Buffer.from('first'), aad: AAD, kek });
    const b = await sealSecret({ plaintext: Buffer.from('other'), aad: AAD, kek });
    // The data key unwraps (same context) but is the wrong key for this ciphertext.
    await expectOpenToFail({ ...clone(a), wrappedDek: Buffer.from(b.wrappedDek) }, AAD, kek);
  });

  it('uses a fresh nonce and a fresh data key for every seal', async () => {
    const kek = new RecordingKekProvider();
    const plaintext = Buffer.from('same plaintext every time');
    const nonces = new Set<string>();
    const wrapped = new Set<string>();
    const ciphertexts = new Set<string>();

    for (let i = 0; i < 2000; i += 1) {
      const sealed = await sealSecret({ plaintext, aad: AAD, kek });
      nonces.add(sealed.nonce.toString('hex'));
      wrapped.add(sealed.wrappedDek.toString('hex'));
      ciphertexts.add(sealed.ciphertext.toString('hex'));
    }

    expect(nonces.size).toBe(2000);
    expect(wrapped.size).toBe(2000);
    expect(ciphertexts.size).toBe(2000);
    expect(new Set(kek.dekDigests).size).toBe(2000);
  });

  it('zeroes its copy of the data key after sealing', async () => {
    const kek = new RecordingKekProvider();
    await sealSecret({ plaintext: Buffer.from('secret'), aad: AAD, kek });
    expect(kek.dekBuffers).toHaveLength(1);
    expect(kek.dekBuffers[0]?.byteLength).toBe(32);
    expect(kek.dekBuffers[0]?.every((byte) => byte === 0)).toBe(true);
  });

  it('rejects invalid seal input without echoing values', async () => {
    const kek = InMemoryKekProvider.random();
    const plaintext = Buffer.from('secret');

    await expect(
      sealSecret({ plaintext: 'a string' as unknown as Uint8Array, aad: AAD, kek }),
    ).rejects.toBeInstanceOf(CryptoInputError);

    const bad: [string, Partial<SecretAad>][] = [
      ['organizationId', { organizationId: 'nope-1234' }],
      ['secretId', { secretId: '' }],
      ['secretType', { secretType: '' }],
      ['secretType', { secretType: 'Has Spaces' }],
      ['secretVersion', { secretVersion: 0 }],
      ['secretVersion', { secretVersion: 1.5 }],
      ['secretVersion', { secretVersion: Number.NaN }],
    ];
    for (const [field, change] of bad) {
      const error: unknown = await sealSecret({ plaintext, aad: { ...AAD, ...change }, kek }).catch(
        (reason: unknown) => reason,
      );
      expect(error).toBeInstanceOf(CryptoInputError);
      expect((error as Error).message).toContain(field);
      expect((error as Error).message).not.toContain('nope-1234');
    }
  });

  it('keeps plaintext and key material out of errors and inspect output', async () => {
    const keyBytes = randomBytes(32);
    const kek = new InMemoryKekProvider([[1, keyBytes]]);
    const plaintext = Buffer.from('PLAINTEXT-MARKER-synthetic-cookie-value');
    const sealed = await sealSecret({ plaintext, aad: AAD, kek });

    const tampered = clone(sealed);
    flipBit(tampered.authTag, 0);
    const error: unknown = await openSecret({ sealed: tampered, aad: AAD, kek }).catch(
      (reason: unknown) => reason,
    );

    const haystack = [
      inspect(error, { depth: 10, showHidden: true }),
      String((error as Error).stack),
      JSON.stringify(error),
      inspect(sealed, { depth: 10, showHidden: true }),
      inspect(kek, { depth: 10, showHidden: true }),
      JSON.stringify(kek),
    ].join('\n');

    for (const secret of [plaintext, keyBytes]) {
      expect(haystack).not.toContain(secret.toString('utf8'));
      expect(haystack).not.toContain(secret.toString('hex'));
      expect(haystack).not.toContain(secret.toString('base64'));
      expect(haystack).not.toContain(secret.toString('base64url'));
    }
    expect(haystack).not.toContain('PLAINTEXT-MARKER');
  });
});

describe('encodeSecretAad', () => {
  it('is deterministic, order-independent and ignores unknown properties', () => {
    const reordered = {
      secretVersion: 1,
      secretType: 'browser_session',
      secretId: AAD.secretId,
      connectionId: AAD.connectionId,
      userId: AAD.userId,
      organizationId: AAD.organizationId,
      extra: 'ignored',
    };
    expect(encodeSecretAad(reordered).equals(encodeSecretAad(AAD))).toBe(true);
  });

  it('encodes the documented canonical JSON', () => {
    expect(encodeSecretAad(AAD).toString('utf8')).toBe(
      `{"aadVersion":1,"connectionId":"${AAD.connectionId}","organizationId":"${AAD.organizationId}",` +
        `"secretId":"${AAD.secretId}","secretType":"browser_session","secretVersion":1,"userId":"${AAD.userId}"}`,
    );
  });

  it('rejects an unsupported AAD version', () => {
    expect(() => encodeSecretAad(AAD, 2)).toThrow(CryptoInputError);
  });
});

describe('rewrapSecret', () => {
  it('moves a secret to a new KEK without touching the ciphertext', async () => {
    const oldKek = InMemoryKekProvider.random(1);
    const newKek = InMemoryKekProvider.random(2);
    const plaintext = Buffer.from('rotate me');
    const sealed = await sealSecret({ plaintext, aad: AAD, kek: oldKek });
    const before = clone(sealed);

    const rewrapped = await rewrapSecret({ sealed, aad: AAD, from: oldKek, to: newKek });

    expect(rewrapped.kekVersion).toBe(2);
    expect(rewrapped.ciphertext.equals(before.ciphertext)).toBe(true);
    expect(rewrapped.nonce.equals(before.nonce)).toBe(true);
    expect(rewrapped.authTag.equals(before.authTag)).toBe(true);
    expect(rewrapped.wrappedDek.equals(before.wrappedDek)).toBe(false);
    expect(rewrapped.algorithm).toBe(before.algorithm);
    expect(rewrapped.aadVersion).toBe(before.aadVersion);

    expect((await openSecret({ sealed: rewrapped, aad: AAD, kek: newKek })).equals(plaintext)).toBe(
      true,
    );
    await expectOpenToFail(rewrapped, AAD, oldKek);

    // The input record is left as it was and still opens under the old KEK.
    expect(sealed.wrappedDek.equals(before.wrappedDek)).toBe(true);
    expect((await openSecret({ sealed, aad: AAD, kek: oldKek })).equals(plaintext)).toBe(true);
  });

  it('rotates within one provider that holds both versions', async () => {
    const v1Key = randomBytes(32);
    const v1Only = new InMemoryKekProvider([[1, v1Key]]);
    const both = new InMemoryKekProvider([
      [1, v1Key],
      [2, randomBytes(32)],
    ]);
    const sealed = await sealSecret({ plaintext: Buffer.from('x'), aad: AAD, kek: v1Only });

    const rewrapped = await rewrapSecret({ sealed, aad: AAD, from: both, to: both });
    expect(rewrapped.kekVersion).toBe(2);
    expect((await openSecret({ sealed: rewrapped, aad: AAD, kek: both })).toString()).toBe('x');
    await expectOpenToFail(rewrapped, AAD, v1Only);
  });

  it('refuses to rewrap for the wrong context or with the wrong source KEK', async () => {
    const oldKek = InMemoryKekProvider.random(1);
    const newKek = InMemoryKekProvider.random(2);
    const sealed = await sealSecret({ plaintext: Buffer.from('x'), aad: AAD, kek: oldKek });

    await expect(
      rewrapSecret({ sealed, aad: { ...AAD, userId: OTHER_UUID }, from: oldKek, to: newKek }),
    ).rejects.toBeInstanceOf(SecretOpenError);
    await expect(
      rewrapSecret({ sealed, aad: AAD, from: InMemoryKekProvider.random(1), to: newKek }),
    ).rejects.toBeInstanceOf(SecretOpenError);

    const tampered = clone(sealed);
    flipBit(tampered.wrappedDek, 20);
    await expect(
      rewrapSecret({ sealed: tampered, aad: AAD, from: oldKek, to: newKek }),
    ).rejects.toBeInstanceOf(SecretOpenError);
  });
});
