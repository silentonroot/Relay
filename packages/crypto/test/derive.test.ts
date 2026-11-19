import { createSecretKey, randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  CryptoInputError,
  deriveKey,
  InMemoryKekProvider,
  KekOperationError,
  KEY_PURPOSES,
  macSha256,
  verifyMac,
} from '../src/index.js';

const hex = (value: string) => Buffer.from(value.replace(/\s+/g, ''), 'hex');
const range = (from: number, to: number) =>
  Buffer.from(Array.from({ length: to - from + 1 }, (_, index) => from + index));

describe('deriveKey (RFC 5869, HKDF-SHA-256)', () => {
  it('matches test case 1', () => {
    const okm = deriveKey(Buffer.alloc(22, 0x0b), {
      salt: hex('000102030405060708090a0b0c'),
      info: hex('f0f1f2f3f4f5f6f7f8f9'),
      length: 42,
    });
    expect(okm.toString('hex')).toBe(
      '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865',
    );
  });

  it('matches test case 2 (longer inputs and outputs)', () => {
    const okm = deriveKey(range(0x00, 0x4f), {
      salt: range(0x60, 0xaf),
      info: range(0xb0, 0xff),
      length: 82,
    });
    expect(okm.toString('hex')).toBe(
      'b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c' +
        '59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71' +
        'cc30c58179ec3e87c14c01d5c1f3434f1d87',
    );
  });

  it('treats an absent salt as the RFC does, a string of zero bytes', () => {
    const ikm = randomBytes(32);
    const info = 'label';
    expect(deriveKey(ikm, { info }).equals(deriveKey(ikm, { info, salt: Buffer.alloc(32) }))).toBe(
      true,
    );
  });

  it('separates domains by info, and accepts a KeyObject as input', () => {
    const ikm = randomBytes(32);
    const a = deriveKey(ikm, { info: 'aab.a' });
    expect(a.equals(deriveKey(ikm, { info: 'aab.b' }))).toBe(false);
    expect(a.equals(deriveKey(createSecretKey(ikm), { info: 'aab.a' }))).toBe(true);
    expect(a.byteLength).toBe(32);
  });

  it('refuses empty or oversized info and out-of-range lengths', () => {
    const ikm = randomBytes(32);
    expect(() => deriveKey(ikm, { info: '' })).toThrow(CryptoInputError);
    expect(() => deriveKey(ikm, { info: 'x'.repeat(1025) })).toThrow(CryptoInputError);
    for (const length of [0, -1, 1.5, 8161, Number.NaN]) {
      expect(() => deriveKey(ikm, { info: 'x', length })).toThrow(CryptoInputError);
    }
  });
});

describe('macSha256 and verifyMac (RFC 4231, HMAC-SHA-256)', () => {
  const vectors: Array<[string, Buffer, string | Buffer, string]> = [
    [
      'test case 1',
      Buffer.alloc(20, 0x0b),
      'Hi There',
      'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7',
    ],
    [
      'test case 2',
      Buffer.from('Jefe'),
      'what do ya want for nothing?',
      '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843',
    ],
    [
      'test case 3',
      Buffer.alloc(20, 0xaa),
      Buffer.alloc(50, 0xdd),
      '773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe',
    ],
    [
      'test case 4',
      range(0x01, 0x19),
      Buffer.alloc(50, 0xcd),
      '82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b',
    ],
    [
      'test case 6 (key larger than the block size)',
      Buffer.alloc(131, 0xaa),
      'Test Using Larger Than Block-Size Key - Hash Key First',
      '60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54',
    ],
    [
      'test case 7 (key and data larger than the block size)',
      Buffer.alloc(131, 0xaa),
      'This is a test using a larger than block-size key and a larger than block-size data. ' +
        'The key needs to be hashed before being used by the HMAC algorithm.',
      '9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2',
    ],
  ];

  it.each(vectors)('matches %s', (_name, key, data, expected) => {
    expect(macSha256(key, data).toString('hex')).toBe(expected);
    expect(verifyMac(key, data, hex(expected))).toBe(true);
  });

  it('refuses a changed message, a changed key, a flipped bit and a wrong length', () => {
    const key = randomBytes(32);
    const mac = macSha256(key, 'message');
    expect(verifyMac(key, 'message', mac)).toBe(true);
    expect(verifyMac(key, 'messagf', mac)).toBe(false);
    expect(verifyMac(randomBytes(32), 'message', mac)).toBe(false);
    const flipped = Buffer.from(mac);
    flipped[31] = (flipped[31] ?? 0) ^ 1;
    expect(verifyMac(key, 'message', flipped)).toBe(false);
    expect(verifyMac(key, 'message', mac.subarray(0, 31))).toBe(false);
    expect(verifyMac(key, 'message', Buffer.concat([mac, Buffer.from([0])]))).toBe(false);
    expect(verifyMac(key, 'message', Buffer.alloc(0))).toBe(false);
    expect(verifyMac(key, 'message', 'abc' as unknown as Uint8Array)).toBe(false);
  });

  it('refuses an empty key', () => {
    expect(() => macSha256(Buffer.alloc(0), 'x')).toThrow(CryptoInputError);
  });
});

describe('KEK provider deriveKeyFor', () => {
  it('derives per KEK version with the purpose label, and records the version', () => {
    const kekV1 = randomBytes(32);
    const kekV2 = randomBytes(32);
    const provider = new InMemoryKekProvider([
      [1, kekV1],
      [2, kekV2],
    ]);
    const first = provider.deriveKeyFor(1, 'vaultCapabilityMac');
    const second = provider.deriveKeyFor(2, 'vaultCapabilityMac');
    expect(first.kekVersion).toBe(1);
    expect(second.kekVersion).toBe(2);
    expect(first.key.equals(second.key)).toBe(false);
    expect(first.key.equals(deriveKey(kekV1, { info: KEY_PURPOSES.vaultCapabilityMac }))).toBe(
      true,
    );
    expect(first.key.equals(kekV1)).toBe(false);
    expect(provider.hasVersion(2)).toBe(true);
    expect(provider.hasVersion(3)).toBe(false);
  });

  it('refuses a version the provider does not hold, with a generic error', () => {
    const provider = InMemoryKekProvider.random();
    expect(() => provider.deriveKeyFor(2, 'vaultCapabilityMac')).toThrow(KekOperationError);
    expect(() => provider.deriveKeyFor(0, 'vaultCapabilityMac')).toThrow(CryptoInputError);
  });
});
