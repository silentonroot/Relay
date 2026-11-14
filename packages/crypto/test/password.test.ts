import { describe, expect, it } from 'vitest';
import {
  CryptoInputError,
  DEFAULT_SCRYPT_PARAMS,
  hashPassword,
  MAX_PASSWORD_BYTES,
  needsRehash,
  verifyPassword,
} from '../src/index.js';
import type { ScryptParams } from '../src/index.js';

// Cheap parameters keep the suite fast. The default-cost path is exercised once below.
const CHEAP: ScryptParams = { logN: 10, r: 8, p: 1 };
const PASSWORD = 'synthetic-correct-horse-battery';

describe('password hashing', () => {
  it('uses the documented default cost and verifies with it', async () => {
    expect(DEFAULT_SCRYPT_PARAMS).toEqual({ logN: 17, r: 8, p: 1 });

    const encoded = await hashPassword(PASSWORD);
    expect(encoded).toMatch(/^\$scrypt\$ln=17,r=8,p=1\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$/);
    expect(await verifyPassword(PASSWORD, encoded)).toBe(true);
    expect(await verifyPassword(`${PASSWORD}!`, encoded)).toBe(false);
    expect(needsRehash(encoded)).toBe(false);
  });

  it('records the parameters actually used', async () => {
    const encoded = await hashPassword(PASSWORD, { params: CHEAP });
    expect(encoded.startsWith('$scrypt$ln=10,r=8,p=1$')).toBe(true);
    expect(await verifyPassword(PASSWORD, encoded)).toBe(true);
  });

  it('rejects wrong passwords', async () => {
    const encoded = await hashPassword(PASSWORD, { params: CHEAP });
    for (const wrong of [
      '',
      'synthetic-correct-horse-batter',
      `${PASSWORD} `,
      PASSWORD.toUpperCase(),
      `${PASSWORD}\0`,
    ]) {
      expect(await verifyPassword(wrong, encoded)).toBe(false);
    }
  });

  it('salts every hash', async () => {
    const a = await hashPassword(PASSWORD, { params: CHEAP });
    const b = await hashPassword(PASSWORD, { params: CHEAP });
    expect(a).not.toBe(b);
    expect(a.split('$')[4]).not.toBe(b.split('$')[4]);
    expect(await verifyPassword(PASSWORD, a)).toBe(true);
    expect(await verifyPassword(PASSWORD, b)).toBe(true);
  });

  it('handles non-ASCII passwords by their UTF-8 bytes', async () => {
    const encoded = await hashPassword('pässwörd-密碼-🔑', { params: CHEAP });
    expect(await verifyPassword('pässwörd-密碼-🔑', encoded)).toBe(true);
    expect(await verifyPassword('passwörd-密碼-🔑', encoded)).toBe(false);
  });

  it('returns false, without throwing, for malformed encoded hashes', async () => {
    const good = await hashPassword(PASSWORD, { params: CHEAP });
    const [, , params, salt, hash] = good.split('$') as [string, string, string, string, string];

    const malformed: unknown[] = [
      '',
      'not a hash',
      PASSWORD,
      good.slice(1),
      `${good}$`,
      `${good}\n`,
      ` ${good}`,
      `$argon2id$${params}$${salt}$${hash}`,
      `$scrypt$${params}$${salt}`,
      `$scrypt$${params}$$${hash}`,
      `$scrypt$ln=10,r=8$${salt}$${hash}`,
      `$scrypt$r=8,ln=10,p=1$${salt}$${hash}`,
      `$scrypt$ln=0,r=8,p=1$${salt}$${hash}`,
      `$scrypt$ln=9,r=8,p=1$${salt}$${hash}`,
      `$scrypt$ln=30,r=8,p=1$${salt}$${hash}`,
      `$scrypt$ln=99,r=99,p=99$${salt}$${hash}`,
      `$scrypt$ln=10,r=64,p=1$${salt}$${hash}`,
      `$scrypt$ln=10,r=8,p=16$${salt}$${hash}`,
      `$scrypt$ln=10,r=-8,p=1$${salt}$${hash}`,
      `$scrypt$ln=1e1,r=8,p=1$${salt}$${hash}`,
      `$scrypt$${params}$${salt}=$${hash}`,
      `$scrypt$${params}$${salt}$${hash}==`,
      `$scrypt$${params}$!!!!$${hash}`,
      `$scrypt$${params}$AAAA$${hash}`,
      `$scrypt$${params}$${salt}$AAAA`,
      `$scrypt$${params}$${salt}$${'A'.repeat(200)}`,
      'x'.repeat(10_000),
      undefined,
      null,
      42,
      {},
    ];
    for (const encoded of malformed) {
      await expect(verifyPassword(PASSWORD, encoded as string)).resolves.toBe(false);
    }
  });

  it('rejects a hash whose value was altered', async () => {
    const good = await hashPassword(PASSWORD, { params: CHEAP });
    const parts = good.split('$');
    const hash = parts[5] ?? '';
    parts[5] = (hash.startsWith('A') ? 'B' : 'A') + hash.slice(1);
    expect(await verifyPassword(PASSWORD, parts.join('$'))).toBe(false);
  });

  it('enforces the maximum password length before hashing', async () => {
    const atLimit = 'a'.repeat(MAX_PASSWORD_BYTES);
    const encoded = await hashPassword(atLimit, { params: CHEAP });
    expect(await verifyPassword(atLimit, encoded)).toBe(true);

    const tooLong = 'a'.repeat(MAX_PASSWORD_BYTES + 1);
    await expect(hashPassword(tooLong, { params: CHEAP })).rejects.toBeInstanceOf(CryptoInputError);
    expect(await verifyPassword(tooLong, encoded)).toBe(false);

    // The limit is in bytes: 400 three-byte characters exceed it.
    const multibyte = '密'.repeat(400);
    await expect(hashPassword(multibyte, { params: CHEAP })).rejects.toBeInstanceOf(
      CryptoInputError,
    );
    expect(await verifyPassword(multibyte, encoded)).toBe(false);
  });

  it('refuses NUL characters, which HMAC key padding would otherwise make insignificant', async () => {
    const encoded = await hashPassword(PASSWORD, { params: CHEAP });
    for (const withNul of [`${PASSWORD}\0`, `${PASSWORD}\0\0`, `\0${PASSWORD}`, 'a\0b']) {
      expect(await verifyPassword(withNul, encoded)).toBe(false);
      await expect(hashPassword(withNul, { params: CHEAP })).rejects.toBeInstanceOf(
        CryptoInputError,
      );
    }
  });

  it('rejects empty and non-string passwords', async () => {
    await expect(hashPassword('', { params: CHEAP })).rejects.toBeInstanceOf(CryptoInputError);
    await expect(
      hashPassword(undefined as unknown as string, { params: CHEAP }),
    ).rejects.toBeInstanceOf(CryptoInputError);

    const encoded = await hashPassword(PASSWORD, { params: CHEAP });
    expect(await verifyPassword(undefined as unknown as string, encoded)).toBe(false);
  });

  it('does not put the password in a rejection', async () => {
    const tooLong = `MARKER-${'a'.repeat(MAX_PASSWORD_BYTES)}`;
    const error: unknown = await hashPassword(tooLong, { params: CHEAP }).catch(
      (reason: unknown) => reason,
    );
    expect(String((error as Error).message)).not.toContain('MARKER');
  });

  it('rejects out-of-range cost parameters', async () => {
    for (const params of [
      { logN: 9, r: 8, p: 1 },
      { logN: 21, r: 8, p: 1 },
      { logN: 10.5, r: 8, p: 1 },
      { logN: 10, r: 0, p: 1 },
      { logN: 10, r: 8, p: 5 },
    ]) {
      await expect(hashPassword(PASSWORD, { params })).rejects.toBeInstanceOf(CryptoInputError);
    }
  });

  it('flags weaker or malformed hashes for rehashing', async () => {
    expect(needsRehash(await hashPassword(PASSWORD, { params: CHEAP }))).toBe(true);
    expect(needsRehash(await hashPassword(PASSWORD, { params: { logN: 16, r: 8, p: 1 } }))).toBe(
      true,
    );
    expect(needsRehash('garbage')).toBe(true);
    expect(needsRehash('')).toBe(true);

    const salt = Buffer.alloc(16, 1).toString('base64').replace(/=+$/, '');
    const hash = Buffer.alloc(32, 2).toString('base64').replace(/=+$/, '');
    const shortSalt = Buffer.alloc(8, 1).toString('base64').replace(/=+$/, '');
    const shortHash = Buffer.alloc(16, 2).toString('base64').replace(/=+$/, '');
    expect(needsRehash(`$scrypt$ln=17,r=8,p=1$${salt}$${hash}`)).toBe(false);
    expect(needsRehash(`$scrypt$ln=18,r=8,p=2$${salt}$${hash}`)).toBe(false);
    expect(needsRehash(`$scrypt$ln=17,r=4,p=1$${salt}$${hash}`)).toBe(true);
    expect(needsRehash(`$scrypt$ln=17,r=8,p=1$${shortSalt}$${hash}`)).toBe(true);
    expect(needsRehash(`$scrypt$ln=17,r=8,p=1$${salt}$${shortHash}`)).toBe(true);
  });
});
