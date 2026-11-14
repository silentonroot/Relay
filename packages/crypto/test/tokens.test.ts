import { describe, expect, it } from 'vitest';
import { constantTimeEqual, CryptoInputError, generateToken, hashToken } from '../src/index.js';

describe('generateToken', () => {
  it('returns 32 random bytes as unpadded base64url by default', () => {
    const token = generateToken();
    expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(Buffer.from(token, 'base64url').byteLength).toBe(32);
  });

  it('honours the requested length', () => {
    expect(Buffer.from(generateToken(16), 'base64url').byteLength).toBe(16);
    expect(Buffer.from(generateToken(64), 'base64url').byteLength).toBe(64);
  });

  it('does not repeat', () => {
    const tokens = new Set(Array.from({ length: 5000 }, () => generateToken()));
    expect(tokens.size).toBe(5000);
  });

  it('rejects lengths that are too short, too long or not integers', () => {
    for (const bytes of [0, 1, 15, 1025, 16.5, -32, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(() => generateToken(bytes)).toThrow(CryptoInputError);
    }
  });
});

describe('hashToken', () => {
  it('is lowercase hex SHA-256 of the UTF-8 token', () => {
    // FIPS 180-2 test vector for "abc".
    expect(hashToken('abc')).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
  });

  it('is deterministic and distinguishes tokens', () => {
    const token = generateToken();
    expect(hashToken(token)).toBe(hashToken(token));
    expect(hashToken(token)).toMatch(/^[0-9a-f]{64}$/);
    expect(hashToken(token)).not.toBe(hashToken(generateToken()));
    expect(hashToken(token)).not.toContain(token);
  });

  it('rejects empty and non-string input', () => {
    expect(() => hashToken('')).toThrow(CryptoInputError);
    expect(() => hashToken(undefined as unknown as string)).toThrow(CryptoInputError);
  });
});

describe('constantTimeEqual', () => {
  it('is true only for identical strings', () => {
    const token = generateToken();
    expect(constantTimeEqual(token, token)).toBe(true);
    expect(constantTimeEqual(token, `${token}`)).toBe(true);
    expect(constantTimeEqual(hashToken(token), hashToken(token))).toBe(true);
    expect(constantTimeEqual('', '')).toBe(true);

    const last = token.at(-1) === 'A' ? 'B' : 'A';
    expect(constantTimeEqual(token, token.slice(0, -1) + last)).toBe(false);
    expect(constantTimeEqual(token, generateToken())).toBe(false);
  });

  it('is false, without throwing, for unequal lengths', () => {
    const token = generateToken();
    expect(constantTimeEqual(token, token.slice(0, -1))).toBe(false);
    expect(constantTimeEqual(token, `${token}A`)).toBe(false);
    expect(constantTimeEqual(token, '')).toBe(false);
    expect(constantTimeEqual('', token)).toBe(false);
  });

  it('is false for non-string input', () => {
    expect(constantTimeEqual(undefined as unknown as string, 'a')).toBe(false);
    expect(constantTimeEqual('a', null as unknown as string)).toBe(false);
    expect(constantTimeEqual(1 as unknown as string, 1 as unknown as string)).toBe(false);
  });
});
