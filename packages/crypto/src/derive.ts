import { createHmac, hkdfSync, timingSafeEqual } from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import { CryptoInputError } from './errors.js';

/*
 * Thin wrappers over `node:crypto`: HKDF-SHA-256 (RFC 5869) to derive a purpose-specific key
 * from a key-encryption key, and HMAC-SHA-256 (RFC 2104) with a constant-time verify. No new
 * construction: the tests run the RFC 5869 and RFC 4231 vectors.
 */

/** Longest output HKDF-SHA-256 can produce: 255 blocks of 32 bytes. */
const MAX_DERIVED_BYTES = 255 * 32;
const MAX_INFO_BYTES = 1024;
export const MAC_BYTES = 32;

/** One label per purpose. A key derived for one purpose is never used for another. */
export const KEY_PURPOSES = {
  /** HMAC key for vault capability authorization and token MACs (ADR-014 section 6). */
  vaultCapabilityMac: 'aab.vault.capability-mac.v1',
} as const;
export type KeyPurpose = keyof typeof KEY_PURPOSES;

export interface DeriveKeyOptions {
  /** Context label (HKDF `info`): non-empty, so every derived key is domain-separated. */
  info: string | Uint8Array;
  /** Optional salt; RFC 5869 treats an absent salt as a string of zero bytes. */
  salt?: Uint8Array;
  /** Output length in bytes, 1 to 8160. Default 32. */
  length?: number;
}

/** A key derived from one specific KEK version, with that version recorded. */
export interface DerivedKey {
  kekVersion: number;
  /** Raw bytes. The caller keeps them only in memory and zeroes any copy it does not need. */
  key: Buffer;
}

/** HKDF-SHA-256 extract-and-expand over `ikm`. */
export function deriveKey(ikm: Uint8Array | KeyObject, options: DeriveKeyOptions): Buffer {
  const info = typeof options.info === 'string' ? Buffer.from(options.info, 'utf8') : options.info;
  const length = options.length ?? 32;
  if (!(info instanceof Uint8Array) || info.byteLength === 0 || info.byteLength > MAX_INFO_BYTES) {
    throw new CryptoInputError('info must be 1 to 1024 bytes');
  }
  if (!Number.isInteger(length) || length < 1 || length > MAX_DERIVED_BYTES) {
    throw new CryptoInputError(
      `derived key length must be an integer from 1 to ${MAX_DERIVED_BYTES}`,
    );
  }
  if (!(ikm instanceof Uint8Array) && typeof ikm !== 'object') {
    throw new CryptoInputError('input key material must be bytes or a key');
  }
  const salt = options.salt ?? Buffer.alloc(0);
  return Buffer.from(hkdfSync('sha256', ikm, salt, info, length));
}

/** HMAC-SHA-256 of `data` under `key`. */
export function macSha256(key: Uint8Array | KeyObject, data: Uint8Array | string): Buffer {
  if (!(key instanceof Uint8Array) && typeof key !== 'object') {
    throw new CryptoInputError('MAC key must be bytes or a key');
  }
  if (key instanceof Uint8Array && key.byteLength === 0) {
    throw new CryptoInputError('MAC key must not be empty');
  }
  return createHmac('sha256', key).update(data).digest();
}

/**
 * Recomputes the MAC and compares it with `mac` in constant time. A MAC of any other length,
 * or one that is not bytes, is simply false.
 */
export function verifyMac(
  key: Uint8Array | KeyObject,
  data: Uint8Array | string,
  mac: Uint8Array,
): boolean {
  if (!(mac instanceof Uint8Array) || mac.byteLength !== MAC_BYTES) return false;
  const expected = macSha256(key, data);
  return timingSafeEqual(expected, mac);
}
