import { randomBytes, scrypt, timingSafeEqual } from 'node:crypto';
import { CryptoInputError } from './errors.js';

/*
 * Password hashing for the local owner login, using Node's scrypt.
 *
 * Encoded form (PHC-style, base64 without padding):
 *   $scrypt$ln=17,r=8,p=1$<salt>$<hash>
 * `ln` is log2(N). The parameters travel with the hash so they can be raised later and old
 * hashes detected with needsRehash().
 */

export interface ScryptParams {
  /** log2 of the CPU/memory cost N. */
  logN: number;
  /** Block size r. */
  r: number;
  /** Parallelization p. */
  p: number;
}

/** N = 2^17, r = 8, p = 1: about 128 MiB and a few hundred milliseconds per hash. */
export const DEFAULT_SCRYPT_PARAMS: Readonly<ScryptParams> = Object.freeze({
  logN: 17,
  r: 8,
  p: 1,
});

/** Longest accepted password, in UTF-8 bytes. Bounds the work an unauthenticated caller can cause. */
export const MAX_PASSWORD_BYTES = 1024;

const SALT_BYTES = 16;
const HASH_BYTES = 32;

// Bounds applied to parameters read back from an encoded string, so a corrupted or hostile
// stored value cannot make verification allocate gigabytes or run for minutes.
const LIMITS = {
  logN: { min: 10, max: 20 },
  r: { min: 1, max: 16 },
  p: { min: 1, max: 4 },
  salt: { min: 8, max: 64 },
  hash: { min: 16, max: 64 },
} as const;

const ENCODED =
  /^\$scrypt\$ln=([1-9]\d?),r=([1-9]\d?),p=([1-9]\d?)\$([A-Za-z0-9+/]{1,128})\$([A-Za-z0-9+/]{1,128})$/;

export interface HashPasswordOptions {
  /** Override the cost parameters. Only tests should lower them. */
  params?: ScryptParams;
}

interface ParsedHash {
  params: ScryptParams;
  salt: Buffer;
  hash: Buffer;
}

function inRange(value: number, range: { min: number; max: number }): boolean {
  return Number.isInteger(value) && value >= range.min && value <= range.max;
}

function paramsInRange(params: ScryptParams): boolean {
  return (
    inRange(params.logN, LIMITS.logN) && inRange(params.r, LIMITS.r) && inRange(params.p, LIMITS.p)
  );
}

function b64(bytes: Buffer): string {
  return bytes.toString('base64').replace(/=+$/, '');
}

function unb64(text: string): Buffer | undefined {
  const bytes = Buffer.from(text, 'base64');
  // Reject non-canonical encodings so one hash has exactly one encoded form.
  return b64(bytes) === text ? bytes : undefined;
}

function parse(encoded: unknown): ParsedHash | undefined {
  if (typeof encoded !== 'string' || encoded.length > 512) return undefined;
  const match = ENCODED.exec(encoded);
  if (match === null) return undefined;
  const params = { logN: Number(match[1]), r: Number(match[2]), p: Number(match[3]) };
  const salt = unb64(match[4] ?? '');
  const hash = unb64(match[5] ?? '');
  if (salt === undefined || hash === undefined || !paramsInRange(params)) return undefined;
  if (!inRange(salt.byteLength, LIMITS.salt) || !inRange(hash.byteLength, LIMITS.hash)) {
    return undefined;
  }
  return { params, salt, hash };
}

function derive(
  password: Buffer,
  salt: Buffer,
  params: ScryptParams,
  length: number,
): Promise<Buffer> {
  const N = 2 ** params.logN;
  // OpenSSL needs 128·r·(N + p + 2) bytes; Node's default maxmem (32 MiB) is far below that
  // for the default parameters, so the limit is set to exactly what these parameters require.
  const maxmem = 128 * params.r * (N + params.p + 2);
  return new Promise((resolve, reject) => {
    scrypt(password, salt, length, { N, r: params.r, p: params.p, maxmem }, (error, key) => {
      if (error) reject(error);
      else resolve(key);
    });
  });
}

function passwordBytes(password: unknown): Buffer | undefined {
  if (typeof password !== 'string' || password.length === 0) return undefined;
  // scrypt starts with PBKDF2-HMAC-SHA256, and HMAC pads short keys with zero bytes, so
  // "pw" and "pw\0" would derive the same hash. Refusing NUL removes that equivalence.
  if (password.includes('\0')) return undefined;
  // A string of n UTF-16 units is at least n bytes of UTF-8: reject before allocating.
  if (password.length > MAX_PASSWORD_BYTES) return undefined;
  const bytes = Buffer.from(password, 'utf8');
  if (bytes.byteLength > MAX_PASSWORD_BYTES) {
    bytes.fill(0);
    return undefined;
  }
  return bytes;
}

/**
 * Hashes a password with a fresh random salt. Throws {@link CryptoInputError} for an empty
 * password, one longer than {@link MAX_PASSWORD_BYTES} UTF-8 bytes, or one containing a NUL
 * character.
 */
export async function hashPassword(
  password: string,
  options: HashPasswordOptions = {},
): Promise<string> {
  const params = options.params ?? DEFAULT_SCRYPT_PARAMS;
  if (!paramsInRange(params)) {
    throw new CryptoInputError('scrypt parameters out of range');
  }
  const bytes = passwordBytes(password);
  if (bytes === undefined) {
    throw new CryptoInputError(
      `password must be 1 to ${MAX_PASSWORD_BYTES} bytes and contain no NUL character`,
    );
  }
  try {
    const salt = randomBytes(SALT_BYTES);
    const hash = await derive(bytes, salt, params, HASH_BYTES);
    return `$scrypt$ln=${params.logN},r=${params.r},p=${params.p}$${b64(salt)}$${b64(hash)}`;
  } finally {
    bytes.fill(0);
  }
}

/**
 * Checks a password against an encoded hash in constant time with respect to the hash value.
 * Returns false, and never throws, for a wrong password, an over-long or empty password, or
 * an encoded string that is malformed or carries out-of-range parameters.
 *
 * Note for callers: when a login names an unknown account, still verify against a fixed
 * dummy hash so response time does not reveal which accounts exist.
 */
export async function verifyPassword(password: string, encoded: string): Promise<boolean> {
  const parsed = parse(encoded);
  const bytes = passwordBytes(password);
  if (parsed === undefined || bytes === undefined) {
    bytes?.fill(0);
    return false;
  }
  try {
    const actual = await derive(bytes, parsed.salt, parsed.params, parsed.hash.byteLength);
    return timingSafeEqual(actual, parsed.hash);
  } catch {
    return false;
  } finally {
    bytes.fill(0);
  }
}

/**
 * True when a stored hash should be replaced after the next successful login: it is
 * malformed, or any of its parameters, its salt or its output is weaker than the current
 * defaults.
 */
export function needsRehash(encoded: string): boolean {
  const parsed = parse(encoded);
  if (parsed === undefined) return true;
  return (
    parsed.params.logN < DEFAULT_SCRYPT_PARAMS.logN ||
    parsed.params.r < DEFAULT_SCRYPT_PARAMS.r ||
    parsed.params.p < DEFAULT_SCRYPT_PARAMS.p ||
    parsed.salt.byteLength < SALT_BYTES ||
    parsed.hash.byteLength < HASH_BYTES
  );
}
