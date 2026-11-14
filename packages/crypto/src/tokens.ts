import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { CryptoInputError } from './errors.js';

const MIN_TOKEN_BYTES = 16;
const MAX_TOKEN_BYTES = 1024;

/**
 * A random bearer token (session id, CSRF token, agent credential) as unpadded base64url.
 * The default 32 bytes is 256 bits of entropy from the operating system CSPRNG.
 */
export function generateToken(bytes: number = 32): string {
  if (!Number.isInteger(bytes) || bytes < MIN_TOKEN_BYTES || bytes > MAX_TOKEN_BYTES) {
    throw new CryptoInputError(
      `token length must be an integer from ${MIN_TOKEN_BYTES} to ${MAX_TOKEN_BYTES} bytes`,
    );
  }
  return randomBytes(bytes).toString('base64url');
}

/**
 * Lowercase hex SHA-256 of a token, for storing tokens hashed so a database read does not
 * yield usable sessions. Plain SHA-256 is appropriate only because tokens are high-entropy
 * random values; never use this for passwords (see hashPassword).
 */
export function hashToken(token: string): string {
  if (typeof token !== 'string' || token.length === 0) {
    throw new CryptoInputError('token must be a non-empty string');
  }
  return createHash('sha256').update(token, 'utf8').digest('hex');
}

/**
 * Compares two strings without leaking, through timing, where they differ. Safe for inputs
 * of different lengths: both are hashed to fixed-size digests before the comparison, so only
 * the lengths themselves influence timing.
 */
export function constantTimeEqual(a: string, b: string): boolean {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const digestA = createHash('sha256').update(a, 'utf8').digest();
  const digestB = createHash('sha256').update(b, 'utf8').digest();
  return timingSafeEqual(digestA, digestB) && a.length === b.length;
}
