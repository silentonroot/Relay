import { createHash, timingSafeEqual } from 'node:crypto';
import { jobArgumentsHashInput } from '@aab/contracts';
import type { JobArgumentsBinding } from '@aab/contracts';

/*
 * The hash that binds an operation job's stored arguments to the operation and connection policy
 * judged them for (threat model PE-14). It lives with the job store rather than in `@aab/crypto`:
 * it involves no key, and the worker's supervisor may not import the key-handling package outside
 * the session store (ADR-013, `import-boundary.test.ts`).
 */

const sha256 = (text: string): Buffer => createHash('sha256').update(text, 'utf8').digest();

/**
 * Lowercase hex SHA-256 of `jobArgumentsHashInput(binding)`: the value the execute route stores
 * in `execution_jobs.arguments_hash` and in the `policy.evaluated` event. Throws, like
 * `canonicalJson`, when the arguments are not plain JSON.
 */
export function hashJobArguments(binding: JobArgumentsBinding): string {
  return sha256(jobArgumentsHashInput(binding)).toString('hex');
}

/**
 * True only when `binding` hashes to `expected`. Both sides are hashed again to fixed-size
 * digests and compared with `timingSafeEqual` (as `constantTimeEqual` in `@aab/crypto` does), so
 * timing does not show where they differ. Arguments that cannot be canonicalized never match.
 */
export function verifyJobArgumentsHash(binding: JobArgumentsBinding, expected: string): boolean {
  if (typeof expected !== 'string') return false;
  let actual: string;
  try {
    actual = hashJobArguments(binding);
  } catch {
    return false;
  }
  return timingSafeEqual(sha256(actual), sha256(expected)) && actual.length === expected.length;
}
