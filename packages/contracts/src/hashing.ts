import { createHash, timingSafeEqual } from 'node:crypto';
import { actionHashInput } from './approval-hash.js';
import type { ApprovalActionBinding, ApprovalArgumentNames } from './approval-hash.js';
import { jobArgumentsHashInputV2 } from './execution.js';
import type { JobArgumentsBindingV2 } from './execution.js';

/*
 * Digest functions for the hashes of Phase 4. Entry point `@aab/contracts/hashing`, kept out of
 * the package index because it imports `node:crypto` and the index is bundled into the dashboard.
 * The same functions are used by the API, the vault and the supervisor (P4-20), so no two sites
 * can disagree about the bytes. SHA-256 comes from `node:crypto`, as in the job arguments hash
 * of `@aab/database`; nothing is implemented here.
 */

const sha256 = (text: string): Buffer => createHash('sha256').update(text, 'utf8').digest();

/** Lowercase hex SHA-256 of `actionHashInput(binding)`. Throws as `actionHashInput` does. */
export function computeActionHash(
  binding: ApprovalActionBinding,
  names: ApprovalArgumentNames,
): string {
  return sha256(actionHashInput(binding, names)).toString('hex');
}

/**
 * True only when `binding` hashes to `expected`. Both sides are hashed again to fixed-size
 * digests and compared with `timingSafeEqual`. An input that cannot be hashed never matches.
 */
export function verifyActionHash(
  binding: ApprovalActionBinding,
  names: ApprovalArgumentNames,
  expected: string,
): boolean {
  return matches(() => computeActionHash(binding, names), expected);
}

/** Lowercase hex SHA-256 of `jobArgumentsHashInputV2(binding)` (job hash layout 2). */
export function computeJobArgumentsHashV2(binding: JobArgumentsBindingV2): string {
  return sha256(jobArgumentsHashInputV2(binding)).toString('hex');
}

export function verifyJobArgumentsHashV2(
  binding: JobArgumentsBindingV2,
  expected: string,
): boolean {
  return matches(() => computeJobArgumentsHashV2(binding), expected);
}

function matches(compute: () => string, expected: string): boolean {
  if (typeof expected !== 'string') return false;
  let actual: string;
  try {
    actual = compute();
  } catch {
    return false;
  }
  return timingSafeEqual(sha256(actual), sha256(expected)) && actual.length === expected.length;
}
