import { ApprovalInputError, checkApprovalInput } from './approval-input.js';
import { canonicalJson } from './canonical.js';
import type { JsonObject } from './primitives.js';

/*
 * The action hash of an approval (Phase 4, ADR-015 section 3, specification §8.2).
 *
 * This file is pure and safe for the dashboard bundle. The function that computes the digest
 * lives in `@aab/contracts/hashing`, which imports `node:crypto`, so that nothing in a browser
 * bundle reaches Node.
 */

/**
 * Domain-separation prefix of the action hash. It is a layout of its own and never a version of
 * the job arguments hash (`aab.job-arguments.v1\n`): the two hash different things and must not
 * be confusable with each other. A change to what is hashed needs a new label.
 */
export const APPROVAL_ACTION_HASH_DOMAIN = 'aab.approval-action.v1\n';

/** The only fields the action hash covers. No id that is created later is among them. */
export const APPROVAL_ACTION_HASH_FIELDS = [
  'agentId',
  'arguments',
  'connectionId',
  'expectedResourceVersion',
  'operation',
  'organizationId',
  'ownerUserId',
  'runId',
  'targetResourceId',
] as const;

/** The version of the target resource the approval was given for. */
export type ResourceVersion = string | number;

/** The operation descriptor's names for the two arguments the approval is bound to. */
export interface ApprovalArgumentNames {
  /** The descriptor's `resourceArgument`. */
  resourceArgument: string;
  /** The descriptor's `versionArgument`. */
  versionArgument: string;
}

export interface ApprovalActionBinding {
  /** The organization id as the database returns it (lowercase). */
  organizationId: string;
  /** The owner of the agent and of the connection, who is the only approver. */
  ownerUserId: string;
  agentId: string;
  /** The run the request belongs to; null when it has none. A redemption must present the same. */
  runId: string | null;
  connectionId: string;
  operation: string;
  /** The final arguments, obligations applied, exactly as the approval stores them. */
  arguments: JsonObject;
  /** The value of the descriptor's `resourceArgument` in the arguments. */
  targetResourceId: string;
  /** The value of the descriptor's `versionArgument` in the arguments. */
  expectedResourceVersion: ResourceVersion;
}

/**
 * The exact text whose SHA-256 is `approval_requests.action_hash`: the domain label followed by
 * the canonical JSON of one object with exactly the nine keys of `APPROVAL_ACTION_HASH_FIELDS`.
 * One object holds everything, so no choice of value can move bytes from one field to another.
 *
 * `names` are the descriptor's `resourceArgument` and `versionArgument`. The function refuses
 * (`argument_mismatch`) a binding whose `targetResourceId` or `expectedResourceVersion` is not
 * exactly the value of that argument in `arguments`, so the two cannot drift apart.
 *
 * Throws `ApprovalInputError` when the binding holds a value the strict check refuses (integers
 * beyond the safe range, `-0`, lone surrogates, non-finite numbers) or the mismatch above, and
 * `TypeError` (from `canonicalJson`) when it is not plain JSON. Two spellings of one value hash
 * the same.
 */
export function actionHashInput(
  binding: ApprovalActionBinding,
  names: ApprovalArgumentNames,
): string {
  const object = {
    agentId: binding.agentId,
    arguments: binding.arguments,
    connectionId: binding.connectionId,
    expectedResourceVersion: binding.expectedResourceVersion,
    operation: binding.operation,
    organizationId: binding.organizationId,
    ownerUserId: binding.ownerUserId,
    runId: binding.runId,
    targetResourceId: binding.targetResourceId,
  };
  const issue = checkApprovalInput(object);
  if (issue !== null) throw new ApprovalInputError(issue);
  const args = binding.arguments as Record<string, unknown>;
  for (const [field, name, expected] of [
    ['targetResourceId', names.resourceArgument, binding.targetResourceId],
    ['expectedResourceVersion', names.versionArgument, binding.expectedResourceVersion],
  ] as const) {
    if (!Object.hasOwn(args, name) || args[name] !== expected) {
      throw new ApprovalInputError({ code: 'argument_mismatch', path: `$.${field}` });
    }
  }
  return APPROVAL_ACTION_HASH_DOMAIN + canonicalJson(object);
}
