/**
 * Errors shared by adapters and the worker. Messages are safe to log and to show in the
 * dashboard: they name operations and field paths, never submitted values or page content.
 */

/** A field-level problem. `path` comes from the schema, not from the submitted data. */
export interface FieldIssue {
  readonly path: string;
  readonly message: string;
}

/** The target application no longer accepts the stored session; the owner must reconnect. */
export class ReauthRequiredError extends Error {
  override readonly name = 'ReauthRequiredError';

  constructor(message = 'the connection session is no longer valid') {
    super(message);
  }
}

/**
 * A write was attempted and its result could not be confirmed. The operation must never be
 * retried blindly and must never be reported as succeeded (spec §7.1, §9.4).
 */
export class OutcomeUnknownError extends Error {
  override readonly name = 'OutcomeUnknownError';

  constructor(message = 'the outcome of the operation could not be verified') {
    super(message);
  }
}

/**
 * The adapter or the target application broke the adapter contract: an invalid definition,
 * an unknown operation, or output that does not match the declared output schema.
 */
export class AdapterContractError extends Error {
  override readonly name = 'AdapterContractError';
  readonly issues: readonly FieldIssue[];

  constructor(message: string, issues: readonly FieldIssue[] = []) {
    super(message);
    this.issues = issues;
  }
}

export type NavigationBlockReason =
  | 'empty_url'
  | 'forbidden_characters'
  | 'unparseable_url'
  | 'credentials_in_url'
  | 'scheme_not_allowed'
  | 'origin_not_allowed'
  | 'non_canonical_url'
  | 'path_traversal'
  | 'unknown_operation'
  | 'path_not_allowed';

/** A navigation or redirect hop left the adapter's allowlist. The URL itself is not recorded. */
export class NavigationBlockedError extends Error {
  override readonly name = 'NavigationBlockedError';
  readonly reason: NavigationBlockReason;

  constructor(reason: NavigationBlockReason) {
    super(`navigation blocked: ${reason}`);
    this.reason = reason;
  }
}

export type OperationInputErrorCode = 'unknown_operation' | 'invalid_arguments';

/** Arguments submitted for an operation failed validation. */
export class OperationInputError extends Error {
  override readonly name = 'OperationInputError';
  readonly code: OperationInputErrorCode;
  readonly issues: readonly FieldIssue[];

  constructor(code: OperationInputErrorCode, message: string, issues: readonly FieldIssue[] = []) {
    super(message);
    this.code = code;
    this.issues = issues;
  }
}
