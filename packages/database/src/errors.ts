import type { ConnectionStatus } from '@aab/contracts';

export type RepositoryErrorCode =
  'not_found' | 'conflict' | 'invalid_transition' | 'validation_failed';

/**
 * Base class for expected failures. The API layer maps `code` onto the contracts ErrorCode;
 * anything that is not a RepositoryError is an unexpected fault (internal_error).
 * Messages never contain row contents or submitted values.
 */
export abstract class RepositoryError extends Error {
  abstract readonly code: RepositoryErrorCode;
}

/**
 * The row does not exist, or exists outside the caller's scope. The two cases are
 * indistinguishable on purpose so IDs belonging to other owners cannot be probed.
 */
export class NotFoundError extends RepositoryError {
  readonly code = 'not_found';
  constructor(readonly entity: string) {
    super(`${entity} not found`);
    this.name = 'NotFoundError';
  }
}

/** A uniqueness rule or a state precondition was violated. */
export class ConflictError extends RepositoryError {
  readonly code = 'conflict';
  constructor(
    message: string,
    /** Name of the violated database constraint, when there is one. */
    readonly constraint?: string,
  ) {
    super(message);
    this.name = 'ConflictError';
  }
}

export class InvalidTransitionError extends RepositoryError {
  readonly code = 'invalid_transition';
  constructor(
    readonly from: ConnectionStatus,
    readonly to: ConnectionStatus,
  ) {
    super(`connection cannot move from ${from} to ${to}`);
    this.name = 'InvalidTransitionError';
  }
}

export class ValidationError extends RepositoryError {
  readonly code = 'validation_failed';
  constructor(
    message: string,
    readonly issues: readonly { path: string; message: string }[] = [],
  ) {
    super(message);
    this.name = 'ValidationError';
  }
}

/** A list cursor that this server did not issue, or that was altered. */
export class InvalidCursorError extends ValidationError {
  constructor() {
    super('invalid cursor', [{ path: 'cursor', message: 'invalid cursor' }]);
    this.name = 'InvalidCursorError';
  }
}

interface PgErrorFields {
  code: string;
  constraint: string | undefined;
}

/** Finds the PostgreSQL error (SQLSTATE) inside whatever the driver or Drizzle threw. */
function findPgError(error: unknown): PgErrorFields | null {
  let current: unknown = error;
  for (let depth = 0; depth < 5 && typeof current === 'object' && current !== null; depth += 1) {
    const candidate = current as { code?: unknown; constraint?: unknown; cause?: unknown };
    if (typeof candidate.code === 'string' && /^[0-9A-Z]{5}$/.test(candidate.code)) {
      return {
        code: candidate.code,
        constraint: typeof candidate.constraint === 'string' ? candidate.constraint : undefined,
      };
    }
    current = candidate.cause;
  }
  return null;
}

const UNIQUE_VIOLATION = '23505';
const FOREIGN_KEY_VIOLATION = '23503';
const CHECK_VIOLATION = '23514';
const NOT_NULL_VIOLATION = '23502';

/**
 * Runs a write and converts constraint violations into typed errors. Call it around the whole
 * transaction, not inside it: after a violation PostgreSQL has aborted that transaction.
 */
export async function translateDbErrors<T>(entity: string, run: () => Promise<T>): Promise<T> {
  try {
    return await run();
  } catch (error) {
    if (error instanceof RepositoryError) throw error;
    const pgError = findPgError(error);
    switch (pgError?.code) {
      case UNIQUE_VIOLATION:
        throw new ConflictError(`${entity} already exists`, pgError.constraint);
      case FOREIGN_KEY_VIOLATION:
        throw new ConflictError(`${entity} references a missing row`, pgError.constraint);
      case CHECK_VIOLATION:
      case NOT_NULL_VIOLATION:
        throw new ValidationError(`${entity} violates a database constraint`);
      default:
        throw error;
    }
  }
}
