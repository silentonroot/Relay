/*
 * Error types for @aab/crypto.
 *
 * None of these ever carries key bytes, plaintext, ciphertext or a `cause` chain: an attached
 * cause could reveal which internal check failed, or drag secret-bearing buffers into logs.
 */

/** The caller passed something structurally invalid. Messages name fields, never values. */
export class CryptoInputError extends Error {
  override readonly name = 'CryptoInputError';
}

/**
 * A sealed secret could not be opened. Deliberately generic: a wrong AAD, a tampered
 * ciphertext, a bad tag, an unknown KEK version and a malformed record all look the same.
 */
export class SecretOpenError extends Error {
  override readonly name = 'SecretOpenError';

  constructor() {
    super('unable to open sealed secret');
  }
}

/** A KEK provider could not wrap or unwrap a data key. Generic for the same reason. */
export class KekOperationError extends Error {
  override readonly name = 'KekOperationError';

  constructor(operation: 'wrap' | 'unwrap') {
    super(`unable to ${operation} data key`);
  }
}

/** A local key file or key directory is missing, malformed or has unsafe permissions. */
export class KekStoreError extends Error {
  override readonly name = 'KekStoreError';
}
