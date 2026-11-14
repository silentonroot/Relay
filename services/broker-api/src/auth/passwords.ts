import { hashPassword, verifyPassword } from '@aab/crypto';
import type { ScryptParams } from '@aab/crypto';

/*
 * Threat model F-5. One scrypt call at the production parameters (N = 2^17, r = 8) needs about
 * 128 MiB, and login is unauthenticated, so a per-client rate limit (which counts requests)
 * does not stop a handful of concurrent attempts from exhausting a small container. Every
 * password hash and verification in this service therefore runs through one limiter with a
 * small fixed concurrency and a bounded wait queue; when the queue is full the work is refused
 * immediately instead of queuing without bound.
 *
 * Size the container for `concurrency × 128 MiB` plus the service's own baseline.
 */

/** Thrown when every slot is busy and the wait queue is full. Maps to 429 `rate_limited`. */
export class PasswordLimiterBusyError extends Error {
  constructor(readonly retryAfterSeconds: number) {
    super('password hashing capacity exhausted');
    this.name = 'PasswordLimiterBusyError';
  }
}

export interface PasswordLimiterOptions {
  /** Password operations allowed to run at the same time. At least 1. */
  concurrency: number;
  /** Operations allowed to wait for a slot. 0 means refuse whenever all slots are busy. */
  maxQueue: number;
  /** Value of the Retry-After header sent with the refusal. */
  retryAfterSeconds?: number;
}

/** A counting semaphore with a bounded FIFO wait queue. */
export class PasswordLimiter {
  readonly concurrency: number;
  readonly maxQueue: number;
  readonly retryAfterSeconds: number;
  private running = 0;
  private readonly waiting: (() => void)[] = [];

  constructor(options: PasswordLimiterOptions) {
    if (!Number.isInteger(options.concurrency) || options.concurrency < 1) {
      throw new RangeError('concurrency must be a positive integer');
    }
    if (!Number.isInteger(options.maxQueue) || options.maxQueue < 0) {
      throw new RangeError('maxQueue must be a non-negative integer');
    }
    this.concurrency = options.concurrency;
    this.maxQueue = options.maxQueue;
    this.retryAfterSeconds = options.retryAfterSeconds ?? 1;
  }

  /** Operations currently running. */
  get active(): number {
    return this.running;
  }

  /** Operations waiting for a slot. */
  get queued(): number {
    return this.waiting.length;
  }

  /**
   * Runs `work` once a slot is free. Rejects with PasswordLimiterBusyError, without running
   * it, when all slots are busy and the queue is full.
   */
  async run<T>(work: () => Promise<T>): Promise<T> {
    if (this.running >= this.concurrency) {
      if (this.waiting.length >= this.maxQueue) {
        throw new PasswordLimiterBusyError(this.retryAfterSeconds);
      }
      // The releasing operation hands its slot over directly, so `running` never dips.
      await new Promise<void>((resolve) => this.waiting.push(resolve));
    } else {
      this.running += 1;
    }
    try {
      return await work();
    } finally {
      const next = this.waiting.shift();
      if (next === undefined) this.running -= 1;
      else next();
    }
  }
}

export type PasswordVerifier = (password: string, encodedHash: string) => Promise<boolean>;
export type PasswordHasher = (
  password: string,
  params: ScryptParams | undefined,
) => Promise<string>;

export const defaultVerifier: PasswordVerifier = verifyPassword;
export const defaultHasher: PasswordHasher = (password, params) =>
  hashPassword(password, params === undefined ? {} : { params });

/** The only way this service hashes or verifies a password. */
export interface PasswordService {
  readonly limiter: PasswordLimiter;
  verify(password: string, encodedHash: string): Promise<boolean>;
  hash(password: string): Promise<string>;
}

export function createPasswordService(options: {
  limiter: PasswordLimiter;
  params: ScryptParams | undefined;
  verifier?: PasswordVerifier;
  hasher?: PasswordHasher;
}): PasswordService {
  const verifier = options.verifier ?? defaultVerifier;
  const hasher = options.hasher ?? defaultHasher;
  return {
    limiter: options.limiter,
    verify: (password, encodedHash) => options.limiter.run(() => verifier(password, encodedHash)),
    hash: (password) => options.limiter.run(() => hasher(password, options.params)),
  };
}
