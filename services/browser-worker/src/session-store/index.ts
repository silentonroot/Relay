import { canonicalJson, checkPlainJson, VAULT_MAX_PLAINTEXT_BYTES } from '@aab/contracts';
import { StorageStateSchema } from '../protocol.js';
import type { StorageState } from '../types.js';

/*
 * The session store: parsing, validation, origin filtering and the size cap for a storage
 * state. Sealing and opening are the vault's alone (ADR-014): this module holds no key, imports
 * no crypto and never sees a ciphertext. What it hands to callers is either a base64url
 * plaintext to send to the vault (`encodeSnapshot`) or a short-lived parsed state with a
 * `dispose()` (`parseSnapshot`).
 */

/** Largest serialized snapshot that will be sent to the vault. Well under the runner's job line cap. */
export const MAX_SNAPSHOT_BYTES = VAULT_MAX_PLAINTEXT_BYTES;

export interface OpenedSnapshot {
  readonly storageState: StorageState;
  /** Version of the stored session the vault read (its `secretVersion`). */
  readonly version: number;
  /** Version of the key-encryption key the vault opened it with (its `kekVersion`). */
  readonly kekVersion: number;
  /** Zeroes the plaintext buffer and drops the parsed state's contents. Idempotent. */
  dispose(): void;
}

/** A snapshot that would exceed {@link MAX_SNAPSHOT_BYTES}. Carries no content. */
export class SnapshotTooLargeError extends Error {
  override readonly name = 'SnapshotTooLargeError';
  constructor() {
    super('the session snapshot exceeds the size limit');
  }
}

/**
 * A snapshot did not validate as a storage state. Deliberately generic: it carries no
 * plaintext and no `cause`.
 */
export class SnapshotOpenError extends Error {
  override readonly name = 'SnapshotOpenError';
  readonly reason = 'invalid' as const;
  constructor() {
    super('the session snapshot is not a valid storage state');
  }
}

/**
 * Validates a storage state and serializes it for `completeLogin`: canonical JSON, base64url.
 * Throws {@link SnapshotOpenError} for an invalid state and {@link SnapshotTooLargeError} over
 * the cap, before anything is sent. The intermediate buffers are zeroed; the returned string is
 * the caller's to send and drop (JavaScript cannot zero a string).
 */
export function encodeSnapshot(state: StorageState): string {
  const parsed = StorageStateSchema.safeParse(state);
  if (!parsed.success) throw new SnapshotOpenError();
  const plaintext = Buffer.from(canonicalJson(parsed.data), 'utf8');
  try {
    if (plaintext.byteLength > MAX_SNAPSHOT_BYTES) throw new SnapshotTooLargeError();
    return plaintext.toString('base64url');
  } finally {
    plaintext.fill(0);
  }
}

/**
 * Parses the plaintext `readForWorker` returned (base64url of the storage-state JSON).
 * Raises {@link SnapshotOpenError} when it does not validate.
 *
 * About `dispose()`: the decoded buffer is zeroed as soon as it has been parsed, and
 * `dispose()` zeroes it again and empties the parsed state's arrays. JavaScript cannot
 * guarantee more than that: the base64url string the vault client received and the parsed
 * cookie values are immutable strings that stay in the heap until the garbage collector reclaims
 * them, the engine may have copied buffers while moving them, and the runner's stdin pipe holds
 * its own copy.
 */
export function parseSnapshot(
  plaintextBase64Url: string,
  meta: { version: number; kekVersion: number },
): OpenedSnapshot {
  const plaintext = Buffer.from(plaintextBase64Url, 'base64url');
  let state: StorageState;
  try {
    let value: unknown;
    try {
      value = JSON.parse(plaintext.toString('utf8'));
    } catch {
      throw new SnapshotOpenError();
    }
    if (checkPlainJson(value) !== null) throw new SnapshotOpenError();
    const parsed = StorageStateSchema.safeParse(value);
    if (!parsed.success) throw new SnapshotOpenError();
    state = parsed.data;
  } finally {
    plaintext.fill(0);
  }

  let disposed = false;
  return {
    storageState: state,
    version: meta.version,
    kekVersion: meta.kekVersion,
    dispose() {
      if (disposed) return;
      disposed = true;
      plaintext.fill(0);
      state.cookies.length = 0;
      state.origins.length = 0;
    },
  };
}

function hostOf(origin: string): string | null {
  try {
    return new URL(origin).hostname.toLowerCase();
  } catch {
    return null;
  }
}

/**
 * Keeps a cookie only when its domain (ignoring one leading dot) is exactly the host of an
 * allowed origin, and an `origins` entry only when its origin is exactly an allowed origin.
 * Returns a new object; the input is not changed.
 */
export function filterStorageState(
  state: StorageState,
  allowedOrigins: readonly string[],
): StorageState {
  const hosts = new Set<string>();
  for (const origin of allowedOrigins) {
    const host = hostOf(origin);
    if (host !== null) hosts.add(host);
  }
  const allowed = new Set(allowedOrigins);
  return {
    cookies: state.cookies
      .filter((cookie) => {
        const domain = cookie.domain.startsWith('.') ? cookie.domain.slice(1) : cookie.domain;
        return hosts.has(domain.toLowerCase());
      })
      .map((cookie) => ({ ...cookie })),
    origins: state.origins
      .filter((entry) => allowed.has(entry.origin))
      .map((entry) => ({
        origin: entry.origin,
        localStorage: entry.localStorage.map((item) => ({ ...item })),
      })),
  };
}

/** True when nothing survives: no cookie and no origin storage. */
export function isEmptyStorageState(state: StorageState): boolean {
  return state.cookies.length === 0 && state.origins.length === 0;
}

/** Cookie expiries this close to now are ignored by {@link sessionExpiry}. */
export const SESSION_EXPIRY_MARGIN_MS = 5 * 60_000;

/**
 * Earliest positive cookie expiry that is more than {@link SESSION_EXPIRY_MARGIN_MS} away, or
 * null when there is none (every cookie is a session cookie or about to expire). A short-lived
 * cookie (a CSRF or flash cookie) must not make the whole login fail: the vault refuses an expiry
 * that is not in the future, and one a few seconds away would be stale before it is stored.
 */
export function sessionExpiry(
  state: StorageState,
  now: Date = new Date(),
  marginMs: number = SESSION_EXPIRY_MARGIN_MS,
): Date | null {
  const floor = now.getTime() + marginMs;
  let earliest: number | null = null;
  for (const cookie of state.cookies) {
    if (!Number.isFinite(cookie.expires) || cookie.expires <= 0) continue;
    if (cookie.expires * 1000 <= floor) continue;
    if (earliest === null || cookie.expires < earliest) earliest = cookie.expires;
  }
  if (earliest === null) return null;
  const date = new Date(earliest * 1000);
  return Number.isNaN(date.getTime()) ? null : date;
}
