import { canonicalJson, checkPlainJson, SESSION_SNAPSHOT_SECRET_TYPE } from '@aab/contracts';
import type { Connection } from '@aab/contracts';
import { LocalFileKekProvider, openSecret, sealSecret } from '@aab/crypto';
import type { KekProvider, SecretAad } from '@aab/crypto';
import type { Repositories } from '@aab/database';
import { StorageStateSchema } from '../protocol.js';
import type { StorageState } from '../types.js';

/*
 * The session store: the only code in the worker that seals or opens a secret (ADR-002,
 * ADR-003, ADR-013). Everything it returns to callers is either metadata or a short-lived
 * plaintext snapshot with a `dispose()`.
 *
 * Associated data is always rebuilt from the connection row the caller loaded, never from
 * anything stored beside the ciphertext, so a ciphertext row moved onto another connection,
 * owner, organization, secret or version fails to open.
 */

/** The key provider type, re-exported so no other module needs to import the crypto package. */
export type { KekProvider };

/**
 * Loads the local key-encryption keys (ADR-003). Fails closed on an unsafe directory or key
 * file; the error names the path, never key material.
 */
export function loadLocalKek(directory: string): Promise<KekProvider> {
  return LocalFileKekProvider.load(directory);
}

/** Largest serialized snapshot that will be sealed. Well under the runner's job line cap. */
export const MAX_SNAPSHOT_BYTES = 2 * 1024 * 1024;

/** The connection fields the associated data is built from. */
export type SnapshotConnection = Pick<Connection, 'id' | 'organizationId' | 'ownerUserId'>;

export interface StoredSnapshot {
  vaultEntryId: string;
  version: number;
  kekVersion: number;
}

export interface OpenedSnapshot {
  readonly storageState: StorageState;
  readonly vaultEntryId: string;
  readonly version: number;
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
 * A stored snapshot could not be decrypted or did not validate. Deliberately generic: it
 * carries no plaintext, no ciphertext and no `cause`.
 */
export class SnapshotOpenError extends Error {
  override readonly name = 'SnapshotOpenError';
  readonly reason: 'decrypt' | 'invalid';
  constructor(reason: 'decrypt' | 'invalid') {
    super(
      reason === 'decrypt'
        ? 'the session snapshot could not be decrypted'
        : 'the session snapshot is not a valid storage state',
    );
    this.reason = reason;
  }
}

function aadFor(connection: SnapshotConnection, secretId: string, version: number): SecretAad {
  return {
    organizationId: connection.organizationId,
    userId: connection.ownerUserId,
    connectionId: connection.id,
    secretId,
    secretType: SESSION_SNAPSHOT_SECRET_TYPE,
    secretVersion: version,
  };
}

export interface StoreSnapshotInput {
  connection: SnapshotConnection;
  storageState: StorageState;
  kek: KekProvider;
  now: Date;
}

/**
 * Seals a storage state and stores it as the connection's active snapshot. Pass the
 * repositories of the caller's transaction to make the write atomic with other changes.
 * Returns metadata only.
 */
export async function storeSnapshot(
  repos: Repositories,
  input: StoreSnapshotInput,
): Promise<StoredSnapshot> {
  // Validate before sealing so nothing unparseable is ever stored.
  const parsed = StorageStateSchema.safeParse(input.storageState);
  if (!parsed.success) throw new SnapshotOpenError('invalid');
  const plaintext = Buffer.from(canonicalJson(parsed.data), 'utf8');
  try {
    if (plaintext.byteLength > MAX_SNAPSHOT_BYTES) throw new SnapshotTooLargeError();
    const ensured = await repos.vault.ensureSecret({
      connectionId: input.connection.id,
      secretType: SESSION_SNAPSHOT_SECRET_TYPE,
      now: input.now,
    });
    const version = ensured.nextVersion;
    const sealed = await sealSecret({
      plaintext,
      aad: aadFor(input.connection, ensured.secretId, version),
      kek: input.kek,
    });
    await repos.vault.putVersion({
      secretId: ensured.secretId,
      version,
      sealed,
      now: input.now,
    });
    return { vaultEntryId: ensured.secretId, version, kekVersion: sealed.kekVersion };
  } finally {
    plaintext.fill(0);
  }
}

/**
 * Opens the connection's active snapshot, or returns null when there is none. Raises
 * {@link SnapshotOpenError} when it cannot be decrypted or does not validate.
 *
 * About `dispose()`: the decrypted buffer is zeroed as soon as it has been parsed, and
 * `dispose()` zeroes it again and empties the parsed state's arrays. JavaScript cannot
 * guarantee more than that: the parsed cookie values are immutable strings that stay in the
 * heap until the garbage collector reclaims them, the engine may have copied buffers while
 * moving them, and the runner's stdin pipe held its own copy.
 */
export async function openSnapshot(
  repos: Repositories,
  connection: SnapshotConnection,
  kek: KekProvider,
): Promise<OpenedSnapshot | null> {
  const active = await repos.vault.getActive(connection.id, SESSION_SNAPSHOT_SECRET_TYPE);
  if (active === null) return null;

  let plaintext: Buffer;
  try {
    plaintext = await openSecret({
      sealed: active.sealed,
      aad: aadFor(connection, active.secretId, active.version),
      kek,
    });
  } catch {
    throw new SnapshotOpenError('decrypt');
  }

  let state: StorageState;
  try {
    let value: unknown;
    try {
      value = JSON.parse(plaintext.toString('utf8'));
    } catch {
      throw new SnapshotOpenError('invalid');
    }
    if (checkPlainJson(value) !== null) throw new SnapshotOpenError('invalid');
    const parsed = StorageStateSchema.safeParse(value);
    if (!parsed.success) throw new SnapshotOpenError('invalid');
    state = parsed.data;
  } finally {
    plaintext.fill(0);
  }

  let disposed = false;
  return {
    storageState: state,
    vaultEntryId: active.secretId,
    version: active.version,
    kekVersion: active.sealed.kekVersion,
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

/** Earliest positive cookie expiry, or null when every cookie is a session cookie. */
export function sessionExpiry(state: StorageState): Date | null {
  let earliest: number | null = null;
  for (const cookie of state.cookies) {
    if (!Number.isFinite(cookie.expires) || cookie.expires <= 0) continue;
    if (earliest === null || cookie.expires < earliest) earliest = cookie.expires;
  }
  if (earliest === null) return null;
  const date = new Date(earliest * 1000);
  return Number.isNaN(date.getTime()) ? null : date;
}
