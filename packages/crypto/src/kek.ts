import { createSecretKey, randomBytes } from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import type { Stats } from 'node:fs';
import { lstat, mkdir, open, readdir, unlink } from 'node:fs/promises';
import type { FileHandle } from 'node:fs/promises';
import { join } from 'node:path';
import { inspect } from 'node:util';
import { CryptoInputError, KekOperationError, KekStoreError } from './errors.js';
import { gcmDecrypt, gcmEncrypt, KEY_BYTES, NONCE_BYTES, TAG_BYTES } from './gcm.js';

/** What a wrapped data key is bound to: the AAD bytes of the secret it protects. */
export interface KekContext {
  secretAad: Uint8Array;
}

export interface WrappedDek {
  /** Version of the key-encryption key that produced `wrappedDek`. */
  kekVersion: number;
  /** Opaque to callers. Local providers use `nonce(12) || ciphertext(32) || tag(16)`. */
  wrappedDek: Buffer;
}

/**
 * Holds key-encryption keys and wraps data keys with them. The KEK itself never leaves the
 * provider. A KMS/HSM-backed implementation can replace the local ones behind this interface.
 */
export interface KekProvider {
  /** Version used for new wraps. */
  readonly currentVersion: number;
  wrap(dek: Uint8Array, context: KekContext): Promise<WrappedDek>;
  /** Rejects with a generic error for an unknown version, wrong context or tampered input. */
  unwrap(wrapped: WrappedDek, context: KekContext): Promise<Buffer>;
}

/** Byte length of a data key wrapped by the local providers. */
export const LOCAL_WRAPPED_DEK_BYTES = NONCE_BYTES + KEY_BYTES + TAG_BYTES;

const MAX_KEK_VERSION = 999_999_999;
const WRAP_LABEL = Buffer.from('aab.dek-wrap.v1\0', 'utf8');
const KEY_FILE_NAME = /^kek-v([1-9]\d{0,8})\.key$/;

function assertKekVersion(version: number): void {
  if (!Number.isSafeInteger(version) || version < 1 || version > MAX_KEK_VERSION) {
    throw new CryptoInputError('KEK version must be a positive integer');
  }
}

/**
 * Associated data for a DEK wrap: a fixed label, the KEK version and the secret's AAD bytes.
 * Binding the secret's AAD means a wrapped DEK copied onto another secret will not unwrap.
 */
function wrapAad(kekVersion: number, context: KekContext): Buffer {
  const version = Buffer.alloc(4);
  version.writeUInt32BE(kekVersion);
  return Buffer.concat([WRAP_LABEL, version, context.secretAad]);
}

/** Shared AES-256-GCM key wrapping over an in-process set of KEK versions. */
abstract class KeyringKekProvider implements KekProvider {
  // Private fields are invisible to util.inspect, JSON.stringify and property enumeration,
  // and KeyObject does not print its key material either.
  readonly #keys = new Map<number, KeyObject>();
  #currentVersion = 0;

  /** Copies the key into a KeyObject. The caller should zero its own buffer afterwards. */
  protected addKey(version: number, key: Uint8Array): void {
    assertKekVersion(version);
    if (!(key instanceof Uint8Array) || key.byteLength !== KEY_BYTES) {
      throw new CryptoInputError(`KEK must be exactly ${KEY_BYTES} bytes`);
    }
    if (this.#keys.has(version)) {
      throw new CryptoInputError('duplicate KEK version');
    }
    this.#keys.set(version, createSecretKey(key));
    this.#currentVersion = Math.max(this.#currentVersion, version);
  }

  get currentVersion(): number {
    if (this.#currentVersion === 0) throw new KekOperationError('wrap');
    return this.#currentVersion;
  }

  /** Known KEK versions, ascending. */
  get versions(): number[] {
    return [...this.#keys.keys()].sort((a, b) => a - b);
  }

  wrap(dek: Uint8Array, context: KekContext): Promise<WrappedDek> {
    return Promise.resolve().then(() => {
      if (!(dek instanceof Uint8Array) || dek.byteLength !== KEY_BYTES) {
        throw new CryptoInputError(`data key must be exactly ${KEY_BYTES} bytes`);
      }
      const kekVersion = this.currentVersion;
      const key = this.#keys.get(kekVersion);
      if (key === undefined) throw new KekOperationError('wrap');
      const sealed = gcmEncrypt(key, dek, wrapAad(kekVersion, context));
      return {
        kekVersion,
        wrappedDek: Buffer.concat([sealed.nonce, sealed.ciphertext, sealed.authTag]),
      };
    });
  }

  unwrap(wrapped: WrappedDek, context: KekContext): Promise<Buffer> {
    return Promise.resolve().then(() => {
      try {
        const key = this.#keys.get(wrapped.kekVersion);
        const blob = wrapped.wrappedDek;
        if (
          key === undefined ||
          !(blob instanceof Uint8Array) ||
          blob.byteLength !== LOCAL_WRAPPED_DEK_BYTES
        ) {
          throw new KekOperationError('unwrap');
        }
        return gcmDecrypt(
          key,
          {
            nonce: blob.subarray(0, NONCE_BYTES),
            ciphertext: blob.subarray(NONCE_BYTES, NONCE_BYTES + KEY_BYTES),
            authTag: blob.subarray(NONCE_BYTES + KEY_BYTES),
          },
          wrapAad(wrapped.kekVersion, context),
        );
      } catch {
        // One error for every cause: unknown version, bad length, wrong context, tampering.
        throw new KekOperationError('unwrap');
      }
    });
  }

  protected describe(extra: Record<string, unknown> = {}): string {
    return `${this.constructor.name} ${inspect({ ...extra, versions: this.versions })}`;
  }

  [inspect.custom](): string {
    return this.describe();
  }

  toJSON(): Record<string, unknown> {
    return { type: this.constructor.name, versions: this.versions };
  }
}

/** KEKs held only in process memory. For tests; nothing is persisted. */
export class InMemoryKekProvider extends KeyringKekProvider {
  /** @param keys `[version, 32-byte key]` pairs. The highest version becomes current. */
  constructor(keys: Iterable<readonly [number, Uint8Array]>) {
    super();
    for (const [version, key] of keys) this.addKey(version, key);
    if (this.versions.length === 0) {
      throw new CryptoInputError('at least one KEK is required');
    }
  }

  /** A provider with a fresh random key for each given version (default: version 1). */
  static random(...versions: number[]): InMemoryKekProvider {
    const wanted = versions.length === 0 ? [1] : versions;
    return new InMemoryKekProvider(wanted.map((version) => [version, randomBytes(KEY_BYTES)]));
  }
}

function isErrno(error: unknown, code: string): boolean {
  return error instanceof Error && (error as NodeJS.ErrnoException).code === code;
}

/** Owned by the user this process runs as, or by root. Skipped where uids do not exist. */
function hasTrustedOwner(stat: Stats): boolean {
  if (typeof process.geteuid !== 'function') return true;
  return stat.uid === process.geteuid() || stat.uid === 0;
}

async function assertSafeKeyDirectory(directory: string): Promise<void> {
  let stat: Stats;
  try {
    stat = await lstat(directory);
  } catch {
    throw new KekStoreError(`KEK directory does not exist or cannot be read: ${directory}`);
  }
  if (!stat.isDirectory()) {
    throw new KekStoreError(
      `KEK path is not a directory (symbolic links are refused): ${directory}`,
    );
  }
  // ADR-003: mode 0700 or stricter. Read or traverse access for group or other would expose
  // the key file names and leave the key files one chmod away from disclosure.
  if ((stat.mode & 0o077) !== 0) {
    throw new KekStoreError(
      `KEK directory must not be accessible by group or other (expected mode 0700): ${directory}`,
    );
  }
  if (!hasTrustedOwner(stat)) {
    throw new KekStoreError(`KEK directory must be owned by the current user: ${directory}`);
  }
}

async function readKeyFile(path: string): Promise<Buffer> {
  let handle: FileHandle;
  try {
    // O_NOFOLLOW refuses a symbolic link at the final path component; O_NONBLOCK keeps a
    // FIFO planted at this path from hanging the open. The checks below use fstat on the
    // already-open descriptor, so the file cannot be swapped between check and read.
    handle = await open(
      path,
      fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK,
    );
  } catch {
    throw new KekStoreError(`KEK file cannot be opened or is a symbolic link: ${path}`);
  }
  try {
    const stat = await handle.stat();
    if (!stat.isFile()) {
      throw new KekStoreError(`KEK file is not a regular file: ${path}`);
    }
    if ((stat.mode & 0o077) !== 0) {
      throw new KekStoreError(
        `KEK file must not be accessible by group or other (expected mode 0600): ${path}`,
      );
    }
    if (!hasTrustedOwner(stat)) {
      throw new KekStoreError(`KEK file must be owned by the current user: ${path}`);
    }
    if (stat.size !== KEY_BYTES) {
      throw new KekStoreError(`KEK file must be exactly ${KEY_BYTES} bytes: ${path}`);
    }
    // One spare byte so a file that grew after fstat is detected rather than truncated.
    const buffer = Buffer.alloc(KEY_BYTES + 1);
    const { bytesRead } = await handle.read(buffer, 0, buffer.byteLength, 0);
    if (bytesRead !== KEY_BYTES) {
      buffer.fill(0);
      throw new KekStoreError(`KEK file must be exactly ${KEY_BYTES} bytes: ${path}`);
    }
    return buffer.subarray(0, KEY_BYTES);
  } finally {
    await handle.close();
  }
}

/**
 * KEKs stored as raw 32-byte files named `kek-v<N>.key` in a local directory (ADR-003).
 * Intended for local single-owner installs on POSIX systems. The directory must live outside
 * the repository and the database: whoever can read these files can decrypt every secret.
 */
export class LocalFileKekProvider extends KeyringKekProvider {
  readonly directory: string;

  private constructor(directory: string) {
    super();
    this.directory = directory;
  }

  /**
   * Loads every `kek-v<N>.key` in `directory`. Fails closed: one unsafe or malformed key file
   * rejects the whole load rather than silently continuing with fewer keys.
   */
  static async load(directory: string): Promise<LocalFileKekProvider> {
    await assertSafeKeyDirectory(directory);
    const provider = new LocalFileKekProvider(directory);

    for (const name of (await readdir(directory)).sort()) {
      const match = KEY_FILE_NAME.exec(name);
      if (match === null) continue;
      const key = await readKeyFile(join(directory, name));
      try {
        provider.addKey(Number(match[1]), key);
      } finally {
        key.fill(0);
      }
    }

    if (provider.versions.length === 0) {
      throw new KekStoreError(`no KEK files (kek-v<N>.key) found in: ${directory}`);
    }
    return provider;
  }

  override [inspect.custom](): string {
    return this.describe({ directory: this.directory });
  }

  override toJSON(): Record<string, unknown> {
    return { ...super.toJSON(), directory: this.directory };
  }
}

/**
 * Creates `kek-v<version>.key` with 32 fresh random bytes and mode 0600. The directory is
 * created 0700 when missing; an existing directory with any group or other permission bit is
 * refused, never silently tightened or used. An existing key file is never overwritten:
 * losing a KEK makes every secret wrapped under it unrecoverable.
 * Returns the path of the new file.
 */
export async function generateLocalKek(directory: string, version: number): Promise<string> {
  assertKekVersion(version);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  await assertSafeKeyDirectory(directory);

  const path = join(directory, `kek-v${version}.key`);
  let handle: FileHandle;
  try {
    handle = await open(
      path,
      fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW,
      0o600,
    );
  } catch (error) {
    if (isErrno(error, 'EEXIST')) {
      throw new KekStoreError(`KEK file already exists and will not be overwritten: ${path}`);
    }
    throw new KekStoreError(`KEK file cannot be created: ${path}`);
  }

  const key = randomBytes(KEY_BYTES);
  try {
    await handle.chmod(0o600);
    await handle.writeFile(key);
    await handle.sync();
  } catch {
    await handle.close().catch(() => undefined);
    // Do not leave a truncated key behind; it would block a retry for this version.
    await unlink(path).catch(() => undefined);
    throw new KekStoreError(`KEK file could not be written: ${path}`);
  } finally {
    key.fill(0);
  }
  await handle.close();
  return path;
}
