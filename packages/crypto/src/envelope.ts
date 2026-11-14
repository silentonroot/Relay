import { randomBytes } from 'node:crypto';
import { AAD_VERSION, encodeSecretAad } from './aad.js';
import type { SecretAad } from './aad.js';
import { CryptoInputError, SecretOpenError } from './errors.js';
import { gcmDecrypt, gcmEncrypt, KEY_BYTES, NONCE_BYTES, TAG_BYTES } from './gcm.js';
import type { KekProvider } from './kek.js';

/** Identifies the construction below. Any other value is refused on open. */
export const ENVELOPE_ALGORITHM = 'aab-envelope-v1/aes-256-gcm';

/**
 * One encrypted secret version. Fields map onto `vault_secret_versions` (spec §11):
 * ciphertext, nonce, auth_tag, wrapped_dek, kek_version, aad_version, plus the algorithm id.
 * Nothing here is secret on its own, and nothing here is useful without the KEK.
 */
export interface SealedSecret {
  algorithm: string;
  ciphertext: Buffer;
  /** 96-bit GCM nonce for `ciphertext`. */
  nonce: Buffer;
  /** 128-bit GCM tag for `ciphertext`. */
  authTag: Buffer;
  /** The data key encrypted under the KEK, including that wrap's own nonce and tag. */
  wrappedDek: Buffer;
  kekVersion: number;
  aadVersion: number;
}

export interface SealSecretInput {
  plaintext: Uint8Array;
  aad: SecretAad;
  kek: KekProvider;
}

export interface OpenSecretInput {
  sealed: SealedSecret;
  aad: SecretAad;
  kek: KekProvider;
}

export interface RewrapSecretInput {
  sealed: SealedSecret;
  aad: SecretAad;
  /** Provider holding the KEK version the secret is currently wrapped under. */
  from: KekProvider;
  /** Provider whose current KEK version the data key is re-wrapped under. */
  to: KekProvider;
}

/**
 * Encrypts one secret version (spec §6.2): a fresh random 256-bit data key per call,
 * AES-256-GCM with a fresh random 96-bit nonce, the secret's context bound as associated
 * data, and the data key wrapped by the KEK provider.
 *
 * Because every data key encrypts exactly one message, nonce reuse under a data key cannot
 * happen. The plaintext buffer is the caller's to zero.
 */
export async function sealSecret(input: SealSecretInput): Promise<SealedSecret> {
  const { plaintext, aad, kek } = input;
  if (!(plaintext instanceof Uint8Array)) {
    // Strings are refused so the bytes that get encrypted are never an implicit encoding choice.
    throw new CryptoInputError('plaintext must be a Uint8Array');
  }
  const aadBytes = encodeSecretAad(aad, AAD_VERSION);

  const dek = randomBytes(KEY_BYTES);
  try {
    const wrapped = await kek.wrap(dek, { secretAad: aadBytes });
    const sealed = gcmEncrypt(dek, plaintext, aadBytes);
    return {
      algorithm: ENVELOPE_ALGORITHM,
      ciphertext: sealed.ciphertext,
      nonce: sealed.nonce,
      authTag: sealed.authTag,
      wrappedDek: wrapped.wrappedDek,
      kekVersion: wrapped.kekVersion,
      aadVersion: AAD_VERSION,
    };
  } finally {
    // Best effort: this clears our copy, but JavaScript gives no guarantee that the runtime
    // has not copied the bytes elsewhere (OpenSSL contexts, GC moves, swap).
    dek.fill(0);
  }
}

function isBytes(value: unknown): value is Uint8Array {
  return value instanceof Uint8Array;
}

/**
 * Decrypts a sealed secret. Rejects with {@link SecretOpenError} for every failure, whether
 * the record is malformed, the context differs, the KEK version is unknown or any byte was
 * altered, so a caller (or an attacker observing errors) cannot tell which check failed.
 *
 * The returned buffer holds plaintext: keep its lifetime short and `fill(0)` it when done.
 */
export async function openSecret(input: OpenSecretInput): Promise<Buffer> {
  let dek: Buffer | undefined;
  try {
    const { sealed, aad, kek } = input;
    if (
      sealed.algorithm !== ENVELOPE_ALGORITHM ||
      !isBytes(sealed.ciphertext) ||
      !isBytes(sealed.nonce) ||
      !isBytes(sealed.authTag) ||
      !isBytes(sealed.wrappedDek) ||
      // Checked here as well as in gcmDecrypt: a truncated tag must never reach the decipher.
      sealed.nonce.byteLength !== NONCE_BYTES ||
      sealed.authTag.byteLength !== TAG_BYTES
    ) {
      throw new SecretOpenError();
    }
    const aadBytes = encodeSecretAad(aad, sealed.aadVersion);
    dek = await kek.unwrap(
      { kekVersion: sealed.kekVersion, wrappedDek: sealed.wrappedDek },
      { secretAad: aadBytes },
    );
    if (dek.byteLength !== KEY_BYTES) throw new SecretOpenError();
    return gcmDecrypt(dek, sealed, aadBytes);
  } catch {
    throw new SecretOpenError();
  } finally {
    dek?.fill(0); // best effort, see sealSecret
  }
}

/**
 * KEK rotation for one secret: unwraps the data key with `from` and wraps it under the
 * current version of `to`. The ciphertext, nonce and tag are carried over unchanged, so no
 * plaintext is ever produced. Rejects with {@link SecretOpenError} if the data key cannot be
 * unwrapped for this context.
 */
export async function rewrapSecret(input: RewrapSecretInput): Promise<SealedSecret> {
  const { sealed, aad, from, to } = input;
  let dek: Buffer | undefined;
  try {
    let aadBytes: Buffer;
    try {
      if (sealed.algorithm !== ENVELOPE_ALGORITHM || !isBytes(sealed.wrappedDek)) {
        throw new SecretOpenError();
      }
      aadBytes = encodeSecretAad(aad, sealed.aadVersion);
      dek = await from.unwrap(
        { kekVersion: sealed.kekVersion, wrappedDek: sealed.wrappedDek },
        { secretAad: aadBytes },
      );
      if (dek.byteLength !== KEY_BYTES) throw new SecretOpenError();
    } catch {
      throw new SecretOpenError();
    }

    const wrapped = await to.wrap(dek, { secretAad: aadBytes });
    return {
      algorithm: sealed.algorithm,
      ciphertext: Buffer.from(sealed.ciphertext),
      nonce: Buffer.from(sealed.nonce),
      authTag: Buffer.from(sealed.authTag),
      wrappedDek: wrapped.wrappedDek,
      kekVersion: wrapped.kekVersion,
      aadVersion: sealed.aadVersion,
    };
  } finally {
    dek?.fill(0); // best effort, see sealSecret
  }
}
