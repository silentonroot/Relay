import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import type { KeyObject } from 'node:crypto';

/*
 * The one place AES-256-GCM is invoked. Everything else in this package goes through these
 * two functions so the parameters below cannot drift between call sites.
 */

export const KEY_BYTES = 32;
export const NONCE_BYTES = 12;
export const TAG_BYTES = 16;

const ALGORITHM = 'aes-256-gcm';

export interface GcmSealed {
  ciphertext: Buffer;
  nonce: Buffer;
  authTag: Buffer;
}

/** Thrown for any decryption failure. Callers translate it into their own generic error. */
export class GcmAuthenticationError extends Error {
  override readonly name = 'GcmAuthenticationError';

  constructor() {
    super('authentication failed');
  }
}

/** Encrypts with a fresh random 96-bit nonce and a full 128-bit tag. */
export function gcmEncrypt(
  key: KeyObject | Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
): GcmSealed {
  const nonce = randomBytes(NONCE_BYTES);
  const cipher = createCipheriv(ALGORITHM, key, nonce, { authTagLength: TAG_BYTES });
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { ciphertext, nonce, authTag: cipher.getAuthTag() };
}

/**
 * Decrypts and authenticates. Plaintext is returned only after `final()` has verified the tag;
 * on failure the partially decrypted buffer is zeroed and never leaves this function.
 *
 * `authTagLength` is passed explicitly and the lengths are checked first: without that option
 * Node accepts truncated tags (as short as 4 bytes), which would make forgery practical.
 */
export function gcmDecrypt(
  key: KeyObject | Uint8Array,
  sealed: { ciphertext: Uint8Array; nonce: Uint8Array; authTag: Uint8Array },
  aad: Uint8Array,
): Buffer {
  if (sealed.nonce.byteLength !== NONCE_BYTES || sealed.authTag.byteLength !== TAG_BYTES) {
    throw new GcmAuthenticationError();
  }

  let partial: Buffer | undefined;
  try {
    const decipher = createDecipheriv(ALGORITHM, key, sealed.nonce, { authTagLength: TAG_BYTES });
    decipher.setAuthTag(sealed.authTag);
    decipher.setAAD(aad);
    partial = decipher.update(sealed.ciphertext);
    const tail = decipher.final();
    if (tail.byteLength === 0) return partial;
    const plaintext = Buffer.concat([partial, tail]);
    partial.fill(0);
    tail.fill(0);
    return plaintext;
  } catch {
    partial?.fill(0);
    throw new GcmAuthenticationError();
  }
}
