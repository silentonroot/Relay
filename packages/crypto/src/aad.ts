import { canonicalJson, Uuid } from '@aab/contracts';
import { CryptoInputError } from './errors.js';

/** Version of the AAD layout below. Stored with every sealed secret (`aad_version`). */
export const AAD_VERSION = 1;

/**
 * The context a secret is bound to (spec §6.2 item 3). A sealed secret only opens when every
 * one of these values matches what it was sealed with, so a ciphertext row copied onto another
 * tenant, user, connection, secret or version fails authentication.
 */
export interface SecretAad {
  organizationId: string;
  userId: string;
  connectionId: string;
  secretId: string;
  /** Kind of secret, e.g. `browser_session`. Lowercase letters, digits, `_`, `.` and `-`. */
  secretType: string;
  /** Positive integer version of the secret this ciphertext belongs to. */
  secretVersion: number;
}

const SECRET_TYPE = /^[a-z][a-z0-9_.-]{0,63}$/;
type UuidField = 'organizationId' | 'userId' | 'connectionId' | 'secretId';

function requireUuid(aad: SecretAad, field: UuidField): string {
  const value: unknown = aad[field];
  if (typeof value !== 'string' || !Uuid.safeParse(value).success) {
    throw new CryptoInputError(`aad.${field} must be a UUID`);
  }
  // UUIDs compare case-insensitively, but the AAD is compared byte-for-byte.
  return value.toLowerCase();
}

/**
 * Deterministic AAD bytes: canonical JSON of the validated fields plus `aadVersion`, UTF-8.
 * Only the known fields are serialized; anything else on the input object is ignored.
 */
export function encodeSecretAad(aad: SecretAad, aadVersion: number = AAD_VERSION): Buffer {
  if (aadVersion !== AAD_VERSION) {
    throw new CryptoInputError('unsupported aadVersion');
  }
  if (typeof aad !== 'object' || aad === null) {
    throw new CryptoInputError('aad must be an object');
  }
  if (typeof aad.secretType !== 'string' || !SECRET_TYPE.test(aad.secretType)) {
    throw new CryptoInputError('aad.secretType must be a short lowercase identifier');
  }
  if (!Number.isSafeInteger(aad.secretVersion) || aad.secretVersion < 1) {
    throw new CryptoInputError('aad.secretVersion must be a positive integer');
  }

  return Buffer.from(
    canonicalJson({
      aadVersion,
      organizationId: requireUuid(aad, 'organizationId'),
      userId: requireUuid(aad, 'userId'),
      connectionId: requireUuid(aad, 'connectionId'),
      secretId: requireUuid(aad, 'secretId'),
      secretType: aad.secretType,
      secretVersion: aad.secretVersion,
    }),
    'utf8',
  );
}
