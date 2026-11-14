export { AAD_VERSION, encodeSecretAad } from './aad.js';
export type { SecretAad } from './aad.js';
export { ENVELOPE_ALGORITHM, openSecret, rewrapSecret, sealSecret } from './envelope.js';
export type {
  OpenSecretInput,
  RewrapSecretInput,
  SealedSecret,
  SealSecretInput,
} from './envelope.js';
export { CryptoInputError, KekOperationError, KekStoreError, SecretOpenError } from './errors.js';
export {
  generateLocalKek,
  InMemoryKekProvider,
  LOCAL_WRAPPED_DEK_BYTES,
  LocalFileKekProvider,
} from './kek.js';
export type { KekContext, KekProvider, WrappedDek } from './kek.js';
export {
  DEFAULT_SCRYPT_PARAMS,
  hashPassword,
  MAX_PASSWORD_BYTES,
  needsRehash,
  verifyPassword,
} from './password.js';
export type { HashPasswordOptions, ScryptParams } from './password.js';
export { constantTimeEqual, generateToken, hashToken } from './tokens.js';
