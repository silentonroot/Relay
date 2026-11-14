import type { JsonObject, JsonValue } from '@aab/contracts';

export const REDACTED = '[REDACTED]';
export const MAX_STRING_LENGTH = 500;
export const MAX_DEPTH = 8;
export const MAX_ARRAY_LENGTH = 100;
export const MAX_OBJECT_KEYS = 100;
export const MAX_KEY_LENGTH = 120;

const DEPTH_MARKER = '[TRUNCATED: depth]';
const CIRCULAR_MARKER = '[CIRCULAR]';
const UNSERIALIZABLE_MARKER = '[UNSERIALIZABLE]';

/**
 * Matched against the key with case and separators removed, so `api_key`, `API-Key`,
 * `apiKey` and `x-api-key` all normalize to something containing `apikey`.
 */
const SECRET_KEY_SUBSTRINGS = [
  'password',
  'passwd',
  'passphrase',
  'secret',
  'token',
  'cookie', // also covers set-cookie
  'authorization',
  'apikey',
  'sessionid',
  'sessionkey',
  'credential',
  'privatekey',
  'storagestate', // Playwright session snapshots (storageState, storage_state)
  'bearer',
  // Cryptographic material (INV-1, threat model F-10). None of these is an ordinary audit fact.
  'ciphertext',
  'nonce',
  'authtag', // AES-GCM authentication tag: authTag, auth_tag
  'wrappedkey',
  'accesskey',
  'signature',
] as const;

/**
 * Short terms that would over-match as substrings; these must be a whole word of the key
 * (`wrappedDek`, `kek_version`, `sid`) or the whole key.
 */
const SECRET_KEY_WORDS = new Set(['dek', 'kek', 'pwd', 'sid', 'jwt', 'otp', 'iv', 'salt']);

/**
 * `tag` alone is usually a label (`tag`, `tags`), so it counts only next to a word that makes
 * it an AEAD or MAC tag (`gcmTag`, `aead_tag`, `macTag`, `cipherTag`). `authTag` is already a
 * substring term above.
 */
const CRYPTO_TAG_QUALIFIERS = new Set(['gcm', 'aead', 'mac', 'hmac', 'cipher', 'crypto', 'auth']);

/**
 * Redacted only when they are the entire key: `session: "..."` is likely a session value,
 * while `sessionExpiresAt` and `authModes` are ordinary facts worth keeping.
 */
const SECRET_KEY_EXACT = new Set(['session', 'auth']);

/**
 * True when a metadata key name suggests its value is authentication material. Deliberately
 * over-broad: a redacted harmless value costs a little audit detail, a persisted secret is a
 * breach. Callers that need a non-secret fact about a secret should name the key for the
 * fact (`secretVersion`, `keyVersion`), not for the secret.
 */
export function isSecretKeyName(key: string): boolean {
  const normalized = key.toLowerCase().replace(/[^a-z0-9]/g, '');
  if (SECRET_KEY_EXACT.has(normalized)) return true;
  if (SECRET_KEY_SUBSTRINGS.some((term) => normalized.includes(term))) return true;
  const words = key
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((word) => word !== '');
  if (words.some((word) => SECRET_KEY_WORDS.has(word))) return true;
  return words.includes('tag') && words.some((word) => CRYPTO_TAG_QUALIFIERS.has(word));
}

/** Credential-shaped substrings that are scrubbed from string values wherever they appear. */
const SECRET_VALUE_PATTERNS: readonly RegExp[] = [
  /\b(?:bearer|basic)\s+[A-Za-z0-9._~+/-]{8,}=*/gi,
  /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*/g,
];

function sanitizeString(value: string): string {
  // jsonb rejects NUL and unpaired surrogates; drop them so an event is never lost to that.
  let text = value.replaceAll('\u0000', '').toWellFormed();
  for (const pattern of SECRET_VALUE_PATTERNS) {
    text = text.replace(pattern, REDACTED);
  }
  if (text.length > MAX_STRING_LENGTH) {
    const omitted = text.length - MAX_STRING_LENGTH;
    text = `${text.slice(0, MAX_STRING_LENGTH)}…[truncated ${omitted} chars]`.toWellFormed();
  }
  return text;
}

function sanitizeKey(key: string): string {
  const cleaned = key.replaceAll('\u0000', '').toWellFormed();
  return cleaned.length > MAX_KEY_LENGTH
    ? cleaned.slice(0, MAX_KEY_LENGTH).toWellFormed()
    : cleaned;
}

function isPlainObject(value: object): value is Record<string, unknown> {
  const prototype: unknown = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function sanitizeValue(value: unknown, depth: number, ancestors: Set<object>): JsonValue {
  if (value === null || value === undefined) return null;

  switch (typeof value) {
    case 'string':
      return sanitizeString(value);
    case 'boolean':
      return value;
    case 'number':
      return Number.isFinite(value) ? value : null;
    case 'bigint':
      return value.toString();
    case 'object':
      break;
    default:
      // functions and symbols carry nothing worth auditing
      return UNSERIALIZABLE_MARKER;
  }

  if (value instanceof Date) {
    return Number.isNaN(value.getTime()) ? null : value.toISOString();
  }
  if (ancestors.has(value)) return CIRCULAR_MARKER;
  if (depth >= MAX_DEPTH) return DEPTH_MARKER;

  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      const items = value
        .slice(0, MAX_ARRAY_LENGTH)
        .map((item) => sanitizeValue(item, depth + 1, ancestors));
      if (value.length > MAX_ARRAY_LENGTH) {
        items.push(`[TRUNCATED: ${value.length - MAX_ARRAY_LENGTH} more items]`);
      }
      return items;
    }
    if (!isPlainObject(value)) return UNSERIALIZABLE_MARKER;
    return sanitizeObject(value, depth, ancestors);
  } finally {
    ancestors.delete(value);
  }
}

function sanitizeObject(
  value: Record<string, unknown>,
  depth: number,
  ancestors: Set<object>,
): JsonObject {
  const entries: [string, JsonValue][] = [];
  const keys = Object.keys(value);
  for (const key of keys.slice(0, MAX_OBJECT_KEYS)) {
    const member = value[key];
    if (member === undefined || typeof member === 'function' || typeof member === 'symbol') {
      continue;
    }
    entries.push([
      sanitizeKey(key),
      isSecretKeyName(key) ? REDACTED : sanitizeValue(member, depth + 1, ancestors),
    ]);
  }
  if (keys.length > MAX_OBJECT_KEYS) {
    entries.push(['[TRUNCATED]', `${keys.length - MAX_OBJECT_KEYS} more keys`]);
  }
  // fromEntries defines own properties, so a hostile "__proto__" key stays plain data.
  return Object.fromEntries(entries);
}

/**
 * Returns a deep copy of `value` that is safe to persist as audit metadata:
 *  - the value under any secret-looking key is replaced by "[REDACTED]", at every depth and
 *    inside arrays, whatever its type;
 *  - bearer/basic credentials and JWT-shaped strings are scrubbed from string values;
 *  - strings, arrays, objects and nesting depth are capped;
 *  - anything that is not plain JSON is dropped or replaced by a marker.
 *
 * The input is never mutated. A non-object input is wrapped as `{ value }`.
 *
 * This is a safety net, not the control: callers must still pass redacted summaries only
 * (spec §11.1). It cannot recognize a secret stored under an innocuous key name.
 */
export function redactMetadata(value: unknown): JsonObject {
  const ancestors = new Set<object>();
  if (
    typeof value === 'object' &&
    value !== null &&
    !Array.isArray(value) &&
    !(value instanceof Date) &&
    isPlainObject(value)
  ) {
    ancestors.add(value);
    return sanitizeObject(value, 0, ancestors);
  }
  if (value === undefined) return {};
  return { value: sanitizeValue(value, 1, ancestors) };
}
