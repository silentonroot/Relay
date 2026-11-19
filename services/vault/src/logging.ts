import { pino } from 'pino';
import type { DestinationStream, Logger } from 'pino';
import type { LogLevel } from './config.js';

/*
 * The vault's logger (P3-15). Nothing secret is passed to it on purpose: handlers log ids,
 * codes, roles and counts, never request params, results or error messages (driver errors
 * quote bound parameters). `redactLogObject` is the backstop for an object logged by mistake:
 * it replaces the value under any key that names a secret, at any depth and in any letter
 * case, before pino serializes the line.
 */

const REDACTED = '[REDACTED]';

/** Words that mark a key as secret-bearing once the key is split at case and separator breaks. */
const SENSITIVE_WORDS: ReadonlySet<string> = new Set([
  'token',
  'tokens',
  'mac',
  'macs',
  'hash',
  'hashes',
  'kek',
  'dek',
  'key',
  'keys',
  'secret',
  'secrets',
  'plaintext',
  'ciphertext',
  'sealed',
  'nonce',
  'tag',
  'authtag',
  'wrapped',
  'wrappeddek',
  'storagestate',
  'cookie',
  'cookies',
  'localstorage',
  'password',
  'passphrase',
  'authorization',
  'credential',
  'credentials',
  'bearer',
  'database',
  'databaseurl',
  'connectionstring',
  'arguments',
  'params',
  'result',
  'request',
  'response',
  'body',
  'line',
  'payload',
  'data',
]);

/** Keys that contain a sensitive word but carry only a number, a path or a flag we want to see. */
const SAFE_KEYS: ReadonlySet<string> = new Set([
  'kekVersion',
  'kekVersions',
  'currentKekVersion',
  'keyVersionFrom',
  'keyVersionTo',
  'keyDirectory',
  'missingKekVersions',
  'requestId',
]);

const MAX_REDACT_DEPTH = 8;

function words(key: string): string[] {
  return key
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
    .split(/[^A-Za-z0-9]+/)
    .filter((word) => word !== '')
    .map((word) => word.toLowerCase());
}

export function isSensitiveKey(key: string): boolean {
  if (SAFE_KEYS.has(key)) return false;
  const parts = words(key);
  if (parts.some((part) => SENSITIVE_WORDS.has(part))) return true;
  // Compound forms such as "storagestate" or "authorizationmac" written without a break.
  const joined = key.toLowerCase();
  return [
    'token',
    'mac',
    'kek',
    'plaintext',
    'ciphertext',
    'storagestate',
    'password',
    'secret',
  ].some((word) => joined.includes(word) && !SAFE_KEYS.has(key));
}

/** A copy of `value` with every sensitive key's value replaced. Never mutates its input. */
export function redactLogObject(value: unknown, depth = 0): unknown {
  if (value === null || typeof value !== 'object') return value;
  if (depth >= MAX_REDACT_DEPTH) return REDACTED;
  if (Array.isArray(value)) return value.map((item) => redactLogObject(item, depth + 1));
  // Buffers and typed arrays are bytes: never print them.
  if (ArrayBuffer.isView(value) || value instanceof ArrayBuffer) return REDACTED;
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(value)) {
    const inner = (value as Record<string, unknown>)[key];
    out[key] = isSensitiveKey(key) ? REDACTED : redactLogObject(inner, depth + 1);
  }
  return out;
}

interface SerializableError {
  name?: unknown;
  code?: unknown;
}

export function createLogger(level: LogLevel, destination?: DestinationStream): Logger {
  const options = {
    level,
    base: { service: 'vault' },
    formatters: {
      log: (object: Record<string, unknown>) => redactLogObject(object) as Record<string, unknown>,
    },
    serializers: {
      // Only the type and code of an error object; messages and stacks can quote values.
      err: (error: SerializableError) => ({
        type: typeof error.name === 'string' ? error.name : 'Error',
        ...(typeof error.code === 'string' ? { code: error.code } : {}),
      }),
    },
  };
  const logger = destination === undefined ? pino(options) : pino(options, destination);
  // Child bindings (`logger.child({...})`) bypass `formatters.log`, so they are redacted here.
  // Children inherit this property (pino builds them with Object.create(parent)).
  const original = logger.child;
  logger.child = function child(this: Logger, bindings, childOptions) {
    return original.call(this, redactLogObject(bindings) as typeof bindings, childOptions);
  } as Logger['child'];
  return logger;
}

/** The facts worth logging about a caught value: its type and code, never its message. */
export function errorFacts(error: unknown): { errorType: string; errorCode?: string } {
  if (typeof error === 'object' && error !== null) {
    const { name, code } = error as SerializableError;
    return {
      errorType: typeof name === 'string' ? name : 'Error',
      ...(typeof code === 'string' ? { errorCode: code } : {}),
    };
  }
  return { errorType: typeof error };
}
