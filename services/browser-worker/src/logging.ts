import { pino } from 'pino';
import type { DestinationStream, Logger } from 'pino';
import type { LogLevel } from './config.js';

/*
 * The supervisor's logger. Nothing secret is ever passed to it on purpose: job handlers log
 * ids, codes and error types only, never error messages (driver errors quote bound
 * parameters, which can include ciphertext or operation results). These redaction paths are
 * the backstop for an object logged by mistake.
 */

const SECRET_FIELDS = [
  'password',
  'token',
  'cookie',
  'cookies',
  'authorization',
  'storageState',
  'localStorage',
  'plaintext',
  'ciphertext',
  'sealed',
  'nonce',
  'authTag',
  'wrappedDek',
  'dek',
  'kek',
  'key',
  'arguments',
  'result',
  'data',
  'databaseUrl',
  'connectionString',
];

export const REDACT_PATHS = [
  ...SECRET_FIELDS,
  ...SECRET_FIELDS.map((field) => `*.${field}`),
  ...SECRET_FIELDS.map((field) => `*.*.${field}`),
];

interface SerializableError {
  name?: unknown;
  code?: unknown;
}

export function createLogger(level: LogLevel, destination?: DestinationStream): Logger {
  const options = {
    level,
    base: { service: 'browser-worker' },
    redact: { paths: REDACT_PATHS, censor: '[REDACTED]' },
    serializers: {
      // Only the type and code of an error object; messages and stacks can quote values.
      err: (error: SerializableError) => ({
        type: typeof error.name === 'string' ? error.name : 'Error',
        ...(typeof error.code === 'string' ? { code: error.code } : {}),
      }),
    },
  };
  return destination === undefined ? pino(options) : pino(options, destination);
}
