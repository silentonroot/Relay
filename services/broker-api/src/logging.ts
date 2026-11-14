import type { FastifyServerOptions } from 'fastify';
import type { LogLevel } from './config.js';

/** Anything with a `write(line)` method: a file stream, stdout, or a test buffer. */
export interface LogDestination {
  write(line: string): void;
}

const SECRET_FIELDS = [
  'password',
  'newPassword',
  'passwordHash',
  'token',
  'sessionToken',
  'tokenHash',
  'csrfToken',
  'csrfTokenHash',
  'cookie',
  'authorization',
];

/**
 * pino redaction. Request and response bodies are never logged (Fastify's default serializers
 * omit them and nothing here adds them); these paths are the backstop for headers and for
 * any object that is logged by mistake.
 */
export const REDACT_PATHS = [
  'req.headers.authorization',
  'req.headers.cookie',
  'req.headers["x-csrf-token"]',
  'res.headers["set-cookie"]',
  'headers.authorization',
  'headers.cookie',
  'headers["set-cookie"]',
  ...SECRET_FIELDS,
  ...SECRET_FIELDS.map((field) => `*.${field}`),
  ...SECRET_FIELDS.map((field) => `*.*.${field}`),
];

interface SerializableError {
  name?: unknown;
  message?: unknown;
  stack?: unknown;
  code?: unknown;
  cause?: unknown;
}

/**
 * Drizzle's query errors put the bound parameters in the message (`params: ...`), and those
 * include token and password hashes. Everything from that marker to the end of its line goes.
 */
export function scrubErrorText(text: string): string {
  return text.replace(/params:[^\n]*/g, 'params: [REDACTED]');
}

function text(value: unknown): string {
  return typeof value === 'string' ? scrubErrorText(value) : '';
}

export function loggerOptions(
  level: LogLevel,
  destination: LogDestination | undefined,
): NonNullable<Exclude<FastifyServerOptions['logger'], boolean>> {
  return {
    level,
    redact: { paths: REDACT_PATHS, censor: '[REDACTED]' },
    serializers: {
      // Driver errors carry enumerable fields such as `detail` that can quote row values;
      // only the type, message, code and stack are kept.
      err: (error: SerializableError) => {
        const cause = error.cause as SerializableError | undefined;
        return {
          type: typeof error.name === 'string' ? error.name : 'Error',
          message: text(error.message),
          stack: text(error.stack),
          ...(typeof error.code === 'string' ? { code: error.code } : {}),
          ...(typeof cause?.message === 'string' ? { cause: text(cause.message) } : {}),
        };
      },
    },
    ...(destination === undefined ? {} : { stream: destination }),
  };
}
