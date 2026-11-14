import { isAbsolute } from 'node:path';
import { DEFAULT_JOB_WAIT_MS } from '@aab/contracts';
import { z } from 'zod';

/*
 * Environment configuration. Everything is validated before the service touches the network
 * or the database, and a failure names the offending variables without echoing their values:
 * DATABASE_URL embeds the database password.
 */

/** Blank values (as in .env.example) mean "not set". */
const blankToUndefined = (value: unknown) =>
  typeof value === 'string' && value.trim() === '' ? undefined : value;

const BooleanFlag = z
  .enum(['true', 'false', '1', '0'], { error: 'expected true or false' })
  .transform((value) => value === 'true' || value === '1');

export const LOG_LEVELS = ['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent'] as const;
export type LogLevel = (typeof LOG_LEVELS)[number];

export const DatabaseUrl = z
  .string({ error: 'is required' })
  .min(1, 'is required')
  .refine((value) => /^postgres(?:ql)?:\/\//.test(value), {
    message: 'expected a postgres:// or postgresql:// connection string',
  });

/** Upper bound for AAB_JOB_WAIT_MS: a request is never held open longer than this. */
export const MAX_JOB_WAIT_MS = 120_000;

const EnvSchema = z.object({
  DATABASE_URL: z.preprocess(blankToUndefined, DatabaseUrl),
  AAB_HOST: z.preprocess(blankToUndefined, z.string().min(1).max(255).default('127.0.0.1')),
  AAB_PORT: z.preprocess(blankToUndefined, z.coerce.number().int().min(1).max(65535).default(4000)),
  AAB_KEK_DIR: z.preprocess(
    blankToUndefined,
    z
      .string()
      .refine((value) => isAbsolute(value), { message: 'expected an absolute path' })
      .optional(),
  ),
  AAB_SESSION_TTL_MINUTES: z.preprocess(
    blankToUndefined,
    z.coerce.number().int().min(5).max(10_080).default(480),
  ),
  AAB_COOKIE_SECURE: z.preprocess(blankToUndefined, BooleanFlag.default(true)),
  AAB_LOG_LEVEL: z.preprocess(blankToUndefined, z.enum(LOG_LEVELS).default('info')),
  AAB_TRUST_PROXY: z.preprocess(blankToUndefined, BooleanFlag.default(false)),
  // F-5: each password operation costs ~128 MiB, so keep these small and size memory for them.
  AAB_PASSWORD_CONCURRENCY: z.preprocess(
    blankToUndefined,
    z.coerce.number().int().min(1).max(8).default(2),
  ),
  AAB_PASSWORD_QUEUE_LIMIT: z.preprocess(
    blankToUndefined,
    z.coerce.number().int().min(0).max(100).default(8),
  ),
  // How long execute and auth/complete hold the request open for a terminal job status.
  AAB_JOB_WAIT_MS: z.preprocess(
    blankToUndefined,
    z.coerce.number().int().min(0).max(MAX_JOB_WAIT_MS).default(DEFAULT_JOB_WAIT_MS),
  ),
});

export interface AppConfig {
  databaseUrl: string;
  host: string;
  port: number;
  kekDir: string | undefined;
  sessionTtlMinutes: number;
  cookieSecure: boolean;
  logLevel: LogLevel;
  trustProxy: boolean;
  /** Password hashes/verifications allowed to run at once (threat model F-5). */
  passwordConcurrency: number;
  /** Password operations allowed to wait for a slot before logins are answered 429. */
  passwordQueueLimit: number;
  /** Longest an execute or auth/complete request waits for its job to finish before 202. */
  jobWaitMs: number;
}

export class ConfigError extends Error {
  constructor(readonly issues: readonly string[]) {
    super(`invalid configuration:\n${issues.map((issue) => `  - ${issue}`).join('\n')}`);
    this.name = 'ConfigError';
  }
}

/** Parses the environment. Throws ConfigError listing variable names and problems, never values. */
export function loadConfig(env: Record<string, string | undefined>): AppConfig {
  const result = EnvSchema.safeParse(env);
  if (!result.success) {
    throw new ConfigError(
      result.error.issues.map((issue) => `${issue.path.map(String).join('.')}: ${issue.message}`),
    );
  }
  const data = result.data;
  return {
    databaseUrl: data.DATABASE_URL,
    host: data.AAB_HOST,
    port: data.AAB_PORT,
    kekDir: data.AAB_KEK_DIR,
    sessionTtlMinutes: data.AAB_SESSION_TTL_MINUTES,
    cookieSecure: data.AAB_COOKIE_SECURE,
    logLevel: data.AAB_LOG_LEVEL,
    trustProxy: data.AAB_TRUST_PROXY,
    passwordConcurrency: data.AAB_PASSWORD_CONCURRENCY,
    passwordQueueLimit: data.AAB_PASSWORD_QUEUE_LIMIT,
    jobWaitMs: data.AAB_JOB_WAIT_MS,
  };
}
