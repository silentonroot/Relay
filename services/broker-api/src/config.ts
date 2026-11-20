import { isAbsolute } from 'node:path';
import {
  AUTHORIZATION_TTL_MAX_SECONDS,
  AUTHORIZATION_TTL_MIN_SECONDS,
  DEFAULT_AUTHORIZATION_TTL_SECONDS,
  DEFAULT_JOB_WAIT_MS,
  LOGIN_HANDOFF_TIMEOUT_MS,
} from '@aab/contracts';
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

/**
 * A strict decimal integer in [min, max], `fallback` when the variable is unset or blank. "1e2",
 * " 5", "0x10" and "5.0" are refused, not coerced (P3-7: no lifetime by accident).
 */
const strictInt = (min: number, max: number, fallback: number) =>
  z.preprocess(
    blankToUndefined,
    z
      .string({ error: 'must be a decimal integer' })
      .regex(/^(?:0|[1-9]\d{0,15})$/, 'must be a decimal integer')
      .transform((value) => Number(value))
      .refine((value) => value >= min && value <= max, {
        message: `must be between ${min} and ${max}`,
      })
      .default(fallback),
  );

/**
 * ADR-014 section 5 gave the login lifetime as the handoff timeout plus 60 seconds. The lifetime
 * runs from authorization, but the sign-in window opens only when a worker claims the job, so
 * queue time came out of the same budget. It is the handoff timeout plus 300 seconds (900 s, well
 * under the 3,600 s ceiling): five minutes for the job to wait for a worker. The supervisor also
 * cuts the window to what the capability has left less 45 s (B3 review M1), so a longer wait
 * shortens the window or fails the login with `timeout` before a window opens; it never ends in
 * `vault_denied` after a capture.
 */
export const LOGIN_AUTHORIZATION_TTL_SECONDS = LOGIN_HANDOFF_TIMEOUT_MS / 1000 + 300;

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
  // The api-role socket of the vault (ADR-014 section 1), an absolute path of a socket file.
  AAB_VAULT_SOCKET: z.preprocess(
    blankToUndefined,
    z
      .string()
      .max(4096)
      .refine((value) => isAbsolute(value) && !value.includes('\0'), {
        message: 'expected an absolute path',
      })
      .optional(),
  ),
  // Mirrors the vault's AAB_VAULT_ISOLATION. In `separate-uid` the API refuses to start if it can
  // open the vault's key directory (P3-1); the vault's answer to `hello` must agree.
  AAB_VAULT_ISOLATION: z.preprocess(
    blankToUndefined,
    z
      .enum(['separate-uid', 'shared-uid'], { error: 'expected "separate-uid" or "shared-uid"' })
      .default('separate-uid'),
  ),
  // Lifetime of the authorization of an operation job. Logins get the handoff timeout plus 60 s.
  AAB_VAULT_AUTHORIZATION_TTL_SECONDS: strictInt(
    AUTHORIZATION_TTL_MIN_SECONDS,
    AUTHORIZATION_TTL_MAX_SECONDS,
    DEFAULT_AUTHORIZATION_TTL_SECONDS,
  ),
  // Per vault call, connect included (ADR-014 section 9: five seconds).
  AAB_VAULT_CALL_TIMEOUT_MS: strictInt(100, 60_000, 5_000),
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
  /** Path of the vault's api-role socket. Required by `main.ts`; tests and dev-memory may omit it. */
  vaultSocket: string | undefined;
  vaultIsolation: 'separate-uid' | 'shared-uid';
  /** Lifetime of an operation job's capability authorization, in seconds. */
  vaultAuthorizationTtlSeconds: number;
  /** Timeout of one vault call, in milliseconds. */
  vaultCallTimeoutMs: number;
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
    vaultSocket: data.AAB_VAULT_SOCKET,
    vaultIsolation: data.AAB_VAULT_ISOLATION,
    vaultAuthorizationTtlSeconds: data.AAB_VAULT_AUTHORIZATION_TTL_SECONDS,
    vaultCallTimeoutMs: data.AAB_VAULT_CALL_TIMEOUT_MS,
    sessionTtlMinutes: data.AAB_SESSION_TTL_MINUTES,
    cookieSecure: data.AAB_COOKIE_SECURE,
    logLevel: data.AAB_LOG_LEVEL,
    trustProxy: data.AAB_TRUST_PROXY,
    passwordConcurrency: data.AAB_PASSWORD_CONCURRENCY,
    passwordQueueLimit: data.AAB_PASSWORD_QUEUE_LIMIT,
    jobWaitMs: data.AAB_JOB_WAIT_MS,
  };
}

/**
 * The API process needs the vault (ADR-014): `main.ts` calls this after the other start-up
 * refusals, so a missing AAB_VAULT_SOCKET stops the start. Tests and `dev:memory` do not call it
 * and run the Phase 2 path without a vault. Returns the socket path.
 */
export function requireVaultSocket(config: AppConfig): string {
  if (config.vaultSocket === undefined) {
    throw new ConfigError(['AAB_VAULT_SOCKET: is required (the api-role socket of the vault)']);
  }
  return config.vaultSocket;
}
