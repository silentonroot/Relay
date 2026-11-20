import { isAbsolute } from 'node:path';
import { z } from 'zod';

/*
 * Worker configuration from the environment. Validated before anything touches the database,
 * the key directory or a sandbox. Errors name the variable and the problem, never the value:
 * DATABASE_URL embeds the database password.
 */

const blankToUndefined = (value: unknown) =>
  typeof value === 'string' && value.trim() === '' ? undefined : value;

export const LOG_LEVELS = ['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent'] as const;
export type LogLevel = (typeof LOG_LEVELS)[number];

const AbsolutePath = z
  .string({ error: 'is required' })
  .min(1, 'is required')
  .refine((value) => isAbsolute(value), { message: 'expected an absolute path' });

const int = (min: number, max: number, fallback: number) =>
  z.preprocess(blankToUndefined, z.coerce.number().int().min(min).max(max).default(fallback));

const EnvSchema = z.object({
  DATABASE_URL: z.preprocess(
    blankToUndefined,
    z
      .string({ error: 'is required' })
      .min(1, 'is required')
      .refine((value) => /^postgres(?:ql)?:\/\//.test(value), {
        message: 'expected a postgres:// or postgresql:// connection string',
      }),
  ),
  // The supervisor-role socket of the vault (ADR-014 section 1).
  AAB_VAULT_SOCKET: z.preprocess(
    blankToUndefined,
    z
      .string({ error: 'is required (the supervisor-role socket of the vault)' })
      .max(4096)
      .refine((value) => isAbsolute(value) && !value.includes('\0'), {
        message: 'expected an absolute path',
      }),
  ),
  // Mirrors the vault's AAB_VAULT_ISOLATION; the vault's `hello` must agree. In `separate-uid`
  // the supervisor refuses to start if it can open the vault's key directory.
  AAB_VAULT_ISOLATION: z.preprocess(
    blankToUndefined,
    z
      .enum(['separate-uid', 'shared-uid'], { error: 'expected "separate-uid" or "shared-uid"' })
      .default('separate-uid'),
  ),
  // Per vault call, connect included (ADR-014 section 9: five seconds).
  AAB_VAULT_CALL_TIMEOUT_MS: int(100, 60_000, 5_000),
  AAB_WORKER_SANDBOX: z.preprocess(
    blankToUndefined,
    z.enum(['bubblewrap', 'docker', 'unsafe-process']).default('bubblewrap'),
  ),
  AAB_WORKER_CONCURRENCY: int(1, 16, 2),
  AAB_WORKER_POLL_MS: int(50, 60_000, 1_000),
  AAB_WORKER_LEASE_MS: int(5_000, 3_600_000, 60_000),
  AAB_WORKER_RUNTIME_DIR: z.preprocess(blankToUndefined, AbsolutePath.optional()),
  AAB_CHROMIUM_PATH: z.preprocess(blankToUndefined, AbsolutePath.optional()),
  AAB_WORKER_DOCKER_IMAGE: z.preprocess(
    blankToUndefined,
    z
      .string()
      .max(255)
      .regex(/^[a-z0-9][a-z0-9._/:@-]*$/, 'expected a container image reference')
      .optional(),
  ),
  AAB_JOB_RESULT_TTL_MINUTES: int(1, 10_080, 60),
  AAB_LOG_LEVEL: z.preprocess(blankToUndefined, z.enum(LOG_LEVELS).default('info')),
});

export interface WorkerConfig {
  databaseUrl: string;
  /** Path of the vault's supervisor-role socket. */
  vaultSocket: string;
  vaultIsolation: 'separate-uid' | 'shared-uid';
  /** Timeout of one vault call, in milliseconds. */
  vaultCallTimeoutMs: number;
  sandbox: 'bubblewrap' | 'docker' | 'unsafe-process';
  concurrency: number;
  pollIntervalMs: number;
  leaseMs: number;
  runtimeDir: string | undefined;
  chromiumPath: string | undefined;
  dockerImage: string | undefined;
  resultTtlMinutes: number;
  logLevel: LogLevel;
}

export class ConfigError extends Error {
  constructor(readonly issues: readonly string[]) {
    super(`invalid configuration:\n${issues.map((issue) => `  - ${issue}`).join('\n')}`);
    this.name = 'ConfigError';
  }
}

/** Parses the environment. Throws ConfigError listing variable names and problems only. */
export function loadWorkerConfig(env: Record<string, string | undefined>): WorkerConfig {
  // Phase 3 inverts the old requirement: the supervisor holds no key (P3-1) and refuses to start
  // when a key directory is configured. Checked first, so no other problem hides it; the value is
  // never used or echoed.
  if (typeof env['AAB_KEK_DIR'] === 'string' && env['AAB_KEK_DIR'].trim() !== '') {
    throw new ConfigError([
      'AAB_KEK_DIR: must not be set for the browser worker; only the vault reads key material',
    ]);
  }
  const result = EnvSchema.safeParse(env);
  if (!result.success) {
    throw new ConfigError(
      result.error.issues.map((issue) => `${issue.path.map(String).join('.')}: ${issue.message}`),
    );
  }
  const data = result.data;
  if (data.AAB_WORKER_SANDBOX === 'unsafe-process' && data.AAB_VAULT_ISOLATION !== 'shared-uid') {
    // The runner then shares the supervisor's user, so it could open the vault's supervisor
    // socket: the separate-uid claim (P3-14) cannot hold. Allowed only where nothing is claimed.
    throw new ConfigError([
      'AAB_WORKER_SANDBOX: unsafe-process is allowed only with AAB_VAULT_ISOLATION=shared-uid',
    ]);
  }
  return {
    databaseUrl: data.DATABASE_URL,
    vaultSocket: data.AAB_VAULT_SOCKET,
    vaultIsolation: data.AAB_VAULT_ISOLATION,
    vaultCallTimeoutMs: data.AAB_VAULT_CALL_TIMEOUT_MS,
    sandbox: data.AAB_WORKER_SANDBOX,
    concurrency: data.AAB_WORKER_CONCURRENCY,
    pollIntervalMs: data.AAB_WORKER_POLL_MS,
    leaseMs: data.AAB_WORKER_LEASE_MS,
    runtimeDir: data.AAB_WORKER_RUNTIME_DIR,
    chromiumPath: data.AAB_CHROMIUM_PATH,
    dockerImage: data.AAB_WORKER_DOCKER_IMAGE,
    resultTtlMinutes: data.AAB_JOB_RESULT_TTL_MINUTES,
    logLevel: data.AAB_LOG_LEVEL,
  };
}
