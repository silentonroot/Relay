import { isAbsolute, normalize } from 'node:path';
import { z } from 'zod';
import {
  DEFAULT_TOKEN_TTL_SECONDS,
  TOKEN_TTL_MAX_SECONDS,
  TOKEN_TTL_MIN_SECONDS,
  VAULT_ROLES,
} from '@aab/contracts';
import type { VaultIsolation, VaultRole } from '@aab/contracts';

/*
 * Vault configuration from the environment. Validated before anything touches the key
 * directory, the sockets or the database. Every error names the variable and the problem,
 * never the value (DATABASE_URL embeds a password; a group name or path may be sensitive).
 *
 * Numbers are strict decimal integers: "1e2", " 5", "0x10", "5.0" and "" are refused, not
 * coerced (P3-7: no lifetime by accident).
 */

export const LOG_LEVELS = ['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent'] as const;
export type LogLevel = (typeof LOG_LEVELS)[number];

/** Unset (not blank) means "use the default"; a blank value is a mistake and is refused. */
const unsetToUndefined = (value: unknown) => (value === undefined ? undefined : value);

const AbsolutePath = z
  .string({ error: 'is required' })
  .min(1, 'is required')
  .max(4096, 'is too long')
  .refine((value) => !value.includes('\0'), { message: 'must not contain a NUL byte' })
  .refine((value) => isAbsolute(value), { message: 'expected an absolute path' })
  .refine(
    (value) => {
      // No "." or ".." segments, no doubled or trailing separators: the path is used as is
      // for symlink and ancestry checks, so it must already be in its canonical text form.
      return value === '/' || (normalize(value) === value && !value.endsWith('/'));
    },
    { message: 'expected a normalized path (no ".", ".." or trailing "/")' },
  );

/** A strict decimal integer in [min, max]; `fallback` when the variable is unset. */
const strictInt = (min: number, max: number, fallback: number) =>
  z.preprocess(
    unsetToUndefined,
    z
      .string({ error: 'must be a decimal integer' })
      .regex(/^(?:0|[1-9]\d{0,15})$/, 'must be a decimal integer')
      .transform((value) => Number(value))
      .refine((value) => Number.isSafeInteger(value), { message: 'must be a safe integer' })
      .refine((value) => value >= min && value <= max, {
        message: `must be between ${min} and ${max}`,
      })
      .default(fallback),
  );

/** A group name or a numeric gid, as written in the environment. */
const GROUP_SPEC = /^(?:[a-z_][a-z0-9_-]{0,31}|\d{1,10})$/;
const GroupSpec = z.preprocess(
  unsetToUndefined,
  z
    .string()
    .regex(GROUP_SPEC, 'expected a group name or a numeric gid')
    .refine((value) => !/^\d+$/.test(value) || Number(value) <= 4_294_967_294, {
      message: 'gid out of range',
    })
    .optional(),
);

const EnvSchema = z.object({
  DATABASE_URL: z
    .string({ error: 'is required' })
    .min(1, 'is required')
    .refine((value) => /^postgres(?:ql)?:\/\//.test(value), {
      message: 'expected a postgres:// or postgresql:// connection string',
    }),
  AAB_KEK_DIR: AbsolutePath,
  AAB_VAULT_SOCKET_DIR: AbsolutePath,
  AAB_VAULT_ISOLATION: z.preprocess(
    unsetToUndefined,
    z
      .enum(['separate-uid', 'shared-uid'], {
        error: 'expected "separate-uid" or "shared-uid"',
      })
      .default('separate-uid'),
  ),
  AAB_VAULT_GROUP_API: GroupSpec,
  AAB_VAULT_GROUP_SUPERVISOR: GroupSpec,
  AAB_VAULT_GROUP_ADMIN: GroupSpec,
  AAB_VAULT_TOKEN_TTL_SECONDS: strictInt(
    TOKEN_TTL_MIN_SECONDS,
    TOKEN_TTL_MAX_SECONDS,
    DEFAULT_TOKEN_TTL_SECONDS,
  ),
  AAB_VAULT_MAX_CONNECTIONS: strictInt(1, 256, 16),
  AAB_VAULT_IDLE_TIMEOUT_MS: strictInt(1_000, 3_600_000, 60_000),
  AAB_VAULT_REQUEST_TIMEOUT_MS: strictInt(100, 120_000, 10_000),
  AAB_VAULT_ADMIN_REQUEST_TIMEOUT_MS: strictInt(1_000, 600_000, 120_000),
  AAB_LOG_LEVEL: z.preprocess(unsetToUndefined, z.enum(LOG_LEVELS).default('info')),
});

export interface VaultConfig {
  databaseUrl: string;
  kekDir: string;
  socketDir: string;
  isolation: VaultIsolation;
  /** Group name or numeric gid per role; present for every role in `separate-uid` only. */
  roleGroups: Readonly<Partial<Record<VaultRole, string>>>;
  /**
   * The vault takes no authorization lifetime: the API sends one with every `authorizeJobAccess`
   * (10 to 3,600 s, `AAB_VAULT_AUTHORIZATION_TTL_SECONDS` on the API). A value set for the vault is
   * ignored; it was parsed and never used before B4's review.
   */
  /** The token lifetime the vault's own checks use (the supervisor sends its own per request). */
  tokenTtlSeconds: number;
  /** Open connections allowed per role socket. */
  maxConnectionsPerRole: number;
  /** A connection with no traffic for this long is closed. */
  idleTimeoutMs: number;
  /** A request line must complete, and be answered, within this long. */
  requestTimeoutMs: number;
  /** The admin socket's request timeout (rewrap, status): longer than the others', never shorter. */
  adminRequestTimeoutMs: number;
  logLevel: LogLevel;
}

export class ConfigError extends Error {
  constructor(readonly issues: readonly string[]) {
    super(`invalid configuration:\n${issues.map((issue) => `  - ${issue}`).join('\n')}`);
    this.name = 'ConfigError';
  }
}

/** Parses the environment. Throws `ConfigError` listing variable names and problems only. */
export function loadVaultConfig(env: Record<string, string | undefined>): VaultConfig {
  const result = EnvSchema.safeParse(env);
  const issues: string[] = [];
  if (!result.success) {
    for (const issue of result.error.issues) {
      issues.push(`${issue.path.map(String).join('.')}: ${issue.message}`);
    }
  }
  const data = result.success ? result.data : undefined;

  if (data !== undefined) {
    const groupVariables = {
      api: 'AAB_VAULT_GROUP_API',
      supervisor: 'AAB_VAULT_GROUP_SUPERVISOR',
      admin: 'AAB_VAULT_GROUP_ADMIN',
    } as const satisfies Record<VaultRole, string>;
    const groups: Partial<Record<VaultRole, string>> = {};
    for (const role of VAULT_ROLES) {
      const value = data[groupVariables[role] as keyof typeof data] as string | undefined;
      if (value !== undefined) groups[role] = value;
    }
    if (data.AAB_VAULT_ISOLATION === 'separate-uid') {
      for (const role of VAULT_ROLES) {
        if (groups[role] === undefined) {
          issues.push(`${groupVariables[role]}: is required when AAB_VAULT_ISOLATION=separate-uid`);
        }
      }
      const values = Object.values(groups);
      if (new Set(values).size !== values.length) {
        issues.push('AAB_VAULT_GROUP_*: each role needs its own group; two roles share one');
      }
    } else if (Object.keys(groups).length > 0) {
      issues.push(
        'AAB_VAULT_GROUP_*: must not be set when AAB_VAULT_ISOLATION=shared-uid ' +
          '(one user, one directory mode; the kernel cannot tell the roles apart)',
      );
    }
    if (issues.length === 0) {
      return {
        databaseUrl: data.DATABASE_URL,
        kekDir: data.AAB_KEK_DIR,
        socketDir: data.AAB_VAULT_SOCKET_DIR,
        isolation: data.AAB_VAULT_ISOLATION,
        roleGroups: groups,
        tokenTtlSeconds: data.AAB_VAULT_TOKEN_TTL_SECONDS,
        maxConnectionsPerRole: data.AAB_VAULT_MAX_CONNECTIONS,
        idleTimeoutMs: data.AAB_VAULT_IDLE_TIMEOUT_MS,
        requestTimeoutMs: data.AAB_VAULT_REQUEST_TIMEOUT_MS,
        adminRequestTimeoutMs: data.AAB_VAULT_ADMIN_REQUEST_TIMEOUT_MS,
        logLevel: data.AAB_LOG_LEVEL,
      };
    }
  }
  throw new ConfigError(issues);
}
