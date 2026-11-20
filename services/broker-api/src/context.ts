import type { AdapterRegistry } from '@aab/adapter-sdk';
import type { ScryptParams } from '@aab/crypto';
import type { Db, Repositories, Scope, ValidSession } from '@aab/database';
import type { FastifyBaseLogger } from 'fastify';
import type { PasswordService } from './auth/passwords.js';
import type { AppConfig } from './config.js';
import type { VaultGateway } from './vault/gateway.js';

/** What a request authenticated by the session cookie carries. */
export interface RequestAuth {
  /** The raw session token from the cookie. Never logged, never returned. */
  token: string;
  session: ValidSession;
  scope: Scope;
}

export interface RateLimitSettings {
  /** Requests per client address per minute, across the whole API. */
  globalMax: number;
  /** Login attempts per (client address, email) per window. */
  loginMax: number;
  /** Login attempts per client address per window, whatever the email. */
  loginAddressMax: number;
  loginWindowMs: number;
  /** Calls to POST /operations/execute per client address per minute. */
  executeMax: number;
}

export const DEFAULT_RATE_LIMITS: RateLimitSettings = {
  globalMax: 300,
  loginMax: 5,
  loginAddressMax: 30,
  loginWindowMs: 15 * 60 * 1000,
  executeMax: 60,
};

/** Shared, per-app state handed to every route module. */
export interface AppContext {
  db: Db;
  repos: Repositories;
  config: AppConfig;
  /**
   * Adapters, used as data only: descriptors, input schemas and `loginPath`. The API never
   * calls `execute` or `checkSession`; the browser worker does.
   */
  adapters: AdapterRegistry;
  clock: () => Date;
  /**
   * The vault, as the `api` role. Undefined only where no vault is wired (tests of the Phase 2
   * path, `dev:memory`): then jobs are not authorized and not swept, and nothing claims them
   * with `requireCapability`. `main.ts` refuses to start without one.
   */
  vault: VaultGateway | undefined;
  passwordParams: ScryptParams | undefined;
  /** Every password hash and verification goes through this, behind one limiter (F-5). */
  passwords: PasswordService;
  /** A real hash of a random password, verified against when the account is unknown. */
  dummyPasswordHash: string;
  /**
   * Runs work after the response without delaying it, and keeps the promise so `close()` can
   * wait for it. Failures are logged, never thrown.
   */
  runInBackground(log: FastifyBaseLogger, label: string, work: () => Promise<unknown>): void;
}

declare module 'fastify' {
  interface FastifyContextConfig {
    /** `public` routes skip session authentication. Everything else requires a session. */
    auth?: 'public';
  }
  interface FastifyRequest {
    auth: RequestAuth | null;
  }
  interface FastifyInstance {
    /** Every route registered on this app, for tests that must cover all of them. */
    routeTable: { method: string; url: string; public: boolean }[];
    /** Runs the vault authorization sweep once; returns how many jobs it ended. For tests. */
    sweepVaultAuthorizations: () => Promise<number>;
  }
}
