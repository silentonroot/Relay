import { hostname } from 'node:os';
import { randomBytes } from 'node:crypto';
import type { AdapterRegistry, ApplicationAdapter } from '@aab/adapter-sdk';
import type { ApplicationDefinition } from '@aab/contracts';
import type { ExecutionJob, Repositories } from '@aab/database';
import type { Logger } from 'pino';
import type { KekProvider } from '../session-store/index.js';
import type { JobRunner } from '../types.js';

export interface SupervisorSettings {
  /** Recorded on claimed jobs; must be unique per supervisor process. */
  workerId: string;
  /** Jobs run at once. */
  concurrency: number;
  /** How often the loop looks for queued jobs. */
  pollIntervalMs: number;
  /** Lease taken on a claimed job, extended by the heartbeat while it runs. */
  leaseMs: number;
  /** How often a running job's lease is extended and its cancel flag checked. */
  heartbeatMs: number;
  /** How often an open login window checks for the owner's completion or a cancel request. */
  loginPollMs: number;
  /** How often expired leases are recovered and old results purged. */
  maintenanceIntervalMs: number;
  /** Stored job results are purged this long after the job finished. */
  resultTtlMinutes: number;
  /** A retry-safe operation whose lease expired is requeued until it was attempted this often. */
  maxAttempts: number;
}

export const DEFAULT_SUPERVISOR_SETTINGS: Omit<SupervisorSettings, 'workerId' | 'heartbeatMs'> = {
  concurrency: 2,
  pollIntervalMs: 1_000,
  leaseMs: 60_000,
  loginPollMs: 500,
  maintenanceIntervalMs: 60_000,
  resultTtlMinutes: 60,
  maxAttempts: 3,
};

export function resolveSupervisorSettings(
  input: Partial<SupervisorSettings> = {},
): SupervisorSettings {
  const merged = { ...DEFAULT_SUPERVISOR_SETTINGS, ...input };
  const settings: SupervisorSettings = {
    ...merged,
    workerId:
      input.workerId ?? `worker-${hostname()}-${process.pid}-${randomBytes(4).toString('hex')}`,
    heartbeatMs: input.heartbeatMs ?? Math.max(50, Math.floor(merged.leaseMs / 3)),
  };
  for (const key of [
    'concurrency',
    'pollIntervalMs',
    'leaseMs',
    'heartbeatMs',
    'loginPollMs',
    'maintenanceIntervalMs',
    'resultTtlMinutes',
    'maxAttempts',
  ] as const) {
    if (!Number.isSafeInteger(settings[key]) || settings[key] < 1) {
      throw new Error(`supervisor setting ${key} must be a positive integer`);
    }
  }
  if (settings.heartbeatMs >= settings.leaseMs) {
    throw new Error('supervisor setting heartbeatMs must be shorter than leaseMs');
  }
  return settings;
}

export interface SupervisorDeps {
  repos: Repositories;
  runner: JobRunner;
  kek: KekProvider;
  adapters: AdapterRegistry;
  clock?: () => Date;
  logger: Logger;
  settings?: Partial<SupervisorSettings>;
}

/** Why a running job was told to stop. */
export type StopReason = 'shutdown' | 'lease_lost' | 'cancelled';

export interface JobContext {
  readonly repos: Repositories;
  readonly runner: JobRunner;
  readonly kek: KekProvider;
  readonly adapters: AdapterRegistry;
  readonly clock: () => Date;
  readonly logger: Logger;
  readonly settings: SupervisorSettings;
  readonly job: ExecutionJob;
  /** Fires on cancellation, lease loss or shutdown. */
  readonly signal: AbortSignal;
  stopReason(): StopReason | null;
  /** `Date.now()` when the job was claimed, for durations. */
  readonly startedAtMs: number;
}

/**
 * The adapter's origins that the application also allows, in the adapter's order. Empty when
 * they share none.
 */
export function intersectOrigins(
  adapter: Pick<ApplicationAdapter, 'allowedOrigins'>,
  application: Pick<ApplicationDefinition, 'allowedOrigins'>,
): string[] {
  const allowed = new Set(application.allowedOrigins);
  return adapter.allowedOrigins.filter((origin) => allowed.has(origin));
}

/** Error facts that are safe to log: the type and a driver code. Never the message. */
export function errorFacts(error: unknown): { errorType: string; errorCode?: string } {
  if (!(error instanceof Error)) return { errorType: typeof error };
  const code = (error as { code?: unknown }).code;
  return {
    errorType: error.name,
    ...(typeof code === 'string' && /^[A-Za-z0-9_.-]{1,40}$/.test(code) ? { errorCode: code } : {}),
  };
}
