import { randomUUID } from 'node:crypto';
import { VaultCallError } from '@aab/vault-client';
import type { ExecutionJob } from '@aab/database';
import { VaultStartupRefusal } from '../vault/gateway.js';
import { errorFacts, resolveSupervisorSettings } from './context.js';
import type { JobContext, StopReason, SupervisorDeps } from './context.js';
import { runLoginJob } from './login.js';
import { runOperationJob } from './operation.js';
import { auditAsWorker, LOGIN_LEASE_EXPIRED_REASON, transitionIfAllowed } from './records.js';

/** Start-up refused. The message names the failed check and never carries secret material. */
export class SupervisorStartError extends Error {
  override readonly name = 'SupervisorStartError';
}

export interface MaintenanceReport {
  recovered: number;
  requeued: number;
  purgedResults: number;
}

export interface Supervisor {
  /** Start-up checks, one lease recovery, then the polling loop. */
  start(): Promise<void>;
  /** Aborts running jobs, records them, and resolves when nothing is running. */
  stop(): Promise<void>;
  /**
   * One deterministic step: claims queued jobs up to the free capacity and starts them.
   * Resolves with the ids of the jobs it started, without waiting for them to finish.
   */
  tick(): Promise<string[]>;
  /** Lease recovery and result purge, once. */
  maintenance(): Promise<MaintenanceReport>;
  /** Resolves when no job is running. */
  idle(): Promise<void>;
  /** Ids of the jobs running now. */
  runningJobIds(): string[];
  readonly workerId: string;
}

interface RunningJob {
  job: ExecutionJob;
  stop(reason: StopReason): void;
  done: Promise<void>;
}

export function createSupervisor(deps: SupervisorDeps): Supervisor {
  const settings = resolveSupervisorSettings(deps.settings);
  const clock = deps.clock ?? (() => new Date());
  const { repos, runner, vault, adapters, logger } = deps;
  const running = new Map<string, RunningJob>();

  let state: 'created' | 'running' | 'stopping' | 'stopped' = 'created';
  let loopTimer: NodeJS.Timeout | undefined;
  let ticking: Promise<string[]> | null = null;
  let maintaining: Promise<MaintenanceReport> | null = null;
  let lastMaintenanceMs = 0;
  let vaultState: 'unknown' | 'ready' | 'unreachable' | 'refused' = 'unknown';

  async function checkStartUp(): Promise<void> {
    try {
      await repos.jobs.getInternal(randomUUID());
    } catch {
      throw new SupervisorStartError('refusing to start: the database did not answer');
    }
    try {
      await vault.check();
      vaultState = 'ready';
    } catch (error) {
      if (error instanceof VaultStartupRefusal) {
        // The vault answered and is wrong for this worker: a configuration error.
        throw new SupervisorStartError(`refusing to start: ${error.message}`);
      }
      // The vault did not answer: start, claim nothing while it is down (P3-11, ADR-014 section 9)
      // and check again before every claim.
      vaultState = 'unreachable';
      logger.warn(errorFacts(error), 'the vault did not answer; no job is claimed until it does');
    }
    try {
      await runner.selfCheck();
    } catch (error) {
      // The sandbox's own reason text, from trusted supervisor-side code; capped.
      const reason = error instanceof Error ? error.message.slice(0, 300) : 'unknown reason';
      throw new SupervisorStartError(`refusing to start: the sandbox self-check failed: ${reason}`);
    }
  }

  /** Starts a handler for a claimed job. False when one for the same id is still winding down. */
  function launch(job: ExecutionJob): boolean {
    const stale = running.get(job.id);
    if (stale !== undefined) {
      // The same job id was claimed again while an earlier attempt's handler is still winding
      // down (its lease was lost and recovery requeued it). Stop the old one and do not start a
      // second handler for the id: the new claim's lease runs out and recovery decides again.
      logger.warn({ jobId: job.id }, 'job claimed again while its earlier attempt still runs');
      stale.stop('lease_lost');
      return false;
    }
    const controller = new AbortController();
    let reason: StopReason | null = null;
    const stop = (why: StopReason) => {
      if (reason === null) reason = why;
      controller.abort();
    };

    let lastExtendedMs = Date.now();
    let beating = false;
    const beat = async () => {
      if (beating || controller.signal.aborted) return;
      beating = true;
      try {
        const held = await repos.jobs.extendLease(
          job.id,
          settings.workerId,
          settings.leaseMs,
          clock(),
          // This attempt only: a stale handler of an earlier attempt must not keep a later one's
          // lease alive (same worker id, requeued and claimed again).
          job.attemptCount,
        );
        if (!held) {
          logger.warn({ jobId: job.id }, 'job lease lost; aborting');
          stop('lease_lost');
          return;
        }
        lastExtendedMs = Date.now();
        const fresh = await repos.jobs.getInternal(job.id);
        const target = await repos.connections.getForExecution(job.connectionId);
        if (
          (fresh !== null && fresh.cancelRequestedAt !== null) ||
          target === null ||
          target.connection.status === 'revoked'
        ) {
          logger.info({ jobId: job.id }, 'cancellation requested; aborting job');
          stop('cancelled');
        }
      } catch (error) {
        logger.warn({ jobId: job.id, ...errorFacts(error) }, 'heartbeat failed');
        if (Date.now() - lastExtendedMs >= settings.leaseMs) stop('lease_lost');
      } finally {
        beating = false;
      }
    };
    const heartbeat = setInterval(() => void beat(), settings.heartbeatMs);

    const ctx: JobContext = {
      repos,
      runner,
      vault,
      adapters,
      clock,
      logger,
      settings,
      job,
      signal: controller.signal,
      stopReason: () => reason,
      startedAtMs: Date.now(),
    };

    logger.info({ jobId: job.id, kind: job.kind, attempt: job.attemptCount }, 'job claimed');
    const done = (async () => {
      try {
        if (job.kind === 'operation') await runOperationJob(ctx);
        else await runLoginJob(ctx);
      } catch (error) {
        // The job stays `running` until its lease expires and recovery ends it.
        logger.error({ jobId: job.id, ...errorFacts(error) }, 'job handler failed');
      } finally {
        clearInterval(heartbeat);
        // Only this claim's own entry: a stale handler must not remove a newer one.
        if (running.get(job.id)?.job === job) running.delete(job.id);
        if (state === 'running') setImmediate(() => void tick());
      }
    })();
    running.set(job.id, { job, stop, done });
    return true;
  }

  /** Checks the vault before a claim; logs only when its state changes. */
  async function vaultReady(): Promise<boolean> {
    try {
      await vault.check();
      if (vaultState !== 'ready') logger.info('the vault answers; claiming jobs');
      vaultState = 'ready';
      return true;
    } catch (error) {
      const next = error instanceof VaultStartupRefusal ? 'refused' : 'unreachable';
      if (vaultState !== next) {
        if (error instanceof VaultStartupRefusal) {
          logger.error({ reason: error.message }, 'the vault is misconfigured; no job is claimed');
        } else {
          logger.warn(
            {
              ...errorFacts(error),
              ...(error instanceof VaultCallError ? { vaultCode: error.code } : {}),
            },
            'the vault is unreachable; no job is claimed',
          );
        }
      }
      vaultState = next;
      return false;
    }
  }

  function tick(): Promise<string[]> {
    if (ticking !== null) return ticking;
    ticking = (async () => {
      const started: string[] = [];
      while ((state === 'created' || state === 'running') && running.size < settings.concurrency) {
        // P3-11: no claim while the vault is unreachable or is not what this worker may use.
        if (!(await vaultReady())) break;
        let job: ExecutionJob | null;
        try {
          job = await repos.jobs.claimNext({
            workerId: settings.workerId,
            leaseMs: settings.leaseMs,
            now: clock(),
            // Phase 3: only a job the API authorized with the vault (`capability_ref`) is claimed.
            requireCapability: true,
          });
        } catch (error) {
          logger.error(errorFacts(error), 'claiming a job failed');
          break;
        }
        if (job === null) break;
        if (launch(job)) started.push(job.id);
      }
      return started;
    })().finally(() => {
      ticking = null;
    });
    return ticking;
  }

  async function runMaintenance(): Promise<MaintenanceReport> {
    const now = clock();
    const report: MaintenanceReport = { recovered: 0, requeued: 0, purgedResults: 0 };
    try {
      const changed = await repos.jobs.recoverExpiredLeases({
        now,
        maxAttempts: settings.maxAttempts,
        // Phase 3: a job whose token was issued may have been read; only never-issued
        // capabilities are requeued (ADR-014 section 6).
        capabilityAware: true,
      });
      for (const job of changed) {
        if (job.status === 'queued') {
          report.requeued += 1;
          logger.info({ jobId: job.id }, 'expired lease: job requeued');
          continue;
        }
        report.recovered += 1;
        try {
          await repos.transaction(async (tx) => {
            let moved = false;
            if (job.kind === 'login') {
              moved = await transitionIfAllowed(
                tx,
                job.connectionId,
                'authentication_required',
                LOGIN_LEASE_EXPIRED_REASON,
              );
            }
            await auditAsWorker(tx, job, now, {
              eventType: job.kind === 'login' ? 'connection.auth_failed' : 'operation.failed',
              metadata: {
                jobId: job.id,
                operation: job.operation,
                status: job.status,
                errorCode: job.error?.code ?? null,
                attempt: job.attemptCount,
                recovered: true,
                ...(job.kind === 'login'
                  ? { connectionId: job.connectionId, connectionReset: moved }
                  : {}),
              },
            });
          });
        } catch (error) {
          logger.error(
            { jobId: job.id, ...errorFacts(error) },
            'recovered job could not be audited',
          );
        }
        logger.warn({ jobId: job.id, status: job.status }, 'expired lease: job ended');
      }
    } catch (error) {
      logger.error(errorFacts(error), 'lease recovery failed');
    }
    try {
      report.purgedResults = await repos.jobs.purgeResults(
        new Date(now.getTime() - settings.resultTtlMinutes * 60_000),
        now,
      );
      if (report.purgedResults > 0) {
        logger.info({ purged: report.purgedResults }, 'expired job results purged');
      }
    } catch (error) {
      logger.error(errorFacts(error), 'result purge failed');
    }
    lastMaintenanceMs = Date.now();
    return report;
  }

  function maintenance(): Promise<MaintenanceReport> {
    if (maintaining !== null) return maintaining;
    maintaining = runMaintenance().finally(() => {
      maintaining = null;
    });
    return maintaining;
  }

  async function idle(): Promise<void> {
    while (running.size > 0) {
      await Promise.all([...running.values()].map((entry) => entry.done));
    }
  }

  return {
    workerId: settings.workerId,

    async start() {
      if (state !== 'created') throw new SupervisorStartError('the supervisor was already started');
      await checkStartUp();
      await maintenance();
      state = 'running';
      loopTimer = setInterval(() => {
        if (state !== 'running') return;
        void tick();
        if (Date.now() - lastMaintenanceMs >= settings.maintenanceIntervalMs) void maintenance();
      }, settings.pollIntervalMs);
      logger.info(
        { workerId: settings.workerId, sandbox: runner.sandbox, concurrency: settings.concurrency },
        'supervisor started',
      );
      void tick();
    },

    async stop() {
      if (state === 'stopped') return;
      state = 'stopping';
      clearInterval(loopTimer);
      await ticking?.catch(() => undefined);
      for (const entry of running.values()) entry.stop('shutdown');
      await idle();
      await maintaining?.catch(() => undefined);
      state = 'stopped';
      logger.info({ workerId: settings.workerId }, 'supervisor stopped');
    },

    tick,
    maintenance,
    idle,
    runningJobIds: () => [...running.keys()],
  };
}
