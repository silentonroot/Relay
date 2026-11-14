import { createDatabase, createRepositories } from '@aab/database';
import type { DatabaseHandle } from '@aab/database';
import type { Logger } from 'pino';
import { loadAdapterRegistry } from './adapter-registry.js';
import { ConfigError, loadWorkerConfig } from './config.js';
import { createLogger } from './logging.js';
import {
  createJobRunner,
  displayFromEnvironment,
  resolveJobRunnerConfig,
} from './sandbox/index.js';
import { loadLocalKek } from './session-store/index.js';
import { createSupervisor, SupervisorStartError } from './supervisor/index.js';
import { errorFacts } from './supervisor/context.js';

/*
 * Browser worker entry point: `node --import tsx src/main.ts`. Builds the supervisor, starts
 * it, and stops it gracefully on SIGINT or SIGTERM. Exits non-zero when start-up fails.
 * Database migrations are the API's job; the worker expects a migrated database.
 */

function fail(message: string): never {
  process.stderr.write(`browser-worker: ${message}\n`);
  process.exit(1);
}

async function main(): Promise<void> {
  let config;
  try {
    config = loadWorkerConfig(process.env);
  } catch (error) {
    if (error instanceof ConfigError) fail(error.message);
    throw error;
  }
  const logger: Logger = createLogger(config.logLevel);

  let database: DatabaseHandle | null = null;
  try {
    const kek = await loadLocalKek(config.kekDir);
    const runnerConfig = resolveJobRunnerConfig({
      sandbox: config.sandbox,
      ...(config.runtimeDir === undefined ? {} : { runtimeBaseDir: config.runtimeDir }),
      ...(config.chromiumPath === undefined ? {} : { chromiumPath: config.chromiumPath }),
      ...(config.dockerImage === undefined ? {} : { docker: { image: config.dockerImage } }),
      display: displayFromEnvironment(process.env),
      logger,
      // Origin, decision and reason code only, at debug level.
      onEgressDecision: (event) =>
        logger.debug(
          {
            jobId: event.jobId,
            origin: event.origin,
            decision: event.decision,
            reason: event.reason,
          },
          'egress decision',
        ),
      // No onRunnerStderr: runner stderr is hostile and never reaches this log.
    });
    const adapters = await loadAdapterRegistry(runnerConfig.adapterRegistryModule);
    const runner = createJobRunner(runnerConfig);
    database = createDatabase({
      connectionString: config.databaseUrl,
      maxConnections: config.concurrency * 2 + 2,
      onPoolError: (error) => logger.error(errorFacts(error), 'idle database connection failed'),
    });
    const db = database;
    const supervisor = createSupervisor({
      repos: createRepositories(db.db),
      runner,
      kek,
      adapters,
      logger,
      settings: {
        concurrency: config.concurrency,
        pollIntervalMs: config.pollIntervalMs,
        leaseMs: config.leaseMs,
        resultTtlMinutes: config.resultTtlMinutes,
      },
    });
    await supervisor.start();

    let stopping = false;
    const shutdown = (signal: string) => {
      if (stopping) {
        logger.warn({ signal }, 'second signal; exiting without waiting');
        process.exit(1);
      }
      stopping = true;
      logger.info({ signal }, 'stopping');
      void supervisor
        .stop()
        .then(() => db.close())
        .then(
          () => process.exit(0),
          (error: unknown) => {
            logger.error(errorFacts(error), 'shutdown failed');
            process.exit(1);
          },
        );
    };
    process.once('SIGINT', () => shutdown('SIGINT'));
    process.once('SIGTERM', () => shutdown('SIGTERM'));
  } catch (error) {
    await database?.close().catch(() => undefined);
    // Start-up and key-store errors carry fixed, secret-free messages; anything else is
    // reported by type only.
    const message =
      error instanceof SupervisorStartError ||
      (error instanceof Error && error.name === 'KekStoreError')
        ? error.message
        : `start-up failed (${errorFacts(error).errorType})`;
    logger.fatal(errorFacts(error), message);
    fail(message);
  }
}

void main();
