import process from 'node:process';
import { createDatabase } from '@aab/database';
import type { DatabaseHandle } from '@aab/database';
import type { FastifyInstance } from 'fastify';
import { buildApp } from './app.js';
import { createVaultGateway, VaultStartupRefusal } from './vault/gateway.js';
import { verifyVaultAtStart } from './vault/startup.js';
import { ConfigError, loadConfig, requireVaultSocket } from './config.js';

/*
 * Service entry point. Configuration problems stop the process before it binds a port, with a
 * message that names variables but never prints their values. Structured logging takes over
 * once the app exists; until then, plain lines go to stderr.
 */

const SHUTDOWN_TIMEOUT_MS = 10_000;

function fail(message: string): never {
  process.stderr.write(`broker-api: ${message}\n`);
  process.exit(1);
}

async function main(): Promise<void> {
  let config;
  try {
    config = loadConfig(process.env);
  } catch (error) {
    if (error instanceof ConfigError) fail(error.message);
    throw error;
  }

  if (config.kekDir !== undefined) {
    // The API never holds key material: only the vault reads the key directory (ADR-014 section
    // 3). Refusing to start makes a shared or copied environment visible instead of leaving the
    // key path lying around in a process that must not use it.
    fail(
      'AAB_KEK_DIR must not be set for the API. Only the vault reads key material; ' +
        'remove the variable from the API environment.',
    );
  }

  let vaultSocket: string;
  try {
    vaultSocket = requireVaultSocket(config);
  } catch (error) {
    if (error instanceof ConfigError) fail(error.message);
    throw error;
  }

  // ADR-014 section 3: ask the vault who it is before this process serves anything. A vault that
  // answers and is wrong for this API (another role, another isolation mode, a key directory this
  // user can open in separate-uid mode) stops the start; a vault that does not answer does not
  // (revocation works without it, and every job fails closed), and the check repeats before any
  // capability is authorized.
  const vault = createVaultGateway({
    socketPath: vaultSocket,
    isolation: config.vaultIsolation,
    timeoutMs: config.vaultCallTimeoutMs,
    // One error line when the vault turns out to be wrong for this API (also after start).
    onRefused: (reason) =>
      process.stderr.write(
        `${JSON.stringify({ level: 'error', msg: 'the vault is not usable by this API', reason })}\n`,
      ),
  });
  let vaultStart;
  try {
    vaultStart = await verifyVaultAtStart(vault);
  } catch (error) {
    if (error instanceof VaultStartupRefusal) fail(error.message);
    throw error;
  }

  // The pool exists before the app (and its logger) does, so the handler looks the app up late.
  const holder: { app?: FastifyInstance } = {};
  const database: DatabaseHandle = createDatabase({
    connectionString: config.databaseUrl,
    onPoolError: (error) =>
      holder.app?.log.error({ err: error }, 'idle database connection failed'),
  });
  const app = await buildApp({ database, config, vault });
  holder.app = app;
  if (vaultStart.state === 'unreachable') {
    app.log.warn(
      { code: vaultStart.code },
      'the vault did not answer at start; starting degraded: jobs fail with vault_unavailable ' +
        'until it does, and revocation still works',
    );
  }

  let shuttingDown = false;
  const shutdown = (signal: string) => {
    if (shuttingDown) {
      app.log.warn({ signal }, 'second signal received; exiting immediately');
      process.exit(1);
    }
    shuttingDown = true;
    app.log.info({ signal }, 'shutting down');
    const forced = setTimeout(() => {
      app.log.error('shutdown timed out; exiting');
      process.exit(1);
    }, SHUTDOWN_TIMEOUT_MS);
    forced.unref();
    void (async () => {
      try {
        await app.close();
        await database.close();
        process.exit(0);
      } catch (error) {
        app.log.error({ err: error }, 'shutdown failed');
        process.exit(1);
      }
    })();
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));

  await app.listen({ host: config.host, port: config.port });
}

main().catch((error: unknown) => {
  fail(`startup failed: ${error instanceof Error ? error.message : 'unknown error'}`);
});
