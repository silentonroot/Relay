import { KekStoreError } from '@aab/crypto';
import type { Logger } from 'pino';
import { ConfigError, loadVaultConfig } from './config.js';
import { createLogger, errorFacts } from './logging.js';
import { SocketSafetyError } from './socket-safety.js';
import { startVault, VaultStartError } from './vault.js';
import type { RunningVault } from './vault.js';

/*
 * Vault entry point: `node --import tsx src/main.ts`. Validates the configuration, starts
 * the role listeners and stops them on SIGINT or SIGTERM (closing and removing the sockets).
 * Exits non-zero on any start-up problem. The operations are stubs in B2a (`not_implemented`);
 * B2b adds them and the database.
 */

function fail(message: string): never {
  process.stderr.write(`vault: ${message}\n`);
  process.exit(1);
}

async function main(): Promise<void> {
  let config;
  try {
    config = loadVaultConfig(process.env);
  } catch (error) {
    if (error instanceof ConfigError) fail(error.message);
    throw error;
  }
  const logger: Logger = createLogger(config.logLevel);

  // ADR-014 section 2: every socket is created 0660 (0600 in shared-uid) whatever the
  // directory says. The socket code also sets the mode explicitly after listen.
  try {
    process.umask(0o117);
  } catch {
    logger.warn('cannot set the umask; relying on explicit socket modes');
  }

  let vault: RunningVault;
  try {
    vault = await startVault(config, { logger });
  } catch (error) {
    // These error classes carry fixed messages naming a setting or a path, never a value.
    const message =
      error instanceof SocketSafetyError ||
      error instanceof VaultStartError ||
      error instanceof KekStoreError
        ? error.message
        : `start-up failed (${errorFacts(error).errorType})`;
    logger.fatal(errorFacts(error), message);
    fail(message);
  }

  let stopping = false;
  const shutdown = (signal: string) => {
    if (stopping) {
      logger.warn({ signal }, 'second signal; exiting without waiting');
      process.exit(1);
    }
    stopping = true;
    logger.info({ signal }, 'stopping');
    void vault.stop().then(
      () => process.exit(0),
      (error: unknown) => {
        logger.error(errorFacts(error), 'shutdown failed');
        process.exit(1);
      },
    );
  };
  process.once('SIGINT', () => shutdown('SIGINT'));
  process.once('SIGTERM', () => shutdown('SIGTERM'));
}

void main();
