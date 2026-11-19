import { resolve } from 'node:path';
import { VAULT_ROLES } from '@aab/contracts';
import type { VaultRole } from '@aab/contracts';
import { createDatabase, createRepositories, withTransactionTimeouts } from '@aab/database';
import type { DatabaseHandle } from '@aab/database';
import type { Logger } from 'pino';
import type { VaultConfig } from './config.js';
import type { VaultHandlers } from './handlers.js';
import { VaultKeys } from './keys.js';
import { createLogger } from './logging.js';
import { createHandlers, newCounters } from './operations.js';
import type { OperationDeps } from './operations.js';
import { createRefusalAuditor } from './refusals.js';
import { currentTimeouts } from './request-scope.js';
import { createRoleServer, defaultLimits } from './server.js';
import type { RequestRefusedEvent, RoleServer, RoleServerLimits } from './server.js';
import {
  finalizeSocket,
  prepareSocketDirectories,
  removeOwnSocket,
  SocketSafetyError,
} from './socket-safety.js';
import type { RolePaths, SocketSafetyDeps } from './socket-safety.js';

export interface StartVaultOptions {
  /** Defaults to a logger at `config.logLevel` writing to stdout. */
  logger?: Logger;
  /** Platform, uid and repository root checks; injected by tests. */
  safety?: SocketSafetyDeps;
  /**
   * Replaces the real operations (protocol tests use `DEFAULT_HANDLERS`, which never touches a
   * database). Without it the vault connects to the database and serves the real operations.
   */
  handlers?: VaultHandlers;
  /** An already open database (tests, PGlite). Without it the vault opens `DATABASE_URL`. */
  database?: DatabaseHandle;
  /** Test seams for the real operations (clock, crash simulation). */
  operations?: Pick<
    OperationDeps,
    'clock' | 'afterRewrapRow' | 'rewrapMaxRowsPerCall' | 'rejectionsPerWindow'
  >;
  /** Overrides the limits derived from the configuration (tests). */
  limits?: Partial<Record<VaultRole, Partial<RoleServerLimits>>>;
  onRequestRefused?: (event: RequestRefusedEvent) => void;
}

export interface RunningVault {
  /** In-memory counters `status` reports (rejections that could not be put on a chain, ...). */
  readonly sockets: Readonly<Record<VaultRole, string>>;
  readonly servers: Readonly<Record<VaultRole, RoleServer>>;
  readonly keys: VaultKeys;
  stop(): Promise<void>;
}

/** The repository this code lives in; a socket directory below it is refused. */
const DEFAULT_REPOSITORY_ROOT = resolve(import.meta.dirname, '..', '..', '..');

type RequestRefusedHook = (event: RequestRefusedEvent) => Promise<void>;

export class VaultStartError extends Error {
  override readonly name = 'VaultStartError';
}

/**
 * Starts the vault: checks the platform and the socket directories, loads the KEKs, derives
 * the MAC keys, then listens on one Unix socket per role. Fails closed: any problem throws
 * before the first socket is reachable by a caller, with a message that names a setting or a
 * path and never a value.
 */
export async function startVault(
  config: VaultConfig,
  options: StartVaultOptions = {},
): Promise<RunningVault> {
  const logger = options.logger ?? createLogger(config.logLevel);
  const safety: SocketSafetyDeps = {
    repositoryRoot: DEFAULT_REPOSITORY_ROOT,
    ...options.safety,
  };

  // Directories first: the cheapest refusals (platform, symlinks, permissions) come before
  // any key is read.
  const paths = await prepareSocketDirectories(config, safety);
  const keys = await VaultKeys.load(config.kekDir);

  if (config.isolation === 'shared-uid') {
    // ADR-014 section 2: nothing protects against code running as this user.
    logger.warn(
      { isolation: 'shared-uid' },
      'shared-uid isolation: every role socket and the key directory belong to one user; ' +
        'any process of that user can call any operation and read the key files',
    );
  }

  // The database, fail closed: the vault refuses to start when it cannot read its own tables.
  let database: DatabaseHandle | undefined;
  let ownsDatabase = false;
  let handlers = options.handlers;
  let onRefused: RequestRefusedHook | undefined;
  const counters = newCounters();
  if (handlers === undefined) {
    if (options.database === undefined) {
      database = createDatabase({
        connectionString: config.databaseUrl,
        maxConnections: 10,
        onPoolError: (error) => logger.error({ errorType: error.name }, 'database pool error'),
      });
      ownsDatabase = true;
    } else {
      database = options.database;
    }
    // Every transaction of a request runs under SET LOCAL statement_timeout / lock_timeout below
    // the role's request timeout (src/request-scope.ts).
    const repositories = createRepositories(withTransactionTimeouts(database.db, currentTimeouts));
    try {
      await repositories.vault.countByKekVersion();
    } catch {
      if (ownsDatabase) await database.close().catch(() => undefined);
      throw new VaultStartError(
        'cannot read the database (DATABASE_URL); the vault refuses to start',
      );
    }
    handlers = createHandlers({
      repositories,
      keys,
      logger,
      counters,
      ...options.operations,
    });
    onRefused = createRefusalAuditor({
      repositories,
      logger,
      counters,
      ...(options.operations?.clock === undefined ? {} : { clock: options.operations.clock }),
    });
  }
  const servers = {} as Record<VaultRole, RoleServer>;
  const sockets = {} as Record<VaultRole, string>;
  const started: Array<{ server: RoleServer; path: RolePaths }> = [];

  const stop = async (): Promise<void> => {
    for (const { server, path } of started.splice(0)) {
      await server.close();
      await removeOwnSocket(path.socket, safety.uid);
    }
    if (ownsDatabase && database !== undefined) {
      const handle = database;
      database = undefined;
      await handle.close().catch(() => undefined);
    }
  };

  try {
    for (const path of paths) {
      const role = path.role;
      const server = createRoleServer({
        role,
        limits: { ...defaultLimits(role, config), ...options.limits?.[role] },
        context: { role, isolation: config.isolation, keys, logger },
        handlers,
        logger,
        onRequestRefused: async (event) => {
          await onRefused?.(event);
          await options.onRequestRefused?.(event);
        },
      });
      started.push({ server, path });
      await new Promise<void>((resolve, reject) => {
        server.server.once('error', reject);
        // A filesystem path only: the vault never listens on TCP (P3-3).
        server.server.listen({ path: path.socket }, () => {
          server.server.off('error', reject);
          resolve();
        });
      });
      await finalizeSocket(path, config, safety);
      servers[role] = server;
      sockets[role] = path.socket;
      logger.info({ role, isolation: config.isolation }, 'vault listening');
    }
  } catch (error) {
    await stop();
    if (error instanceof SocketSafetyError) throw error;
    throw new VaultStartError('cannot listen on a vault socket');
  }

  if (VAULT_ROLES.some((role) => servers[role] === undefined)) {
    await stop();
    throw new VaultStartError('not every role socket is listening');
  }
  return { sockets, servers, keys, stop };
}
