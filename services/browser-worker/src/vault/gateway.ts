import { opendir } from 'node:fs/promises';
import { connect } from 'node:net';
import { dirname, join } from 'node:path';
import { VAULT_PROTOCOL_VERSION, VAULT_ROLES } from '@aab/contracts';
import type { VaultIsolation, VaultOperation, VaultParams, VaultResult } from '@aab/contracts';
import { createVaultClient, VaultCallError } from '@aab/vault-client';
import type { VaultClient } from '@aab/vault-client';
import type { JobErrorCode } from '@aab/contracts';

/*
 * The supervisor's only way to the vault (ADR-014 sections 3, 4 and 9). It speaks as the
 * `supervisor` role (the socket it is given decides that, never a request field), holds no key
 * and imports no crypto (P3-1).
 *
 * Start-up and per-claim check (ADR-014 section 3): `hello` must answer with role `supervisor`
 * and with the isolation mode this worker was configured for, and in `separate-uid` mode the
 * supervisor must not be able to open the vault's key directory. A vault that answers and fails
 * any of those is a misconfiguration (`VaultStartupRefusal`). A vault that does not answer is
 * not: the supervisor starts, claims nothing while it is down (P3-11) and checks again before
 * every claim. A job is never claimed through an unchecked vault.
 *
 * This mirrors `services/broker-api/src/vault/gateway.ts`, with the supervisor's role.
 */

/** The vault answered and is not what this supervisor may use. The message names settings and paths, never values. */
export class VaultStartupRefusal extends Error {
  override readonly name = 'VaultStartupRefusal';
}

export interface SupervisorVault {
  readonly isolation: VaultIsolation;
  /**
   * Asks `hello` and verifies role, isolation and (in `separate-uid`) that the key directory
   * cannot be opened. Throws `VaultCallError` (`unavailable`) when the vault cannot be reached,
   * and `VaultStartupRefusal` when it is misconfigured.
   */
  check(): Promise<void>;
  call<Op extends VaultOperation>(operation: Op, params: VaultParams<Op>): Promise<VaultResult<Op>>;
}

export interface SupervisorVaultOptions {
  /** Absolute path of the supervisor-role socket (`AAB_VAULT_SOCKET`). */
  socketPath: string;
  /** What the operator configured (`AAB_VAULT_ISOLATION`); the vault's `hello` must agree. */
  isolation: VaultIsolation;
  timeoutMs?: number;
  /** Replaces the client, for tests. */
  client?: VaultClient;
  /** Replaces the directory probe, for tests: true when the directory can be opened for reading. */
  canOpenDirectory?: (path: string) => Promise<boolean>;
  /** Replaces the socket probe, for tests: true when a connection to the socket succeeds. */
  canConnect?: (path: string) => Promise<boolean>;
}

/** Opens the directory for reading, the way the vault's own user would, and closes it again. */
export async function canOpenDirectory(path: string): Promise<boolean> {
  try {
    const directory = await opendir(path);
    await directory.close();
    return true;
  } catch {
    return false;
  }
}

/** Tries to connect to a Unix socket; true when it accepts, false on any error or after a second. */
export function canConnectSocket(path: string): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = connect(path);
    const done = (value: boolean) => {
      clearTimeout(timer);
      socket.destroy();
      resolve(value);
    };
    const timer = setTimeout(() => done(false), 1_000);
    socket.once('connect', () => done(true));
    socket.once('error', () => done(false));
  });
}

export function createSupervisorVault(options: SupervisorVaultOptions): SupervisorVault {
  const client =
    options.client ??
    createVaultClient({
      socketPath: options.socketPath,
      ...(options.timeoutMs === undefined ? {} : { timeoutMs: options.timeoutMs }),
    });
  const probe = options.canOpenDirectory ?? canOpenDirectory;
  const canConnectTo = options.canConnect ?? canConnectSocket;

  return {
    isolation: options.isolation,
    call: (operation, params) => client.call(operation, params),
    async check() {
      const hello = await client.call('hello', { protocolVersion: VAULT_PROTOCOL_VERSION });
      if (hello.role !== 'supervisor') {
        throw new VaultStartupRefusal(
          'AAB_VAULT_SOCKET: the vault answered as a role other than supervisor; ' +
            'point it at the supervisor-role socket',
        );
      }
      if (hello.isolation !== options.isolation) {
        throw new VaultStartupRefusal(
          'AAB_VAULT_ISOLATION: does not match the isolation mode the vault reports',
        );
      }
      if (options.isolation === 'separate-uid' && (await probe(hello.keyDirectory))) {
        throw new VaultStartupRefusal(
          `the supervisor can open the vault's key directory (${hello.keyDirectory}); in ` +
            'separate-uid mode it must run as a user that cannot read it',
        );
      }
      if (options.isolation === 'separate-uid') {
        // The other roles' sockets sit beside ours (`<root>/<role>/vault.sock`); in separate-uid
        // mode the kernel keeps this user out of them. If one accepts a connection the groups
        // are wrong (B3 review L1).
        const root = dirname(dirname(options.socketPath));
        for (const role of VAULT_ROLES) {
          if (role === 'supervisor') continue;
          const other = join(root, role, 'vault.sock');
          if (await canConnectTo(other)) {
            throw new VaultStartupRefusal(
              `the supervisor can connect to the ${role}-role socket (${other}); in separate-uid ` +
                'mode it must be in the supervisor group only',
            );
          }
        }
      }
    },
  };
}

/** How a failed vault call ends a job (ADR-014 section 9). Anything unrecognized fails closed as unavailable. */
export function failureCodeFor(
  error: unknown,
): Extract<JobErrorCode, 'vault_unavailable' | 'vault_denied'> {
  return error instanceof VaultCallError && error.kind === 'denied'
    ? 'vault_denied'
    : 'vault_unavailable';
}
