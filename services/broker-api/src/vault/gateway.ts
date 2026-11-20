import { opendir } from 'node:fs/promises';
import { connect } from 'node:net';
import { dirname, join } from 'node:path';
import { VAULT_PROTOCOL_VERSION, VAULT_ROLES } from '@aab/contracts';
import type { VaultIsolation, VaultResult } from '@aab/contracts';
import { createVaultClient, VaultCallError } from '@aab/vault-client';
import type { VaultClient } from '@aab/vault-client';

/*
 * The API's only way to the vault (ADR-014 sections 3, 4 and 9). It speaks as the `api` role (the
 * socket it is given decides that, never a request field), holds no key and imports no crypto.
 *
 * Start-up check (ADR-014 section 3, P3-1): `hello` must answer with role `api` and with the
 * isolation mode this API was configured for, and in `separate-uid` mode the API must not be able
 * to open the vault's key directory. A vault that answers and fails any of those is a
 * misconfiguration and the API refuses to start (`VaultStartupRefusal`). A vault that does not
 * answer is not: ADR-014 section 7 says revocation must keep working while the vault is down and
 * section 9 fails each job closed, so the API starts degraded and every authorization first
 * (re-)runs the same check. No capability is ever authorized through an unchecked vault.
 */

/** The vault answered and is not what this API may use. The message names settings and paths, never values. */
export class VaultStartupRefusal extends Error {
  override readonly name = 'VaultStartupRefusal';
}

export type VaultGatewayState = 'unverified' | 'ready' | 'refused';

export interface VaultGateway {
  readonly isolation: VaultIsolation;
  state(): VaultGatewayState;
  /**
   * Runs the start-up check if it has not passed yet. Resolves when the vault is verified;
   * throws a `VaultCallError` (`unavailable`) when it cannot be reached, and a
   * `VaultStartupRefusal` when it is misconfigured (and from then on, every time).
   */
  verify(): Promise<void>;
  /** Stage 1 of a capability (ADR-014 section 5). Verifies first. */
  authorizeJobAccess(jobId: string, ttlSeconds: number): Promise<VaultResult<'authorizeJobAccess'>>;
  /** The vault's `status` for the owner's dashboard (the api role may call it). Verifies first. */
  status(): Promise<VaultResult<'status'>>;
}

export interface VaultGatewayOptions {
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
  /** Told once when the vault turns out to be wrong for this API (a refusal is permanent). */
  onRefused?: (reason: string) => void;
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

export function createVaultGateway(options: VaultGatewayOptions): VaultGateway {
  const client =
    options.client ??
    createVaultClient({
      socketPath: options.socketPath,
      ...(options.timeoutMs === undefined ? {} : { timeoutMs: options.timeoutMs }),
    });
  const probe = options.canOpenDirectory ?? canOpenDirectory;
  const canConnectTo = options.canConnect ?? canConnectSocket;
  let state: VaultGatewayState = 'unverified';
  let refusal: VaultStartupRefusal | null = null;
  let inFlight: Promise<void> | null = null;

  async function check(): Promise<void> {
    const hello = await client.call('hello', { protocolVersion: VAULT_PROTOCOL_VERSION });
    if (hello.role !== 'api') {
      throw new VaultStartupRefusal(
        'AAB_VAULT_SOCKET: the vault answered as a role other than api; ' +
          'point it at the api-role socket',
      );
    }
    if (hello.isolation !== options.isolation) {
      throw new VaultStartupRefusal(
        'AAB_VAULT_ISOLATION: does not match the isolation mode the vault reports',
      );
    }
    if (options.isolation === 'separate-uid' && (await probe(hello.keyDirectory))) {
      throw new VaultStartupRefusal(
        `the API can open the vault's key directory (${hello.keyDirectory}); in separate-uid ` +
          'mode it must run as a user that cannot read it',
      );
    }
    if (options.isolation === 'separate-uid') {
      // Sockets of the other roles sit beside ours (`<root>/<role>/vault.sock`). In separate-uid
      // mode the kernel keeps this user out of them; if one accepts a connection the groups are
      // wrong (B3 review L1).
      const root = dirname(dirname(options.socketPath));
      for (const role of VAULT_ROLES) {
        if (role === 'api') continue;
        const other = join(root, role, 'vault.sock');
        if (await canConnectTo(other)) {
          throw new VaultStartupRefusal(
            `the API can connect to the ${role}-role socket (${other}); in separate-uid mode ` +
              'it must be in the api group only',
          );
        }
      }
    }
  }

  async function verify(): Promise<void> {
    if (state === 'ready') return;
    if (refusal !== null) throw refusal;
    inFlight ??= check()
      .then(() => {
        state = 'ready';
      })
      .catch((error: unknown) => {
        if (error instanceof VaultStartupRefusal) {
          state = 'refused';
          refusal = error;
          options.onRefused?.(error.message);
        }
        throw error;
      })
      .finally(() => {
        inFlight = null;
      });
    return inFlight;
  }

  return {
    isolation: options.isolation,
    state: () => state,
    verify,
    async authorizeJobAccess(jobId, ttlSeconds) {
      await verify();
      return client.call('authorizeJobAccess', { jobId, ttlSeconds });
    },
    async status() {
      await verify();
      return client.call('status', {});
    },
  };
}

/** How a failed vault call ends a job (ADR-014 section 9). Anything unrecognized fails closed as unavailable. */
export function failureCodeFor(error: unknown): 'vault_unavailable' | 'vault_denied' {
  return error instanceof VaultCallError && error.kind === 'denied'
    ? 'vault_denied'
    : 'vault_unavailable';
}
