import { randomUUID } from 'node:crypto';
import { connect } from 'node:net';
import { VAULT_OPERATION_SCHEMAS, VaultResponse } from '@aab/contracts';
import type {
  VaultErrorCode,
  VaultOperation,
  VaultParams,
  VaultResult,
  VaultRole,
} from '@aab/contracts';

/*
 * A caller's client for the vault's line protocol (ADR-014 sections 1, 4 and 9): one Unix socket
 * connection per request, one request line, one response line, a timeout over the whole
 * exchange. Nothing here imports key material or crypto: a caller of the vault never holds a key.
 *
 * Every failure is one of two kinds, so a caller can fail closed without reading the vault's
 * reasons:
 *
 *   `unavailable`  the vault could not be reached or did not give a usable answer: connect
 *                  refused, timeout, a closed connection, a malformed or oversize reply, or
 *                  the vault's own `service_unavailable` / `internal_error` / `not_implemented`.
 *   `denied`       the vault answered and refused: `forbidden` and every other refusal
 *                  (`not_found`, `validation_failed`, `conflict`, `malformed`), and a request
 *                  this client would not send because it fails the contracts schema.
 *
 * The error carries a short code and the kind, never a message from the peer, and never any
 * value from the request (a token or a plaintext must not reach a log through an error).
 */

/** ADR-014 section 9: five seconds per request. */
export const DEFAULT_REQUEST_TIMEOUT_MS = 5_000;
/** Largest response line accepted: the supervisor's 2 MiB plaintext, base64url encoded, fits. */
export const DEFAULT_MAX_RESPONSE_BYTES = 4 * 1024 * 1024;

export type VaultCallKind = 'unavailable' | 'denied';

export type VaultCallErrorCode =
  /** The request did not complete in time. */
  | 'timeout'
  /** Connecting failed (no socket, refused, no permission). */
  | 'unreachable'
  /** The connection closed before a full response line arrived. */
  | 'closed'
  /** The reply was not a valid response, did not match the request, or failed its schema. */
  | 'bad_response'
  /** The reply line was longer than the cap. */
  | 'oversize'
  /** The request failed the contracts schema; nothing was sent. */
  | 'invalid_request'
  /** An error code the vault answered with. */
  | VaultErrorCode;

const UNAVAILABLE_VAULT_CODES: ReadonlySet<string> = new Set([
  'service_unavailable',
  'internal_error',
  'not_implemented',
]);

export class VaultCallError extends Error {
  override readonly name = 'VaultCallError';
  constructor(
    readonly kind: VaultCallKind,
    readonly code: VaultCallErrorCode,
  ) {
    super(`vault call failed: ${kind} (${code})`);
  }
}

const unavailable = (code: VaultCallErrorCode) => new VaultCallError('unavailable', code);

/** Where a role's socket lives under the vault's socket directory (ADR-014 section 1). */
export function vaultSocketPath(socketDir: string, role: VaultRole): string {
  return `${socketDir}/${role}/vault.sock`;
}

export interface VaultClientOptions {
  /** Absolute path of the socket of the caller's role. */
  socketPath: string;
  /** Over the whole exchange, connect included. Default 5 seconds. */
  timeoutMs?: number;
  /** Longest response line accepted, in bytes. Default 4 MiB. */
  maxResponseBytes?: number;
}

export interface VaultClient {
  call<Op extends VaultOperation>(operation: Op, params: VaultParams<Op>): Promise<VaultResult<Op>>;
}

export function createVaultClient(options: VaultClientOptions): VaultClient {
  const timeoutMs = options.timeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
  const maxBytes = options.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1) {
    throw new RangeError('timeoutMs must be a positive integer');
  }
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1) {
    throw new RangeError('maxResponseBytes must be a positive integer');
  }

  return {
    call<Op extends VaultOperation>(operation: Op, params: VaultParams<Op>) {
      const schemas = VAULT_OPERATION_SCHEMAS[operation];
      const checked = schemas.params.safeParse(params);
      if (!checked.success) {
        return Promise.reject(new VaultCallError('denied', 'invalid_request'));
      }
      const id = `c-${randomUUID()}`;
      const line = `${JSON.stringify({ id, operation, params: checked.data })}\n`;

      return new Promise<VaultResult<Op>>((resolve, reject) => {
        const socket = connect(options.socketPath);
        const chunks: Buffer[] = [];
        let received = 0;
        let settled = false;

        const finish = (outcome: () => void) => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          socket.destroy();
          outcome();
        };
        const fail = (error: VaultCallError) => finish(() => reject(error));
        const timer = setTimeout(() => fail(unavailable('timeout')), timeoutMs);

        socket.on('connect', () => socket.write(line));
        socket.on('data', (chunk: Buffer) => {
          if (settled) return;
          const newline = chunk.indexOf(0x0a);
          const taken = newline === -1 ? chunk.length : newline;
          received += taken;
          if (received > maxBytes) return fail(unavailable('oversize'));
          chunks.push(newline === -1 ? chunk : chunk.subarray(0, newline));
          if (newline === -1) return;
          finish(() => {
            try {
              resolve(interpret(Buffer.concat(chunks).toString('utf8'), id, operation));
            } catch (error) {
              reject(error instanceof VaultCallError ? error : unavailable('bad_response'));
            }
          });
        });
        socket.on('error', () => fail(unavailable('unreachable')));
        socket.on('close', () => fail(unavailable('closed')));
      });
    },
  };
}

/** Turns one response line into a result, or throws a `VaultCallError`. */
function interpret<Op extends VaultOperation>(
  text: string,
  requestId: string,
  operation: Op,
): VaultResult<Op> {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw unavailable('bad_response');
  }
  const response = VaultResponse.safeParse(value);
  if (!response.success) throw unavailable('bad_response');
  const body = response.data;
  if (!body.ok) {
    // The vault answers an unparseable request with a null id; anything else must echo ours.
    if (body.id !== null && body.id !== requestId) throw unavailable('bad_response');
    const code = body.error.code;
    throw new VaultCallError(UNAVAILABLE_VAULT_CODES.has(code) ? 'unavailable' : 'denied', code);
  }
  if (body.id !== requestId) throw unavailable('bad_response');
  const result = VAULT_OPERATION_SCHEMAS[operation].result.safeParse(body.result);
  if (!result.success) throw unavailable('bad_response');
  return result.data as VaultResult<Op>;
}
