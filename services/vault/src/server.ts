import { createServer } from 'node:net';
import type { Server, Socket } from 'node:net';
import {
  checkPlainJson,
  isOperationAllowedForRole,
  isVaultOperation,
  VAULT_MAX_LINE_BYTES,
  VAULT_MAX_SUPERVISOR_LINE_BYTES,
  VAULT_OPERATION_SCHEMAS,
  VaultRequestEnvelope,
  VaultRequestId,
} from '@aab/contracts';
import type { VaultErrorCode, VaultResponse, VaultRole } from '@aab/contracts';
import type { Logger } from 'pino';
import { errorFacts } from './logging.js';
import { VaultOperationError } from './handlers.js';
import { runWithTimeouts, timeoutsFor } from './request-scope.js';
import type { VaultContext, VaultHandlers } from './handlers.js';

/*
 * One listener per role. The protocol is newline-delimited JSON, one request and one
 * response per line, answered in order. The role of a request is the listener it arrived on:
 * nothing in a request names or selects it (the envelope and every parameter object are
 * strict, so a `role` field is `malformed`). Everything read from a socket is hostile input
 * until it has passed, in this order:
 *
 *   line size cap -> JSON.parse -> checkPlainJson -> strict envelope -> known operation
 *   -> operation allowed for this socket's role -> strict parameters -> handler -> result schema
 *
 * A response is `{ id, ok: true, result }` or `{ id, ok: false, error: { code } }`. An error
 * carries a code and nothing else: no message, no stack, no echo of any request value.
 */

export interface RoleServerLimits {
  /** Open connections allowed on this socket; the next one is answered and closed. */
  maxConnections: number;
  /** A connection with no traffic for this long is closed. */
  idleTimeoutMs: number;
  /** A request line must complete, and be answered, within this long. */
  requestTimeoutMs: number;
  /** Largest request line in bytes, before it is parsed. */
  maxLineBytes: number;
  /** Unsent response bytes above which the connection stops being read until it drains. */
  writeBufferSoftBytes: number;
  /** Unsent response bytes above which the connection is destroyed after `writeGraceMs`. */
  writeBufferHardBytes: number;
  /** How long the unsent bytes may stay above the hard cap. */
  writeGraceMs: number;
  /** How long a connection that stopped draining may stay blocked before it is destroyed. */
  writeStallMs: number;
  /** Complete request lines buffered or being handled per connection; the next one closes it. */
  maxInFlightPerConnection: number;
  /** Handlers (database work) running at once across every connection of this role. */
  maxConcurrentHandlers: number;
  /** An over-cap or aborted connection is destroyed this long after its last line is written. */
  closeGraceMs: number;
}

/** What a refused request tells the audit trail. B2b appends `vault.request_refused` from it. */
export interface RequestRefusedEvent {
  role: VaultRole;
  operation: string;
  /** The caller's request id; a validated short identifier. */
  requestId: string;
  /**
   * The `jobId` of the refused request's params when it is a UUID (unvalidated otherwise: the role
   * check comes before parameter validation). Only a handle for attributing the audit event.
   */
  jobId?: string;
}

export interface RoleServerOptions {
  role: VaultRole;
  limits: RoleServerLimits;
  context: VaultContext;
  handlers: VaultHandlers;
  logger: Logger;
  /**
   * Called for an operation the role may not call, after it is logged as `vault.request_refused`.
   * `startVault` appends the audit event from it (src/refusals.ts).
   */
  onRequestRefused?: (event: RequestRefusedEvent) => void | Promise<void>;
}

export interface RoleServer {
  readonly role: VaultRole;
  readonly server: Server;
  /** Accepted connections. */
  readonly connections: ReadonlySet<Socket>;
  /** Over-cap connections that were answered and are waiting to be closed. */
  readonly refusedConnections: ReadonlySet<Socket>;
  /** Closes the listener and destroys every open connection. */
  close(): Promise<void>;
}

/** Handlers at once per role: the database pool is shared, one role must not exhaust it. */
export const DEFAULT_CONCURRENT_HANDLERS: Readonly<Record<VaultRole, number>> = {
  api: 4,
  supervisor: 8,
  admin: 1,
};

export function defaultLimits(
  role: VaultRole,
  config: {
    maxConnectionsPerRole: number;
    idleTimeoutMs: number;
    requestTimeoutMs: number;
    /** Admin requests (rewrap, status over a big table) get their own, longer timeout. */
    adminRequestTimeoutMs?: number;
  },
): RoleServerLimits {
  return {
    maxConnections: config.maxConnectionsPerRole,
    idleTimeoutMs: config.idleTimeoutMs,
    requestTimeoutMs:
      role === 'admin'
        ? Math.max(config.requestTimeoutMs, config.adminRequestTimeoutMs ?? 0)
        : config.requestTimeoutMs,
    writeBufferSoftBytes: 1024 * 1024,
    writeBufferHardBytes: 4 * 1024 * 1024,
    writeGraceMs: 2_000,
    writeStallMs: 30_000,
    maxInFlightPerConnection: 4,
    maxConcurrentHandlers: DEFAULT_CONCURRENT_HANDLERS[role],
    closeGraceMs: 1_000,
    // Only the supervisor carries a session (completeLogin, readForWorker): ADR-014's 4 MiB.
    maxLineBytes: role === 'supervisor' ? VAULT_MAX_SUPERVISOR_LINE_BYTES : VAULT_MAX_LINE_BYTES,
  };
}

const NEWLINE = 0x0a;
const UUID_TEXT = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function failure(id: string | null, code: VaultErrorCode): VaultResponse {
  return { id, ok: false, error: { code } };
}

/** The request id of a parsed value when it is a well-formed one; never anything else. */
function extractId(value: unknown): string | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return null;
  const id = (value as Record<string, unknown>)['id'];
  const parsed = VaultRequestId.safeParse(id);
  return parsed.success ? parsed.data : null;
}

/** Counting semaphore: waiters are served in order. */
class Slots {
  #free: number;
  readonly #waiters: Array<() => void> = [];
  constructor(size: number) {
    this.#free = Math.max(1, size);
  }
  acquire(): Promise<() => void> {
    const release = () => {
      const next = this.#waiters.shift();
      if (next === undefined) this.#free += 1;
      else next();
    };
    if (this.#free > 0) {
      this.#free -= 1;
      return Promise.resolve(release);
    }
    return new Promise((resolve) => this.#waiters.push(() => resolve(release)));
  }
}

/** One framed unit: a request line, or the end of the connection (after earlier lines are answered). */
type Framed = Buffer | { abort: VaultErrorCode; reason: string };

export function createRoleServer(options: RoleServerOptions): RoleServer {
  const { role, limits, context, handlers, logger } = options;
  const connections = new Set<Socket>();
  const refused = new Set<Socket>();
  const slots = new Slots(limits.maxConcurrentHandlers);
  const log = logger.child({ role });
  const timeouts = timeoutsFor(limits.requestTimeoutMs);

  /**
   * `abandoned()` is true once the request timer has fired: the connection is gone and the handler
   * must not start (it may already be running; then it finishes and its answer is dropped).
   */
  async function dispatch(line: Buffer, abandoned: () => boolean): Promise<VaultResponse> {
    let value: unknown;
    try {
      value = JSON.parse(line.toString('utf8'));
    } catch {
      return failure(null, 'malformed');
    }
    const id = extractId(value);
    // Refuse `__proto__`, constructor/prototype keys, non-plain objects, cycles, depth.
    if (checkPlainJson(value) !== null) return failure(id, 'malformed');

    const envelope = VaultRequestEnvelope.safeParse(value);
    if (!envelope.success) return failure(id, 'malformed');
    const { operation, params } = envelope.data;
    const requestId = envelope.data.id;

    if (!isVaultOperation(operation)) return failure(requestId, 'malformed');
    if (!isOperationAllowedForRole(operation, role)) {
      log.warn({ event: 'vault.request_refused', operation, requestId }, 'vault request refused');
      // The hook appends `vault.request_refused` to the audit trail (own transaction, ADR-014
      // section 10). Its failure never changes the answer.
      const rawJobId = (params as Record<string, unknown>)['jobId'];
      try {
        await options.onRequestRefused?.({
          role,
          operation,
          requestId,
          ...(typeof rawJobId === 'string' && UUID_TEXT.test(rawJobId) ? { jobId: rawJobId } : {}),
        });
      } catch {
        log.error({ operation, requestId }, 'vault request failed');
      }
      return failure(requestId, 'forbidden');
    }

    const schemas = VAULT_OPERATION_SCHEMAS[operation];
    const parsedParams = schemas.params.safeParse(params);
    if (!parsedParams.success) return failure(requestId, 'malformed');

    // `hello` never touches the database: it does not wait for, or take, a handler slot.
    const release = operation === 'hello' ? () => undefined : await slots.acquire();
    try {
      if (abandoned()) return failure(requestId, 'service_unavailable');
      const handler = handlers[operation] as unknown as (
        context: VaultContext,
        params: unknown,
      ) => Promise<unknown>;
      const result = await runWithTimeouts(timeouts, () => handler(context, parsedParams.data));
      const checked = schemas.result.safeParse(result);
      if (!checked.success) {
        log.error({ operation, requestId }, 'vault handler result failed its own schema');
        return failure(requestId, 'internal_error');
      }
      return { id: requestId, ok: true, result: checked.data as Record<string, unknown> };
    } catch (error) {
      if (error instanceof VaultOperationError) return failure(requestId, error.code);
      // Type and code only: driver and crypto errors can quote values.
      log.error({ operation, requestId, ...errorFacts(error) }, 'vault request failed');
      return failure(requestId, 'internal_error');
    } finally {
      // Held until the handler settles, even when the request timer already closed the
      // connection: the cap counts work, not connections.
      release();
    }
  }

  function handleConnection(socket: Socket): void {
    if (connections.size >= limits.maxConnections) {
      log.warn({ event: 'vault.connection_refused' }, 'connection cap reached');
      // The caller gets one answer; a client that never closes must not keep the descriptor:
      // destroy unconditionally after a short grace, and track the socket until it is closed.
      refused.add(socket);
      const destroyTimer = setTimeout(() => socket.destroy(), limits.closeGraceMs);
      socket.on('error', () => undefined);
      socket.once('close', () => {
        clearTimeout(destroyTimer);
        refused.delete(socket);
      });
      socket.end(`${JSON.stringify(failure(null, 'service_unavailable'))}\n`);
      socket.resume(); // discard anything the caller sends meanwhile
      return;
    }
    connections.add(socket);
    socket.setTimeout(limits.idleTimeoutMs);

    // Framing state: the chunks of the line being received, and complete lines waiting for their turn.
    let partial: Buffer[] = [];
    let partialBytes = 0;
    const queue: Framed[] = [];
    let terminal = false; // a framed abort is queued: ignore everything after it
    let handling = 0; // 1 while a request is being answered
    let draining = false;
    let closed = false;
    let writeBlocked = false;
    let drainWaiter: (() => void) | null = null;
    let lineTimer: NodeJS.Timeout | null = null;
    let stallTimer: NodeJS.Timeout | null = null;
    let hardTimer: NodeJS.Timeout | null = null;
    let closeTimer: NodeJS.Timeout | null = null;

    const clearLineTimer = () => {
      if (lineTimer !== null) clearTimeout(lineTimer);
      lineTimer = null;
    };
    const clearWriteTimers = () => {
      if (stallTimer !== null) clearTimeout(stallTimer);
      if (hardTimer !== null) clearTimeout(hardTimer);
      stallTimer = null;
      hardTimer = null;
    };
    const wakeWriter = () => {
      const waiter = drainWaiter;
      drainWaiter = null;
      waiter?.();
    };
    const abort = (code: VaultErrorCode | null, reason: string) => {
      if (closed) return;
      log.warn({ event: 'vault.connection_closed', reason }, 'vault connection closed');
      const payload = code === null ? null : `${JSON.stringify(failure(null, code))}\n`;
      closed = true;
      clearLineTimer();
      clearWriteTimers();
      wakeWriter();
      // Flush the one error line, then close; destroy() alone could drop it. A peer that does
      // not read cannot hold the descriptor: destroy unconditionally after the grace.
      if (payload !== null && !socket.destroyed) {
        socket.write(payload);
        socket.destroySoon();
        closeTimer = setTimeout(() => socket.destroy(), limits.closeGraceMs);
      } else {
        socket.destroy();
      }
    };
    /** A partial line must complete within the request timeout (slow-sender defence). */
    const armLineTimer = () => {
      if (lineTimer !== null || partialBytes === 0) return;
      lineTimer = setTimeout(() => abort('malformed', 'line_timeout'), limits.requestTimeoutMs);
    };

    /** Writes a response and notes whether the peer is keeping up. */
    const send = (response: VaultResponse) => {
      if (closed || socket.destroyed) return;
      const flushed = socket.write(`${JSON.stringify(response)}\n`);
      const queued = socket.writableLength;
      if (queued > limits.writeBufferHardBytes && hardTimer === null) {
        hardTimer = setTimeout(() => abort(null, 'write_buffer_over_cap'), limits.writeGraceMs);
      }
      if (!flushed || queued > limits.writeBufferSoftBytes) {
        writeBlocked = true;
        if (stallTimer === null) {
          stallTimer = setTimeout(() => abort(null, 'write_stalled'), limits.writeStallMs);
        }
      }
    };

    async function answer(line: Buffer): Promise<void> {
      let timer: NodeJS.Timeout | undefined;
      let timedOut = false;
      const timeout = new Promise<'timeout'>((resolve) => {
        timer = setTimeout(() => {
          timedOut = true;
          resolve('timeout');
        }, limits.requestTimeoutMs);
      });
      try {
        const outcome = await Promise.race([
          dispatch(line, () => timedOut).catch(() => failure(null, 'internal_error')),
          timeout,
        ]);
        if (outcome === 'timeout') {
          // The handler may still be running, and may yet commit: claiming "failed" now would
          // be a guess. Close without an answer; the database limits (set below the request
          // timeout) normally end the work first, with an answer.
          abort(null, 'request_timeout');
          return;
        }
        send(outcome);
      } finally {
        if (timer !== undefined) clearTimeout(timer);
      }
    }

    async function drain(): Promise<void> {
      if (draining) return;
      draining = true;
      socket.pause();
      try {
        while (!closed && queue.length > 0) {
          const next = queue.shift()!;
          if (!Buffer.isBuffer(next)) {
            abort(next.abort, next.reason);
            return;
          }
          handling = 1;
          try {
            await answer(next);
          } finally {
            handling = 0;
          }
          // Backpressure: do not read or answer further requests until the peer has taken what
          // was already written.
          while (writeBlocked && !closed) {
            await new Promise<void>((resolve) => {
              drainWaiter = resolve;
            });
          }
        }
      } finally {
        draining = false;
        if (!closed) {
          armLineTimer();
          if (queue.length > 0) void drain();
          else socket.resume();
        }
      }
    }

    /**
     * Splits a received chunk into lines. Only the new chunk is scanned for the newline; the
     * pieces of a long line are kept as a list and joined once, when the line completes.
     */
    const frame = (chunk: Buffer) => {
      let offset = 0;
      while (offset < chunk.length && !terminal) {
        const newline = chunk.indexOf(NEWLINE, offset);
        if (newline === -1) {
          const rest = chunk.subarray(offset);
          partial.push(rest);
          partialBytes += rest.length;
          if (partialBytes > limits.maxLineBytes) {
            queue.push({ abort: 'malformed', reason: 'line_too_long' });
            terminal = true;
          }
          return;
        }
        const piece = chunk.subarray(offset, newline);
        offset = newline + 1;
        const total = partialBytes + piece.length;
        if (total > limits.maxLineBytes) {
          queue.push({ abort: 'malformed', reason: 'line_too_long' });
          terminal = true;
          return;
        }
        const line = partial.length === 0 ? piece : Buffer.concat([...partial, piece], total);
        partial = [];
        partialBytes = 0;
        clearLineTimer();
        if (line.length === 0) {
          // An empty line is never a request: answering each one is an amplifier.
          queue.push({ abort: 'malformed', reason: 'empty_line' });
          terminal = true;
          return;
        }
        if (queue.length + handling >= limits.maxInFlightPerConnection) {
          queue.push({ abort: 'service_unavailable', reason: 'too_many_in_flight' });
          terminal = true;
          return;
        }
        queue.push(line);
      }
    };

    socket.on('data', (chunk: Buffer) => {
      if (closed || terminal) return;
      frame(chunk);
      armLineTimer();
      void drain();
    });
    socket.on('drain', () => {
      writeBlocked = false;
      clearWriteTimers();
      wakeWriter();
    });
    socket.on('timeout', () => {
      // A long request (admin rewrap) is not idleness: re-arm and keep the connection.
      if (handling > 0) {
        socket.setTimeout(limits.idleTimeoutMs);
        return;
      }
      abort(null, 'idle_timeout');
    });
    socket.on('error', (error) => {
      log.debug(errorFacts(error), 'vault connection error');
      abort(null, 'socket_error');
    });
    socket.on('close', () => {
      closed = true;
      clearLineTimer();
      clearWriteTimers();
      if (closeTimer !== null) clearTimeout(closeTimer);
      wakeWriter();
      connections.delete(socket);
    });
  }

  const server = createServer({ allowHalfOpen: false }, handleConnection);
  // Never use `maxConnections` of net.Server: it drops the connection silently. The cap above
  // answers the caller first.

  const destroyAll = () => {
    for (const socket of connections) socket.destroy();
    for (const socket of refused) socket.destroy();
  };

  return {
    role,
    server,
    connections,
    refusedConnections: refused,
    close(): Promise<void> {
      return new Promise((resolve) => {
        const finish = () => resolve();
        if (!server.listening) {
          destroyAll();
          finish();
          return;
        }
        server.close(() => finish());
        destroyAll();
      });
    },
  };
}
