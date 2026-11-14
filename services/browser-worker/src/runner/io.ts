import type { Readable } from 'node:stream';
import { pino } from 'pino';
import type { RunnerDiagnosticEvent, RunnerMessage } from '../protocol.js';

/*
 * Runner I/O. stdout carries protocol messages only; anything else that tries to write there is
 * discarded. Diagnostics go to stderr as JSON lines holding a fixed event name and, at most, a
 * short reason code: never a URL, a header, a cookie, page text or exception text.
 */

const originalStdoutWrite = process.stdout.write.bind(process.stdout);

/** Discards stray stdout writes from libraries so stdout stays protocol-only. */
export function reserveStdout(): void {
  process.stdout.write = ((
    _chunk: unknown,
    encodingOrCallback?: unknown,
    callback?: unknown,
  ): boolean => {
    const done = typeof encodingOrCallback === 'function' ? encodingOrCallback : callback;
    if (typeof done === 'function') queueMicrotask(() => (done as () => void)());
    return true;
  }) as typeof process.stdout.write;
}

export function emit(message: RunnerMessage): Promise<void> {
  return new Promise((resolve) => {
    originalStdoutWrite(`${JSON.stringify(message)}\n`, () => resolve());
  });
}

const logger = pino(
  { base: null, timestamp: false, messageKey: 'event' },
  pino.destination({ fd: 2, sync: true }),
);

export interface DiagnosticFields {
  /** A short reason code from a fixed vocabulary (e.g. a NavigationBlockReason). */
  readonly code?: string;
  readonly count?: number;
}

export function diag(event: RunnerDiagnosticEvent, fields: DiagnosticFields = {}): void {
  const safe: Record<string, string | number> = {};
  if (fields.code !== undefined && /^[a-z_]{1,48}$/.test(fields.code)) safe['code'] = fields.code;
  if (fields.count !== undefined && Number.isFinite(fields.count)) safe['count'] = fields.count;
  logger.info(safe, event);
}

/** Reads newline-delimited messages with a hard per-line cap. */
export class LineReader {
  readonly #lines: string[] = [];
  readonly #waiters: ((line: string | null) => void)[] = [];
  #buffer = '';
  #ended = false;

  constructor(stream: Readable, maxLineBytes: number) {
    stream.setEncoding('utf8');
    stream.on('data', (chunk: string) => {
      this.#buffer += chunk;
      let index = this.#buffer.indexOf('\n');
      while (index >= 0) {
        this.#push(this.#buffer.slice(0, index));
        this.#buffer = this.#buffer.slice(index + 1);
        index = this.#buffer.indexOf('\n');
      }
      if (Buffer.byteLength(this.#buffer) > maxLineBytes) {
        this.#buffer = '';
        this.#end();
        stream.destroy();
      }
    });
    stream.on('end', () => this.#end());
    stream.on('error', () => this.#end());
  }

  #push(line: string): void {
    const waiter = this.#waiters.shift();
    if (waiter !== undefined) waiter(line);
    else this.#lines.push(line);
  }

  #end(): void {
    if (this.#ended) return;
    this.#ended = true;
    for (const waiter of this.#waiters.splice(0)) waiter(null);
  }

  /** The next line, or null once the stream has ended (or a line was too long). */
  next(): Promise<string | null> {
    const line = this.#lines.shift();
    if (line !== undefined) return Promise.resolve(line);
    if (this.#ended) return Promise.resolve(null);
    return new Promise((resolve) => this.#waiters.push(resolve));
  }
}
