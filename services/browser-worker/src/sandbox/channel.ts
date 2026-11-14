import { checkPlainJson } from '@aab/contracts';
import type { Logger } from 'pino';
import { RUNNER_DIAGNOSTIC_EVENTS, RunnerMessage } from '../protocol.js';
import type { SandboxProcess } from './launcher.js';

/*
 * The supervisor's view of a runner's output. Everything here is hostile input: stdout is
 * size-capped as a whole, each line is checked with `checkPlainJson` and parsed strictly, and
 * the first malformed line ends the job. stderr is read up to a cap; only allowlisted event
 * names (and a short code) reach the supervisor's log.
 */

export type ChannelEvent =
  | { readonly kind: 'message'; readonly message: RunnerMessage }
  | { readonly kind: 'protocol_error'; readonly reason: 'too_large' | 'malformed' }
  | { readonly kind: 'exit' };

export function parseRunnerLine(line: string): RunnerMessage | null {
  let value: unknown;
  try {
    value = JSON.parse(line);
  } catch {
    return null;
  }
  if (checkPlainJson(value) !== null) return null;
  const parsed = RunnerMessage.safeParse(value);
  return parsed.success ? parsed.data : null;
}

const EVENTS: ReadonlySet<string> = new Set(RUNNER_DIAGNOSTIC_EVENTS);

/** Extracts `{event, code}` from a runner stderr line when both are from the fixed vocabulary. */
export function parseDiagnostic(line: string): { event: string; code?: string } | null {
  if (line.length > 2048) return null;
  let value: unknown;
  try {
    value = JSON.parse(line);
  } catch {
    return null;
  }
  if (typeof value !== 'object' || value === null) return null;
  const { event, code } = value as { event?: unknown; code?: unknown };
  if (typeof event !== 'string' || !EVENTS.has(event)) return null;
  if (typeof code === 'string' && /^[a-z_]{1,48}$/.test(code)) return { event, code };
  return { event };
}

export class RunnerChannel {
  readonly #events: ChannelEvent[] = [];
  readonly #waiters: ((event: ChannelEvent) => void)[] = [];
  #done = false;
  #terminal: ChannelEvent | null = null;

  constructor(
    process: SandboxProcess,
    options: {
      readonly maxStdoutBytes: number;
      readonly maxStderrBytes: number;
      readonly jobId: string;
      readonly logger: Logger;
      readonly onStderr?: (line: string, jobId: string) => void;
    },
  ) {
    let stdoutBytes = 0;
    let buffer = '';
    process.stdout.setEncoding('utf8');
    process.stdout.on('data', (chunk: string) => {
      if (this.#done) return;
      stdoutBytes += Buffer.byteLength(chunk);
      if (stdoutBytes > options.maxStdoutBytes) {
        this.#finish({ kind: 'protocol_error', reason: 'too_large' });
        return;
      }
      buffer += chunk;
      let index = buffer.indexOf('\n');
      while (index >= 0 && !this.#done) {
        const line = buffer.slice(0, index);
        buffer = buffer.slice(index + 1);
        const message = parseRunnerLine(line);
        if (message === null) this.#finish({ kind: 'protocol_error', reason: 'malformed' });
        else this.#push({ kind: 'message', message });
        index = buffer.indexOf('\n');
      }
    });

    let stderrBytes = 0;
    let errBuffer = '';
    process.stderr.setEncoding('utf8');
    process.stderr.on('data', (chunk: string) => {
      if (stderrBytes > options.maxStderrBytes) return;
      stderrBytes += Buffer.byteLength(chunk);
      errBuffer += chunk;
      let index = errBuffer.indexOf('\n');
      while (index >= 0) {
        const line = errBuffer.slice(0, index);
        errBuffer = errBuffer.slice(index + 1);
        options.onStderr?.(line, options.jobId);
        const diagnostic = parseDiagnostic(line);
        if (diagnostic !== null) {
          options.logger.debug({ jobId: options.jobId, ...diagnostic }, 'runner diagnostic');
        }
        index = errBuffer.indexOf('\n');
      }
      if (errBuffer.length > 4096) errBuffer = '';
    });

    void process.exited.then(() => {
      // Let any final stdout chunk arrive before reporting the exit.
      setImmediate(() => this.#finish({ kind: 'exit' }));
    });
  }

  #push(event: ChannelEvent): void {
    const waiter = this.#waiters.shift();
    if (waiter !== undefined) waiter(event);
    else this.#events.push(event);
  }

  #finish(event: ChannelEvent): void {
    if (this.#done) return;
    this.#done = true;
    this.#terminal = event;
    for (const waiter of this.#waiters.splice(0)) waiter(event);
  }

  /** The next message, or the terminal event (protocol error or exit), which then repeats. */
  next(): Promise<ChannelEvent> {
    const event = this.#events.shift();
    if (event !== undefined) return Promise.resolve(event);
    if (this.#terminal !== null) return Promise.resolve(this.#terminal);
    return new Promise((resolve) => this.#waiters.push(resolve));
  }
}
