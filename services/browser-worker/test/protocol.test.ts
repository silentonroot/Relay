import { PassThrough } from 'node:stream';
import { pino } from 'pino';
import { describe, expect, it } from 'vitest';
import {
  JOB_ERROR_MESSAGES,
  mapAdapterErrorCode,
  OperationJobMessage,
  StorageStateSchema,
} from '../src/protocol.js';
import { parseDiagnostic, parseRunnerLine, RunnerChannel } from '../src/sandbox/channel.js';
import type { SandboxProcess } from '../src/sandbox/launcher.js';

function fakeProcess(): SandboxProcess & {
  out: PassThrough;
  err: PassThrough;
  exit(): void;
} {
  const out = new PassThrough();
  const err = new PassThrough();
  let exit: () => void = () => undefined;
  const exited = new Promise<{ code: number | null; signal: null }>((resolve) => {
    exit = () => resolve({ code: 0, signal: null });
  });
  return {
    pid: undefined,
    stdin: new PassThrough(),
    stdout: out,
    stderr: err,
    exited,
    kill: async () => exit(),
    out,
    err,
    exit: () => exit(),
  };
}

const silent = pino({ level: 'silent' });

describe('runner output parsing', () => {
  it('accepts a well-formed result', () => {
    const line = JSON.stringify({
      type: 'operation_result',
      outcome: { status: 'succeeded', data: { a: 1 } },
    });
    expect(parseRunnerLine(line)).toEqual({
      type: 'operation_result',
      outcome: { status: 'succeeded', data: { a: 1 } },
    });
  });

  it('accepts outcome_unknown and nothing beside it', () => {
    const line = JSON.stringify({
      type: 'operation_result',
      outcome: { status: 'outcome_unknown' },
    });
    expect(parseRunnerLine(line)).toEqual({
      type: 'operation_result',
      outcome: { status: 'outcome_unknown' },
    });
    expect(
      parseRunnerLine(
        JSON.stringify({ type: 'operation_result', outcome: { status: 'outcome_unknown', x: 1 } }),
      ),
    ).toBeNull();
  });

  it.each([
    ['not JSON', 'nope'],
    ['an unknown type', JSON.stringify({ type: 'shell', cmd: 'x' })],
    [
      'an unknown key',
      JSON.stringify({ type: 'operation_result', outcome: { status: 'reauth_required' }, x: 1 }),
    ],
    [
      'an unknown error code',
      JSON.stringify({
        type: 'operation_result',
        outcome: { status: 'failed', error: { code: 'pwned', message: 'x' } },
      }),
    ],
    [
      'a forbidden key',
      '{"type":"operation_result","outcome":{"status":"succeeded","data":{"__proto__":{"x":1}}}}',
    ],
    [
      'an over-long error message',
      JSON.stringify({
        type: 'operation_result',
        outcome: { status: 'failed', error: { code: 'timeout', message: 'x'.repeat(301) } },
      }),
    ],
    [
      'a storage state with too many cookies',
      JSON.stringify({
        type: 'login_result',
        outcome: {
          status: 'succeeded',
          externalAccountHint: null,
          storageState: {
            origins: [],
            cookies: Array.from({ length: 301 }, (_, i) => ({
              name: `c${i}`,
              value: 'v',
              domain: 'a.test',
              path: '/',
              expires: -1,
              httpOnly: true,
              secure: true,
              sameSite: 'Lax',
            })),
          },
        },
      }),
    ],
  ])('rejects %s', (_label, line) => {
    expect(parseRunnerLine(line)).toBeNull();
  });

  it('bounds storage state cookie values and rejects extra cookie fields', () => {
    const cookie = {
      name: 'a',
      value: 'v',
      domain: 'a.test',
      path: '/',
      expires: -1,
      httpOnly: true,
      secure: true,
      sameSite: 'Lax',
    };
    expect(StorageStateSchema.safeParse({ cookies: [cookie], origins: [] }).success).toBe(true);
    expect(
      StorageStateSchema.safeParse({
        cookies: [{ ...cookie, value: 'x'.repeat(5000) }],
        origins: [],
      }).success,
    ).toBe(false);
    expect(
      StorageStateSchema.safeParse({ cookies: [{ ...cookie, partitionKey: 'x' }], origins: [] })
        .success,
    ).toBe(false);
    expect(
      StorageStateSchema.safeParse({ cookies: [{ ...cookie, expires: Infinity }], origins: [] })
        .success,
    ).toBe(false);
  });

  it('rejects a job message with extra fields', () => {
    const job = {
      jobId: 'j',
      connectionId: 'c',
      adapterId: 'a',
      adapterVersion: '1.0.0',
      allowedOrigins: ['https://a.test'],
      operation: 'x.y',
      arguments: {},
      storageState: { cookies: [], origins: [] },
      expectedAccountHint: null,
      timeoutMs: 1000,
    };
    expect(OperationJobMessage.safeParse({ type: 'operation', job }).success).toBe(true);
    expect(
      OperationJobMessage.safeParse({ type: 'operation', job: { ...job, registry: '/tmp/x.ts' } })
        .success,
    ).toBe(false);
  });
});

describe('RunnerChannel', () => {
  const channel = (process: SandboxProcess, maxStdoutBytes = 1024) =>
    new RunnerChannel(process, {
      maxStdoutBytes,
      maxStderrBytes: 1024,
      jobId: 'j',
      logger: silent,
    });

  it('delivers messages in order, then the exit', async () => {
    const process = fakeProcess();
    const ch = channel(process);
    process.out.write('{"type":"login_ready"}\n{"type":"operation_result","outcome":');
    process.out.write('{"status":"reauth_required"}}\n');
    expect(await ch.next()).toEqual({ kind: 'message', message: { type: 'login_ready' } });
    expect(await ch.next()).toMatchObject({ kind: 'message' });
    process.exit();
    expect(await ch.next()).toEqual({ kind: 'exit' });
    expect(await ch.next()).toEqual({ kind: 'exit' });
  });

  it('ends with a protocol error on oversized output, even without a newline', async () => {
    const process = fakeProcess();
    const ch = channel(process, 100);
    process.out.write('x'.repeat(200));
    expect(await ch.next()).toEqual({ kind: 'protocol_error', reason: 'too_large' });
  });

  it('ends with a protocol error on the first malformed line and ignores later lines', async () => {
    const process = fakeProcess();
    const ch = channel(process);
    process.out.write('hello\n{"type":"login_ready"}\n');
    expect(await ch.next()).toEqual({ kind: 'protocol_error', reason: 'malformed' });
    expect(await ch.next()).toEqual({ kind: 'protocol_error', reason: 'malformed' });
  });

  it('passes raw stderr to the hook but logs only allowlisted events', async () => {
    const process = fakeProcess();
    const raw: string[] = [];
    const logged: string[] = [];
    new RunnerChannel(process, {
      maxStdoutBytes: 1024,
      maxStderrBytes: 1024,
      jobId: 'j',
      logger: pino({ level: 'debug' }, { write: (line: string) => logged.push(line) }),
      onStderr: (line) => raw.push(line),
    });
    process.err.write('{"event":"browser_launched"}\n{"event":"cookie","value":"SECRET"}\n');
    process.err.write('{"event":"navigation_blocked","code":"Has Spaces SECRET"}\nSECRET plain\n');
    await new Promise((resolve) => setImmediate(resolve));
    expect(raw).toHaveLength(4);
    expect(logged).toHaveLength(2);
    expect(logged.join('')).not.toContain('SECRET');
  });

  it('parseDiagnostic keeps only fixed event names and short codes', () => {
    expect(parseDiagnostic('{"event":"navigation_blocked","code":"path_not_allowed"}')).toEqual({
      event: 'navigation_blocked',
      code: 'path_not_allowed',
    });
    expect(parseDiagnostic('{"event":"made_up"}')).toBeNull();
    expect(parseDiagnostic('{"event":"runner_error","code":"x y"}')).toEqual({
      event: 'runner_error',
    });
  });
});

describe('adapter error codes', () => {
  it.each([
    ['not_found', 'not_found'],
    ['unexpected_page', 'unexpected_page'],
    ['invalid_arguments', 'invalid_arguments'],
    ['aborted', 'cancelled'],
    ['identity_mismatch', 'worker_failure'],
    ['navigation_blocked', 'worker_failure'],
    ['__proto__', 'worker_failure'],
    ['toString', 'worker_failure'],
    [42, 'worker_failure'],
  ])('maps %s to %s', (code, expected) => {
    expect(mapAdapterErrorCode(code)).toBe(expected);
  });

  it('has a fixed message for every code', () => {
    for (const message of Object.values(JOB_ERROR_MESSAGES)) {
      expect(message.length).toBeGreaterThan(0);
      expect(message.length).toBeLessThanOrEqual(300);
    }
  });
});
