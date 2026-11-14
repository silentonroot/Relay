import net from 'node:net';
import os from 'node:os';
import { checkPlainJson } from '@aab/contracts';
import { loadAdapterRegistry } from '../adapter-registry.js';
import { ControlMessage, JobMessage, MAX_JOB_LINE_BYTES } from '../protocol.js';
import type { SelfCheckMessage } from '../protocol.js';
import { launchBrowser, startRelay } from './browser.js';
import { diag, emit, LineReader, reserveStdout } from './io.js';
import { runLogin } from './login.js';
import { runOperation } from './operation.js';
import { readRunnerEnvironment } from './session.js';
import type { RunnerEnvironment } from './session.js';

/*
 * The runner: the only code that runs inside the sandbox. It reads one job from stdin, runs it
 * and writes one result to stdout. See docs/adr/ADR-013-per-job-sandbox-egress-proxy.md.
 */

reserveStdout();

function fatal(code: string): never {
  diag('runner_error', { code });
  process.exit(1);
}

process.on('uncaughtException', () => fatal('uncaught_exception'));
process.on('unhandledRejection', () => fatal('unhandled_rejection'));

function parseLine<T>(
  line: string,
  schema: { safeParse(value: unknown): { success: boolean; data?: T } },
): T | null {
  let value: unknown;
  try {
    value = JSON.parse(line);
  } catch {
    return null;
  }
  if (checkPlainJson(value) !== null) return null;
  const parsed = schema.safeParse(value);
  return parsed.success ? (parsed.data as T) : null;
}

async function probeLoopback(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = net.connect({ host: '127.0.0.1', port });
    const timer = setTimeout(() => {
      socket.destroy();
      resolve(false);
    }, 1_500);
    socket.once('connect', () => {
      clearTimeout(timer);
      socket.destroy();
      resolve(true);
    });
    socket.once('error', () => {
      clearTimeout(timer);
      resolve(false);
    });
  });
}

async function selfCheck(message: SelfCheckMessage, env: RunnerEnvironment): Promise<void> {
  const interfaces = Object.keys(os.networkInterfaces());
  const hostLoopbackReachable = await probeLoopback(message.hostLoopbackPort);
  let browserStarted: boolean | null = null;
  if (message.launchBrowser) {
    const relay = await startRelay(env.egressSocket);
    try {
      const browser = await launchBrowser({
        executablePath: env.chromiumPath,
        chromiumSandbox: env.chromiumSandbox,
        relayPort: relay.port,
        headed: null,
      });
      await (await browser.newContext()).newPage();
      await browser.close();
      browserStarted = true;
    } catch {
      browserStarted = false;
    } finally {
      relay.close();
    }
  }
  await emit({ type: 'self_check_result', interfaces, hostLoopbackReachable, browserStarted });
}

async function main(): Promise<void> {
  diag('runner_started');
  const env = readRunnerEnvironment(process.env);
  const input = new LineReader(process.stdin, MAX_JOB_LINE_BYTES);
  const first = await input.next();
  if (first === null) fatal('no_job');
  const message = parseLine(first, JobMessage);
  if (message === null) {
    diag('job_rejected');
    fatal('bad_job');
  }
  diag('job_received', { code: message.type });

  if (message.type === 'self_check') {
    await selfCheck(message, env);
    return;
  }

  const registry = await loadAdapterRegistry(env.registryModule);

  if (message.type === 'operation') {
    // stdin closing during an operation means the supervisor is gone: stop.
    const stopped = (async (): Promise<'cancelled'> => {
      for (;;) {
        const line = await input.next();
        if (line === null) return 'cancelled';
        const control = parseLine(line, ControlMessage);
        if (control?.type === 'cancel') return 'cancelled';
      }
    })();
    const outcome = await runOperation(message, registry, env, stopped);
    diag('operation_finished', { code: outcome.status });
    await emit({ type: 'operation_result', outcome });
    return;
  }

  const outcome = await runLogin(message, registry, env, async () => {
    for (;;) {
      const line = await input.next();
      if (line === null) return null;
      const control = parseLine(line, ControlMessage);
      if (control !== null) return control;
    }
  });
  await emit({ type: 'login_result', outcome });
}

main().then(
  () => process.exit(0),
  () => fatal('main_failed'),
);
