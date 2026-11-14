import { randomBytes } from 'node:crypto';
import { accessSync, constants } from 'node:fs';
import net from 'node:net';
import { sanitizeOperationOutput, validateOperationInput } from '@aab/adapter-sdk';
import type { AdapterRegistry, ApplicationAdapter } from '@aab/adapter-sdk';
import { Origin } from '@aab/contracts';
import type { JobErrorCode } from '@aab/contracts';
import { pino } from 'pino';
import type { Logger } from 'pino';
import { loadAdapterRegistry } from '../adapter-registry.js';
import { createEgressProxy } from '../egress/proxy.js';
import type { EgressProxy } from '../egress/proxy.js';
import { jobError } from '../protocol.js';
import type { JobMessage, RunnerMessage } from '../protocol.js';
import type {
  JobRunner,
  LoginHandle,
  LoginJobSpec,
  LoginOutcome,
  OperationJobOutcome,
  OperationJobSpec,
} from '../types.js';
import { createBubblewrapLauncher } from './bubblewrap.js';
import { RunnerChannel } from './channel.js';
import type { ChannelEvent } from './channel.js';
import { resolveJobRunnerConfig } from './config.js';
import type { JobRunnerConfig, JobRunnerConfigInput } from './config.js';
import { createDockerLauncher } from './docker.js';
import type { SandboxLauncher, SandboxProcess } from './launcher.js';
import { createJobRuntimeDir } from './runtime-dir.js';
import type { JobRuntimeDir } from './runtime-dir.js';
import { createUnsafeProcessLauncher } from './unsafe-process.js';

/** `startLogin` rejects with this when the window cannot be opened. */
export class LoginStartError extends Error {
  override readonly name = 'LoginStartError';
  readonly code: JobErrorCode;
  constructor(code: JobErrorCode) {
    super(`the login window could not be opened (${code})`);
    this.code = code;
  }
}

const failed = (code: JobErrorCode): { status: 'failed'; error: ReturnType<typeof jobError> } => ({
  status: 'failed',
  error: jobError(code),
});

export function createLauncher(config: JobRunnerConfig): SandboxLauncher {
  switch (config.sandbox) {
    case 'bubblewrap':
      return createBubblewrapLauncher(config);
    case 'docker':
      return createDockerLauncher(config);
    case 'unsafe-process':
      return createUnsafeProcessLauncher(config);
    default:
      throw new Error('unknown sandbox kind');
  }
}

interface RunningJob {
  readonly jobId: string;
  readonly process: SandboxProcess;
  readonly channel: RunnerChannel;
  send(message: JobMessage | { type: 'complete' } | { type: 'cancel' }): void;
  /** Kills the sandbox, closes the proxy and removes the runtime directory. Idempotent. */
  stop(): Promise<void>;
}

function delay<T>(ms: number, value: T): { promise: Promise<T>; cancel(): void } {
  let timer: NodeJS.Timeout | undefined;
  const promise = new Promise<T>((resolve) => {
    timer = setTimeout(() => resolve(value), ms);
  });
  return { promise, cancel: () => clearTimeout(timer) };
}

function aborted(signal: AbortSignal): { promise: Promise<'aborted'>; cancel(): void } {
  let listener: (() => void) | undefined;
  const promise = new Promise<'aborted'>((resolve) => {
    if (signal.aborted) {
      resolve('aborted');
      return;
    }
    listener = () => resolve('aborted');
    signal.addEventListener('abort', listener, { once: true });
  });
  return {
    promise,
    cancel: () => {
      if (listener !== undefined) signal.removeEventListener('abort', listener);
    },
  };
}

/** Creates the `JobRunner` the supervisor uses. See src/types.ts for the contract. */
export function createJobRunner(input: JobRunnerConfigInput | JobRunnerConfig = {}): JobRunner {
  const config = resolveJobRunnerConfig(input as JobRunnerConfigInput);
  const logger: Logger = config.logger ?? pino({ level: 'silent' });
  const launcher = createLauncher(config);
  let registryPromise: Promise<AdapterRegistry> | null = null;
  const registry = (): Promise<AdapterRegistry> => {
    registryPromise ??= loadAdapterRegistry(config.adapterRegistryModule);
    return registryPromise;
  };

  if (config.sandbox === 'unsafe-process') {
    logger.warn(
      'UNSAFE: browser worker sandbox is "unsafe-process"; runners have NO isolation and no ' +
        'ADR-013 security property holds',
    );
  }

  const warnUnsafe = (jobId: string): void => {
    if (config.sandbox === 'unsafe-process') {
      logger.warn({ jobId }, 'UNSAFE: running job without a sandbox');
    }
  };

  async function findAdapter(
    adapterId: string,
    adapterVersion: string,
    allowedOrigins: readonly string[],
  ): Promise<{ ok: true; adapter: ApplicationAdapter } | { ok: false; code: JobErrorCode }> {
    let loaded: AdapterRegistry;
    try {
      loaded = await registry();
    } catch {
      logger.error('adapter registry could not be loaded');
      return { ok: false, code: 'worker_failure' };
    }
    const adapter = loaded.get(adapterId, adapterVersion);
    if (adapter === undefined) return { ok: false, code: 'adapter_unavailable' };
    if (
      allowedOrigins.length === 0 ||
      !allowedOrigins.every(
        (origin) => Origin.safeParse(origin).success && adapter.allowedOrigins.includes(origin),
      )
    ) {
      return { ok: false, code: 'origin_not_allowed' };
    }
    return { ok: true, adapter };
  }

  async function startJob(
    jobId: string,
    allowedOrigins: readonly string[],
    headed: boolean,
  ): Promise<RunningJob> {
    let dir: JobRuntimeDir | null = null;
    let proxy: EgressProxy | null = null;
    let sandbox: SandboxProcess | null = null;
    const cleanup = async (): Promise<void> => {
      await sandbox?.kill().catch(() => undefined);
      await proxy?.close().catch(() => undefined);
      await dir?.remove().catch(() => undefined);
    };
    try {
      dir = await createJobRuntimeDir(config.runtimeBaseDir);
      proxy = await createEgressProxy({
        socketPath: dir.socketPath,
        allowedOrigins,
        ...(config.egressResolver === undefined ? {} : { resolver: config.egressResolver }),
        limits: config.limits.egress,
        onDecision: (decision) => {
          logger.info(
            {
              jobId,
              origin: decision.origin,
              decision: decision.decision,
              reason: decision.reason,
            },
            'egress',
          );
          config.onEgressDecision?.({ ...decision, jobId });
        },
      });
      sandbox = await launcher.launch({
        jobId,
        jobDir: dir.dir,
        socketPath: dir.socketPath,
        headed,
      });
    } catch (error) {
      await cleanup();
      throw error;
    }
    const process = sandbox;
    const channel = new RunnerChannel(process, {
      maxStdoutBytes: config.limits.maxRunnerStdoutBytes,
      maxStderrBytes: config.limits.maxRunnerStderrBytes,
      jobId,
      logger,
      ...(config.onRunnerStderr === undefined ? {} : { onStderr: config.onRunnerStderr }),
    });
    let stopping: Promise<void> | null = null;
    return {
      jobId,
      process,
      channel,
      send(message) {
        if (!process.stdin.writable) return;
        process.stdin.write(`${JSON.stringify(message)}\n`);
      },
      stop() {
        stopping ??= (async () => {
          process.stdin.end();
          // A runner that has finished gets a moment to exit on its own.
          await Promise.race([process.exited, delay(config.limits.exitGraceMs, null).promise]);
          await cleanup();
        })();
        return stopping;
      },
    };
  }

  /** Next channel event, but a protocol error or premature exit kills the job. */
  async function nextMessage(job: RunningJob): Promise<ChannelEvent> {
    const event = await job.channel.next();
    if (event.kind === 'protocol_error') {
      logger.warn({ jobId: job.jobId, reason: event.reason }, 'runner protocol violation');
      await job.process.kill();
    }
    return event;
  }

  const runner: JobRunner = {
    sandbox: config.sandbox,

    async runOperation(spec: OperationJobSpec, signal: AbortSignal): Promise<OperationJobOutcome> {
      warnUnsafe(spec.jobId);
      if (signal.aborted) return failed('cancelled');
      const found = await findAdapter(spec.adapterId, spec.adapterVersion, spec.allowedOrigins);
      if (!found.ok) return failed(found.code);
      if (found.adapter.execute === undefined) return failed('adapter_unavailable');
      // Checked here too (the runner re-validates), so a bad job never costs a sandbox.
      const input = validateOperationInput(found.adapter, spec.operation, spec.arguments);
      if (!input.ok) {
        return failed(
          input.error.code === 'unknown_operation' ? 'adapter_unavailable' : 'invalid_arguments',
        );
      }

      let job: RunningJob;
      try {
        job = await startJob(spec.jobId, spec.allowedOrigins, false);
      } catch {
        logger.error({ jobId: spec.jobId }, 'sandbox could not be started');
        return failed('worker_failure');
      }

      const deadline = delay(spec.timeoutMs + config.limits.startupGraceMs, 'timeout' as const);
      const abort = aborted(signal);
      try {
        // The storage state goes to the runner's stdin only.
        job.send({
          type: 'operation',
          job: {
            jobId: spec.jobId,
            connectionId: spec.connectionId,
            adapterId: spec.adapterId,
            adapterVersion: spec.adapterVersion,
            allowedOrigins: [...spec.allowedOrigins],
            operation: spec.operation,
            arguments: spec.arguments,
            storageState: spec.storageState,
            expectedAccountHint: spec.expectedAccountHint,
            timeoutMs: spec.timeoutMs,
          },
        });
        const result = await Promise.race([nextMessage(job), deadline.promise, abort.promise]);
        if (result === 'timeout') {
          logger.warn({ jobId: spec.jobId }, 'job hit the hard deadline; sandbox killed');
          return failed('timeout');
        }
        if (result === 'aborted') return failed('cancelled');
        if (result.kind !== 'message' || result.message.type !== 'operation_result') {
          if (result.kind === 'message') await job.process.kill();
          return failed('worker_failure');
        }
        const outcome = result.message.outcome;
        switch (outcome.status) {
          case 'succeeded':
            try {
              // Second, independent pass outside the sandbox (ADR-013).
              const data = sanitizeOperationOutput(found.adapter, spec.operation, outcome.data);
              return { status: 'succeeded', data };
            } catch {
              return failed('output_rejected');
            }
          case 'reauth_required':
            return { status: 'reauth_required' };
          case 'outcome_unknown':
            return { status: 'outcome_unknown' };
          case 'failed':
            // The runner's message text is discarded; the code is from a closed enum.
            return failed(outcome.error.code);
        }
      } catch {
        return failed('worker_failure');
      } finally {
        deadline.cancel();
        abort.cancel();
        await job.stop();
      }
    },

    async startLogin(spec: LoginJobSpec, signal: AbortSignal): Promise<LoginHandle> {
      warnUnsafe(spec.jobId);
      if (!launcher.supportsHeaded) throw new LoginStartError('worker_failure');
      if (config.display === null) throw new LoginStartError('worker_failure');
      if (signal.aborted) throw new LoginStartError('cancelled');
      const found = await findAdapter(spec.adapterId, spec.adapterVersion, spec.allowedOrigins);
      if (!found.ok) throw new LoginStartError(found.code);

      let job: RunningJob;
      try {
        job = await startJob(spec.jobId, spec.allowedOrigins, true);
      } catch {
        throw new LoginStartError('worker_failure');
      }
      job.send({
        type: 'login',
        job: {
          jobId: spec.jobId,
          connectionId: spec.connectionId,
          adapterId: spec.adapterId,
          adapterVersion: spec.adapterVersion,
          allowedOrigins: [...spec.allowedOrigins],
          timeoutMs: spec.timeoutMs,
        },
      });

      const hardDeadline = delay(spec.timeoutMs + config.limits.startupGraceMs, 'timeout' as const);
      const abort = aborted(signal);
      const first = await Promise.race([nextMessage(job), hardDeadline.promise, abort.promise]);
      if (first === 'timeout' || first === 'aborted' || first.kind !== 'message') {
        hardDeadline.cancel();
        abort.cancel();
        await job.stop();
        throw new LoginStartError(
          first === 'timeout' ? 'timeout' : first === 'aborted' ? 'cancelled' : 'worker_failure',
        );
      }
      if (first.message.type !== 'login_ready') {
        hardDeadline.cancel();
        abort.cancel();
        await job.stop();
        const code =
          first.message.type === 'login_result' && first.message.outcome.status === 'failed'
            ? first.message.outcome.error.code
            : 'worker_failure';
        throw new LoginStartError(code);
      }

      let cancelRequested = false;
      const toOutcome = (message: RunnerMessage | null): LoginOutcome => {
        if (message === null || message.type !== 'login_result') return failed('worker_failure');
        const outcome = message.outcome;
        if (outcome.status === 'failed') return failed(outcome.error.code);
        return {
          status: 'succeeded',
          storageState: outcome.storageState,
          externalAccountHint: outcome.externalAccountHint,
        };
      };
      const outcome: Promise<LoginOutcome> = (async () => {
        const event = await Promise.race([nextMessage(job), hardDeadline.promise, abort.promise]);
        if (event === 'timeout') return failed('timeout');
        if (event === 'aborted') return failed('cancelled');
        if (event.kind === 'exit') return failed(cancelRequested ? 'cancelled' : 'worker_failure');
        if (event.kind === 'protocol_error') return failed('worker_failure');
        return toOutcome(event.message);
      })();
      const closed = outcome
        .catch(() => undefined)
        .then(async () => {
          hardDeadline.cancel();
          abort.cancel();
          await job.stop();
        });

      let completion: Promise<LoginOutcome> | null = null;
      return {
        closed,
        complete(): Promise<LoginOutcome> {
          if (completion === null) {
            job.send({ type: 'complete' });
            completion = outcome.then(async (result) => {
              await closed;
              return result;
            });
          }
          return completion;
        },
        async cancel(): Promise<void> {
          if (!cancelRequested) {
            cancelRequested = true;
            job.send({ type: 'cancel' });
          }
          await Promise.race([closed, delay(config.limits.exitGraceMs, null).promise]);
          await job.stop();
          await closed;
        },
      };
    },

    async selfCheck(): Promise<void> {
      const mustExist = (path: string, what: string): void => {
        try {
          accessSync(path, constants.X_OK);
        } catch {
          throw new Error(`${what} not found or not executable at ${path}`);
        }
      };
      if (config.sandbox === 'bubblewrap') {
        mustExist(config.bwrapPath, 'bubblewrap');
        mustExist(config.nodePath, 'node');
        mustExist(config.chromiumPath, 'Chromium');
      }
      await registry();
      if (config.sandbox === 'unsafe-process') {
        logger.warn('UNSAFE: self-check skipped the isolation checks for "unsafe-process"');
        return;
      }

      const listener = net.createServer((socket) => socket.destroy());
      await new Promise<void>((resolve) => listener.listen(0, '127.0.0.1', resolve));
      const address = listener.address();
      const port = typeof address === 'object' && address !== null ? address.port : 0;
      const jobId = `self-check-${randomBytes(4).toString('hex')}`;
      let job: RunningJob | null = null;
      try {
        job = await startJob(jobId, ['https://self-check.invalid'], false);
        job.send({ type: 'self_check', hostLoopbackPort: port, launchBrowser: true });
        const wait = delay(90_000, 'timeout' as const);
        const result = await Promise.race([nextMessage(job), wait.promise]);
        wait.cancel();
        if (result === 'timeout') throw new Error('sandbox self-check timed out');
        if (result.kind !== 'message' || result.message.type !== 'self_check_result') {
          throw new Error('sandbox self-check: the runner did not start inside the sandbox');
        }
        const report = result.message;
        if (report.interfaces.some((name) => name !== 'lo')) {
          throw new Error('sandbox self-check: the sandbox has a network interface besides lo');
        }
        if (report.hostLoopbackReachable) {
          throw new Error("sandbox self-check: the sandbox can reach the host's loopback");
        }
        if (report.browserStarted !== true) {
          throw new Error('sandbox self-check: Chromium could not start inside the sandbox');
        }
      } finally {
        await job?.stop();
        listener.close();
      }
    },
  };
  return runner;
}
