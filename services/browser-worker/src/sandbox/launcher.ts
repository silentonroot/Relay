import { spawn } from 'node:child_process';
import type { ChildProcessWithoutNullStreams } from 'node:child_process';
import type { Readable, Writable } from 'node:stream';
import type { SandboxKind } from './config.js';
import { killProcessTree } from './process-tree.js';

/** What a launcher needs to start one runner for one job. */
export interface LaunchRequest {
  readonly jobId: string;
  /** Host path of the job's runtime directory. */
  readonly jobDir: string;
  /** Host path of the job's egress socket, inside `jobDir`. */
  readonly socketPath: string;
  /** Headed login window: the display is bound in. */
  readonly headed: boolean;
  /**
   * Test hook: run this host script (inside the mounted code) instead of the runner entry.
   * Never derived from a job.
   */
  readonly entryOverride?: string;
}

export interface SandboxExit {
  readonly code: number | null;
  readonly signal: NodeJS.Signals | null;
}

export interface SandboxProcess {
  readonly pid: number | undefined;
  readonly stdin: Writable;
  readonly stdout: Readable;
  readonly stderr: Readable;
  readonly exited: Promise<SandboxExit>;
  /** Kills the whole process tree (and, for Docker, the container). Idempotent. */
  kill(): Promise<void>;
}

export interface SandboxLauncher {
  readonly kind: SandboxKind;
  /** Whether this launcher can open a headed window. */
  readonly supportsHeaded: boolean;
  launch(request: LaunchRequest): Promise<SandboxProcess>;
}

/** Names of the environment variables the runner reads. Values never carry secrets. */
export const RUNNER_ENV = {
  chromium: 'AAB_RUNNER_CHROMIUM',
  chromiumSandbox: 'AAB_RUNNER_CHROMIUM_SANDBOX',
  registry: 'AAB_RUNNER_REGISTRY',
  egressSocket: 'AAB_RUNNER_EGRESS_SOCKET',
  display: 'AAB_RUNNER_DISPLAY',
  jobMarker: 'AAB_SANDBOX_JOB',
} as const;

/** Wraps a spawned child so that `kill` takes the whole tree down and waits for the exit. */
export function wrapChild(
  child: ChildProcessWithoutNullStreams,
  extraKill?: () => Promise<void>,
): SandboxProcess {
  const exited = new Promise<SandboxExit>((resolve) => {
    child.once('exit', (code, signal) => resolve({ code, signal }));
    child.once('error', () => resolve({ code: null, signal: null }));
  });
  let killing: Promise<void> | null = null;
  // Errors on the pipes (EPIPE after the child died) are expected and not interesting.
  child.stdin.on('error', () => undefined);
  child.stdout.on('error', () => undefined);
  child.stderr.on('error', () => undefined);
  return {
    pid: child.pid,
    stdin: child.stdin,
    stdout: child.stdout,
    stderr: child.stderr,
    exited,
    kill(): Promise<void> {
      killing ??= (async () => {
        if (extraKill !== undefined) await extraKill().catch(() => undefined);
        if (child.pid !== undefined && child.exitCode === null && child.signalCode === null) {
          await killProcessTree(child.pid, { group: true });
        }
        await Promise.race([exited, new Promise((r) => setTimeout(r, 5_000))]);
      })();
      return killing;
    },
  };
}

export function spawnDetached(
  command: string,
  args: readonly string[],
  options: { env: NodeJS.ProcessEnv; cwd?: string },
): ChildProcessWithoutNullStreams {
  return spawn(command, args, {
    stdio: ['pipe', 'pipe', 'pipe'],
    detached: true,
    env: options.env,
    ...(options.cwd === undefined ? {} : { cwd: options.cwd }),
  });
}
