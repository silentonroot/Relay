import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Logger } from 'pino';
import type { EgressDecision, EgressLimits, EgressResolver } from '../egress/proxy.js';
import { DEFAULT_MAX_RUNNER_STDOUT_BYTES } from '../protocol.js';
import { defaultRuntimeBaseDir } from './runtime-dir.js';

export type SandboxKind = 'bubblewrap' | 'docker' | 'unsafe-process';

/** How the headed login window reaches the owner's display. */
export interface DisplayConfig {
  /** Preferred when set: path of the compositor socket, e.g. `$XDG_RUNTIME_DIR/wayland-0`. */
  readonly waylandSocket?: string;
  /** X11 display name such as `:0`. Only local displays (`:N` / `unix:N`) are supported. */
  readonly x11Display?: string;
  /** Xauthority file for the X11 display, bound read-only into the sandbox. */
  readonly xauthority?: string;
}

export interface DockerConfig {
  readonly binary: string;
  readonly image: string;
  /**
   * Seccomp profile that lets Chromium create its own user-namespace sandbox. When null (the
   * default), Docker's default profile is used and Chromium's own sandbox is disabled: the
   * container is then the only boundary. Must be set together with `apparmorProfile`.
   */
  readonly seccompProfile: string | null;
  /**
   * Name of a loaded AppArmor profile that permits user namespaces (see
   * infra/docker/apparmor/). Null (the default) keeps Docker's default profile.
   */
  readonly apparmorProfile: string | null;
  readonly memory: string;
  readonly pidsLimit: number;
  readonly cpus: string;
  /** `uid:gid` the container runs as. Must not be root; defaults to the supervisor's ids. */
  readonly user: string;
  /** Path of the runner entry point inside the image. */
  readonly runnerEntry: string;
  readonly chromiumPath: string;
}

export interface JobRunnerLimits {
  /** Total bytes a runner may write to stdout before it is killed. */
  readonly maxRunnerStdoutBytes: number;
  /** Total stderr bytes read from a runner; the rest is discarded. */
  readonly maxRunnerStderrBytes: number;
  /**
   * Added to a job's `timeoutMs` for the supervisor's hard deadline, covering sandbox and
   * browser start. The runner applies `timeoutMs` itself and reports `timeout` cleanly first.
   */
  readonly startupGraceMs: number;
  /** How long a finished runner gets to exit before it is killed. */
  readonly exitGraceMs: number;
  readonly egress: Partial<EgressLimits>;
}

export interface JobRunnerConfig {
  readonly sandbox: SandboxKind;
  /** Repository root on the host. Only selected code directories under it are mounted. */
  readonly repoRoot: string;
  /** Short base for per-job runtime directories (Unix socket paths are limited). */
  readonly runtimeBaseDir: string;
  readonly nodePath: string;
  readonly chromiumPath: string;
  readonly bwrapPath: string;
  /**
   * Host path of the module exporting `adapters: readonly ApplicationAdapter[]`. Set by
   * supervisor configuration only (tests point it at a fixture); never by a job message. It
   * must lie inside `repoRoot`; its directory is mounted read-only into the sandbox.
   */
  readonly adapterRegistryModule: string;
  readonly docker: DockerConfig;
  /** Display for the headed login window, or null when no display is available. */
  readonly display: DisplayConfig | null;
  readonly limits: JobRunnerLimits;
  /** Supervisor-side logger. Defaults to a silent logger. */
  readonly logger?: Logger;
  /** Called for every egress decision of every job (origin, decision, reason code only). */
  readonly onEgressDecision?: (event: EgressDecision & { readonly jobId: string }) => void;
  /**
   * Raw runner stderr lines, for diagnostics and tests. Treat them as hostile: a compromised
   * runner controls them. The supervisor's own log only ever gets allowlisted event names.
   */
  readonly onRunnerStderr?: (line: string, jobId: string) => void;
  /** Test hook: replaces DNS resolution in the egress proxy. */
  readonly egressResolver?: EgressResolver;
}

const here = path.dirname(fileURLToPath(import.meta.url));
/** `services/browser-worker` on the host. */
export const WORKER_PACKAGE_DIR = path.resolve(here, '..', '..');
export const DEFAULT_REPO_ROOT = path.resolve(WORKER_PACKAGE_DIR, '..', '..');

export const DEFAULT_LIMITS: JobRunnerLimits = {
  maxRunnerStdoutBytes: DEFAULT_MAX_RUNNER_STDOUT_BYTES,
  maxRunnerStderrBytes: 1024 * 1024,
  startupGraceMs: 20_000,
  exitGraceMs: 2_000,
  egress: {},
};

export type JobRunnerConfigInput = Partial<Omit<JobRunnerConfig, 'docker' | 'limits'>> & {
  readonly docker?: Partial<DockerConfig>;
  readonly limits?: Partial<JobRunnerLimits>;
};

/** Name reserved for the AppArmor profile of the opt-in mode. No such profile exists yet (AAB-017). */
export const BROWSER_SANDBOX_APPARMOR_PROFILE = 'aab-browser-runner';

/** Docker settings that keep Chromium's own sandbox on inside the container (opt-in). */
export function dockerBrowserSandboxProfiles(
  repoRoot: string,
): Pick<DockerConfig, 'seccompProfile' | 'apparmorProfile'> {
  return {
    seccompProfile: path.join(repoRoot, 'infra', 'docker', 'seccomp', 'browser-runner.json'),
    apparmorProfile: BROWSER_SANDBOX_APPARMOR_PROFILE,
  };
}

/** Fills in defaults. `sandbox` defaults to `bubblewrap`; `unsafe-process` is never implied. */
export function resolveJobRunnerConfig(input: JobRunnerConfigInput = {}): JobRunnerConfig {
  const repoRoot = path.resolve(input.repoRoot ?? DEFAULT_REPO_ROOT);
  const uid = process.getuid?.() ?? 1000;
  const gid = process.getgid?.() ?? 1000;
  return {
    sandbox: input.sandbox ?? 'bubblewrap',
    repoRoot,
    runtimeBaseDir: input.runtimeBaseDir ?? defaultRuntimeBaseDir(),
    nodePath: input.nodePath ?? '/usr/bin/node',
    chromiumPath: input.chromiumPath ?? '/usr/lib/chromium/chromium',
    bwrapPath: input.bwrapPath ?? '/usr/bin/bwrap',
    adapterRegistryModule:
      input.adapterRegistryModule ??
      path.join(repoRoot, 'services', 'browser-worker', 'src', 'adapters.ts'),
    docker: {
      binary: 'docker',
      image: 'aab/browser-runner:local',
      seccompProfile: null,
      apparmorProfile: null,
      memory: '1g',
      pidsLimit: 512,
      cpus: '2',
      user: `${uid}:${gid}`,
      runnerEntry: '/app/services/browser-worker/src/runner/main.ts',
      chromiumPath: '/usr/lib/chromium/chromium',
      ...input.docker,
    },
    display: input.display === undefined ? null : input.display,
    limits: { ...DEFAULT_LIMITS, ...input.limits },
    ...(input.logger === undefined ? {} : { logger: input.logger }),
    ...(input.onEgressDecision === undefined ? {} : { onEgressDecision: input.onEgressDecision }),
    ...(input.onRunnerStderr === undefined ? {} : { onRunnerStderr: input.onRunnerStderr }),
    ...(input.egressResolver === undefined ? {} : { egressResolver: input.egressResolver }),
  };
}

/**
 * Reads display settings from an environment (for the supervisor's config mapping). Wayland is
 * preferred when both are present.
 */
export function displayFromEnvironment(env: NodeJS.ProcessEnv = process.env): DisplayConfig | null {
  const runtimeDir = env['XDG_RUNTIME_DIR'];
  const wayland = env['WAYLAND_DISPLAY'];
  if (wayland !== undefined && wayland !== '') {
    const socket = path.isAbsolute(wayland)
      ? wayland
      : runtimeDir === undefined
        ? undefined
        : path.join(runtimeDir, wayland);
    if (socket !== undefined && existsSync(socket)) return { waylandSocket: socket };
  }
  const display = env['DISPLAY'];
  if (display !== undefined && display !== '') {
    const home = env['HOME'];
    const xauthority =
      env['XAUTHORITY'] ?? (home === undefined ? undefined : path.join(home, '.Xauthority'));
    return {
      x11Display: display,
      ...(xauthority !== undefined && existsSync(xauthority) ? { xauthority } : {}),
    };
  }
  return null;
}
