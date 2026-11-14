import { existsSync, statSync } from 'node:fs';
import { readdir } from 'node:fs/promises';
import path from 'node:path';
import type { DisplayConfig, JobRunnerConfig } from './config.js';
import { RUNNER_ENV, spawnDetached, wrapChild } from './launcher.js';
import type { LaunchRequest, SandboxLauncher, SandboxProcess } from './launcher.js';

/** Where the code is mounted inside the sandbox. A neutral path, never the host path. */
export const SANDBOX_APP_DIR = '/app';
export const SANDBOX_RUN_DIR = '/run/aab';
export const SANDBOX_HOME = '/home/runner';
export const RUNNER_ENTRY_RELATIVE = 'services/browser-worker/src/runner/main.ts';

/**
 * The only parts of the repository the runner needs, relative to the repository root. Never
 * the whole repository: it can hold `.env` files and key material.
 */
export const CODE_MOUNTS: readonly string[] = [
  'package.json',
  'node_modules',
  'packages',
  'services/browser-worker/package.json',
  'services/browser-worker/node_modules',
  'services/browser-worker/src',
];

/** Names that are hidden (bound over with /dev/null) wherever they appear in mounted code. */
const SENSITIVE_FILE = /^(?:\.env(?:\..*)?|.*\.(?:pem|key|kek|p12|pfx)|id_[a-z0-9]+)$/i;
const SENSITIVE_DIR = /^(?:\.aab|\.git|\.ssh|\.gnupg|var)$/;

function isInside(parent: string, child: string): boolean {
  const relative = path.relative(parent, child);
  return relative !== '' && !relative.startsWith('..') && !path.isAbsolute(relative);
}

/** Directory to mount for the adapter registry, relative to the repo root, or null if covered. */
export function registryMountFor(repoRoot: string, registryModule: string): string | null {
  const absolute = path.resolve(registryModule);
  if (!isInside(repoRoot, absolute)) {
    throw new Error('the adapter registry module must be inside the repository root');
  }
  const relative = path.relative(repoRoot, absolute);
  const covered = CODE_MOUNTS.some(
    (mount) => relative === mount || relative.startsWith(`${mount}${path.sep}`),
  );
  if (covered) return null;
  const directory = path.dirname(relative);
  if (directory === '.' || directory.split(path.sep).length < 2) {
    throw new Error('the adapter registry module must be at least two directories deep');
  }
  return directory;
}

/** Translates a host path inside the repository to its path in the sandbox. */
export function sandboxPathFor(repoRoot: string, hostPath: string): string {
  const absolute = path.resolve(hostPath);
  if (!isInside(repoRoot, absolute)) throw new Error('path is outside the repository root');
  return path.posix.join(SANDBOX_APP_DIR, ...path.relative(repoRoot, absolute).split(path.sep));
}

/** Finds files and directories to hide under the mounted code (skipping dependency trees). */
export async function findSensitivePaths(root: string, relative: string): Promise<string[]> {
  const found: string[] = [];
  const walk = async (dir: string, depth: number): Promise<void> => {
    if (depth > 12) return;
    let entries;
    try {
      entries = await readdir(path.join(root, dir), { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const child = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (entry.name === 'node_modules') continue;
        if (SENSITIVE_DIR.test(entry.name)) {
          found.push(child);
          continue;
        }
        await walk(child, depth + 1);
      } else if (SENSITIVE_FILE.test(entry.name)) {
        found.push(child);
      }
    }
  };
  await walk(relative, 0);
  return found;
}

interface DisplayBinding {
  readonly args: string[];
  readonly env: Record<string, string>;
  readonly kind: 'x11' | 'wayland';
}

/** Mounts and variables for the headed login window. Prefers Wayland when both are set. */
export function displayBinding(display: DisplayConfig | null): DisplayBinding {
  if (display?.waylandSocket !== undefined) {
    if (!existsSync(display.waylandSocket)) {
      throw new Error('the configured Wayland socket does not exist');
    }
    const target = `${SANDBOX_RUN_DIR}/wayland-0`;
    return {
      kind: 'wayland',
      args: ['--ro-bind', display.waylandSocket, target],
      env: { XDG_RUNTIME_DIR: SANDBOX_RUN_DIR, WAYLAND_DISPLAY: 'wayland-0' },
    };
  }
  if (display?.x11Display !== undefined) {
    // Only local displays: the sandbox has no network, so TCP displays cannot work, and the
    // abstract socket namespace belongs to the host's network namespace.
    const match = /^(?:unix)?:(\d+)(?:\.\d+)?$/.exec(display.x11Display);
    if (match === null) {
      throw new Error('only a local X11 display (":N") can be used for the login window');
    }
    const socket = `/tmp/.X11-unix/X${match[1]}`;
    if (!existsSync(socket)) throw new Error(`the X11 socket ${socket} does not exist`);
    const args = ['--ro-bind', socket, socket];
    const env: Record<string, string> = { DISPLAY: `:${match[1]}` };
    if (display.xauthority !== undefined) {
      const target = `${SANDBOX_RUN_DIR}/Xauthority`;
      args.push('--ro-bind', display.xauthority, target);
      env['XAUTHORITY'] = target;
    }
    return { kind: 'x11', args, env };
  }
  throw new Error('no display is configured for the login window');
}

export interface BubblewrapPlan {
  readonly args: string[];
  readonly displayKind: 'x11' | 'wayland' | null;
}

function bindSystemBinary(binary: string, args: string[]): void {
  if (binary.startsWith('/usr/')) return;
  const directory = path.dirname(binary);
  args.push('--ro-bind', directory, directory);
}

/** Builds the full bubblewrap argument list for one job. Exported for tests. */
export async function buildBubblewrapArgs(
  config: JobRunnerConfig,
  request: LaunchRequest,
): Promise<BubblewrapPlan> {
  const repo = config.repoRoot;
  const args: string[] = [
    '--unshare-all',
    '--die-with-parent',
    '--new-session',
    '--cap-drop',
    'ALL',
    '--clearenv',
    '--ro-bind',
    '/usr',
    '/usr',
    '--symlink',
    'usr/lib',
    '/lib',
    '--symlink',
    'usr/lib64',
    '/lib64',
    '--symlink',
    'usr/bin',
    '/bin',
    '--symlink',
    'usr/sbin',
    '/sbin',
    '--ro-bind',
    '/etc/fonts',
    '/etc/fonts',
    '--ro-bind-try',
    '/etc/ssl',
    '/etc/ssl',
    '--ro-bind-try',
    '/etc/ca-certificates',
    '/etc/ca-certificates',
    '--ro-bind-try',
    '/etc/ld.so.cache',
    '/etc/ld.so.cache',
    '--ro-bind-try',
    '/etc/localtime',
    '/etc/localtime',
    '--proc',
    '/proc',
    '--dev',
    '/dev',
    '--tmpfs',
    '/tmp',
    '--tmpfs',
    SANDBOX_HOME,
    '--dir',
    SANDBOX_RUN_DIR,
    '--ro-bind',
    request.socketPath,
    `${SANDBOX_RUN_DIR}/egress.sock`,
  ];
  bindSystemBinary(config.nodePath, args);
  bindSystemBinary(config.chromiumPath, args);

  const mounts = [...CODE_MOUNTS];
  const registryDir = registryMountFor(repo, config.adapterRegistryModule);
  if (registryDir !== null) mounts.push(registryDir);
  for (const mount of mounts) {
    const host = path.join(repo, mount);
    if (!existsSync(host)) throw new Error(`required code path is missing: ${mount}`);
    args.push('--ro-bind', host, sandboxPathFor(repo, host));
  }
  // Hide anything that looks like configuration or key material inside the mounted code.
  for (const mount of mounts) {
    const host = path.join(repo, mount);
    if (!statSync(host).isDirectory()) continue;
    for (const hidden of await findSensitivePaths(repo, mount)) {
      const target = sandboxPathFor(repo, path.join(repo, hidden));
      if (statSync(path.join(repo, hidden)).isDirectory()) {
        args.push('--tmpfs', target);
      } else {
        args.push('--ro-bind', '/dev/null', target);
      }
    }
  }

  let displayKind: BubblewrapPlan['displayKind'] = null;
  const env: Record<string, string> = {
    HOME: SANDBOX_HOME,
    PATH: '/usr/bin:/bin',
    TMPDIR: '/tmp',
    LANG: 'C.UTF-8',
    [RUNNER_ENV.chromium]: config.chromiumPath,
    [RUNNER_ENV.chromiumSandbox]: '1',
    [RUNNER_ENV.registry]: sandboxPathFor(repo, config.adapterRegistryModule),
    [RUNNER_ENV.egressSocket]: `${SANDBOX_RUN_DIR}/egress.sock`,
    [RUNNER_ENV.jobMarker]: request.jobId,
  };
  if (request.headed) {
    const binding = displayBinding(config.display);
    args.push(...binding.args);
    Object.assign(env, binding.env);
    env[RUNNER_ENV.display] = binding.kind;
    displayKind = binding.kind;
  }
  for (const [name, value] of Object.entries(env)) args.push('--setenv', name, value);

  const entry =
    request.entryOverride === undefined
      ? path.posix.join(SANDBOX_APP_DIR, RUNNER_ENTRY_RELATIVE)
      : sandboxPathFor(repo, request.entryOverride);
  args.push('--chdir', SANDBOX_APP_DIR, '--', config.nodePath, '--import', 'tsx', entry);
  return { args, displayKind };
}

export function createBubblewrapLauncher(config: JobRunnerConfig): SandboxLauncher {
  return {
    kind: 'bubblewrap',
    supportsHeaded: true,
    async launch(request: LaunchRequest): Promise<SandboxProcess> {
      const plan = await buildBubblewrapArgs(config, request);
      const child = spawnDetached(config.bwrapPath, plan.args, { env: {} });
      return wrapChild(child);
    },
  };
}
