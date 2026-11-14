import { spawn } from 'node:child_process';
import type { JobRunnerConfig } from './config.js';
import { SANDBOX_HOME, SANDBOX_RUN_DIR, sandboxPathFor } from './bubblewrap.js';
import { RUNNER_ENV, spawnDetached, wrapChild } from './launcher.js';
import type { LaunchRequest, SandboxLauncher, SandboxProcess } from './launcher.js';

/*
 * Docker launcher. Run against Docker 28.5 on 2026-11-13 (see docs/operations.md).
 *
 * Chromium's own sandbox needs to create user namespaces. Docker forbids that twice over: its
 * default seccomp profile blocks the system calls without CAP_SYS_ADMIN, and on kernels where
 * AppArmor mediates user namespaces its default AppArmor profile denies their creation. So
 * there are two modes:
 *
 * - Default (`seccompProfile` null): Docker's own seccomp and AppArmor profiles, unchanged,
 *   and Chromium runs with its sandbox off. The container is the only boundary around the
 *   browser, and it is Docker's standard, widely reviewed one.
 * - Opt-in (`seccompProfile` and `apparmorProfile` both set): the container allows user
 *   namespaces and Chromium's sandbox stays on. Two layers, but the outer one exposes more of
 *   the kernel. NOT USABLE YET: infra/docker/seccomp/browser-runner.json is an unreviewed
 *   draft, and the AppArmor profile it needs (which an administrator would load once) has not
 *   been written (backlog AAB-017). No environment variable selects this mode.
 *
 * Setting only one of the two is refused: a seccomp profile without the AppArmor profile
 * fails at browser start on such kernels, and `apparmor=unconfined` is never used.
 */

const SAFE_NAME = /^[A-Za-z0-9_.-]{1,64}$/;

export function containerNameFor(jobId: string): string {
  const cleaned = jobId.replace(/[^A-Za-z0-9_.-]/g, '').slice(0, 40);
  return `aab-runner-${cleaned === '' ? 'job' : cleaned}`;
}

/** Builds the `docker run` argument list for one job. Exported for tests. */
export function buildDockerRunArgs(config: JobRunnerConfig, request: LaunchRequest): string[] {
  if (request.headed) {
    throw new Error('the docker sandbox does not support the headed login window in Phase 2');
  }
  const docker = config.docker;
  if (/^0(?::|$)/.test(docker.user) || /^root(?::|$)/.test(docker.user)) {
    throw new Error('the docker sandbox must not run as root');
  }
  const ids = /^(\d+):(\d+)$/.exec(docker.user);
  if (ids === null) throw new Error('the docker sandbox user must be numeric "uid:gid"');
  const [, uid, gid] = ids;
  if ((docker.seccompProfile === null) !== (docker.apparmorProfile === null)) {
    throw new Error(
      'the docker sandbox needs both a seccomp profile and an AppArmor profile to keep the ' +
        "browser's own sandbox on, or neither",
    );
  }
  if (docker.apparmorProfile !== null && !/^[A-Za-z0-9_.-]{1,64}$/.test(docker.apparmorProfile)) {
    throw new Error('invalid AppArmor profile name');
  }
  if (docker.apparmorProfile === 'unconfined') {
    throw new Error('the docker sandbox never runs without AppArmor confinement');
  }
  const name = containerNameFor(request.jobId);
  if (!SAFE_NAME.test(name)) throw new Error('invalid container name');
  const chromiumSandbox = docker.seccompProfile !== null;

  return [
    'run',
    '--rm',
    '-i',
    '--name',
    name,
    '--network',
    'none',
    '--read-only',
    '--cap-drop',
    'ALL',
    '--security-opt',
    'no-new-privileges',
    ...(docker.seccompProfile === null || docker.apparmorProfile === null
      ? []
      : [
          '--security-opt',
          `seccomp=${docker.seccompProfile}`,
          '--security-opt',
          `apparmor=${docker.apparmorProfile}`,
        ]),
    '--memory',
    docker.memory,
    '--memory-swap',
    docker.memory,
    '--pids-limit',
    String(docker.pidsLimit),
    '--cpus',
    docker.cpus,
    '--user',
    docker.user,
    '--init',
    '--ipc',
    'private',
    '--log-driver',
    'none',
    // A tmpfs takes the owner and mode of the image directory under it unless told otherwise,
    // and the job runs as an arbitrary non-root uid, so both are stated here.
    '--tmpfs',
    '/tmp:rw,nosuid,nodev,size=512m,mode=1777',
    '--tmpfs',
    `${SANDBOX_HOME}:rw,nosuid,nodev,size=64m,uid=${uid},gid=${gid},mode=0700`,
    // The job directory holds only the egress socket; mounted read-only.
    '--mount',
    `type=bind,source=${request.jobDir},target=${SANDBOX_RUN_DIR},readonly`,
    '--workdir',
    '/app',
    '--env',
    `HOME=${SANDBOX_HOME}`,
    '--env',
    'TMPDIR=/tmp',
    '--env',
    `${RUNNER_ENV.chromium}=${docker.chromiumPath}`,
    '--env',
    `${RUNNER_ENV.chromiumSandbox}=${chromiumSandbox ? '1' : '0'}`,
    '--env',
    `${RUNNER_ENV.registry}=${sandboxPathFor(config.repoRoot, config.adapterRegistryModule)}`,
    '--env',
    `${RUNNER_ENV.egressSocket}=${SANDBOX_RUN_DIR}/egress.sock`,
    '--env',
    `${RUNNER_ENV.jobMarker}=${name}`,
    docker.image,
    'node',
    '--import',
    'tsx',
    docker.runnerEntry,
  ];
}

export function createDockerLauncher(config: JobRunnerConfig): SandboxLauncher {
  return {
    kind: 'docker',
    supportsHeaded: false,
    async launch(request: LaunchRequest): Promise<SandboxProcess> {
      if (request.entryOverride !== undefined) {
        throw new Error('the docker sandbox does not support entry overrides');
      }
      const args = buildDockerRunArgs(config, request);
      const name = containerNameFor(request.jobId);
      const child = spawnDetached(config.docker.binary, args, {
        env: { PATH: process.env['PATH'] ?? '/usr/bin:/bin', HOME: process.env['HOME'] ?? '/' },
      });
      return wrapChild(
        child,
        () =>
          new Promise<void>((resolve) => {
            const killer = spawn(config.docker.binary, ['kill', name], { stdio: 'ignore' });
            killer.once('exit', () => resolve());
            killer.once('error', () => resolve());
          }),
      );
    },
  };
}
