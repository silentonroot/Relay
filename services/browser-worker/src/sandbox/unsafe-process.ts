import path from 'node:path';
import type { JobRunnerConfig } from './config.js';
import { RUNNER_ENTRY_RELATIVE } from './bubblewrap.js';
import { RUNNER_ENV, spawnDetached, wrapChild } from './launcher.js';
import type { LaunchRequest, SandboxLauncher, SandboxProcess } from './launcher.js';

/**
 * No isolation at all: the runner is an ordinary child process with the supervisor's network
 * and filesystem. For development on hosts with neither bubblewrap nor a container engine.
 * The environment is still cleared and the egress proxy is still used by the browser, but
 * nothing stops a compromised runner from ignoring it. No ADR-013 claim holds.
 */
export function createUnsafeProcessLauncher(config: JobRunnerConfig): SandboxLauncher {
  return {
    kind: 'unsafe-process',
    supportsHeaded: true,
    async launch(request: LaunchRequest): Promise<SandboxProcess> {
      const env: NodeJS.ProcessEnv = {
        HOME: request.jobDir,
        PATH: '/usr/bin:/bin',
        TMPDIR: request.jobDir,
        LANG: 'C.UTF-8',
        [RUNNER_ENV.chromium]: config.chromiumPath,
        [RUNNER_ENV.chromiumSandbox]: '1',
        [RUNNER_ENV.registry]: path.resolve(config.adapterRegistryModule),
        [RUNNER_ENV.egressSocket]: request.socketPath,
        [RUNNER_ENV.jobMarker]: request.jobId,
      };
      if (request.headed) {
        const display = config.display;
        if (display?.waylandSocket !== undefined) {
          env['XDG_RUNTIME_DIR'] = path.dirname(display.waylandSocket);
          env['WAYLAND_DISPLAY'] = path.basename(display.waylandSocket);
          env[RUNNER_ENV.display] = 'wayland';
        } else if (display?.x11Display !== undefined) {
          env['DISPLAY'] = display.x11Display;
          if (display.xauthority !== undefined) env['XAUTHORITY'] = display.xauthority;
          env[RUNNER_ENV.display] = 'x11';
        } else {
          throw new Error('no display is configured for the login window');
        }
      }
      const entry = request.entryOverride ?? path.join(config.repoRoot, RUNNER_ENTRY_RELATIVE);
      const child = spawnDetached(config.nodePath, ['--import', 'tsx', entry], {
        env,
        cwd: config.repoRoot,
      });
      return wrapChild(child);
    },
  };
}
