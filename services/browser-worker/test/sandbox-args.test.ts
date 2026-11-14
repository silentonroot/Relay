import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import {
  buildBubblewrapArgs,
  displayBinding,
  registryMountFor,
} from '../src/sandbox/bubblewrap.js';
import {
  DEFAULT_REPO_ROOT,
  dockerBrowserSandboxProfiles,
  resolveJobRunnerConfig,
} from '../src/sandbox/config.js';
import type { DockerConfig } from '../src/sandbox/config.js';
import { buildDockerRunArgs, containerNameFor } from '../src/sandbox/docker.js';
import { createJobRuntimeDir } from '../src/sandbox/runtime-dir.js';

const request = {
  jobId: 'job-1',
  jobDir: '/run/user/1000/aab-worker/abc',
  socketPath: '/run/user/1000/aab-worker/abc/egress.sock',
  headed: false,
};

/** Pairs of `--flag value` from an argument list. */
function pairs(args: readonly string[], flag: string): string[] {
  return args.flatMap((arg, index) => (arg === flag ? [args[index + 1] ?? ''] : []));
}

describe('docker arguments', () => {
  const config = resolveJobRunnerConfig({
    sandbox: 'docker',
    docker: { image: 'aab/browser-runner:test', user: '1000:1000', memory: '768m', pidsLimit: 256 },
  });

  it('builds a locked-down docker run command', () => {
    const args = buildDockerRunArgs(config, request);
    expect(args.slice(0, 3)).toEqual(['run', '--rm', '-i']);
    expect(pairs(args, '--network')).toEqual(['none']);
    expect(args).toContain('--read-only');
    expect(pairs(args, '--cap-drop')).toEqual(['ALL']);
    // Default: Docker's own seccomp and AppArmor profiles, and Chromium's sandbox off.
    expect(pairs(args, '--security-opt')).toEqual(['no-new-privileges']);
    expect(pairs(args, '--memory')).toEqual(['768m']);
    expect(pairs(args, '--memory-swap')).toEqual(['768m']);
    expect(pairs(args, '--pids-limit')).toEqual(['256']);
    expect(pairs(args, '--user')).toEqual(['1000:1000']);
    expect(pairs(args, '--tmpfs')).toEqual([
      '/tmp:rw,nosuid,nodev,size=512m,mode=1777',
      '/home/runner:rw,nosuid,nodev,size=64m,uid=1000,gid=1000,mode=0700',
    ]);
    expect(pairs(args, '--mount')).toEqual([
      'type=bind,source=/run/user/1000/aab-worker/abc,target=/run/aab,readonly',
    ]);
    expect(pairs(args, '--name')).toEqual([containerNameFor('job-1')]);
    expect(pairs(args, '--env')).toContain('AAB_RUNNER_CHROMIUM_SANDBOX=0');
    expect(pairs(args, '--env')).toContain(
      'AAB_RUNNER_REGISTRY=/app/services/browser-worker/src/adapters.ts',
    );
    // No other mounts, no host environment passthrough, no privileges.
    expect(args).not.toContain('-v');
    expect(args).not.toContain('--volume');
    expect(args).not.toContain('--privileged');
    expect(args.some((arg) => arg.startsWith('--env-file'))).toBe(false);
    expect(pairs(args, '--env').every((env) => env.includes('='))).toBe(true);
    const imageIndex = args.indexOf('aab/browser-runner:test');
    expect(args.slice(imageIndex + 1)).toEqual([
      'node',
      '--import',
      'tsx',
      '/app/services/browser-worker/src/runner/main.ts',
    ]);
  });

  it("keeps Chromium's sandbox on only with both the seccomp and the AppArmor profile", () => {
    const profiles = dockerBrowserSandboxProfiles(DEFAULT_REPO_ROOT);
    const hardened = resolveJobRunnerConfig({ sandbox: 'docker', docker: profiles });
    const args = buildDockerRunArgs(hardened, request);
    expect(pairs(args, '--security-opt')).toEqual([
      'no-new-privileges',
      `seccomp=${path.join(DEFAULT_REPO_ROOT, 'infra/docker/seccomp/browser-runner.json')}`,
      'apparmor=aab-browser-runner',
    ]);
    expect(pairs(args, '--env')).toContain('AAB_RUNNER_CHROMIUM_SANDBOX=1');

    const only = (docker: Partial<DockerConfig>) =>
      buildDockerRunArgs(resolveJobRunnerConfig({ sandbox: 'docker', docker }), request);
    expect(() => only({ seccompProfile: profiles.seccompProfile })).toThrow(/both/);
    expect(() => only({ apparmorProfile: profiles.apparmorProfile })).toThrow(/both/);
    expect(() => only({ ...profiles, apparmorProfile: 'unconfined' })).toThrow(/AppArmor/);
    expect(() => only({ ...profiles, apparmorProfile: 'bad name' })).toThrow(/AppArmor/);
  });

  it('refuses root and headed jobs', () => {
    expect(() =>
      buildDockerRunArgs(resolveJobRunnerConfig({ docker: { user: '0:0' } }), request),
    ).toThrow(/root/);
    expect(() =>
      buildDockerRunArgs(resolveJobRunnerConfig({ docker: { user: 'root' } }), request),
    ).toThrow(/root/);
    expect(() =>
      buildDockerRunArgs(resolveJobRunnerConfig({ docker: { user: 'node' } }), request),
    ).toThrow(/numeric/);
    expect(() => buildDockerRunArgs(config, { ...request, headed: true })).toThrow(/headed/);
  });

  it('sanitizes the container name', () => {
    expect(containerNameFor('a/b c;$(x)')).toBe('aab-runner-abcx');
  });
});

describe('bubblewrap arguments', () => {
  const config = resolveJobRunnerConfig({});

  it('mounts only the code the runner needs, read-only, at /app', async () => {
    const { args } = await buildBubblewrapArgs(config, request);
    for (const flag of ['--unshare-all', '--die-with-parent', '--new-session', '--clearenv']) {
      expect(args).toContain(flag);
    }
    expect(pairs(args, '--cap-drop')).toEqual(['ALL']);
    expect(args).not.toContain('--share-net');
    const binds: [string, string][] = [];
    args.forEach((arg, index) => {
      if (arg === '--ro-bind') binds.push([args[index + 1] ?? '', args[index + 2] ?? '']);
    });
    const repo = config.repoRoot;
    expect(binds).toContainEqual([path.join(repo, 'node_modules'), '/app/node_modules']);
    expect(binds).toContainEqual([
      path.join(repo, 'services/browser-worker/src'),
      '/app/services/browser-worker/src',
    ]);
    // Never the repository root, never a home directory.
    expect(binds.map(([source]) => source)).not.toContain(repo);
    expect(binds.some(([, target]) => target === '/app')).toBe(false);
    expect(binds.some(([source]) => source === os.homedir() || source === '/home')).toBe(false);
    expect(args).not.toContain('--bind');
    expect(pairs(args, '--chdir')).toEqual(['/app']);
    expect(args.slice(-4)).toEqual([
      '/usr/bin/node',
      '--import',
      'tsx',
      '/app/services/browser-worker/src/runner/main.ts',
    ]);
  });

  it('mounts a registry module outside src by its own directory only', () => {
    const repo = config.repoRoot;
    expect(
      registryMountFor(repo, path.join(repo, 'services/browser-worker/src/adapters.ts')),
    ).toBeNull();
    expect(
      registryMountFor(
        repo,
        path.join(repo, 'services/browser-worker/test/fixtures/registry/index.ts'),
      ),
    ).toBe('services/browser-worker/test/fixtures/registry');
    expect(() => registryMountFor(repo, '/etc/passwd')).toThrow();
    expect(() => registryMountFor(repo, path.join(repo, 'evil.ts'))).toThrow();
    expect(() => registryMountFor(repo, path.join(repo, 'apps/x.ts'))).toThrow();
  });

  it('binds the display only for headed jobs and prefers Wayland', async () => {
    const dir = await mkdtemp(path.join(os.tmpdir(), 'aab-display-'));
    try {
      const wayland = path.join(dir, 'wayland-1');
      await writeFile(wayland, '');
      expect(displayBinding({ waylandSocket: wayland, x11Display: ':0' })).toMatchObject({
        kind: 'wayland',
        env: { WAYLAND_DISPLAY: 'wayland-0', XDG_RUNTIME_DIR: '/run/aab' },
      });
      expect(() => displayBinding({ x11Display: 'remote.example:10' })).toThrow(/local X11/);
      expect(() => displayBinding(null)).toThrow(/no display/);
      const { args } = await buildBubblewrapArgs(config, request);
      expect(args.join(' ')).not.toContain('X11-unix');
      expect(args.join(' ')).not.toContain('WAYLAND');
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe('runtime directory', () => {
  const base = '/run/user/1000/aab-worker-test-ignored';
  afterAll(async () => {
    await rm(base, { recursive: true, force: true });
  });

  it('fails clearly when the socket path would be too long', async () => {
    const long = path.join(os.tmpdir(), 'x'.repeat(120));
    await expect(createJobRuntimeDir(long)).rejects.toThrow(/Unix socket limit/);
    await rm(long, { recursive: true, force: true });
  });
});
