import { execFileSync } from 'node:child_process';
import { describe, expect, it } from 'vitest';
import { resolveJobRunnerConfig } from '../../src/sandbox/config.js';
import { buildDockerRunArgs } from '../../src/sandbox/docker.js';
import { createJobRunner } from '../../src/sandbox/index.js';
import { runtimeBaseDir } from '../fixtures/run-context.js';

/*
 * The Docker launcher against a real engine, in its default mode: Docker's own seccomp and
 * AppArmor profiles, Chromium's sandbox off, the container as the boundary.
 *
 * Needs a reachable Docker engine and the image built from
 * infra/docker/browser-runner.Dockerfile (`aab/browser-runner:local`). Skips otherwise, with
 * the reason in the title.
 */

const IMAGE = 'aab/browser-runner:local';

function docker(args: string[]): string {
  return execFileSync('docker', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
}

function skipReason(): string | null {
  try {
    docker(['version', '--format', '{{.Server.Version}}']);
  } catch {
    return 'no reachable Docker engine';
  }
  try {
    docker(['image', 'inspect', '--format', '{{.Id}}', IMAGE]);
  } catch {
    return `image ${IMAGE} is not built`;
  }
  return null;
}

const reason = skipReason();
if (reason !== null && process.env['AAB_REQUIRE_DOCKER'] === '1') {
  // Continuous integration builds the image first, so a skip there is a failure.
  throw new Error(`AAB_REQUIRE_DOCKER=1 but the Docker launcher tests cannot run: ${reason}`);
}
const title = `docker sandbox${reason === null ? '' : ` (skipped: ${reason})`}`;

/** Job ids and container names carry this process's pid, so a concurrent run has its own. */
const RUN_TAG = `${process.pid}`;

function runnerContainers(prefix = 'aab-runner-'): string[] {
  return docker(['ps', '-a', '--filter', `name=${prefix}`, '--format', '{{.Names}}'])
    .split('\n')
    .filter((name) => name !== '');
}

/**
 * Self-check containers get a random name the test cannot choose, so another run's self-check
 * may be alive for a moment. Waits for them all to be gone instead of failing on a stranger's.
 */
async function expectNoSelfCheckContainers(): Promise<void> {
  const deadline = Date.now() + 60_000;
  while (runnerContainers('aab-runner-self-check-').length > 0 && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  expect(runnerContainers('aab-runner-self-check-')).toEqual([]);
}

/** Runs a shell snippet in a container started with exactly the launcher's flags. */
function probe(script: string): string {
  const config = resolveJobRunnerConfig({ sandbox: 'docker' });
  const jobDir = '/tmp';
  const args = buildDockerRunArgs(config, {
    jobId: `probe-${RUN_TAG}`,
    jobDir,
    socketPath: `${jobDir}/egress.sock`,
    headed: false,
  });
  const image = args.indexOf(IMAGE);
  // Same flags; only the command after the image differs. `-i` is dropped so stdin is closed.
  const flags = args.slice(0, image).filter((arg) => arg !== '-i');
  return docker([...flags, IMAGE, 'sh', '-c', script]);
}

describe.skipIf(reason !== null)(title, () => {
  it('passes the self-check: runner and Chromium start, no network, no host loopback', async () => {
    const runner = createJobRunner({ sandbox: 'docker', runtimeBaseDir: runtimeBaseDir() });
    await expect(runner.selfCheck()).resolves.toBeUndefined();
    await expectNoSelfCheckContainers();
  }, 120_000);

  it('gives the job a read-only root, a private writable home and no capabilities', () => {
    const output = probe(
      [
        'id -u',
        'touch /app/x 2>/dev/null && echo root-writable || echo root-readonly',
        'touch "$HOME/x" && echo home-writable',
        'touch /run/aab/x 2>/dev/null && echo run-writable || echo run-readonly',
        "grep -E '^(CapEff|CapPrm|CapBnd|NoNewPrivs|Seccomp):' /proc/self/status",
        'ls /sys/class/net',
        'env | grep -c -E "DATABASE_URL|AAB_KEK_DIR" || true',
      ].join('; '),
    );
    const lines = output.trim().split('\n');
    expect(lines[0]).toBe(String(process.getuid?.()));
    expect(lines).toContain('root-readonly');
    expect(lines).toContain('home-writable');
    expect(lines).toContain('run-readonly');
    expect(output).toMatch(/CapEff:\s+0000000000000000/);
    expect(output).toMatch(/CapBnd:\s+0000000000000000/);
    expect(output).toMatch(/NoNewPrivs:\s+1/);
    // Seccomp mode 2 is "filter": Docker's default profile is in force.
    expect(output).toMatch(/Seccomp:\s+2/);
    expect(lines).toContain('lo');
    expect(lines.filter((line) => /^(eth|en|wl|veth)/.test(line))).toEqual([]);
    expect(lines.at(-1)).toBe('0');
  }, 60_000);

  it('refuses user namespaces under the default profiles', () => {
    // This is why Chromium's own sandbox is off in the default mode.
    const output = probe('unshare -U true 2>&1 || echo userns-refused');
    expect(output).toContain('userns-refused');
  }, 60_000);

  it('fails a job cleanly when the application is unreachable, leaving no container', async () => {
    const runner = createJobRunner({ sandbox: 'docker', runtimeBaseDir: runtimeBaseDir() });
    const outcome = await runner.runOperation(
      {
        jobId: `dockertest-unreachable-${RUN_TAG}`,
        connectionId: '00000000-0000-4000-8000-000000000001',
        adapterId: 'northstar',
        adapterVersion: '0.1.0',
        // Nothing is expected to listen here; if the demo happens to run, the stale cookie
        // below is rejected and the job ends as reauth_required instead.
        allowedOrigins: ['http://localhost:4100'],
        operation: 'orders.list',
        arguments: { limit: 1 },
        storageState: {
          cookies: [
            {
              name: 'northstar_sid',
              value: 'synthetic-not-a-session',
              domain: 'localhost',
              path: '/',
              expires: -1,
              httpOnly: true,
              secure: false,
              sameSite: 'Lax',
            },
          ],
          origins: [],
        },
        expectedAccountHint: null,
        timeoutMs: 30_000,
      },
      new AbortController().signal,
    );
    expect(['failed', 'reauth_required']).toContain(outcome.status);
    expect(runnerContainers(`aab-runner-dockertest-unreachable-${RUN_TAG}`)).toEqual([]);
  }, 120_000);

  it('rejects the headed login window', async () => {
    const runner = createJobRunner({ sandbox: 'docker', runtimeBaseDir: runtimeBaseDir() });
    await expect(
      runner.startLogin(
        {
          jobId: `dockertest-login-${RUN_TAG}`,
          connectionId: '00000000-0000-4000-8000-000000000001',
          adapterId: 'northstar',
          adapterVersion: '0.1.0',
          allowedOrigins: ['http://localhost:4100'],
          timeoutMs: 10_000,
        },
        new AbortController().signal,
      ),
    ).rejects.toThrow();
    expect(runnerContainers(`aab-runner-dockertest-login-${RUN_TAG}`)).toEqual([]);
  }, 60_000);
});
