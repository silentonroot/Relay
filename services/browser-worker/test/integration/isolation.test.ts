import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { copyFileSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import net from 'node:net';
import type { AddressInfo } from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createEgressProxy } from '../../src/egress/proxy.js';
import { DEFAULT_REPO_ROOT, resolveJobRunnerConfig } from '../../src/sandbox/config.js';
import { createLauncher } from '../../src/sandbox/job-runner.js';
import { createJobRuntimeDir } from '../../src/sandbox/runtime-dir.js';
import { runtimeBaseDir } from '../fixtures/run-context.js';
import {
  BWRAP,
  CHROMIUM,
  createHarness,
  integrationSkipReason,
  integrationTitle,
} from './helpers.js';

/*
 * Proves what the sandbox cannot reach. A "repo-like" directory is assembled in a temp
 * location (code copied, dependencies symlinked) with canary secrets planted where a real
 * checkout keeps them; a probe script runs in the sandbox in place of the runner.
 */

const CANARY = `CANARY-${randomBytes(8).toString('hex')}`;
const real = DEFAULT_REPO_ROOT;
let fakeRepo: string;
let listener: net.Server;
let port: number;

interface ProbeResult {
  contents: Record<string, string | null>;
  exists: Record<string, boolean>;
  home: string[] | null;
  root: string[];
  app: string[];
  interfaces: string[];
  loopback: string;
  unix: Record<string, string>;
  envKeys: string[];
}

describe.skipIf(integrationSkipReason !== null)(integrationTitle('bubblewrap isolation'), () => {
  beforeAll(async () => {
    fakeRepo = mkdtempSync(path.join(os.tmpdir(), 'aab-fake-repo-'));
    const copy = (relative: string): void => {
      mkdirSync(path.dirname(path.join(fakeRepo, relative)), { recursive: true });
      // -a keeps pnpm's relative symlinks, so they resolve under /app exactly as in a checkout.
      execFileSync('cp', ['-a', path.join(real, relative), path.join(fakeRepo, relative)]);
    };
    copyFileSync(path.join(real, 'package.json'), path.join(fakeRepo, 'package.json'));
    symlinkSync(path.join(real, 'node_modules'), path.join(fakeRepo, 'node_modules'));
    copy('packages');
    copy('services/browser-worker/package.json');
    copy('services/browser-worker/src');
    copy('services/browser-worker/node_modules');
    copy('services/browser-worker/test/fixtures/registry');

    // Canaries where a real checkout keeps secrets.
    writeFileSync(path.join(fakeRepo, '.env'), `ROOT=${CANARY}\n`);
    mkdirSync(path.join(fakeRepo, '.aab'));
    writeFileSync(path.join(fakeRepo, '.aab', 'kek'), CANARY);
    writeFileSync(path.join(fakeRepo, 'packages', 'contracts', '.env'), `PKG=${CANARY}\n`);
    writeFileSync(path.join(fakeRepo, 'packages', 'crypto', 'local.pem'), CANARY);
    writeFileSync(path.join(fakeRepo, 'services/browser-worker/src/.env.local'), CANARY);

    listener = net.createServer((socket) => socket.end('host loopback'));
    await new Promise<void>((resolve) => listener.listen(0, '127.0.0.1', resolve));
    port = (listener.address() as AddressInfo).port;
  });

  afterAll(async () => {
    listener?.close();
    if (fakeRepo !== undefined) rmSync(fakeRepo, { recursive: true, force: true });
  });

  it('cannot read planted secrets, /home, the host loopback or any network', async () => {
    const config = resolveJobRunnerConfig({
      repoRoot: fakeRepo,
      runtimeBaseDir: runtimeBaseDir(),
      bwrapPath: BWRAP,
      chromiumPath: CHROMIUM,
      adapterRegistryModule: path.join(
        fakeRepo,
        'services/browser-worker/test/fixtures/registry/index.ts',
      ),
    });
    const launcher = createLauncher(config);
    const dir = await createJobRuntimeDir(config.runtimeBaseDir);
    const proxy = await createEgressProxy({
      socketPath: dir.socketPath,
      allowedOrigins: ['https://unused.invalid'],
    });
    try {
      const sandbox = await launcher.launch({
        jobId: 'isolation-probe',
        jobDir: dir.dir,
        socketPath: dir.socketPath,
        headed: false,
        entryOverride: path.join(
          fakeRepo,
          'services/browser-worker/test/fixtures/registry/probe.ts',
        ),
      });
      const paths = [
        '/app/.env',
        '/app/.aab/kek',
        '/app/packages/contracts/.env',
        '/app/packages/crypto/local.pem',
        '/app/services/browser-worker/src/.env.local',
        path.join(fakeRepo, '.env'),
        path.join(real, '.env.example'),
        path.join(os.homedir(), '.bashrc'),
        '/etc/shadow',
        '/etc/passwd',
      ];
      let output = '';
      sandbox.stdout.on('data', (chunk: Buffer) => (output += chunk.toString()));
      let errors = '';
      sandbox.stderr.on('data', (chunk: Buffer) => (errors += chunk.toString()));
      sandbox.stdin.write(`${JSON.stringify({ paths, port })}\n`);
      const exit = await sandbox.exited;
      expect(errors).toBe('');
      expect(exit.code).toBe(0);
      const result = JSON.parse(output) as ProbeResult;

      // The planted files inside mounted code are masked; the rest are not mounted at all.
      expect(JSON.stringify(result.contents)).not.toContain(CANARY);
      // Masked with /dev/null on a nodev mount: present but unreadable or empty.
      expect(result.exists['/app/packages/contracts/.env']).toBe(true);
      expect(['', null]).toContain(result.contents['/app/packages/contracts/.env']);
      expect(['', null]).toContain(result.contents['/app/services/browser-worker/src/.env.local']);
      expect(result.exists['/app/.env']).toBe(false);
      expect(result.exists['/app/.aab/kek']).toBe(false);
      expect(result.exists[path.join(fakeRepo, '.env')]).toBe(false);
      expect(result.exists[path.join(real, '.env.example')]).toBe(false);
      expect(result.exists[path.join(os.homedir(), '.bashrc')]).toBe(false);
      expect(result.exists['/etc/shadow']).toBe(false);
      expect(result.exists['/etc/passwd']).toBe(false);
      // /home does not exist at all (the job's tmpfs home is /sandbox-home); only the selected
      // code exists under /app.
      expect(result.home).toBeNull();
      expect(result.root).toContain('sandbox-home');
      expect(result.app.sort()).toEqual(['node_modules', 'package.json', 'packages', 'services']);
      expect(result.root).not.toContain('root');
      // No interface except loopback, and the host's loopback is unreachable.
      expect(result.interfaces).toEqual(['lo']);
      expect(result.loopback).not.toBe('connected');
      // A cleared environment.
      expect(result.envKeys).toEqual(
        [
          'AAB_RUNNER_CHROMIUM',
          'AAB_RUNNER_CHROMIUM_SANDBOX',
          'AAB_RUNNER_EGRESS_SOCKET',
          'AAB_RUNNER_REGISTRY',
          'AAB_SANDBOX_JOB',
          'HOME',
          'LANG',
          'PATH',
          'PWD', // set by bubblewrap's --chdir: /app
          'TMPDIR',
        ].sort(),
      );
      await sandbox.kill();
    } finally {
      await proxy.close();
      await dir.remove();
    }
  });

  it('the vault socket directory is absent inside the sandbox', async () => {
    // P3-14: the runner is hostile and must not be able to reach the vault. A real vault-shaped
    // socket directory (one directory per role, a listening socket in each) sits on the host,
    // where the supervisor would reach it; the sandbox is given no mount for it.
    const parent = process.env['XDG_RUNTIME_DIR'] ?? os.tmpdir();
    const vaultDir = mkdtempSync(path.join(parent, 'aab-vault-iso-'));
    const servers: net.Server[] = [];
    const socketPaths: string[] = [];
    for (const role of ['api', 'supervisor', 'admin']) {
      mkdirSync(path.join(vaultDir, role));
      const socketPath = path.join(vaultDir, role, 'vault.sock');
      const server = net.createServer((socket) => socket.end('{"vault":"answered"}\n'));
      await new Promise<void>((resolve) => server.listen(socketPath, resolve));
      servers.push(server);
      socketPaths.push(socketPath);
    }
    const config = resolveJobRunnerConfig({
      repoRoot: fakeRepo,
      runtimeBaseDir: runtimeBaseDir(),
      bwrapPath: BWRAP,
      chromiumPath: CHROMIUM,
      adapterRegistryModule: path.join(
        fakeRepo,
        'services/browser-worker/test/fixtures/registry/index.ts',
      ),
    });
    const launcher = createLauncher(config);
    const dir = await createJobRuntimeDir(config.runtimeBaseDir);
    const proxy = await createEgressProxy({
      socketPath: dir.socketPath,
      allowedOrigins: ['https://unused.invalid'],
    });
    try {
      const sandbox = await launcher.launch({
        jobId: 'isolation-probe-vault',
        jobDir: dir.dir,
        socketPath: dir.socketPath,
        headed: false,
        entryOverride: path.join(
          fakeRepo,
          'services/browser-worker/test/fixtures/registry/probe.ts',
        ),
      });
      const paths = [vaultDir, path.dirname(vaultDir), ...socketPaths];
      let output = '';
      sandbox.stdout.on('data', (chunk: Buffer) => (output += chunk.toString()));
      let errors = '';
      sandbox.stderr.on('data', (chunk: Buffer) => (errors += chunk.toString()));
      sandbox.stdin.write(`${JSON.stringify({ paths, port, sockets: socketPaths })}\n`);
      const exit = await sandbox.exited;
      expect(errors).toBe('');
      expect(exit.code).toBe(0);
      const result = JSON.parse(output) as ProbeResult;

      // Host side first: the sockets are really there and really answer, so an absent path in
      // the sandbox is the sandbox's doing and not a broken fixture.
      for (const socketPath of socketPaths) {
        const answer = await new Promise<string>((resolve) => {
          const client = net.connect({ path: socketPath });
          let data = '';
          client.on('data', (chunk) => (data += chunk.toString()));
          client.once('close', () => resolve(data));
          client.once('error', () => resolve('error'));
        });
        expect(answer).toContain('answered');
      }
      for (const entry of paths) expect(result.exists[entry]).toBe(false);
      for (const socketPath of socketPaths) {
        // ENOENT: the path does not exist there. Anything else (a refusal, a connection) would mean it does.
        expect(result.unix[socketPath]).toBe('ENOENT');
      }
      expect(result.envKeys.filter((key) => /VAULT|KEK|SOCKET_DIR/.test(key))).toEqual([]);
      await sandbox.kill();
    } finally {
      await proxy.close();
      await dir.remove();
      for (const server of servers) server.close();
      rmSync(vaultDir, { recursive: true, force: true });
    }
  });

  it('selfCheck passes on this host and fails when the sandbox cannot start', async () => {
    const { runner } = createHarness();
    await expect(runner.selfCheck()).resolves.toBeUndefined();
    const { runner: broken } = createHarness({ bwrapPath: '/nonexistent/bwrap' });
    await expect(broken.selfCheck()).rejects.toThrow(/bubblewrap not found/);
    const { runner: noChromium } = createHarness({ chromiumPath: '/usr/bin/true' });
    await expect(noChromium.selfCheck()).rejects.toThrow(/Chromium could not start/);
  });
});
