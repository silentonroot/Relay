import { cpSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import type { TestProject } from 'vitest/node';

/*
 * Per-run state for the browser-worker suite, so two runs on one machine never share anything.
 *
 *  - runtimeBaseDir: a fresh directory for the sandbox's per-job sockets. The prefix is short
 *    because the job runner creates `<base>/<jobid>/egress.sock` and Unix socket paths are
 *    limited to about 100 bytes.
 *  - fixturePort: a free loopback port the operating system chose for this run.
 *  - registryModule: a copy of the fixture adapter registry whose allowed origin names that port.
 *    The runner process loads the registry from the mounted directory and has a cleared
 *    environment, so the origin has to be in the files it can read. The copy lives inside the
 *    repository (the sandbox only mounts paths under the repository root) in a uniquely named
 *    directory that is removed when the run ends.
 */

declare module 'vitest' {
  export interface ProvidedContext {
    runtimeBaseDir: string;
    fixturePort: number;
    registryModule: string;
  }
}

const TEST_DIR = import.meta.dirname;

function reservePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address() as net.AddressInfo;
      server.close(() => resolve(port));
    });
  });
}

export default async function setup(project: TestProject): Promise<() => void> {
  const runtimeParent = process.env['XDG_RUNTIME_DIR'] ?? os.tmpdir();
  const runtimeBaseDir = mkdtempSync(path.join(runtimeParent, 'aab-t-'));

  const fixturePort = await reservePort();

  const runDir = mkdtempSync(path.join(TEST_DIR, '.run-'));
  const registryDir = path.join(runDir, 'registry');
  mkdirSync(registryDir);
  for (const file of ['fixture-adapter.ts', 'index.ts']) {
    cpSync(path.join(TEST_DIR, 'fixtures/registry', file), path.join(registryDir, file));
  }
  writeFileSync(
    path.join(registryDir, 'constants.ts'),
    `export const FIXTURE_ORIGIN = 'http://127.0.0.1:${fixturePort}';\n`,
  );

  project.provide('runtimeBaseDir', runtimeBaseDir);
  project.provide('fixturePort', fixturePort);
  project.provide('registryModule', path.join(registryDir, 'index.ts'));

  return () => {
    rmSync(runtimeBaseDir, { recursive: true, force: true });
    rmSync(runDir, { recursive: true, force: true });
  };
}
