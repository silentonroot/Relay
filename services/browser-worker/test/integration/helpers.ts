import { accessSync, constants, existsSync } from 'node:fs';
import { readdir, readFile } from 'node:fs/promises';
import { pino } from 'pino';
import type { EgressDecision } from '../../src/egress/proxy.js';
import { createJobRunner } from '../../src/sandbox/index.js';
import type { JobRunnerConfigInput } from '../../src/sandbox/index.js';
import type { JobRunner, OperationJobSpec } from '../../src/types.js';
import { fixtureOrigin, registryModule, runtimeBaseDir } from '../fixtures/run-context.js';
import { sessionStorageState } from '../fixtures/app-server.js';

export const BWRAP = '/usr/bin/bwrap';
/** Override with AAB_TEST_CHROMIUM_PATH where Chromium is not the Debian package (CI). */
export const CHROMIUM = process.env['AAB_TEST_CHROMIUM_PATH'] ?? '/usr/lib/chromium/chromium';

function executable(file: string): boolean {
  try {
    accessSync(file, constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

/** Why the integration tests cannot run here, or null when they can. */
export const integrationSkipReason: string | null = !executable(BWRAP)
  ? `bubblewrap not found at ${BWRAP}`
  : !executable(CHROMIUM)
    ? `Chromium not found at ${CHROMIUM}`
    : null;

/**
 * Continuous integration sets AAB_REQUIRE_INTEGRATION=1 so that a missing prerequisite fails
 * the run. Without it these tests skip, and a skipped isolation test proves nothing.
 */
export function requireOrSkip(reason: string | null): string | null {
  if (reason !== null && process.env['AAB_REQUIRE_INTEGRATION'] === '1') {
    throw new Error(`AAB_REQUIRE_INTEGRATION=1 but the integration tests cannot run: ${reason}`);
  }
  return reason;
}
requireOrSkip(integrationSkipReason);

export const integrationTitle = (title: string): string =>
  integrationSkipReason === null ? title : `${title} (SKIPPED: ${integrationSkipReason})`;

/** This run's copy of the fixture registry, with this run's fixture origin (test/global-setup.ts). */
export const fixtureRegistry = registryModule;

export interface Harness {
  readonly runner: JobRunner;
  readonly stderr: string[];
  readonly logs: string[];
  readonly decisions: (EgressDecision & { jobId: string })[];
}

export function createHarness(overrides: JobRunnerConfigInput = {}): Harness {
  const stderr: string[] = [];
  const logs: string[] = [];
  const decisions: (EgressDecision & { jobId: string })[] = [];
  const runner = createJobRunner({
    adapterRegistryModule: fixtureRegistry(),
    runtimeBaseDir: runtimeBaseDir(),
    chromiumPath: CHROMIUM,
    bwrapPath: BWRAP,
    logger: pino({ level: 'debug' }, { write: (line: string) => logs.push(line) }),
    onRunnerStderr: (line) => stderr.push(line),
    onEgressDecision: (decision) => decisions.push(decision),
    ...overrides,
  });
  return { runner, stderr, logs, decisions };
}

let counter = 0;
export function operationSpec(
  operation: string,
  token: string,
  overrides: Partial<OperationJobSpec> = {},
): OperationJobSpec {
  counter += 1;
  return {
    jobId: `itest-${process.pid}-${counter}-${Math.random().toString(16).slice(2, 8)}`,
    connectionId: 'conn-1',
    adapterId: 'fixture-app',
    adapterVersion: '1.0.0',
    allowedOrigins: [fixtureOrigin()],
    operation,
    arguments: {},
    storageState: sessionStorageState(token),
    expectedAccountHint: null,
    timeoutMs: 30_000,
    ...overrides,
  };
}

/** Pids of processes whose environment carries the job marker the launcher sets. */
export async function processesForJob(jobId: string): Promise<number[]> {
  const needle = `AAB_SANDBOX_JOB=${jobId}\0`;
  const found: number[] = [];
  for (const entry of await readdir('/proc')) {
    if (!/^\d+$/.test(entry)) continue;
    try {
      const environ = await readFile(`/proc/${entry}/environ`, 'latin1');
      if (`${environ}\0`.includes(needle)) found.push(Number(entry));
    } catch {
      // Not ours or gone.
    }
  }
  return found;
}

export async function runtimeDirEntries(): Promise<string[]> {
  const base = runtimeBaseDir();
  return existsSync(base) ? readdir(base) : [];
}
