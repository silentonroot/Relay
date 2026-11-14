/*
 * Safety net for the Phase 2 end-to-end test. The test starts the demo, the API, the worker
 * and Xvfb in their own process groups; when the test process is killed (Ctrl-C on vitest,
 * a timeout, a crash) its afterAll never runs and those would be orphaned, and so would the
 * temporary database and directories.
 *
 * This process is started by the test, outlives it, and cleans up from a spec file the test
 * keeps current. In a normal run the test's own teardown runs first, marks the spec `done`
 * and kills this process, so it never does anything.
 *
 *   node watchdog.mjs <spec.json> <pid of the test process>
 */
import { execFileSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { setTimeout as sleep } from 'node:timers/promises';

const [specPath, parentArg] = process.argv.slice(2);
const parentPid = Number(parentArg);

function alive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error.code === 'EPERM';
  }
}

function readSpec() {
  try {
    return JSON.parse(readFileSync(specPath, 'utf8'));
  } catch {
    return null;
  }
}

function signalGroup(pid, signal) {
  try {
    process.kill(-pid, signal);
  } catch {
    // Already gone.
  }
}

function killByMarker(markers) {
  for (const entry of readdirSync('/proc')) {
    if (!/^\d+$/.test(entry) || Number(entry) === process.pid) continue;
    try {
      const line = readFileSync(`/proc/${entry}/cmdline`, 'latin1').split('\0').join(' ');
      if (markers.some((marker) => marker !== '' && line.includes(marker))) {
        process.kill(Number(entry), 'SIGKILL');
      }
    } catch {
      // Gone, or not ours.
    }
  }
}

while (alive(parentPid)) await sleep(500);
await sleep(1500); // a normal afterAll gets the first go
const spec = readSpec();
if (spec === null || spec.done === true) process.exit(0);

for (const pid of spec.groups ?? []) signalGroup(pid, 'SIGTERM');
await sleep(1500);
for (const pid of spec.groups ?? []) signalGroup(pid, 'SIGKILL');
killByMarker(spec.markers ?? []);
await sleep(500);
if (spec.dbName) {
  try {
    execFileSync(
      `${spec.pgBin}/dropdb`,
      ['--if-exists', '--force', '-h', spec.pgDir, '-p', String(spec.pgPort), spec.dbName],
      { env: { PATH: '/usr/bin' }, stdio: 'ignore' },
    );
  } catch {
    // Best effort.
  }
}
if (spec.displayNumber) {
  for (const file of [
    `/tmp/.X11-unix/X${spec.displayNumber}`,
    `/tmp/.X${spec.displayNumber}-lock`,
  ]) {
    if (existsSync(file)) rmSync(file, { force: true });
  }
}
for (const dir of spec.dirs ?? []) rmSync(dir, { recursive: true, force: true });
