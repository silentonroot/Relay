import { execFile, spawn } from 'node:child_process';
import type { ChildProcess } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { LoginJobSpec } from '../../src/types.js';
import { startFixtureApp } from '../fixtures/app-server.js';
import type { FixtureApp } from '../fixtures/app-server.js';
import { FIXTURE_ORIGIN } from '../fixtures/registry/constants.js';
import {
  createHarness,
  integrationSkipReason,
  requireOrSkip,
  integrationTitle,
  operationSpec,
  processesForJob,
  runtimeDirEntries,
} from './helpers.js';
import type { Harness } from './helpers.js';

/*
 * The headed login handoff on a private Xvfb display. xdotool plays the owner: it types
 * synthetic credentials into the fixture's login form. Never uses the desktop's own display.
 */

const run = promisify(execFile);
const XVFB = '/usr/bin/Xvfb';
const XDOTOOL = '/usr/bin/xdotool';
const XAUTH = '/usr/bin/xauth';
const loginSkip = requireOrSkip(
  integrationSkipReason ??
    ([XVFB, XDOTOOL, XAUTH].find((tool) => !existsSync(tool)) === undefined
      ? null
      : 'Xvfb, xdotool or xauth is missing'),
);

let xvfb: ChildProcess | null = null;
let workDir: string;
let display = '';
let xauthority = '';
let app: FixtureApp;
let harness: Harness;

function freeDisplay(): number {
  for (let n = 87; n < 140; n += 1) {
    if (!existsSync(`/tmp/.X11-unix/X${n}`) && !existsSync(`/tmp/.X${n}-lock`)) return n;
  }
  throw new Error('no free X display number');
}

async function waitFor(condition: () => boolean | Promise<boolean>, ms: number): Promise<void> {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (await condition()) return;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error('condition not met in time');
}

const xenv = (): NodeJS.ProcessEnv => ({
  DISPLAY: display,
  XAUTHORITY: xauthority,
  PATH: '/usr/bin',
});

async function xdotool(...args: string[]): Promise<string> {
  const { stdout } = await run(XDOTOOL, args, { env: xenv(), timeout: 20_000 });
  return stdout.trim();
}

/** The Chromium window's id, once it is mapped. */
async function chromiumWindow(): Promise<string> {
  let id = '';
  await waitFor(async () => {
    try {
      id = (await xdotool('search', '--onlyvisible', '--class', 'chromium')).split('\n')[0] ?? '';
    } catch {
      id = '';
    }
    return id !== '';
  }, 20_000);
  return id;
}

let jobCounter = 0;
function loginSpec(timeoutMs = 60_000): LoginJobSpec {
  jobCounter += 1;
  return {
    jobId: `login-${process.pid}-${jobCounter}-${randomBytes(3).toString('hex')}`,
    connectionId: 'conn-login',
    adapterId: 'fixture-app',
    adapterVersion: '1.0.0',
    allowedOrigins: [FIXTURE_ORIGIN],
    timeoutMs,
  };
}

describe.skipIf(loginSkip !== null)(
  integrationTitle(
    `headed login on a private Xvfb display${loginSkip === null ? '' : ` (SKIPPED: ${loginSkip})`}`,
  ),
  () => {
    beforeAll(async () => {
      workDir = mkdtempSync(path.join(os.tmpdir(), 'aab-xvfb-'));
      const number = freeDisplay();
      display = `:${number}`;
      xauthority = path.join(workDir, 'Xauthority');
      await run(XAUTH, ['-f', xauthority, 'add', display, '.', randomBytes(16).toString('hex')]);
      xvfb = spawn(
        XVFB,
        [display, '-auth', xauthority, '-nolisten', 'tcp', '-screen', '0', '1280x800x24'],
        { stdio: 'ignore' },
      );
      await waitFor(() => existsSync(`/tmp/.X11-unix/X${number}`), 10_000);
      app = await startFixtureApp();
      harness = createHarness({
        display: { x11Display: display, xauthority },
        limits: { startupGraceMs: 10_000, exitGraceMs: 500 },
      });
    });

    afterAll(async () => {
      await app?.close();
      if (xvfb !== null) {
        const exited = new Promise((resolve) => xvfb?.once('exit', resolve));
        xvfb.kill('SIGTERM');
        await exited;
      }
      if (workDir !== undefined) rmSync(workDir, { recursive: true, force: true });
    });

    it('the owner signs in; complete() returns the session cookie and account hint', async () => {
      const before = await runtimeDirEntries();
      const spec = loginSpec();
      const handle = await harness.runner.startLogin(spec, new AbortController().signal);
      const window = await chromiumWindow();
      // Without a window manager, X keyboard focus follows a click: click the username field
      // (top left of the page, below Chromium's toolbar).
      await xdotool('mousemove', '--window', window, '100', '105', 'click', '1');
      await xdotool('type', '--delay', '15', 'alice');
      await xdotool('key', 'Tab');
      await xdotool('type', '--delay', '15', 'alice-password');
      await xdotool('key', 'Return');
      await waitFor(() => app.loginSuccesses.includes('alice'), 15_000);

      const outcome = await handle.complete();
      expect(outcome.status).toBe('succeeded');
      if (outcome.status !== 'succeeded') return;
      expect(outcome.externalAccountHint).toBe('alice');
      const cookie = outcome.storageState.cookies.find((c) => c.name === 'fx_session');
      expect(cookie).toMatchObject({ domain: '127.0.0.1', path: '/', httpOnly: true });
      expect(cookie?.value).toMatch(/^[0-9a-f]{32}$/);
      await handle.closed;
      // The captured state really is alice's session: an operation job signed in with it.
      const replay = await harness.runner.runOperation(
        operationSpec('account.read', '', { storageState: outcome.storageState }),
        new AbortController().signal,
      );
      expect(replay).toMatchObject({ status: 'succeeded', data: { account: 'alice' } });
      expect(await processesForJob(spec.jobId)).toEqual([]);
      expect(await runtimeDirEntries()).toEqual(before);
      // Nothing typed or captured reaches diagnostics.
      for (const line of [...harness.stderr, ...harness.logs]) {
        expect(line).not.toContain('alice-password');
        expect(line).not.toContain(cookie?.value ?? 'unreachable');
      }
    });

    it('closing the window ends the handoff with login_window_closed', async () => {
      const spec = loginSpec();
      const handle = await harness.runner.startLogin(spec, new AbortController().signal);
      const window = await chromiumWindow();
      await xdotool('mousemove', '--window', window, '600', '400', 'click', '1');
      await xdotool('key', 'ctrl+w');
      await handle.closed;
      expect(await handle.complete()).toMatchObject({
        status: 'failed',
        error: { code: 'login_window_closed' },
      });
      expect(await processesForJob(spec.jobId)).toEqual([]);
    });

    it('a handoff nobody completes times out', async () => {
      const spec = loginSpec(4_000);
      const handle = await harness.runner.startLogin(spec, new AbortController().signal);
      await handle.closed;
      expect(await handle.complete()).toMatchObject({
        status: 'failed',
        error: { code: 'timeout' },
      });
      expect(await processesForJob(spec.jobId)).toEqual([]);
    });

    it('cancel() closes the window without capturing anything', async () => {
      const spec = loginSpec();
      const handle = await harness.runner.startLogin(spec, new AbortController().signal);
      await handle.cancel();
      await handle.cancel();
      expect(await handle.complete()).toMatchObject({
        status: 'failed',
        error: { code: 'cancelled' },
      });
      expect(await processesForJob(spec.jobId)).toEqual([]);
    });

    it('complete() before signing in reports login_not_completed', async () => {
      const handle = await harness.runner.startLogin(loginSpec(), new AbortController().signal);
      expect(await handle.complete()).toMatchObject({
        status: 'failed',
        error: { code: 'login_not_completed' },
      });
      await handle.closed;
    });
  },
);
