import { randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { JOB_ERROR_MESSAGES } from '../../src/protocol.js';
import type { OperationJobOutcome } from '../../src/types.js';
import { startFixtureApp } from '../fixtures/app-server.js';
import type { FixtureApp } from '../fixtures/app-server.js';
import { FIXTURE_PORT } from '../fixtures/registry/constants.js';
import {
  createHarness,
  integrationSkipReason,
  integrationTitle,
  operationSpec,
  processesForJob,
  runtimeDirEntries,
} from './helpers.js';
import type { Harness } from './helpers.js';

/*
 * Real jobs: bubblewrap + Chromium (with its own sandbox) + the egress proxy + a fixture app
 * and fixture adapter. Every job gets a fresh sandbox and browser.
 */

// The session cookie value for alice. It must never appear in any log, diagnostic or outcome.
const CANARY = `canary${randomBytes(12).toString('hex')}`;
const BOB = `bob${randomBytes(12).toString('hex')}`;

let app: FixtureApp;
let harness: Harness;
const outcomes: OperationJobOutcome[] = [];

async function run(
  operation: string,
  token = CANARY,
  overrides: Parameters<typeof operationSpec>[2] = {},
  h: Harness = harness,
): Promise<OperationJobOutcome> {
  const outcome = await h.runner.runOperation(
    operationSpec(operation, token, overrides),
    new AbortController().signal,
  );
  outcomes.push(outcome);
  return outcome;
}

const blocked = { status: 'failed', error: { code: 'navigation_blocked' } };
const adminHits = (): number => app.hits.filter((hit) => hit.path === '/admin').length;

describe.skipIf(integrationSkipReason !== null)(integrationTitle('operation jobs'), () => {
  beforeAll(async () => {
    app = await startFixtureApp();
    app.addSession(CANARY, 'alice');
    app.addSession(BOB, 'bob');
    harness = createHarness();
  });

  afterAll(async () => {
    await app?.close();
  });

  it('reads only schema-declared fields with the supplied session', async () => {
    const outcome = await run('account.read', CANARY, { expectedAccountHint: 'alice' });
    expect(outcome).toEqual({
      status: 'succeeded',
      data: {
        account: 'alice',
        orders: [
          { id: 'A-100', total: '10.00' },
          { id: 'A-101', total: '11.50' },
        ],
      },
    });
  });

  it('two jobs with two storage states each see only their own account', async () => {
    const [alice, bob] = await Promise.all([run('account.read', CANARY), run('account.read', BOB)]);
    expect(alice).toMatchObject({ status: 'succeeded', data: { account: 'alice' } });
    expect(bob).toEqual({
      status: 'succeeded',
      data: { account: 'bob', orders: [{ id: 'B-200', total: '20.00' }] },
    });
  });

  it('a redirect to a disallowed path is stopped before the hop is sent', async () => {
    const before = adminHits();
    expect(await run('nav.redirectPath')).toMatchObject(blocked);
    expect(adminHits()).toBe(before);
  });

  it('a redirect to a disallowed origin is stopped before the hop is sent', async () => {
    const before = app.hits.length;
    expect(await run('nav.redirectOrigin')).toMatchObject(blocked);
    const after = app.hits.slice(before).filter((hit) => hit.path !== '/favicon.ico');
    expect(after.map((hit) => hit.path)).toEqual(['/account', '/redirect-origin']);
    expect(after.some((hit) => hit.host.startsWith('localhost'))).toBe(false);
  });

  it.each([
    ['a meta refresh', 'nav.metaRefresh'],
    ['a script-driven navigation', 'nav.script'],
    ['a form submission', 'nav.form'],
    ['a disallowed goto by the adapter', 'nav.disallowedGoto'],
  ])('%s away from the allowed paths aborts the operation', async (_label, operation) => {
    const before = adminHits();
    const started = Date.now();
    expect(await run(operation)).toMatchObject(blocked);
    expect(adminHits()).toBe(before);
    // The violation ends the job at once instead of waiting for the adapter's 8 s wait.
    expect(Date.now() - started).toBeLessThan(8_000);
  });

  it('an expired session (redirect to the login path) gives reauth_required', async () => {
    expect(await run('account.read', 'not-a-session')).toEqual({ status: 'reauth_required' });
  });

  it('a navigation landing on the login path during execute gives reauth_required', async () => {
    const before = app.hits.filter((hit) => hit.path === '/login').length;
    expect(await run('nav.goLogin')).toEqual({ status: 'reauth_required' });
    expect(app.hits.filter((hit) => hit.path === '/login').length).toBe(before);
  });

  it('a different signed-in account gives identity_mismatch before execute runs', async () => {
    const before = app.hits.filter((hit) => hit.path === '/orders').length;
    expect(await run('account.read', CANARY, { expectedAccountHint: 'bob' })).toMatchObject({
      status: 'failed',
      error: { code: 'identity_mismatch' },
    });
    expect(app.hits.filter((hit) => hit.path === '/orders').length).toBe(before);
  });

  it('requests from page content to other origins are refused by the proxy and logged', async () => {
    const before = harness.decisions.length;
    const pixelsBefore = app.hits.filter((hit) => hit.path === '/pixel').length;
    expect(await run('page.exfil')).toEqual({ status: 'succeeded', data: { ok: true } });
    const decisions = harness.decisions.slice(before);
    expect(decisions).toContainEqual(
      expect.objectContaining({
        origin: `http://localhost:${FIXTURE_PORT}`,
        decision: 'deny',
        reason: 'origin_not_allowed',
      }),
    );
    expect(decisions).toContainEqual(
      expect.objectContaining({
        origin: 'http://evil.test',
        decision: 'deny',
        reason: 'origin_not_allowed',
      }),
    );
    expect(app.hits.filter((hit) => hit.path === '/pixel').length).toBe(pixelsBefore);
    expect(harness.logs.some((line) => line.includes('"origin":"http://evil.test"'))).toBe(true);
  });

  it('oversized text is rejected by the output schema, and reads are bounded', async () => {
    expect(await run('page.big')).toMatchObject({
      status: 'failed',
      error: { code: 'output_rejected' },
    });
    expect(await run('page.bigLength')).toEqual({
      status: 'succeeded',
      data: { length: 64 * 1024 },
    });
  });

  it('a 404 page loads normally and a missing element reads as null', async () => {
    expect(await run('page.missing')).toEqual({
      status: 'succeeded',
      data: { status: '404', absent: null },
    });
  });

  it("maps an adapter's failure code and replaces its message", async () => {
    expect(await run('op.adapterFails')).toEqual({
      status: 'failed',
      error: { code: 'not_found', message: JOB_ERROR_MESSAGES.not_found },
    });
  });

  it('refuses unknown adapters and origins outside the adapter before starting a sandbox', async () => {
    const before = (await runtimeDirEntries()).length;
    expect(await run('account.read', CANARY, { adapterId: 'nope' })).toMatchObject({
      status: 'failed',
      error: { code: 'adapter_unavailable' },
    });
    expect(
      await run('account.read', CANARY, { allowedOrigins: ['https://evil.example'] }),
    ).toMatchObject({ status: 'failed', error: { code: 'origin_not_allowed' } });
    expect(await run('account.read', CANARY, { arguments: { extra: 1 } })).toMatchObject({
      status: 'failed',
      error: { code: 'invalid_arguments' },
    });
    expect((await runtimeDirEntries()).length).toBe(before);
  });

  it('the runner reports its own timeout cleanly', async () => {
    expect(await run('op.slow', CANARY, { timeoutMs: 4_000 })).toMatchObject({
      status: 'failed',
      error: { code: 'timeout' },
    });
  });

  it('a runner that hangs is killed at the hard deadline, leaving no process or directory', async () => {
    const strict = createHarness({ limits: { startupGraceMs: 2_000, exitGraceMs: 200 } });
    const spec = operationSpec('op.hang', CANARY, { timeoutMs: 4_000 });
    const before = await runtimeDirEntries();
    const started = Date.now();
    let seenRunning: number[] = [];
    const watcher = setInterval(() => {
      void processesForJob(spec.jobId).then((pids) => {
        if (pids.length > seenRunning.length) seenRunning = pids;
      });
    }, 500);
    const outcome = await strict.runner.runOperation(spec, new AbortController().signal);
    clearInterval(watcher);
    outcomes.push(outcome);
    expect(outcome).toMatchObject({ status: 'failed', error: { code: 'timeout' } });
    expect(Date.now() - started).toBeLessThan(15_000);
    // The probe saw the runner and Chromium alive, and none of them survive.
    expect(seenRunning.length).toBeGreaterThan(1);
    expect(await processesForJob(spec.jobId)).toEqual([]);
    expect(await runtimeDirEntries()).toEqual(before);
    expect(strict.logs.some((line) => line.includes('hard deadline'))).toBe(true);
  });

  it('an abort cancels the job and cleans up', async () => {
    const controller = new AbortController();
    const spec = operationSpec('op.slow', CANARY);
    const before = await runtimeDirEntries();
    setTimeout(() => controller.abort(), 3_000);
    const outcome = await harness.runner.runOperation(spec, controller.signal);
    outcomes.push(outcome);
    expect(outcome).toMatchObject({ status: 'failed', error: { code: 'cancelled' } });
    expect(await processesForJob(spec.jobId)).toEqual([]);
    expect(await runtimeDirEntries()).toEqual(before);
  });

  it('the unsafe-process launcher runs a job and warns on every job', async () => {
    const unsafe = createHarness({ sandbox: 'unsafe-process' });
    expect(unsafe.runner.sandbox).toBe('unsafe-process');
    expect(await run('account.read', BOB, {}, unsafe)).toMatchObject({
      status: 'succeeded',
      data: { account: 'bob' },
    });
    expect(unsafe.logs.filter((line) => line.includes('UNSAFE')).length).toBeGreaterThanOrEqual(2);
  });

  it('the session cookie never appears in runner stderr, proxy logs or outcomes', () => {
    expect(harness.stderr.length).toBeGreaterThan(0);
    expect(harness.logs.length).toBeGreaterThan(0);
    for (const line of harness.stderr) expect(line).not.toContain(CANARY);
    for (const line of harness.logs) expect(line).not.toContain(CANARY);
    expect(JSON.stringify(outcomes)).not.toContain(CANARY);
    expect(JSON.stringify(harness.decisions)).not.toContain(CANARY);
    // And the fixture's page-only data never shows up in diagnostics either.
    for (const line of [...harness.stderr, ...harness.logs]) {
      expect(line).not.toContain('alice-internal-note');
      expect(line).not.toContain('secret text');
    }
  });
});
