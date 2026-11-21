import { afterAll, beforeAll, describe, expect, it } from 'vitest';

/*
 * Phase 2 end-to-end acceptance test. Black box: the demo app, the API and the browser worker
 * run as separate processes (the worker with the real bubblewrap sandbox and Chromium on a
 * private Xvfb display), and everything else goes through the HTTP API exactly as the
 * dashboard would, plus xdotool for the sign-in windows.
 *
 *   AAB_E2E=1 node_modules/.bin/vitest run --root services/browser-worker test/e2e
 *
 * Skipped unless AAB_E2E=1. Prerequisites are checked up front with one clear message.
 * Environment overrides: AAB_CHROMIUM_PATH, AAB_E2E_DEMO_DIR (default: ../northstar-demo next to the repository),
 * AAB_E2E_PG_DIR, AAB_E2E_PG_PORT, AAB_E2E_PG_BIN. Temporary files go under os.tmpdir().
 * The step letters in the test names are the Phase 2 acceptance steps A to K.
 *
 * Phase 3 (B3b): the vault runs as a fourth process (shared-uid isolation: one user, one
 * directory mode), the API and the worker talk to it over their own role sockets, and the worker
 * holds no key: it is started without AAB_KEK_DIR and would refuse to start with it.
 */
import { existsSync, readdirSync, readFileSync, readlinkSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  NorthstarOrderDetail,
  NorthstarOrderItem,
  NorthstarOrderSummary,
} from '@aab/adapter-northstar';
import {
  ENABLED,
  PG_DIR,
  DEMO_ORIGIN,
  ALICE,
  BOB,
  INJECTION_ORDER,
  COOKIE_NAME,
  type Loose,
  sleep,
  waitFor,
  S,
  psql,
  count,
  jsonRows,
  snapshotCounts,
  delta,
  versionsFor,
  demoQuery,
  demoOrderRows,
  collectDemoSessions,
  demoSessionCount,
  type DemoRequest,
  demoRequests,
  api,
  execute,
  connectionOf,
  vaultSocket,
  startApi,
  startWorker,
  startHandoff,
  signIn,
  completeHandoff,
  ancestorsOf,
  browserTree,
  rssKb,
  type Needle,
  scan,
  databaseHaystacks,
  logHaystacks,
  prepareEnvironment,
  teardownEnvironment,
  setupStack,
} from './harness.js';

function needles(): Needle[] {
  const key = S.keyBytes;
  return [
    { kind: 'demo password (alice)', value: S.passwords.alice },
    { kind: 'demo password (bob)', value: S.passwords.bob },
    { kind: 'owner password', value: S.passwords.owner },
    { kind: 'KEK bytes (hex)', value: key.toString('hex') },
    { kind: 'KEK bytes (HEX)', value: key.toString('hex').toUpperCase() },
    { kind: 'KEK bytes (base64)', value: key.toString('base64') },
    { kind: 'KEK bytes (base64url)', value: key.toString('base64url') },
    { kind: 'KEK bytes (raw latin1)', value: key.toString('latin1') },
    { kind: 'demo cookie name', value: COOKIE_NAME },
    ...[...S.csrfTokens].map((value) => ({ kind: 'demo session CSRF token', value })),
  ];
}

async function leakScan(label: string): Promise<void> {
  collectDemoSessions();
  const haystacks: Record<string, string> = {
    ...logHaystacks(),
    'http response bodies and headers': S.httpBodies.join('\n'),
    ...(await databaseHaystacks()),
  };
  // Positive control: the scanner must see planted secrets, or a zero-hit result means nothing.
  const response = await fetch(`${DEMO_ORIGIN}/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ username: ALICE, password: S.passwords.alice }),
    redirect: 'manual',
  });
  const controlCookie = response.headers.getSetCookie().join(';');
  const controlToken = new RegExp(`${COOKIE_NAME}=([A-Za-z0-9_-]+)`).exec(controlCookie)?.[1] ?? '';
  expect(controlToken.length, 'control login to the demo').toBeGreaterThan(20);
  collectDemoSessions();
  const control = scan(
    {
      control: `planted: ${controlToken} and ${S.passwords.alice} and ${S.keyBytes.toString('hex')}`,
    },
    needles(),
    S.tokenHashes,
  );
  expect(control).toEqual(
    expect.arrayContaining([
      'control :: demo session token',
      'control :: demo password (alice)',
      'control :: KEK bytes (hex)',
    ]),
  );

  const hits = scan(haystacks, needles(), S.tokenHashes);
  expect(hits, `${label}: secrets found in these haystacks (needle kinds only)`).toEqual([]);
  S.metrics[`${label} scanned haystacks`] = Object.keys(haystacks).length;
}

/* ------------------------------------------------------------------ the test */

let failedStep: string | null = null;

function step(name: string, body: () => Promise<void>, options: { critical?: boolean } = {}): void {
  it(
    name,
    async () => {
      if (failedStep !== null) throw new Error(`not run: critical step ${failedStep} failed`);
      try {
        await body();
      } catch (error) {
        if (options.critical === true) failedStep = name.split(' ')[0] ?? name;
        throw error;
      }
    },
    150_000,
  );
}

describe.skipIf(!ENABLED)(
  'Phase 2 end-to-end: connect, read, isolate, restart, expire, revoke',
  () => {
    beforeAll(async () => {
      await prepareEnvironment('Phase 2');
    }, 120_000);

    afterAll(async () => {
      await teardownEnvironment('Phase 2', '');
    }, 60_000);

    /* ============================================================ A */
    step(
      'A. setup through the API (stack start, application, two connections, one agent)',
      async () => {
        await setupStack();
      },
      { critical: true },
    );

    /* ============================================================ B */
    step('B. an ungranted read is denied before any worker runs', async () => {
      const jobsBefore = await count('select count(*) from execution_jobs');
      const response = await execute(S.conn.alice, 'orders.list');
      expect(response.status).toBe(403);
      expect(response.json.error.code).toBe('denied');
      expect(
        await count(`select count(*) from execution_jobs where operation = 'orders.list'`),
      ).toBe(0);
      expect(await count('select count(*) from execution_jobs')).toBe(jobsBefore);
      expect(
        await count(
          `select count(*) from audit_events where event_type = 'policy.evaluated' and decision = 'deny'`,
        ),
      ).toBeGreaterThanOrEqual(1);
    });

    /* ============================================================ C */
    step(
      'C. login handoff: complete before sign-in stores nothing; then twice for real',
      async () => {
        /* a third, throwaway connection: complete without signing in */
        const created = await api('POST', '/connections', {
          applicationId: S.applicationId,
          displayName: 'Throwaway (e2e)',
        });
        expect(created.status).toBe(201);
        S.conn.throwaway = created.json.id;
        await startHandoff(S.conn.throwaway);
        const early = await completeHandoff(S.conn.throwaway);
        expect(early.status).toBe(200);
        expect(early.json.jobStatus).toBe('failed');
        expect(early.json.error.code).toBe('login_not_completed');
        const throwaway = await connectionOf(S.conn.throwaway);
        expect(throwaway.status).toBe('authentication_required');
        expect(throwaway.statusReason).toBeTruthy();
        expect(throwaway.externalAccountHint).toBeNull();
        expect(await versionsFor(S.conn.throwaway)).toBe(0);
        expect(
          await count(
            `select count(*) from audit_events where event_type = 'vault.secret_stored' and connection_id = '${S.conn.throwaway}'`,
          ),
        ).toBe(0);

        /* the real handoffs */
        const durations: number[] = [];
        for (const [key, username, password] of [
          ['alice', ALICE, S.passwords.alice],
          ['bob', BOB, S.passwords.bob],
        ] as const) {
          const { window, t0 } = await startHandoff(S.conn[key]);
          await signIn(window, username, password);
          const complete = await completeHandoff(S.conn[key]);
          expect(complete.status).toBe(200);
          expect(complete.json.jobStatus).toBe('succeeded');
          await waitFor(
            async () => (await connectionOf(S.conn[key])).status === 'active',
            15_000,
            `${key} to become active`,
          );
          durations.push(Date.now() - t0);
          const connection = await connectionOf(S.conn[key]);
          expect(connection.externalAccountHint).toBe(username);
          expect(connection.sessionExpiresAt).toBeTruthy();
          expect(await versionsFor(S.conn[key])).toBe(1);
          expect(
            await count(
              `select count(*) from audit_events where event_type = 'vault.secret_stored' and connection_id = '${S.conn[key]}'`,
            ),
          ).toBe(1);
        }
        S.metrics['login handoff total ms (alice, bob; includes typing)'] = durations.join(', ');
        collectDemoSessions();

        /* still ungranted although the connections are active now */
        const jobs = await count("select count(*) from execution_jobs where kind = 'operation'");
        const denied = await execute(S.conn.alice, 'orders.list');
        expect(denied.status).toBe(403);
        expect(denied.json.error.code).toBe('denied');
        expect(await count("select count(*) from execution_jobs where kind = 'operation'")).toBe(
          jobs,
        );
      },
      { critical: true },
    );

    /* ============================================================ D */
    step(
      'D. grants and reads: isolation between the two accounts',
      async () => {
        for (const connectionId of [S.conn.alice, S.conn.bob]) {
          for (const operation of ['orders.list', 'orders.get']) {
            const grant = await api('POST', `/agents/${S.agentId}/grants`, {
              connectionId,
              operation,
              effect: 'allow',
            });
            expect(grant.status).toBe(201);
          }
        }
        const listKeys = Object.keys(NorthstarOrderSummary.shape).sort();
        const idsOf: Record<string, string[]> = {};
        for (const [key, username, owned] of [
          ['alice', ALICE, S.aliceOrders],
          ['bob', BOB, S.bobOrders],
        ] as const) {
          const t0 = Date.now();
          const response = await execute(S.conn[key], 'orders.list', { limit: 100 });
          S.metrics[`orders.list latency ms (${key}, first)`] = Date.now() - t0;
          expect(response.status).toBe(200);
          expect(response.json.status).toBe('succeeded');
          const orders: Loose[] = response.json.result.orders;
          expect(Object.keys(response.json.result)).toEqual(['orders']);
          idsOf[key] = orders.map((order) => order.id as string);
          // Every returned order belongs to this account according to the demo's own data ...
          for (const id of idsOf[key] ?? [])
            expect(owned.has(id), `${id} belongs to ${username}`).toBe(true);
          // ... and the account's orders are all there.
          expect(new Set(idsOf[key])).toEqual(owned);
          // Only the fields the adapter's output schema declares, with the demo's values.
          const demoRows = new Map(
            demoQuery('select id, customer, status from orders').map((row) => [
              String(row.id),
              row,
            ]),
          );
          for (const order of orders) {
            expect(Object.keys(order).sort()).toEqual(listKeys);
            expect(order.status).toBe(demoRows.get(order.id)?.status);
            expect(order.customer).toBe(demoRows.get(order.id)?.customer);
          }
        }
        const overlap = (idsOf['alice'] ?? []).filter((id) => (idsOf['bob'] ?? []).includes(id));
        expect(overlap).toEqual([]);

        /* another account's order, and a missing one, look the same */
        const aliceOrder = [...S.aliceOrders].find((id) => id !== INJECTION_ORDER) as string;
        const crossAccount = await execute(S.conn.bob, 'orders.get', { orderId: aliceOrder });
        const missing = await execute(S.conn.bob, 'orders.get', { orderId: 'NS-9999' });
        for (const response of [crossAccount, missing]) {
          expect(response.status).toBe(200);
          expect(response.json.status).toBe('failed');
          expect(response.json.error.code).toBe('not_found');
          expect(response.json.result).toBeNull();
        }
        const shape = (job: Loose) => ({
          status: job.status,
          error: job.error,
          result: job.result,
          keys: Object.keys(job).sort(),
        });
        expect(shape(crossAccount.json)).toEqual(shape(missing.json));
        const rows = await jsonRows(
          `select status, error_code, error_message, result is null as no_result from execution_jobs where id in ('${crossAccount.json.jobId}', '${missing.json.jobId}')`,
        );
        expect(new Set(rows.map((row) => JSON.stringify(row))).size).toBe(1);

        /* and Bob can read his own order with the full schema */
        const bobOrder = [...S.bobOrders][0] as string;
        const own = await execute(S.conn.bob, 'orders.get', { orderId: bobOrder });
        expect(own.json.status).toBe('succeeded');
        const detail = own.json.result.order;
        expect(Object.keys(detail).sort()).toEqual(Object.keys(NorthstarOrderDetail.shape).sort());
        for (const item of detail.items) {
          expect(Object.keys(item).sort()).toEqual(Object.keys(NorthstarOrderItem.shape).sort());
        }
      },
      { critical: true },
    );

    /* ============================================================ E */
    step('E. prompt-injection invariance', async () => {
      const benignId = [...S.aliceOrders].find((id) => id !== INJECTION_ORDER) as string;
      const demoBefore = demoOrderRows();
      const requestsBefore = demoRequests().length;

      const s0 = await snapshotCounts();
      const benign = await execute(S.conn.alice, 'orders.get', { orderId: benignId });
      const requestsMid = demoRequests().length;
      const s1 = await snapshotCounts();
      const injected = await execute(S.conn.alice, 'orders.get', { orderId: INJECTION_ORDER });
      const requestsAfter = demoRequests().length;
      const s2 = await snapshotCounts();

      expect(benign.json.status).toBe('succeeded');
      expect(injected.json.status).toBe('succeeded');
      // The note comes back verbatim, as data.
      const storedNote = String(
        demoQuery('select notes from orders where id = ?', [INJECTION_ORDER])[0]?.notes,
      );
      expect(storedNote).toContain('ignore all previous instructions');
      expect(injected.json.result.order.notes).toBe(storedNote);
      expect(injected.json.result.order.id).toBe(INJECTION_ORDER);

      // Same job status, same audit event type, same connection status.
      const eventType = async (jobId: string) =>
        psql(
          `select a.event_type from execution_jobs j join audit_events a on a.id = j.audit_event_id where j.id = '${jobId}'`,
        );
      expect(await eventType(injected.json.jobId)).toBe('operation.succeeded');
      expect(await eventType(benign.json.jobId)).toBe(await eventType(injected.json.jobId));
      expect((await connectionOf(S.conn.alice)).status).toBe('active');

      // No extra job, grant, audit event or navigation beyond what the benign order caused.
      expect(delta(s1, s2)).toEqual(delta(s0, s1));
      expect(delta(s0, s1).jobs).toBe(1);
      expect(delta(s0, s1).grants).toBe(0);
      const signature = (requests: DemoRequest[]) =>
        requests
          .filter((r) => r.url !== '/favicon.ico')
          .map((r) => `${r.method} ${r.url.replace(/NS-\d+/, 'NS-n')}`);
      const all = demoRequests();
      const benignRequests = signature(all.slice(requestsBefore, requestsMid));
      const injectedRequests = signature(all.slice(requestsMid, requestsAfter));
      expect(injectedRequests).toEqual(benignRequests);
      expect(benignRequests.length).toBeGreaterThan(0);
      expect(all.slice(requestsBefore).filter((r) => r.method !== 'GET')).toEqual([]);
      // Nothing was changed in the demo either.
      expect(demoOrderRows()).toBe(demoBefore);
    });

    /* ============================================================ F */
    step('F. restart API and worker; read again without signing in', async () => {
      const before = { api: S.api?.pid ?? 0, worker: S.worker?.pid ?? 0 };
      const listBefore = (await execute(S.conn.bob, 'orders.list', { limit: 100 })).json.result
        .orders.length as number;
      await S.worker?.stop();
      await S.api?.stop();
      expect(S.worker?.exit).toEqual({ code: 0, signal: null });
      expect(S.api?.exit).toEqual({ code: 0, signal: null });
      S.oldApiLogs.push(S.api?.text() ?? '');
      S.oldWorkerLogs.push(S.worker?.text() ?? '');
      // Same database, same key directory. The API comes up first, as an operator would.
      await startApi();
      await startWorker();
      S.pids.apiAfter = S.api?.pid ?? 0;
      S.pids.workerAfter = S.worker?.pid ?? 0;
      expect(S.pids.workerAfter).not.toBe(S.pids.apiAfter);
      expect(S.pids.apiAfter).not.toBe(before.api);
      expect(S.pids.workerAfter).not.toBe(before.worker);
      expect(S.pids.apiAfter).not.toBe(before.worker);
      expect(S.pids.workerAfter).not.toBe(before.api);
      // The processes' own logs agree with the pids we spawned.
      expect(S.api?.text()).toContain(`"pid":${S.pids.apiAfter},`);
      expect(
        new RegExp(`"workerId":"worker-[^"]*-${S.pids.workerAfter}-`).test(S.worker?.text() ?? ''),
      ).toBe(true);

      // The owner's dashboard session lives in the database and survives the restart.
      const session = await api('GET', '/auth/session');
      expect(session.status).toBe(200);
      S.csrf = session.json.csrfToken;

      for (const [key, owned] of [
        ['alice', S.aliceOrders],
        ['bob', S.bobOrders],
      ] as const) {
        const t0 = Date.now();
        const response = await execute(S.conn[key], 'orders.list', { limit: 100 });
        S.metrics[`orders.list latency ms (${key}, after restart)`] = Date.now() - t0;
        expect(response.status).toBe(200);
        expect(response.json.status).toBe('succeeded');
        expect(new Set((response.json.result.orders as Loose[]).map((o) => o.id))).toEqual(owned);
      }
      expect(listBefore).toBe(S.bobOrders.size);
      expect((await connectionOf(S.conn.alice)).status).toBe('active');
      expect((await connectionOf(S.conn.bob)).status).toBe('active');
      S.metrics['rss MiB (api, worker)'] =
        `${Math.round(rssKb(S.pids.apiAfter) / 1024)}, ${Math.round(rssKb(S.pids.workerAfter) / 1024)}`;
    });

    /* ============================================================ J (live job) */
    step('J. sandbox properties during a real job', async () => {
      const workerPid = S.pids.workerAfter;
      expect(browserTree(workerPid).chromium).toEqual([]); // idle between jobs

      const t0 = Date.now();
      const job = execute(S.conn.bob, 'orders.list', { limit: 100 });
      let settled = false;
      void job.then(
        () => (settled = true),
        () => (settled = true),
      );
      let seen: ReturnType<typeof browserTree> | null = null;
      while (!settled && seen === null) {
        const tree = browserTree(workerPid);
        if (tree.chromium.length > 0) seen = tree;
        else await sleep(40);
      }
      expect(seen, 'a live job with a browser process was caught').not.toBeNull();
      if (seen === null) return;
      S.metrics['live job caught by'] =
        'polling /proc while orders.list ran through POST /v1/operations/execute (real job)';

      // Every browser process sits below a bwrap with --unshare-all, in other namespaces.
      const { chromium, table } = seen;
      for (const pid of chromium) {
        const chain = ancestorsOf(pid, table, workerPid) ?? [];
        const sandbox = chain.filter((ancestor) => {
          const argv = table.get(ancestor)?.argv ?? [];
          return path.basename(argv[0] ?? '') === 'bwrap' && argv.includes('--unshare-all');
        });
        expect(
          sandbox.length,
          `chromium ${pid} has a bwrap --unshare-all ancestor`,
        ).toBeGreaterThan(0);
        const sandboxArgs = table.get(sandbox[0] as number)?.argv ?? [];
        expect(sandboxArgs).toEqual(expect.arrayContaining(['--die-with-parent', '--clearenv']));
        expect(sandboxArgs.join(' ')).not.toContain(S.keyDir);
        expect(sandboxArgs.join(' ')).not.toContain(S.socketDir);
      }
      const mainPid = chromium[0] as number;
      const namespaces: string[] = [];
      for (const ns of ['net', 'pid', 'mnt', 'ipc']) {
        try {
          expect(readlinkSync(`/proc/${mainPid}/ns/${ns}`)).not.toBe(
            readlinkSync(`/proc/${workerPid}/ns/${ns}`),
          );
          namespaces.push(ns);
        } catch (error) {
          if (error instanceof Error && error.name === 'AssertionError') throw error;
        }
      }
      S.metrics['namespaces verified different from worker'] =
        namespaces.join(',') || 'none readable';
      expect(namespaces, 'net namespace differs from the worker').toContain('net');
      // The only network interface the browser sees is its own loopback.
      const interfaces = readFileSync(`/proc/${mainPid}/net/dev`, 'utf8')
        .split('\n')
        .slice(2)
        .map((line) => line.split(':')[0]?.trim() ?? '')
        .filter(Boolean);
      expect(interfaces).toEqual(['lo']);
      S.metrics['interfaces visible to the browser'] = interfaces.join(',');
      // What the sandbox can see: the mounted code, but not the key directory, the database
      // socket directory, the home directory or the demo's data.
      const root = `/proc/${mainPid}/root`;
      if (existsSync(`${root}/app/package.json`)) {
        expect(existsSync(`${root}${S.keyDir}`)).toBe(false);
        expect(existsSync(`${root}${path.join(S.keyDir, 'kek-v1.key')}`)).toBe(false);
        // P3-14: nor the vault's sockets.
        expect(existsSync(`${root}${S.socketDir}`)).toBe(false);
        expect(existsSync(`${root}${vaultSocket('supervisor')}`)).toBe(false);
        expect(existsSync(`${root}${PG_DIR}`)).toBe(false);
        expect(existsSync(`${root}${os.homedir()}`)).toBe(false);
        expect(existsSync(`${root}${S.demoDb}`)).toBe(false);
        S.metrics['key directory seen from inside the sandbox'] =
          'absent (checked via /proc/<pid>/root)';
      } else {
        S.metrics['key directory seen from inside the sandbox'] =
          'NOT VERIFIED: /proc/<pid>/root is not readable';
      }

      const response = await job;
      S.metrics['orders.list latency ms (bob, live-job step)'] = Date.now() - t0;
      expect(response.json.status).toBe('succeeded');

      // After the job: no sandbox, no browser, no job directory.
      const started = Date.now();
      await waitFor(
        () => {
          const tree = browserTree(workerPid);
          return tree.chromium.length === 0 && tree.bwrap.length === 0;
        },
        15_000,
        'the sandbox to be gone after the job',
        50,
      );
      S.metrics['sandbox gone after response, ms'] = Date.now() - started;
      expect(readdirSync(S.runtimeDir)).toEqual([]);
    });

    /* ============================================================ G */
    step('G. expired session ends as reauth_required', async () => {
      collectDemoSessions();
      demoQuery(
        'delete from sessions where account_id = (select id from accounts where username = ?)',
        [ALICE],
        true,
      );
      expect(demoSessionCount(ALICE)).toBe(0);
      const jobsBefore = await count('select count(*) from execution_jobs');

      const response = await execute(S.conn.alice, 'orders.list', { limit: 100 });
      expect(response.status).toBe(200);
      expect(response.json.status).toBe('reauth_required');
      expect(response.json.result).toBeNull();
      const connection = await connectionOf(S.conn.alice);
      expect(connection.status).toBe('expired');
      expect(connection.statusReason).toBeTruthy();
      expect(await count('select count(*) from execution_jobs')).toBe(jobsBefore + 1);

      // A second execute is refused up front and creates no job.
      const second = await execute(S.conn.alice, 'orders.list', { limit: 100 });
      expect(second.status).toBe(409);
      expect(second.json.error.code).toBe('reauth_required');
      expect(await count('select count(*) from execution_jobs')).toBe(jobsBefore + 1);

      // Her stored ciphertext is gone; Bob is unaffected.
      expect(await versionsFor(S.conn.alice)).toBe(0);
      expect(
        await count(
          `select count(*) from audit_events where event_type = 'operation.reauth_required' and connection_id = '${S.conn.alice}'`,
        ),
      ).toBe(1);
      const bob = await execute(S.conn.bob, 'orders.list', { limit: 100 });
      expect(bob.json.status).toBe('succeeded');
      expect(new Set((bob.json.result.orders as Loose[]).map((o) => o.id))).toEqual(S.bobOrders);
    });

    /* ============================================================ I (before H) */
    step('I1. stored sessions are ciphertext and nothing leaked (before revocation)', async () => {
      // Bob's snapshot is still stored: it must be there, and it must not be readable.
      expect(await versionsFor(S.conn.bob)).toBe(1);
      const hex = await psql(
        `select encode(v.ciphertext, 'hex') from vault_secret_versions v join vault_secrets s on s.id = v.secret_id where s.connection_id = '${S.conn.bob}'`,
      );
      const bytes = Buffer.from(hex, 'hex');
      expect(bytes.length).toBeGreaterThan(100); // a real storage state, not a stub
      const text = bytes.toString('latin1');
      for (const plain of ['cookies', 'localhost', 'origins', '{"', 'northstar']) {
        expect(text).not.toContain(plain);
      }
      // Ciphertext looks random: high entropy: about 7 bits per byte for a few hundred random bytes (JSON text is near 5).
      const frequency = new Array<number>(256).fill(0);
      for (const byte of bytes) frequency[byte] = (frequency[byte] ?? 0) + 1;
      const entropy = -frequency.reduce(
        (sum, n) => (n === 0 ? sum : sum + (n / bytes.length) * Math.log2(n / bytes.length)),
        0,
      );
      expect(entropy).toBeGreaterThan(6.3);
      S.metrics['stored snapshot: bytes, entropy bits/byte'] =
        `${bytes.length}, ${entropy.toFixed(2)}`;
      await leakScan('I1');
    });

    /* ============================================================ H */
    step('H. revocation removes the ciphertext and denies execution', async () => {
      const revoked = await api('POST', `/connections/${S.conn.bob}/revoke`);
      expect(revoked.status).toBe(200);
      expect(revoked.json.status).toBe('revoked');
      expect(await versionsFor(S.conn.bob)).toBe(0);
      const jobsBefore = await count('select count(*) from execution_jobs');
      const response = await execute(S.conn.bob, 'orders.list', { limit: 100 });
      expect(response.status).toBe(403);
      expect(response.json.error.code).toBe('denied');
      expect(await count('select count(*) from execution_jobs')).toBe(jobsBefore);
      expect(
        await count(
          `select count(*) from audit_events where event_type = 'vault.secret_deleted' and connection_id = '${S.conn.bob}'`,
        ),
      ).toBe(1);
    });

    /* ============================================================ shutdown, then the log checks */
    step('shutdown: SIGTERM the services; nothing of ours is left running', async () => {
      S.metrics['rss MiB at end (api, worker)'] =
        `${Math.round(rssKb(S.api?.pid ?? 0) / 1024)}, ${Math.round(rssKb(S.worker?.pid ?? 0) / 1024)}`;
      await S.worker?.stop();
      await S.api?.stop();
      await S.vault?.stop();
      expect(S.worker?.exit).toEqual({ code: 0, signal: null });
      expect(S.api?.exit).toEqual({ code: 0, signal: null });
      expect(S.vault?.exit).toEqual({ code: 0, signal: null });
      const tree = browserTree(S.pids.workerAfter);
      expect(tree.chromium).toEqual([]);
      expect(tree.bwrap).toEqual([]);
      expect(readdirSync(S.runtimeDir)).toEqual([]);
    });

    step('J2. egress decisions in the worker log: only the demo origin is allowed', async () => {
      const allowed = new Set<string>();
      const denied = new Set<string>();
      let decisions = 0;
      for (const log of [...S.oldWorkerLogs, S.worker?.text() ?? '']) {
        for (const line of log.split('\n')) {
          if (!line.includes('"egress decision"')) continue;
          const parsed = JSON.parse(line) as Loose;
          decisions += 1;
          expect(['allow', 'deny']).toContain(parsed.decision);
          (parsed.decision === 'allow' ? allowed : denied).add(String(parsed.origin));
        }
      }
      expect(decisions).toBeGreaterThan(0);
      expect([...allowed]).toEqual([DEMO_ORIGIN]);
      expect(denied.has(DEMO_ORIGIN)).toBe(false);
      // Chromium's own background traffic was attempted and refused.
      expect(denied.size).toBeGreaterThan(0);
      S.metrics['egress: denied origins'] = [...denied].sort().join(', ');
      S.metrics['egress: allowed origins'] = [...allowed].join(', ');
      S.metrics['egress: distinct denied origins'] = denied.size;
    });

    step('logs: no error-level lines from the API or the worker', async () => {
      const levels = (text: string) =>
        text
          .split('\n')
          .filter((line) => line.startsWith('{'))
          .map((line) => {
            try {
              return JSON.parse(line) as Loose;
            } catch {
              return {};
            }
          });
      for (const [name, logs] of Object.entries(logHaystacks())) {
        const lines = levels(logs);
        const warnings = lines.filter((l) => l.level === 40).map((l) => String(l.msg));
        const errors = lines
          .filter((l) => typeof l.level === 'number' && l.level >= 50)
          .map((l) => String(l.msg));
        S.metrics[`${name}: warn lines`] = warnings.length;
        if (warnings.length > 0)
          S.metrics[`${name}: warn messages`] = [...new Set(warnings)].join(' | ');
        expect(errors, `${name} error-level messages`).toEqual([]);
      }
    });

    step('I2. nothing leaked: complete logs, every response, every table', async () => {
      await leakScan('I2');
    });

    /* ============================================================ K */
    step('K. audit chain intact and expected event types present', async () => {
      const { createDatabase, createRepositories } = await import('@aab/database');
      const database = createDatabase({ connectionString: S.dbUrl, maxConnections: 1 });
      try {
        const verification = await createRepositories(database.db).audit.verify({
          organizationId: S.organizationId,
          userId: S.userId,
        });
        expect(verification.ok).toBe(true);
        const total = await count(
          `select count(*) from audit_events where organization_id = '${S.organizationId}'`,
        );
        if (verification.ok) expect(verification.count).toBe(total);
        S.metrics['audit events verified'] = total;
      } finally {
        await database.close();
      }
      const types = new Set(
        (await psql('select distinct event_type from audit_events')).split('\n'),
      );
      for (const expected of [
        'policy.evaluated',
        'connection.auth_started',
        'connection.auth_completed',
        'vault.secret_stored',
        'vault.secret_read',
        'operation.succeeded',
        'operation.reauth_required',
        'vault.secret_deleted',
        'connection.revoked',
      ]) {
        expect(types.has(expected), `audit event type ${expected}`).toBe(true);
      }
      const decisions = new Set(
        (
          await psql(
            `select distinct decision from audit_events where event_type = 'policy.evaluated'`,
          )
        ).split('\n'),
      );
      expect(decisions.has('allow')).toBe(true);
      expect(decisions.has('deny')).toBe(true);
    });
  },
);
