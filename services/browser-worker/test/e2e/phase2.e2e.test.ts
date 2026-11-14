import { execFile, spawn } from 'node:child_process';
import type { ChildProcess } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  readlinkSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import {
  NorthstarOrderDetail,
  NorthstarOrderItem,
  NorthstarOrderSummary,
  northstarAdapter,
} from '@aab/adapter-northstar';
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
 */

const ENABLED = process.env['AAB_E2E'] === '1';
const run = promisify(execFile);

const REPO = path.resolve(import.meta.dirname, '../../../..');
const API_DIR = path.join(REPO, 'services/broker-api');
const WORKER_DIR = path.join(REPO, 'services/browser-worker');
const DEMO_DIR = process.env['AAB_E2E_DEMO_DIR'] ?? path.resolve(REPO, '..', 'northstar-demo');
const UID = process.getuid?.() ?? 1000;
const PG_DIR = process.env['AAB_E2E_PG_DIR'] ?? `/run/user/${UID}/aab-pg`;
const PG_PORT = process.env['AAB_E2E_PG_PORT'] ?? '54329';
const PG_BIN = process.env['AAB_E2E_PG_BIN'] ?? '/usr/lib/postgresql/18/bin';
const BWRAP = '/usr/bin/bwrap';
const CHROMIUM = process.env['AAB_CHROMIUM_PATH'] ?? '/usr/lib/chromium/chromium';
const XVFB = '/usr/bin/Xvfb';
const XDOTOOL = '/usr/bin/xdotool';
const XAUTH = '/usr/bin/xauth';
const NODE = process.execPath;
const DEMO_PORT = 4100;
const DEMO_ORIGIN = `http://localhost:${DEMO_PORT}`;
const ALICE = 'alice.synthetic';
const BOB = 'bob.synthetic';
const INJECTION_ORDER = 'NS-1007';
const COOKIE_NAME = 'northstar_sid';

/* ------------------------------------------------------------------ small helpers */

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Loose = any;

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

async function waitFor(
  condition: () => boolean | Promise<boolean>,
  ms: number,
  what: string,
  intervalMs = 100,
): Promise<void> {
  const end = Date.now() + ms;
  for (;;) {
    if (await condition()) return;
    if (Date.now() > end) throw new Error(`timed out after ${ms} ms waiting for ${what}`);
    await sleep(intervalMs);
  }
}

function isExecutable(file: string): boolean {
  try {
    return statSync(file).isFile() && (statSync(file).mode & 0o111) !== 0;
  } catch {
    return false;
  }
}

function portOpen(port: number, host: string): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = net.connect({ port, host });
    socket.once('connect', () => {
      socket.destroy();
      resolve(true);
    });
    socket.once('error', () => resolve(false));
  });
}

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address() as net.AddressInfo;
      server.close(() => resolve(port));
    });
  });
}

const sha256Hex = (text: string) => createHash('sha256').update(text).digest('hex');

/** A child process in its own process group, with its output captured. */
class Proc {
  readonly child: ChildProcess;
  private readonly chunks: string[] = [];
  exit: { code: number | null; signal: NodeJS.Signals | null } | null = null;
  readonly exited: Promise<void>;

  constructor(
    readonly name: string,
    command: string,
    args: string[],
    options: { cwd: string; env: Record<string, string> },
  ) {
    this.child = spawn(command, args, {
      cwd: options.cwd,
      env: options.env,
      detached: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    for (const stream of [this.child.stdout, this.child.stderr]) {
      stream?.setEncoding('utf8');
      stream?.on('data', (chunk: string) => this.chunks.push(chunk));
    }
    this.exited = new Promise((resolve) => {
      this.child.once('exit', (code, signal) => {
        this.exit = { code, signal };
        resolve();
      });
      this.child.once('error', () => resolve());
    });
    PROCS.push(this);
    writeWatchSpec();
  }

  get pid(): number {
    return this.child.pid ?? -1;
  }

  text(): string {
    return this.chunks.join('');
  }

  killGroup(signal: NodeJS.Signals): void {
    try {
      process.kill(-this.pid, signal);
    } catch {
      // Already gone.
    }
  }

  /** SIGTERM the main process, wait for it, then clean up the rest of its group. */
  async stop(graceMs = 20_000): Promise<void> {
    if (this.exit === null) {
      try {
        process.kill(this.pid, 'SIGTERM');
      } catch {
        // Already gone.
      }
      await Promise.race([this.exited, sleep(graceMs)]);
    }
    const graceful = this.exit !== null;
    this.killGroup('SIGKILL');
    await Promise.race([this.exited, sleep(2_000)]);
    if (!graceful) throw new Error(`${this.name} did not exit within ${graceMs} ms of SIGTERM`);
  }
}

const PROCS: Proc[] = [];

/**
 * What test/e2e/watchdog.mjs must clean up if this process is killed before afterAll runs.
 * Rewritten whenever something is created.
 */
function writeWatchSpec(done = false): void {
  if (S.tmp === '') return;
  writeFileSync(
    path.join(S.tmp, 'watch.json'),
    JSON.stringify({
      done,
      groups: PROCS.map((proc) => proc.pid).filter((pid) => pid > 0),
      markers: [S.runtimeDir, S.tmp],
      dirs: [S.runtimeDir, S.tmp],
      dbName: S.dbName,
      pgBin: PG_BIN,
      pgDir: PG_DIR,
      pgPort: PG_PORT,
      displayNumber: /^:(\d+)$/.exec(S.display)?.[1] ?? null,
    }),
  );
}

let watchdog: ChildProcess | null = null;

/* ------------------------------------------------------------------ shared state */

interface State {
  tmp: string;
  runtimeDir: string;
  keyDir: string;
  keyBytes: Buffer;
  demoDb: string;
  display: string;
  xauth: string;
  dbName: string;
  dbUrl: string;
  apiPort: number;
  apiBase: string;
  xvfb: Proc | null;
  demo: Proc | null;
  api: Proc | null;
  worker: Proc | null;
  /** Output of earlier API and worker processes (before the restart). */
  oldApiLogs: string[];
  oldWorkerLogs: string[];
  passwords: { alice: string; bob: string; owner: string };
  ownerEmail: string;
  cookie: string;
  csrf: string;
  organizationId: string;
  userId: string;
  applicationId: string;
  agentId: string;
  conn: { alice: string; bob: string; throwaway: string };
  aliceOrders: Set<string>;
  bobOrders: Set<string>;
  httpBodies: string[];
  tokenHashes: Set<string>;
  csrfTokens: Set<string>;
  pids: { api: number; worker: number; apiAfter: number; workerAfter: number };
  metrics: Record<string, number | string>;
  counter: number;
}

const S: State = {
  tmp: '',
  runtimeDir: '',
  keyDir: '',
  keyBytes: Buffer.alloc(0),
  demoDb: '',
  display: '',
  xauth: '',
  dbName: '',
  dbUrl: '',
  apiPort: 0,
  apiBase: '',
  xvfb: null,
  demo: null,
  api: null,
  worker: null,
  oldApiLogs: [],
  oldWorkerLogs: [],
  passwords: { alice: '', bob: '', owner: '' },
  ownerEmail: 'owner@e2e.test',
  cookie: '',
  csrf: '',
  organizationId: '',
  userId: '',
  applicationId: '',
  agentId: '',
  conn: { alice: '', bob: '', throwaway: '' },
  aliceOrders: new Set(),
  bobOrders: new Set(),
  httpBodies: [],
  tokenHashes: new Set(),
  csrfTokens: new Set(),
  pids: { api: 0, worker: 0, apiAfter: 0, workerAfter: 0 },
  metrics: {},
  counter: 0,
};

/* ------------------------------------------------------------------ database helpers */

async function psql(sql: string, database = S.dbName): Promise<string> {
  const url = `postgresql://${os.userInfo().username}@localhost:${PG_PORT}/${database}?host=${PG_DIR}`;
  const { stdout } = await run(
    path.join(PG_BIN, 'psql'),
    ['-X', '-A', '-t', '-q', '-v', 'ON_ERROR_STOP=1', '-c', sql, url],
    { env: { PATH: '/usr/bin' }, maxBuffer: 256 * 1024 * 1024 },
  );
  return stdout.trim();
}

const count = async (sql: string): Promise<number> => Number(await psql(sql));

async function jsonRows(sql: string): Promise<Loose[]> {
  const out = await psql(`select coalesce(json_agg(t), '[]'::json) from (${sql}) t`);
  return JSON.parse(out) as Loose[];
}

interface Counts {
  jobs: number;
  audit: Record<string, number>;
  grants: number;
}

async function snapshotCounts(): Promise<Counts> {
  const rows = await jsonRows(
    'select event_type as t, count(*)::int as n from audit_events group by event_type',
  );
  return {
    jobs: await count('select count(*) from execution_jobs'),
    audit: Object.fromEntries(rows.map((row: Loose) => [row.t as string, row.n as number])),
    grants: await count('select count(*) from agent_grants'),
  };
}

function delta(before: Counts, after: Counts): Counts {
  const audit: Record<string, number> = {};
  for (const type of new Set([...Object.keys(before.audit), ...Object.keys(after.audit)])) {
    const change = (after.audit[type] ?? 0) - (before.audit[type] ?? 0);
    if (change !== 0) audit[type] = change;
  }
  return { jobs: after.jobs - before.jobs, audit, grants: after.grants - before.grants };
}

const versionsFor = (connectionId: string) =>
  count(
    `select count(*) from vault_secret_versions v join vault_secrets s on s.id = v.secret_id where s.connection_id = '${connectionId}'`,
  );

/* ------------------------------------------------------------------ demo (SQLite) helpers */

function demoQuery(sql: string, params: string[] = [], write = false): Loose[] {
  const { DatabaseSync } = process.getBuiltinModule('node:sqlite');
  const db = new DatabaseSync(S.demoDb, { readOnly: !write });
  try {
    db.exec('PRAGMA busy_timeout = 5000');
    const statement = db.prepare(sql);
    return (write ? (statement.run(...params), []) : statement.all(...params)) as Loose[];
  } finally {
    db.close();
  }
}

function demoOrdersOf(username: string): Set<string> {
  const rows = demoQuery(
    'select o.id from orders o join accounts a on a.id = o.account_id where a.username = ?',
    [username],
  );
  return new Set(rows.map((row) => String(row.id)));
}

function demoOrderRows(): string {
  return JSON.stringify(
    demoQuery(
      'select id, account_id, status, shipping_method, notes, version, updated_at from orders order by id',
    ),
  );
}

/** Remembers every live demo session token hash (and CSRF token) so leaks can be recognised later. */
function collectDemoSessions(): number {
  const rows = demoQuery('select token_hash, csrf_token from sessions');
  for (const row of rows) {
    S.tokenHashes.add(String(row.token_hash));
    S.csrfTokens.add(String(row.csrf_token));
  }
  return rows.length;
}

function demoSessionCount(username: string): number {
  return Number(
    demoQuery(
      'select count(*) as n from sessions s join accounts a on a.id = s.account_id where a.username = ?',
      [username],
    )[0]?.n ?? 0,
  );
}

interface DemoRequest {
  method: string;
  url: string;
}

function demoRequests(): DemoRequest[] {
  const found: DemoRequest[] = [];
  for (const line of (S.demo?.text() ?? '').split('\n')) {
    if (!line.startsWith('{')) continue;
    try {
      const parsed = JSON.parse(line) as Loose;
      if (parsed.msg === 'incoming request') {
        found.push({ method: String(parsed.req.method), url: String(parsed.req.url) });
      }
    } catch {
      // Not a log line.
    }
  }
  return found;
}

/* ------------------------------------------------------------------ HTTP helpers */

interface Resp {
  status: number;
  json: Loose;
  text: string;
}

async function api(method: string, route: string, body?: unknown, auth = true): Promise<Resp> {
  const headers: Record<string, string> = { accept: 'application/json' };
  if (auth && S.cookie !== '') headers['cookie'] = S.cookie;
  if (auth && method !== 'GET' && S.csrf !== '') headers['x-csrf-token'] = S.csrf;
  // A JSON content type with an empty body is rejected by the API, as the dashboard knows.
  if (body !== undefined) headers['content-type'] = 'application/json';
  const response = await fetch(`${S.apiBase}/v1${route}`, {
    method,
    headers,
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    redirect: 'manual',
    signal: AbortSignal.timeout(90_000),
  });
  const text = await response.text();
  if (route === '/auth/login' && response.status === 200) {
    S.cookie =
      (response.headers.getSetCookie().find((c) => c.startsWith('aab_session=')) ?? '').split(
        ';',
      )[0] ?? '';
  }
  S.httpBodies.push(text, [...response.headers.entries()].map(([k, v]) => `${k}: ${v}`).join('\n'));
  const parse = (): Loose => {
    try {
      return text === '' ? null : JSON.parse(text);
    } catch {
      return null;
    }
  };
  return { status: response.status, json: parse(), text };
}

function idempotencyKey(): string {
  S.counter += 1;
  return `e2e-${S.counter}-${randomBytes(4).toString('hex')}`;
}

async function execute(
  connectionId: string,
  operation: string,
  args: Record<string, unknown> = {},
): Promise<Resp> {
  return api('POST', '/operations/execute', {
    agentId: S.agentId,
    connectionId,
    operation,
    arguments: args,
    idempotencyKey: idempotencyKey(),
  });
}

const connectionOf = async (id: string): Promise<Loose> =>
  (await api('GET', `/connections/${id}`)).json;

function startProcessEnv(extra: Record<string, string>): Record<string, string> {
  return { PATH: '/usr/bin:/bin', HOME: os.homedir(), ...extra };
}

/* ------------------------------------------------------------------ stack control */

async function startApi(): Promise<void> {
  S.api = new Proc('api', NODE, ['--import', 'tsx', 'src/main.ts'], {
    cwd: API_DIR,
    env: startProcessEnv({
      DATABASE_URL: S.dbUrl,
      AAB_HOST: '127.0.0.1',
      AAB_PORT: String(S.apiPort),
      AAB_COOKIE_SECURE: 'false',
      AAB_LOG_LEVEL: 'info',
    }),
  });
  await waitFor(
    async () => {
      if (S.api?.exit !== null)
        throw new Error(`the API exited early:\n${S.api?.text().slice(-1500)}`);
      try {
        const response = await fetch(`${S.apiBase}/v1/health`, {
          signal: AbortSignal.timeout(2_000),
        });
        return response.status === 200;
      } catch {
        return false;
      }
    },
    60_000,
    'the API to answer /v1/health',
  );
}

async function startWorker(): Promise<void> {
  S.worker = new Proc('worker', NODE, ['--import', 'tsx', 'src/main.ts'], {
    cwd: WORKER_DIR,
    // WAYLAND_DISPLAY and XDG_RUNTIME_DIR are deliberately absent.
    env: startProcessEnv({
      DATABASE_URL: S.dbUrl,
      AAB_KEK_DIR: S.keyDir,
      DISPLAY: S.display,
      XAUTHORITY: S.xauth,
      AAB_WORKER_RUNTIME_DIR: S.runtimeDir,
      AAB_CHROMIUM_PATH: CHROMIUM,
      AAB_LOG_LEVEL: 'debug',
    }),
  });
  await waitFor(
    () => {
      if (S.worker?.exit !== null) {
        throw new Error(`the worker exited early:\n${S.worker?.text().slice(-1500)}`);
      }
      return (S.worker?.text() ?? '').includes('supervisor started');
    },
    90_000,
    'the worker to report "supervisor started"',
  );
}

async function xdotool(...args: string[]): Promise<string> {
  const { stdout } = await run(XDOTOOL, args, {
    env: { DISPLAY: S.display, XAUTHORITY: S.xauth, PATH: '/usr/bin' },
    timeout: 20_000,
  });
  return stdout.trim();
}

async function chromiumWindow(): Promise<{ id: string; width: number }> {
  let id = '';
  await waitFor(
    async () => {
      try {
        id = (await xdotool('search', '--onlyvisible', '--class', 'chromium')).split('\n')[0] ?? '';
      } catch {
        id = '';
      }
      return id !== '';
    },
    30_000,
    'the Chromium login window',
  );
  const geometry = await xdotool('getwindowgeometry', '--shell', id);
  const width = Number(/WIDTH=(\d+)/.exec(geometry)?.[1] ?? 1280);
  return { id, width };
}

async function noLoginWindow(): Promise<void> {
  await waitFor(
    async () => {
      try {
        return (await xdotool('search', '--onlyvisible', '--class', 'chromium')) === '';
      } catch {
        return true;
      }
    },
    20_000,
    'the login window to close',
  );
}

/** Starts a login handoff and waits until the window shows the login page. */
async function startHandoff(
  connectionId: string,
): Promise<{ window: { id: string; width: number }; t0: number }> {
  const loginsBefore = demoRequests().filter(
    (r) => r.method === 'GET' && r.url === '/login',
  ).length;
  const t0 = Date.now();
  const start = await api('POST', `/connections/${connectionId}/auth/start`);
  expect(start.status).toBe(200);
  expect(start.json.connection.status).toBe('authenticating');
  const window = await chromiumWindow();
  await waitFor(
    () =>
      demoRequests().filter((r) => r.method === 'GET' && r.url === '/login').length > loginsBefore,
    30_000,
    'the login window to load the demo login page',
  );
  await sleep(800); // let the page paint
  return { window, t0 };
}

async function signIn(window: { id: string; width: number }, username: string, password: string) {
  const before = demoSessionCount(username);
  // No window manager: X keyboard focus follows a click, so click the username field first.
  await xdotool(
    'mousemove',
    '--window',
    window.id,
    String(Math.round(window.width / 2)),
    '338',
    'click',
    '1',
  );
  await xdotool('type', '--delay', '15', '--', username);
  await xdotool('key', 'Tab');
  await xdotool('type', '--delay', '15', '--', password);
  await xdotool('key', 'Return');
  await waitFor(
    () => demoSessionCount(username) > before,
    20_000,
    `the demo to sign ${username} in`,
  );
}

async function completeHandoff(connectionId: string): Promise<Resp> {
  const complete = await api('POST', `/connections/${connectionId}/auth/complete`);
  await noLoginWindow();
  return complete;
}

/* ------------------------------------------------------------------ process inspection */

interface ProcInfo {
  ppid: number;
  argv: string[];
}

function procTable(): Map<number, ProcInfo> {
  const table = new Map<number, ProcInfo>();
  for (const entry of readdirSync('/proc')) {
    if (!/^\d+$/.test(entry)) continue;
    try {
      const stat = readFileSync(`/proc/${entry}/stat`, 'latin1');
      const fields = stat.slice(stat.lastIndexOf(')') + 2).split(' ');
      const argv = readFileSync(`/proc/${entry}/cmdline`, 'latin1').split('\0').filter(Boolean);
      table.set(Number(entry), { ppid: Number(fields[1]), argv });
    } catch {
      // Gone, or not ours.
    }
  }
  return table;
}

function ancestorsOf(pid: number, table: Map<number, ProcInfo>, stopAt: number): number[] | null {
  const chain: number[] = [];
  let current = table.get(pid)?.ppid;
  for (let hops = 0; current !== undefined && hops < 64; hops += 1) {
    if (current === stopAt) return chain;
    chain.push(current);
    current = table.get(current)?.ppid;
  }
  return null;
}

interface BrowserTree {
  chromium: number[];
  bwrap: number[];
}

function browserTree(rootPid: number): BrowserTree & { table: Map<number, ProcInfo> } {
  const table = procTable();
  const tree: BrowserTree = { chromium: [], bwrap: [] };
  for (const [pid, info] of table) {
    if (ancestorsOf(pid, table, rootPid) === null) continue;
    const exe = info.argv[0] ?? '';
    if (exe === CHROMIUM) tree.chromium.push(pid);
    if (path.basename(exe) === 'bwrap') tree.bwrap.push(pid);
  }
  return { ...tree, table };
}

const rssKb = (pid: number): number => {
  try {
    return Number(/VmRSS:\s+(\d+)/.exec(readFileSync(`/proc/${pid}/status`, 'utf8'))?.[1] ?? 0);
  } catch {
    return 0;
  }
};

/* ------------------------------------------------------------------ leak scanner */

interface Needle {
  kind: string;
  value: string;
}

/** Returns "haystack :: needle kind" for every hit. Never returns the secret itself. */
function scan(
  haystacks: Record<string, string>,
  needles: Needle[],
  tokenHashes: ReadonlySet<string>,
): string[] {
  const hits: string[] = [];
  for (const [label, haystack] of Object.entries(haystacks)) {
    for (const needle of needles) {
      if (needle.value !== '' && haystack.includes(needle.value))
        hits.push(`${label} :: ${needle.kind}`);
    }
    // Session tokens: hash every token-shaped run (and every 43-character window inside a
    // longer run) the way the demo does, and compare with the demo's sessions table.
    const seen = new Set<string>();
    for (const match of haystack.matchAll(/[A-Za-z0-9_-]{20,}/g)) {
      const run = match[0];
      if (run.length <= 100) seen.add(run);
      for (let offset = 0; offset + 43 <= run.length; offset += 1)
        seen.add(run.slice(offset, offset + 43));
    }
    for (const candidate of seen) {
      if (tokenHashes.has(sha256Hex(candidate))) hits.push(`${label} :: demo session token`);
    }
  }
  return hits;
}

async function databaseHaystacks(): Promise<Record<string, string>> {
  const haystacks: Record<string, string> = {};
  const tables = (
    await psql(
      "select table_name from information_schema.tables where table_schema = 'public' and table_type = 'BASE TABLE' order by 1",
    )
  )
    .split('\n')
    .filter(Boolean);
  for (const table of tables) {
    haystacks[`db:${table}`] = await psql(`select row_to_json(t)::text from "${table}" t`);
  }
  const byteaColumns = (
    await psql(
      "select table_name || ' ' || column_name from information_schema.columns where table_schema = 'public' and data_type = 'bytea'",
    )
  )
    .split('\n')
    .filter(Boolean);
  for (const entry of byteaColumns) {
    const [table, column] = entry.split(' ') as [string, string];
    const buffers = (await psql(`select encode("${column}", 'base64') from "${table}"`))
      .split('\n')
      .filter(Boolean)
      .map((line) => Buffer.from(line, 'base64'));
    haystacks[`db:${table}.${column}(hex)`] = buffers.map((b) => b.toString('hex')).join('\n');
    haystacks[`db:${table}.${column}(utf8)`] = buffers.map((b) => b.toString('utf8')).join('\n');
    haystacks[`db:${table}.${column}(latin1)`] = buffers
      .map((b) => b.toString('latin1'))
      .join('\n');
  }
  return haystacks;
}

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

function logHaystacks(): Record<string, string> {
  return {
    'api stdout/stderr': [...S.oldApiLogs, S.api?.text() ?? ''].join('\n'),
    'worker stdout/stderr': [...S.oldWorkerLogs, S.worker?.text() ?? ''].join('\n'),
  };
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
      /* prerequisites, one clear message */
      const missing: string[] = [];
      for (const tool of [BWRAP, CHROMIUM, XVFB, XDOTOOL, XAUTH]) {
        if (!isExecutable(tool)) missing.push(`${tool} is not installed or not executable`);
      }
      for (const tool of ['psql', 'createdb', 'dropdb']) {
        if (!isExecutable(path.join(PG_BIN, tool)))
          missing.push(`${path.join(PG_BIN, tool)} is missing (AAB_E2E_PG_BIN)`);
      }
      if (!existsSync(path.join(PG_DIR, `.s.PGSQL.${PG_PORT}`))) {
        missing.push(
          `no PostgreSQL socket at ${PG_DIR}/.s.PGSQL.${PG_PORT} (AAB_E2E_PG_DIR, AAB_E2E_PG_PORT)`,
        );
      }
      if (!existsSync(path.join(DEMO_DIR, 'node_modules/.bin/tsx'))) {
        missing.push(`the Northstar demo is not installed at ${DEMO_DIR} (AAB_E2E_DEMO_DIR)`);
      }
      if (!existsSync(path.join(REPO, 'node_modules/.bin/tsx')))
        missing.push('repository dependencies are not installed');
      if (!existsSync(`/run/user/${UID}`))
        missing.push(`/run/user/${UID} does not exist (short runtime directory)`);
      if ((await portOpen(DEMO_PORT, '127.0.0.1')) || (await portOpen(DEMO_PORT, '::1'))) {
        missing.push(
          `port ${DEMO_PORT} is already in use; the Northstar adapter only allows ${DEMO_ORIGIN}`,
        );
      }
      if (missing.length > 0) {
        throw new Error(`Phase 2 e2e prerequisites missing:\n  - ${missing.join('\n  - ')}`);
      }

      /* directories */
      const random = randomBytes(4).toString('hex');
      S.tmp = mkdtempSync(path.join(os.tmpdir(), 'e2e-'));
      S.runtimeDir = `/run/user/${UID}/aabe-${random}`;
      mkdirSync(S.runtimeDir, { mode: 0o700 });
      S.keyDir = path.join(S.tmp, 'keys');
      S.demoDb = path.join(S.tmp, 'northstar.sqlite');
      S.xauth = path.join(S.tmp, 'Xauthority');
      S.passwords.owner = `owner-${randomBytes(12).toString('base64url')}`;

      /* the safety net first, then everything it has to clean up */
      S.dbName = `aab_e2e_${random}`;
      writeWatchSpec();
      watchdog = spawn(
        NODE,
        [
          path.join(import.meta.dirname, 'watchdog.mjs'),
          path.join(S.tmp, 'watch.json'),
          String(process.pid),
        ],
        { detached: true, stdio: 'ignore', env: { PATH: '/usr/bin:/bin' } },
      );
      watchdog.unref();

      /* database */
      await run(path.join(PG_BIN, 'createdb'), ['-h', PG_DIR, '-p', PG_PORT, S.dbName], {
        env: { PATH: '/usr/bin' },
      });
      S.dbUrl = `postgresql://${os.userInfo().username}@localhost:${PG_PORT}/${S.dbName}?host=${PG_DIR}`;

      /* private X display */
      let displayNumber = 0;
      for (let n = 87; n < 140 && displayNumber === 0; n += 1) {
        if (!existsSync(`/tmp/.X11-unix/X${n}`) && !existsSync(`/tmp/.X${n}-lock`))
          displayNumber = n;
      }
      if (displayNumber === 0) throw new Error('no free X display number between :87 and :139');
      S.display = `:${displayNumber}`;
      writeWatchSpec();
      await run(XAUTH, ['-f', S.xauth, 'add', S.display, '.', randomBytes(16).toString('hex')], {
        env: { PATH: '/usr/bin' },
      });
      S.xvfb = new Proc(
        'xvfb',
        XVFB,
        [S.display, '-auth', S.xauth, '-nolisten', 'tcp', '-screen', '0', '1280x800x24'],
        {
          cwd: S.tmp,
          env: { PATH: '/usr/bin' },
        },
      );
      await waitFor(() => existsSync(`/tmp/.X11-unix/X${displayNumber}`), 15_000, 'Xvfb');
    }, 120_000);

    afterAll(async () => {
      for (const proc of [...PROCS].reverse()) {
        proc.killGroup('SIGTERM');
      }
      await sleep(1_000);
      for (const proc of PROCS) proc.killGroup('SIGKILL');
      // Anything still mentioning our private directories (sandboxes whose parent died).
      for (const [pid, info] of procTable()) {
        const line = info.argv.join(' ');
        if (
          pid !== process.pid &&
          ((S.runtimeDir !== '' && line.includes(S.runtimeDir)) ||
            (S.tmp !== '' && line.includes(S.tmp)))
        ) {
          try {
            process.kill(pid, 'SIGKILL');
          } catch {
            // Gone.
          }
        }
      }
      await Promise.race([Promise.all(PROCS.map((p) => p.exited)), sleep(5_000)]);
      const keep = process.env['AAB_E2E_KEEP_LOGS'];
      if (keep !== undefined && keep !== '') {
        // For debugging only. These logs hold no secrets (that is what step I checks), but the
        // directory is still the caller's choice.
        mkdirSync(keep, { recursive: true });
        const logs = logHaystacks();
        writeFileSync(path.join(keep, 'api.log'), logs['api stdout/stderr'] ?? '');
        writeFileSync(path.join(keep, 'worker.log'), logs['worker stdout/stderr'] ?? '');
        writeFileSync(path.join(keep, 'demo.log'), S.demo?.text() ?? '');
        if (S.dbName !== '') {
          const audit = await psql(
            'select sequence, event_type, decision, actor_type, metadata from audit_events order by sequence',
          ).catch(() => '');
          writeFileSync(path.join(keep, 'audit.txt'), audit);
        }
      }
      if (S.dbName !== '') {
        await run(
          path.join(PG_BIN, 'dropdb'),
          ['--if-exists', '--force', '-h', PG_DIR, '-p', PG_PORT, S.dbName],
          {
            env: { PATH: '/usr/bin' },
          },
        ).catch(() => undefined);
      }
      writeWatchSpec(true);
      watchdog?.kill('SIGKILL');
      if (S.runtimeDir !== '') rmSync(S.runtimeDir, { recursive: true, force: true });
      if (S.tmp !== '') rmSync(S.tmp, { recursive: true, force: true });
      process.stdout.write(`\nPhase 2 e2e metrics: ${JSON.stringify(S.metrics, null, 2)}\n`);
    }, 60_000);

    /* ============================================================ A */
    step(
      'A. setup through the API (stack start, application, two connections, one agent)',
      async () => {
        /* demo, seeded into a temp SQLite file */
        const demoEnv = startProcessEnv({
          NORTHSTAR_DB_PATH: S.demoDb,
          NORTHSTAR_PORT: String(DEMO_PORT),
          NORTHSTAR_SESSION_TTL_SECONDS: '3600',
          NORTHSTAR_LOG_LEVEL: 'info',
        });
        const demoTsx = path.join(DEMO_DIR, 'node_modules/.bin/tsx');
        const seed = await run(demoTsx, ['seed/seed.ts'], { cwd: DEMO_DIR, env: demoEnv });
        const alicePassword = new RegExp(`${ALICE}\\s+(\\S+)`).exec(seed.stdout)?.[1];
        const bobPassword = new RegExp(`${BOB}\\s+(\\S+)`).exec(seed.stdout)?.[1];
        expect(alicePassword, 'the seed prints a password for alice').toBeTruthy();
        expect(bobPassword, 'the seed prints a password for bob').toBeTruthy();
        S.passwords.alice = alicePassword ?? '';
        S.passwords.bob = bobPassword ?? '';
        S.demo = new Proc('demo', demoTsx, ['server/main.ts'], { cwd: DEMO_DIR, env: demoEnv });
        await waitFor(
          async () => {
            if (S.demo?.exit !== null)
              throw new Error(`the demo exited early:\n${S.demo?.text().slice(-1000)}`);
            try {
              return (
                (await fetch(`${DEMO_ORIGIN}/healthz`, { signal: AbortSignal.timeout(2_000) }))
                  .status === 200
              );
            } catch {
              return false;
            }
          },
          30_000,
          'the demo to answer /healthz',
        );
        S.aliceOrders = demoOrdersOf(ALICE);
        S.bobOrders = demoOrdersOf(BOB);
        expect(S.aliceOrders.size).toBeGreaterThan(0);
        expect(S.bobOrders.size).toBeGreaterThan(0);

        /* fresh database: migrate, then the owner non-interactively */
        const scriptEnv = startProcessEnv({ DATABASE_URL: S.dbUrl });
        const migrate = await run(NODE, ['--import', 'tsx', 'src/scripts/migrate.ts'], {
          cwd: API_DIR,
          env: scriptEnv,
        });
        expect(migrate.stdout).toContain('migrate: applied');
        await new Promise<void>((resolve, reject) => {
          const child = spawn(
            NODE,
            ['--import', 'tsx', 'src/scripts/create-owner.ts', '--email', S.ownerEmail],
            {
              cwd: API_DIR,
              env: scriptEnv,
              stdio: ['pipe', 'pipe', 'pipe'],
            },
          );
          let output = '';
          child.stdout.on('data', (chunk: Buffer) => (output += chunk.toString()));
          child.stderr.on('data', (chunk: Buffer) => (output += chunk.toString()));
          child.once('exit', (code) =>
            code === 0 ? resolve() : reject(new Error(`create-owner failed: ${output}`)),
          );
          child.stdin.end(`${S.passwords.owner}\n`);
        });

        /* key directory from the worker's init-kek script */
        S.keyDir = path.join(S.tmp, 'keys');
        await run(NODE, ['--import', 'tsx', 'src/scripts/init-kek.ts', S.keyDir], {
          cwd: WORKER_DIR,
          env: startProcessEnv({}),
        });
        expect(statSync(S.keyDir).mode & 0o777).toBe(0o700);
        const keyFile = path.join(S.keyDir, 'kek-v1.key');
        expect(statSync(keyFile).mode & 0o777).toBe(0o600);
        S.keyBytes = readFileSync(keyFile);
        expect(S.keyBytes.length).toBe(32);
        expect(path.relative(REPO, S.keyDir).startsWith('..')).toBe(true);

        /* API (no AAB_KEK_DIR) and worker */
        S.apiPort = await freePort();
        S.apiBase = `http://127.0.0.1:${S.apiPort}`;
        await startApi();
        await startWorker();
        S.pids.api = S.api?.pid ?? 0;
        S.pids.worker = S.worker?.pid ?? 0;

        /* log in as the dashboard would */
        const login = await api(
          'POST',
          '/auth/login',
          { email: S.ownerEmail, password: S.passwords.owner },
          false,
        );
        expect(login.status).toBe(200);
        expect(S.cookie, 'the session cookie').toMatch(/^aab_session=.+/);
        S.csrf = login.json.csrfToken;
        S.organizationId = login.json.organization.id;
        S.userId = login.json.user.id;

        /* application, connections, agent */
        const application = await api('POST', '/applications/register', {
          adapterId: northstarAdapter.id,
          adapterVersion: northstarAdapter.version,
          name: 'Northstar (e2e)',
          allowedOrigins: [DEMO_ORIGIN],
          authModes: ['browser_session'],
        });
        expect(application.status).toBe(201);
        S.applicationId = application.json.id;
        for (const [key, name] of [
          ['alice', 'Alice (e2e)'],
          ['bob', 'Bob (e2e)'],
        ] as const) {
          const created = await api('POST', '/connections', {
            applicationId: S.applicationId,
            displayName: name,
          });
          expect(created.status).toBe(201);
          expect(created.json.status).toBe('created');
          S.conn[key] = created.json.id;
        }
        const agent = await api('POST', '/agents', {
          name: 'e2e agent',
          clientIdentity: 'e2e-agent',
        });
        expect(agent.status).toBe(201);
        S.agentId = agent.json.id;
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
    step('shutdown: SIGTERM both services; nothing of ours is left running', async () => {
      S.metrics['rss MiB at end (api, worker)'] =
        `${Math.round(rssKb(S.api?.pid ?? 0) / 1024)}, ${Math.round(rssKb(S.worker?.pid ?? 0) / 1024)}`;
      await S.worker?.stop();
      await S.api?.stop();
      expect(S.worker?.exit).toEqual({ code: 0, signal: null });
      expect(S.api?.exit).toEqual({ code: 0, signal: null });
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
