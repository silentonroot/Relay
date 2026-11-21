import { execFile, spawn } from 'node:child_process';
import type { ChildProcess } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { northstarAdapter } from '@aab/adapter-northstar';
import { expect } from 'vitest';

/*
 * Shared harness of the end-to-end tests (phase2.e2e.test.ts, phase3.e2e.test.ts): the real
 * stack (PostgreSQL, the vault, the API, the supervisor, the Northstar demo, a private Xvfb
 * display) and the helpers that drive it. Moved out of phase2.e2e.test.ts unchanged, except that
 * the set-up, tear-down and step A bodies became functions and the label of the file is a
 * parameter. Module state is per test file (vitest isolates modules per file), and the files run
 * one after the other (fileParallelism is off in vitest.config.ts), so they share the demo port,
 * the PostgreSQL server and the display numbers without collisions: each run creates its own
 * database, directories and display.
 */

export const ENABLED = process.env['AAB_E2E'] === '1';
export const run = promisify(execFile);

export const REPO = path.resolve(import.meta.dirname, '../../../..');
export const API_DIR = path.join(REPO, 'services/broker-api');
export const WORKER_DIR = path.join(REPO, 'services/browser-worker');
export const VAULT_DIR = path.join(REPO, 'services/vault');
export const DEMO_DIR =
  process.env['AAB_E2E_DEMO_DIR'] ?? path.resolve(REPO, '..', 'northstar-demo');
export const UID = process.getuid?.() ?? 1000;
export const PG_DIR = process.env['AAB_E2E_PG_DIR'] ?? `/run/user/${UID}/aab-pg`;
export const PG_PORT = process.env['AAB_E2E_PG_PORT'] ?? '54329';
export const PG_BIN = process.env['AAB_E2E_PG_BIN'] ?? '/usr/lib/postgresql/18/bin';
export const BWRAP = '/usr/bin/bwrap';
export const CHROMIUM = process.env['AAB_CHROMIUM_PATH'] ?? '/usr/lib/chromium/chromium';
export const XVFB = '/usr/bin/Xvfb';
export const XDOTOOL = '/usr/bin/xdotool';
export const XAUTH = '/usr/bin/xauth';
export const NODE = process.execPath;
export const DEMO_PORT = 4100;
export const DEMO_ORIGIN = `http://localhost:${DEMO_PORT}`;
export const ALICE = 'alice.synthetic';
export const BOB = 'bob.synthetic';
export const INJECTION_ORDER = 'NS-1007';
export const COOKIE_NAME = 'northstar_sid';

/* ------------------------------------------------------------------ small helpers */

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type Loose = any;

export const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

export async function waitFor(
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

export function isExecutable(file: string): boolean {
  try {
    return statSync(file).isFile() && (statSync(file).mode & 0o111) !== 0;
  } catch {
    return false;
  }
}

export function portOpen(port: number, host: string): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = net.connect({ port, host });
    socket.once('connect', () => {
      socket.destroy();
      resolve(true);
    });
    socket.once('error', () => resolve(false));
  });
}

export function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address() as net.AddressInfo;
      server.close(() => resolve(port));
    });
  });
}

export const sha256Hex = (text: string) => createHash('sha256').update(text).digest('hex');

/** A child process in its own process group, with its output captured. */
export class Proc {
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

export const PROCS: Proc[] = [];

/**
 * What test/e2e/watchdog.mjs must clean up if this process is killed before afterAll runs.
 * Rewritten whenever something is created.
 */
/** The private directories of a run, including the Phase 3 proxy's (`<socketDir>-proxy`). */
function watchDirs(): string[] {
  return [
    S.runtimeDir,
    S.socketDir,
    S.socketDir === '' ? '' : `${S.socketDir}-proxy`,
    S.tmp,
  ].filter((entry) => entry !== '');
}

export function writeWatchSpec(done = false): void {
  if (S.tmp === '') return;
  writeFileSync(
    path.join(S.tmp, 'watch.json'),
    JSON.stringify({
      done,
      groups: PROCS.map((proc) => proc.pid).filter((pid) => pid > 0),
      markers: watchDirs(),
      dirs: watchDirs(),
      // Processes a test froze (SIGSTOP): the watchdog resumes and kills them. Removed from the
      // set as soon as the test has resumed them, so a reused pid is never signalled.
      pids: [...S.watchPids],
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

export interface State {
  tmp: string;
  runtimeDir: string;
  keyDir: string;
  /** The vault's socket directory: `<dir>/<role>/vault.sock`. */
  socketDir: string;
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
  vault: Proc | null;
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
  /** Pids the test froze and the watchdog must resume and kill if the test dies (see writeWatchSpec). */
  watchPids: Set<number>;
  metrics: Record<string, number | string>;
  counter: number;
}

export const S: State = {
  tmp: '',
  runtimeDir: '',
  keyDir: '',
  socketDir: '',
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
  vault: null,
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
  watchPids: new Set(),
  metrics: {},
  counter: 0,
};

/* ------------------------------------------------------------------ database helpers */

export async function psql(sql: string, database = S.dbName): Promise<string> {
  const url = `postgresql://${os.userInfo().username}@localhost:${PG_PORT}/${database}?host=${PG_DIR}`;
  const { stdout } = await run(
    path.join(PG_BIN, 'psql'),
    ['-X', '-A', '-t', '-q', '-v', 'ON_ERROR_STOP=1', '-c', sql, url],
    { env: { PATH: '/usr/bin' }, maxBuffer: 256 * 1024 * 1024 },
  );
  return stdout.trim();
}

export const count = async (sql: string): Promise<number> => Number(await psql(sql));

export async function jsonRows(sql: string): Promise<Loose[]> {
  const out = await psql(`select coalesce(json_agg(t), '[]'::json) from (${sql}) t`);
  return JSON.parse(out) as Loose[];
}

export interface Counts {
  jobs: number;
  audit: Record<string, number>;
  grants: number;
}

export async function snapshotCounts(): Promise<Counts> {
  const rows = await jsonRows(
    'select event_type as t, count(*)::int as n from audit_events group by event_type',
  );
  return {
    jobs: await count('select count(*) from execution_jobs'),
    audit: Object.fromEntries(rows.map((row: Loose) => [row.t as string, row.n as number])),
    grants: await count('select count(*) from agent_grants'),
  };
}

export function delta(before: Counts, after: Counts): Counts {
  const audit: Record<string, number> = {};
  for (const type of new Set([...Object.keys(before.audit), ...Object.keys(after.audit)])) {
    const change = (after.audit[type] ?? 0) - (before.audit[type] ?? 0);
    if (change !== 0) audit[type] = change;
  }
  return { jobs: after.jobs - before.jobs, audit, grants: after.grants - before.grants };
}

export const versionsFor = (connectionId: string) =>
  count(
    `select count(*) from vault_secret_versions v join vault_secrets s on s.id = v.secret_id where s.connection_id = '${connectionId}'`,
  );

/* ------------------------------------------------------------------ demo (SQLite) helpers */

export function demoQuery(sql: string, params: string[] = [], write = false): Loose[] {
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

export function demoOrdersOf(username: string): Set<string> {
  const rows = demoQuery(
    'select o.id from orders o join accounts a on a.id = o.account_id where a.username = ?',
    [username],
  );
  return new Set(rows.map((row) => String(row.id)));
}

export function demoOrderRows(): string {
  return JSON.stringify(
    demoQuery(
      'select id, account_id, status, shipping_method, notes, version, updated_at from orders order by id',
    ),
  );
}

/** Remembers every live demo session token hash (and CSRF token) so leaks can be recognised later. */
export function collectDemoSessions(): number {
  const rows = demoQuery('select token_hash, csrf_token from sessions');
  for (const row of rows) {
    S.tokenHashes.add(String(row.token_hash));
    S.csrfTokens.add(String(row.csrf_token));
  }
  return rows.length;
}

export function demoSessionCount(username: string): number {
  return Number(
    demoQuery(
      'select count(*) as n from sessions s join accounts a on a.id = s.account_id where a.username = ?',
      [username],
    )[0]?.n ?? 0,
  );
}

export interface DemoRequest {
  method: string;
  url: string;
}

export function demoRequests(): DemoRequest[] {
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

export interface Resp {
  status: number;
  json: Loose;
  text: string;
}

export async function api(
  method: string,
  route: string,
  body?: unknown,
  auth = true,
): Promise<Resp> {
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

export function idempotencyKey(): string {
  S.counter += 1;
  return `e2e-${S.counter}-${randomBytes(4).toString('hex')}`;
}

export async function execute(
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

export const connectionOf = async (id: string): Promise<Loose> =>
  (await api('GET', `/connections/${id}`)).json;

export function startProcessEnv(extra: Record<string, string>): Record<string, string> {
  return { PATH: '/usr/bin:/bin', HOME: os.homedir(), ...extra };
}

/* ------------------------------------------------------------------ stack control */

export const vaultSocket = (role: 'api' | 'supervisor' | 'admin') =>
  path.join(S.socketDir, role, 'vault.sock');

export async function startVault(): Promise<void> {
  S.vault = new Proc('vault', NODE, ['--import', 'tsx', 'src/main.ts'], {
    cwd: VAULT_DIR,
    env: startProcessEnv({
      DATABASE_URL: S.dbUrl,
      AAB_KEK_DIR: S.keyDir,
      AAB_VAULT_SOCKET_DIR: S.socketDir,
      AAB_VAULT_ISOLATION: 'shared-uid',
      // Debug, as the worker runs: the scan then reads the most the vault can say.
      AAB_LOG_LEVEL: 'debug',
    }),
  });
  await waitFor(
    () => {
      if (S.vault?.exit !== null) {
        throw new Error(`the vault exited early:\n${S.vault?.text().slice(-1500)}`);
      }
      return (
        (S.vault?.text().match(/vault listening/g) ?? []).length >= 3 &&
        existsSync(vaultSocket('api')) &&
        existsSync(vaultSocket('supervisor'))
      );
    },
    60_000,
    'the vault to listen on its three role sockets',
  );
}

export async function startApi(): Promise<void> {
  S.api = new Proc('api', NODE, ['--import', 'tsx', 'src/main.ts'], {
    cwd: API_DIR,
    env: startProcessEnv({
      DATABASE_URL: S.dbUrl,
      AAB_HOST: '127.0.0.1',
      AAB_PORT: String(S.apiPort),
      AAB_COOKIE_SECURE: 'false',
      AAB_LOG_LEVEL: 'info',
      AAB_VAULT_SOCKET: vaultSocket('api'),
      AAB_VAULT_ISOLATION: 'shared-uid',
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

export async function startWorker(
  supervisorSocket = vaultSocket('supervisor'),
  extraEnv: Record<string, string> = {},
): Promise<void> {
  S.worker = new Proc('worker', NODE, ['--import', 'tsx', 'src/main.ts'], {
    cwd: WORKER_DIR,
    // WAYLAND_DISPLAY and XDG_RUNTIME_DIR are deliberately absent.
    env: startProcessEnv({
      DATABASE_URL: S.dbUrl,
      // No AAB_KEK_DIR: the worker holds no key and refuses to start with one (P3-1).
      AAB_VAULT_SOCKET: supervisorSocket,
      AAB_VAULT_ISOLATION: 'shared-uid',
      DISPLAY: S.display,
      XAUTHORITY: S.xauth,
      AAB_WORKER_RUNTIME_DIR: S.runtimeDir,
      AAB_CHROMIUM_PATH: CHROMIUM,
      AAB_LOG_LEVEL: 'debug',
      ...extraEnv,
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

export async function xdotool(...args: string[]): Promise<string> {
  const { stdout } = await run(XDOTOOL, args, {
    env: { DISPLAY: S.display, XAUTHORITY: S.xauth, PATH: '/usr/bin' },
    timeout: 20_000,
  });
  return stdout.trim();
}

export async function chromiumWindow(): Promise<{ id: string; width: number }> {
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

export async function noLoginWindow(): Promise<void> {
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
export async function startHandoff(
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

export async function signIn(
  window: { id: string; width: number },
  username: string,
  password: string,
) {
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

export async function completeHandoff(connectionId: string): Promise<Resp> {
  const complete = await api('POST', `/connections/${connectionId}/auth/complete`);
  await noLoginWindow();
  return complete;
}

/* ------------------------------------------------------------------ process inspection */

export interface ProcInfo {
  ppid: number;
  argv: string[];
}

export function procTable(): Map<number, ProcInfo> {
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

export function ancestorsOf(
  pid: number,
  table: Map<number, ProcInfo>,
  stopAt: number,
): number[] | null {
  const chain: number[] = [];
  let current = table.get(pid)?.ppid;
  for (let hops = 0; current !== undefined && hops < 64; hops += 1) {
    if (current === stopAt) return chain;
    chain.push(current);
    current = table.get(current)?.ppid;
  }
  return null;
}

export interface BrowserTree {
  chromium: number[];
  bwrap: number[];
}

export function browserTree(rootPid: number): BrowserTree & { table: Map<number, ProcInfo> } {
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

/** True when the process is gone or only a zombie (killed, waiting to be reaped). */
export function pidGone(pid: number): boolean {
  try {
    const stat = readFileSync(`/proc/${pid}/stat`, 'latin1');
    return stat.slice(stat.lastIndexOf(')') + 2, stat.lastIndexOf(')') + 3) === 'Z';
  } catch {
    return true;
  }
}

export const rssKb = (pid: number): number => {
  try {
    return Number(/VmRSS:\s+(\d+)/.exec(readFileSync(`/proc/${pid}/status`, 'utf8'))?.[1] ?? 0);
  } catch {
    return 0;
  }
};

export interface Needle {
  kind: string;
  value: string;
}

/** Returns "haystack :: needle kind" for every hit. Never returns the secret itself. */
export function scan(
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

export async function databaseHaystacks(): Promise<Record<string, string>> {
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

export function logHaystacks(): Record<string, string> {
  return {
    'api stdout/stderr': [...S.oldApiLogs, S.api?.text() ?? ''].join('\n'),
    'worker stdout/stderr': [...S.oldWorkerLogs, S.worker?.text() ?? ''].join('\n'),
    'vault stdout/stderr': S.vault?.text() ?? '',
  };
}

export async function prepareEnvironment(label: string): Promise<void> {
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
    throw new Error(`${label} e2e prerequisites missing:\n  - ${missing.join('\n  - ')}`);
  }

  /* directories */
  const random = randomBytes(4).toString('hex');
  S.tmp = mkdtempSync(path.join(os.tmpdir(), 'e2e-'));
  S.runtimeDir = `/run/user/${UID}/aabe-${random}`;
  mkdirSync(S.runtimeDir, { mode: 0o700 });
  // The vault's socket directory: short (socket paths are limited to ~100 bytes), outside the
  // repository, owned by this user and closed to everyone else.
  S.socketDir = `/run/user/${UID}/aabv-${random}`;
  mkdirSync(S.socketDir, { mode: 0o700 });
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
    if (!existsSync(`/tmp/.X11-unix/X${n}`) && !existsSync(`/tmp/.X${n}-lock`)) displayNumber = n;
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
}

export async function teardownEnvironment(label: string, keepSubdir: string): Promise<void> {
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
  const keepBase = process.env['AAB_E2E_KEEP_LOGS'];
  const keep =
    keepBase === undefined || keepBase === '' ? keepBase : path.join(keepBase, keepSubdir);
  if (keep !== undefined && keep !== '') {
    // For debugging only. These logs hold no secrets (that is what step I checks), but the
    // directory is still the caller's choice.
    mkdirSync(keep, { recursive: true });
    const logs = logHaystacks();
    writeFileSync(path.join(keep, 'api.log'), logs['api stdout/stderr'] ?? '');
    writeFileSync(path.join(keep, 'worker.log'), logs['worker stdout/stderr'] ?? '');
    writeFileSync(path.join(keep, 'vault.log'), logs['vault stdout/stderr'] ?? '');
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
  if (S.socketDir !== '') rmSync(S.socketDir, { recursive: true, force: true });
  if (S.tmp !== '') rmSync(S.tmp, { recursive: true, force: true });
  process.stdout.write(`\n${label} e2e metrics: ${JSON.stringify(S.metrics, null, 2)}\n`);
}

/** Step A of both files: demo, database, key, vault, API, worker, owner, application, two connections, one agent. */
export async function setupStack(
  options: { workerSocket?: string; workerEnv?: Record<string, string> } = {},
): Promise<void> {
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
          (await fetch(`${DEMO_ORIGIN}/healthz`, { signal: AbortSignal.timeout(2_000) })).status ===
          200
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

  /* vault (the only process that reads the key), then the API (no AAB_KEK_DIR) and the worker */
  await startVault();
  S.apiPort = await freePort();
  S.apiBase = `http://127.0.0.1:${S.apiPort}`;
  await startApi();
  await startWorker(options.workerSocket, options.workerEnv);
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
}
