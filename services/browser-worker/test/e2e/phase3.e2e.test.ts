import { mkdirSync, rmSync } from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  ALICE,
  BOB,
  ENABLED,
  PG_BIN,
  PG_DIR,
  PG_PORT,
  S,
  api,
  ancestorsOf,
  browserTree,
  completeHandoff,
  connectionOf,
  count,
  demoOrdersOf,
  demoRequests,
  execute,
  jsonRows,
  logHaystacks,
  pidGone,
  prepareEnvironment,
  procTable,
  psql,
  run,
  setupStack,
  signIn,
  sleep,
  startHandoff,
  startWorker,
  teardownEnvironment,
  vaultSocket,
  versionsFor,
  waitFor,
  writeWatchSpec,
} from './harness.js';
import type { Loose } from './harness.js';

/*
 * Phase 3 end-to-end test (B6b). The same real stack as phase2.e2e.test.ts (PostgreSQL, the vault
 * as a fourth process with shared-uid isolation, the API, the supervisor with the real sandbox,
 * the Northstar demo, a private Xvfb display), with the vault in the path of every read.
 *
 *   AAB_E2E=1 AAB_E2E_PG_BIN=/usr/lib/postgresql/17/bin \
 *     corepack pnpm --filter @aab/browser-worker exec vitest run test/e2e/phase3.e2e.test.ts
 *
 * Same gates, overrides and clean-up as phase 2 (see harness.ts). Synthetic data only: the demo's
 * seeded fake accounts. Step by step:
 *
 *   1  a real login handoff and a real read job through the vault
 *   2  the test plays the supervisor on the vault's real supervisor socket and presents job A's
 *      capability for the wrong connection, operation, job, purpose, secret version, worker and
 *      attempt (P3-5, AT-009, VA-12), and asks for tokens for jobs the API did not authorize (VS-5)
 *   3  revocation of a connection while a real job runs: (a) between the token issue and the
 *      consume, held deterministically by a proxy on the worker's vault socket; (b) while the
 *      browser holds the session, with the browser frozen so the job cannot finish first
 *   4  a canary scan of every log, response, audit event, job row and column (P3-15, VS-16)
 *   5  a real pg_dump (P3-16)
 *
 * How the test gets at what the production path hides, and what it does NOT prove:
 *  - The worker reaches the vault through a pass-through proxy on a socket of this test (the
 *    worker is started with AAB_VAULT_SOCKET pointing at it). The proxy forwards every byte and
 *    can hold one `readForWorker` line. It also lets the test see the real tokens in transit,
 *    which are needed as scan canaries (they are never stored).
 *  - In step 2 the worker process is paused (SIGSTOP) and the test claims jobs the API really
 *    created and authorized, by editing the job row the way a claim does (status running, worker,
 *    attempt, lease). A "moved to another worker or attempt" and a "rotated secret version" are
 *    simulated by editing the job or secret rows and restoring them; the vault then judges them
 *    from the database as it would after a real lease reassignment or a second login.
 *  - There is one owner (create-owner refuses a second user), so "another connection" is the
 *    second connection of the same owner and organization. Cross-user and cross-organization
 *    isolation is covered by services/vault/test (service-boundary, socket-negative).
 */

/* ------------------------------------------------------------------ the vault socket */

type Role = 'api' | 'supervisor' | 'admin';

let rpcCounter = 0;

/** One request on a role socket of the running vault: the same line protocol the services speak. */
function vaultCall(role: Role, operation: string, params: Record<string, unknown>): Promise<Loose> {
  return new Promise((resolve, reject) => {
    const socket = net.connect(vaultSocket(role));
    let buffer = '';
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error(`vault ${operation} timed out`));
    }, 60_000);
    socket.setEncoding('utf8');
    socket.on('data', (chunk: string) => {
      buffer += chunk;
      const end = buffer.indexOf('\n');
      if (end < 0) return;
      clearTimeout(timer);
      socket.destroy();
      try {
        resolve(JSON.parse(buffer.slice(0, end)));
      } catch (error) {
        reject(error as Error);
      }
    });
    socket.once('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
    socket.once('connect', () => {
      rpcCounter += 1;
      socket.write(`${JSON.stringify({ id: `e2e3-${rpcCounter}`, operation, params })}\n`);
    });
  });
}

/**
 * Sends `text` as is (no newline unless it holds one) and resolves with everything the vault
 * answers before it closes the connection.
 */
function vaultRaw(role: Role, text: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = net.connect(vaultSocket(role));
    let received = '';
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error(`vault raw line on ${role} was not answered or closed in time`));
    }, 20_000);
    socket.setEncoding('utf8');
    socket.on('data', (chunk: string) => (received += chunk));
    socket.once('error', () => undefined); // a reset after the answer is fine
    socket.once('close', () => {
      clearTimeout(timer);
      resolve(received);
    });
    socket.once('connect', () => socket.write(text));
  });
}

/* ------------------------------------------------------------------ the pass-through proxy */

/**
 * Sits between the worker and the vault's supervisor socket. Forwards bytes unchanged; while
 * armed it holds the next `readForWorker` request line until released.
 */
class VaultProxy {
  readonly dir: string;
  readonly socketPath: string;
  readonly operations: string[] = [];
  /** Every token the worker presented in a readForWorker or completeLogin, seen in transit. */
  readonly tokens = new Set<string>();
  /** `readForWorker` lines actually written on to the vault (a held line counts once it is released). */
  forwardedReads = 0;
  /** The session plaintexts (base64url) seen in transit, by connection: completeLogin requests and readForWorker answers. */
  readonly sessions = new Map<string, Set<string>>();
  private readonly server: net.Server;
  private armed = false;
  private waiting: Array<() => void> = [];

  constructor(baseDir: string) {
    this.dir = `${baseDir}-proxy`;
    this.socketPath = path.join(this.dir, 's.sock');
    this.server = net.createServer((client) => this.accept(client));
  }

  async start(): Promise<void> {
    mkdirSync(this.dir, { mode: 0o700 });
    await new Promise<void>((resolve, reject) => {
      this.server.once('error', reject);
      this.server.listen(this.socketPath, resolve);
    });
  }

  async stop(): Promise<void> {
    this.release();
    await new Promise<void>((resolve) => this.server.close(() => resolve()));
    rmSync(this.dir, { recursive: true, force: true });
  }

  arm(): void {
    this.armed = true;
  }

  get heldCount(): number {
    return this.waiting.length;
  }

  release(): void {
    this.armed = false;
    const waiting = this.waiting;
    this.waiting = [];
    for (const resume of waiting) resume();
  }

  private accept(client: net.Socket): void {
    const upstream = net.connect(vaultSocket('supervisor'));
    upstream.pipe(client);
    // The answers, in order, matched to the requests of this connection (one answer per request).
    const asked: Array<{ operation: string; connectionId: string }> = [];
    let answers = '';
    upstream.on('data', (chunk: Buffer) => {
      answers += chunk.toString('utf8');
      for (;;) {
        const end = answers.indexOf('\n');
        if (end < 0) break;
        const text = answers.slice(0, end);
        answers = answers.slice(end + 1);
        const request = asked.shift();
        try {
          const response = JSON.parse(text) as Loose;
          if (
            request?.operation === 'readForWorker' &&
            response.ok === true &&
            typeof response.result?.plaintext === 'string'
          ) {
            this.remember(request.connectionId, response.result.plaintext as string);
          }
        } catch {
          // Not JSON: nothing to learn.
        }
      }
    });
    const closeBoth = () => {
      client.destroy();
      upstream.destroy();
    };
    client.once('error', closeBoth);
    upstream.once('error', closeBoth);
    client.once('close', closeBoth);
    upstream.once('close', closeBoth);
    let buffer = Buffer.alloc(0);
    let chain: Promise<void> = Promise.resolve();
    client.on('data', (chunk: Buffer) => {
      buffer = Buffer.concat([buffer, chunk]);
      for (;;) {
        const end = buffer.indexOf(0x0a);
        if (end < 0) break;
        const line = buffer.subarray(0, end + 1);
        buffer = buffer.subarray(end + 1);
        chain = chain.then(() => this.forward(line, upstream, asked));
      }
    });
  }

  private remember(connectionId: string, plaintext: string): void {
    const known = this.sessions.get(connectionId) ?? new Set<string>();
    known.add(plaintext);
    this.sessions.set(connectionId, known);
  }

  private async forward(
    line: Buffer,
    upstream: net.Socket,
    asked: Array<{ operation: string; connectionId: string }>,
  ): Promise<void> {
    let operation = '';
    let connectionId = '';
    try {
      const request = JSON.parse(line.toString('utf8')) as Loose;
      operation = String(request.operation);
      connectionId = String(request.params?.connectionId);
      this.operations.push(operation);
      const token = request.params?.token;
      if (typeof token === 'string') this.tokens.add(token);
      if (operation === 'completeLogin' && typeof request.params?.plaintext === 'string') {
        this.remember(connectionId, request.params.plaintext as string);
      }
    } catch {
      // Not JSON: forward it and let the vault refuse it.
    }
    if (operation === 'readForWorker' && this.armed) {
      await new Promise<void>((resume) => this.waiting.push(resume));
    }
    if (!upstream.destroyed) {
      asked.push({ operation, connectionId });
      if (operation === 'readForWorker') this.forwardedReads += 1;
      upstream.write(line);
    }
  }
}

/* ------------------------------------------------------------------ test state and helpers */

interface Phase3State {
  proxy: VaultProxy | null;
  /** Raw tokens this test obtained as the supervisor (and the proxy saw), never stored by the stack. */
  tokens: Set<string>;
  /** Known plaintext values: label -> value. Synthetic demo session data read through the vault. */
  canaries: Map<string, string>;
  /** Every answer to a refused request, for the "nothing came back" checks. */
  refusedResponses: string[];
  revokedRead: string;
  liveRead: string;
  extraRevokeConnection: string;
  timings: Record<string, number>;
}

const T: Phase3State = {
  proxy: null,
  tokens: new Set(),
  canaries: new Map(),
  refusedResponses: [],
  revokedRead: '',
  liveRead: '',
  extraRevokeConnection: '',
  timings: {},
};

const SUPERVISOR_WORKER = 'e2e-supervisor-1';

let failedStep: string | null = null;

function step(name: string, body: () => Promise<void>, options: { critical?: boolean } = {}): void {
  it(
    name,
    async () => {
      if (failedStep !== null) throw new Error(`not run: critical step ${failedStep} failed`);
      const t0 = Date.now();
      try {
        await body();
      } catch (error) {
        if (options.critical === true) {
          failedStep = name.split(' ')[0] ?? name;
          await diagnose(failedStep);
        }
        throw error;
      } finally {
        T.timings[`step ${name.split(' ')[0] ?? name} ms`] = Date.now() - t0;
      }
    },
    420_000,
  );
}

/**
 * What a future failure needs to be diagnosable: the worker's warn and error lines (ids, codes and
 * error types only; the scan in step 4 shows that log holds no secret) and the error code of the
 * most recent jobs.
 */
async function diagnose(stepName: string): Promise<void> {
  try {
    const logs = logHaystacks()['worker stdout/stderr'] ?? '';
    const lines = logs
      .split('\n')
      .filter((line) => /"level":(40|50|60)\b/.test(line))
      .slice(-40);
    const jobs = await jsonRows(
      `select id, kind, operation, status, error_code, attempt_count, worker_id from execution_jobs order by created_at desc limit 8`,
    );
    process.stderr.write(
      `\n--- diagnostics for failed critical step ${stepName} ---\nworker warn/error lines (last ${lines.length}):\n${lines.join('\n')}\nlast jobs:\n${JSON.stringify(jobs, null, 1)}\n---\n`,
    );
  } catch (error) {
    process.stderr.write(`diagnostics for step ${stepName} failed: ${String(error)}\n`);
  }
}

async function loginAs(connectionId: string, username: string, password: string): Promise<void> {
  const { window } = await startHandoff(connectionId);
  await signIn(window, username, password);
  const complete = await completeHandoff(connectionId);
  expect(complete.status).toBe(200);
  expect(complete.json.jobStatus).toBe('succeeded');
  await waitFor(
    async () => (await connectionOf(connectionId)).status === 'active',
    15_000,
    `${connectionId} to become active`,
  );
  expect(await versionsFor(connectionId)).toBe(1);
}

async function grant(connectionId: string, operation: string): Promise<void> {
  const response = await api('POST', `/agents/${S.agentId}/grants`, {
    connectionId,
    operation,
    effect: 'allow',
  });
  expect(response.status).toBe(201);
}

async function newConnection(name: string): Promise<string> {
  const created = await api('POST', '/connections', {
    applicationId: S.applicationId,
    displayName: name,
  });
  expect(created.status).toBe(201);
  return created.json.id as string;
}

const isPlainForbidden = (response: Loose): boolean =>
  Object.keys(response).sort().join(',') === 'error,id,ok' &&
  response.ok === false &&
  Object.keys(response.error).join(',') === 'code' &&
  response.error.code === 'forbidden';

interface Rejected {
  reason: string;
  role: string;
  purpose: string;
  capabilityId: string | null;
  jobId: string | null;
}

async function rejections(): Promise<Rejected[]> {
  const rows = await jsonRows(
    `select metadata from audit_events where event_type = 'vault.capability_rejected' order by sequence`,
  );
  return rows.map((row) => ({
    reason: row.metadata.reason as string,
    role: row.metadata.role as string,
    purpose: row.metadata.purpose as string,
    capabilityId: row.metadata.capabilityId as string | null,
    jobId: row.metadata.jobId as string | null,
  }));
}

const secretReads = (where: string) =>
  count(`select count(*) from audit_events where event_type = 'vault.secret_read' and ${where}`);

interface FakeJob {
  jobId: string;
  capabilityId: string;
  connectionId: string;
  operation: string;
  /** The API call that created the job; it returns when the job is terminal. */
  pending: Promise<Loose>;
}

const usedJobIds = new Set<string>();

/**
 * Creates a real job through the API (policy, audit, authorization by the vault) while the worker
 * is paused, so it stays queued with its capability authorized.
 */
async function queuedJob(
  connectionId: string,
  operation = 'orders.list',
  args: Record<string, unknown> = { limit: 5 },
): Promise<FakeJob> {
  const pending = execute(connectionId, operation, args).then(
    (response) => response,
    (error: unknown) => ({ error }),
  );
  let found: Loose | undefined;
  await waitFor(
    async () => {
      const rows = await jsonRows(
        `select id, capability_ref from execution_jobs where connection_id = '${connectionId}' and operation = '${operation}' and status = 'queued' and capability_ref is not null`,
      );
      found = rows.find((row) => !usedJobIds.has(row.id as string));
      return found !== undefined;
    },
    30_000,
    'the API to create and authorize a job',
  );
  const jobId = found?.id as string;
  usedJobIds.add(jobId);
  return { jobId, capabilityId: found?.capability_ref as string, connectionId, operation, pending };
}

/** What a worker's claim leaves on the row. */
async function claim(job: FakeJob, workerId = SUPERVISOR_WORKER, attempt = 1): Promise<void> {
  await psql(
    `update execution_jobs set status = 'running', worker_id = '${workerId}', attempt_count = ${attempt}, started_at = now(), lease_expires_at = now() + interval '30 minutes' where id = '${job.jobId}'`,
  );
}

async function endJob(job: FakeJob): Promise<void> {
  await psql(
    `update execution_jobs set status = 'cancelled', error_code = 'cancelled', error_message = 'ended by the end-to-end test', finished_at = now() where id = '${job.jobId}'`,
  );
  await job.pending;
}

async function issue(
  job: FakeJob,
  options: { workerId?: string; attempt?: number; ttl?: number; capabilityId?: string } = {},
): Promise<Loose> {
  return vaultCall('supervisor', 'issueAccessCapability', {
    capabilityId: options.capabilityId ?? job.capabilityId,
    jobId: job.jobId,
    workerId: options.workerId ?? SUPERVISOR_WORKER,
    attempt: options.attempt ?? 1,
    ttlSeconds: options.ttl ?? 60,
  });
}

async function issued(job: FakeJob): Promise<string> {
  const response = await issue(job);
  expect(response.ok, `issue for ${job.jobId}`).toBe(true);
  const token = response.result.token as string;
  expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
  T.tokens.add(token);
  return token;
}

const readParams = (job: FakeJob, token: string, overrides: Record<string, unknown> = {}) => ({
  token,
  jobId: job.jobId,
  connectionId: job.connectionId,
  operation: job.operation,
  ...overrides,
});

const capabilityRow = async (capabilityId: string): Promise<Loose> =>
  (await jsonRows(`select * from vault_access_capabilities where id = '${capabilityId}'`))[0];

/** A refused request: the plain forbidden answer, one rejection event with the expected reason. */
async function expectRefused(
  label: string,
  reason: string,
  request: () => Promise<Loose>,
  expected: { jobId: string; capabilityId: string | null; role?: string; purpose?: string },
): Promise<void> {
  const before = await rejections();
  const response = await request();
  T.refusedResponses.push(JSON.stringify(response));
  expect(isPlainForbidden(response), `${label}: answer is a plain forbidden`).toBe(true);
  const after = await rejections();
  expect(after.length - before.length, `${label}: exactly one rejection event`).toBe(1);
  const event = after[after.length - 1] as Rejected;
  expect(event.reason, `${label}: rejection reason`).toBe(reason);
  expect(event.role).toBe(expected.role ?? 'supervisor');
  expect(event.purpose).toBe(expected.purpose ?? 'read');
  expect(event.jobId).toBe(expected.jobId);
  expect(event.capabilityId).toBe(expected.capabilityId);
}

/** A successful read as the supervisor: records the plaintext's values as canaries. */
function learnCanaries(label: string, plaintext: string): void {
  const json = Buffer.from(plaintext, 'base64url').toString('utf8');
  const state = JSON.parse(json) as Loose;
  T.canaries.set(`${label} storage state (base64url, as sent)`, plaintext);
  T.canaries.set(`${label} storage state (JSON)`, json);
  for (const cookie of state.cookies as Loose[]) {
    if (String(cookie.value).length >= 8) {
      T.canaries.set(`${label} cookie ${String(cookie.name)}`, String(cookie.value));
    }
  }
  for (const origin of state.origins as Loose[]) {
    for (const item of (origin.localStorage ?? []) as Loose[]) {
      if (String(item.value).length >= 8) {
        T.canaries.set(`${label} localStorage ${String(item.name)}`, String(item.value));
      }
    }
  }
}

/* ------------------------------------------------------------------ encodings and the scanner */

const alignedBase64 = (buffer: Buffer, encoding: 'base64' | 'base64url'): string[] => {
  // A value inside a longer base64 text starts at any of three alignments; keep only the
  // characters that do not depend on the neighbouring bytes.
  const found: string[] = [];
  for (const offset of [0, 1, 2]) {
    const text = Buffer.concat([Buffer.alloc(offset), buffer])
      .toString(encoding)
      .replace(/=+$/, '');
    const head = [0, 2, 3][offset] as number;
    const tail = (offset + buffer.length) % 3 === 0 ? 0 : 1;
    const part = text.slice(head, text.length - tail);
    if (part.length >= 8) found.push(part);
  }
  return found;
};

/** A value in raw, base64, base64url and hex (and, for a hex value, the bytes it stands for). */
function variantsOf(value: string): Array<[string, string]> {
  const bytes = Buffer.from(value, 'utf8');
  const out: Array<[string, string]> = [['raw', value]];
  out.push(...alignedBase64(bytes, 'base64').map((v): [string, string] => ['base64', v]));
  out.push(...alignedBase64(bytes, 'base64url').map((v): [string, string] => ['base64url', v]));
  out.push(['hex', bytes.toString('hex')]);
  if (/^[0-9a-f]+$/.test(value) && value.length % 2 === 0) {
    out.push(['HEX', value.toUpperCase()]);
    const decoded = Buffer.from(value, 'hex');
    out.push(
      ...alignedBase64(decoded, 'base64').map((v): [string, string] => ['bytes as base64', v]),
    );
    out.push(
      ...alignedBase64(decoded, 'base64url').map((v): [string, string] => [
        'bytes as base64url',
        v,
      ]),
    );
  }
  if (TOKEN_SHAPE.test(value)) {
    // A token is 32 random bytes written as 43 base64url characters: also search those 32 bytes
    // as hex, as standard base64 and as raw characters, in case something re-encodes them.
    const decoded = Buffer.from(value, 'base64url');
    out.push(['token bytes as hex', decoded.toString('hex')]);
    out.push(['token bytes as HEX', decoded.toString('hex').toUpperCase()]);
    out.push(
      ...alignedBase64(decoded, 'base64').map((v): [string, string] => [
        'token bytes as base64',
        v,
      ]),
    );
    out.push(['token bytes as latin1', decoded.toString('latin1')]);
  }
  return out;
}

/** The least lines the vault log may have in step 4 (a real run has 7 at that point: 4 start-up lines and the 3 refusals; the vault says little by design). */
const VAULT_LOG_MIN_LINES = 7;

const TOKEN_SHAPE = /^[A-Za-z0-9_-]{43}$/;

/**
 * 'client' values (the dashboard session cookie and CSRF token) legitimately appear in the API's
 * own responses to the client that was given them; everywhere else they must not.
 */
type NeedleClass = 'plain' | 'token' | 'hashmac' | 'client';

interface Needle {
  kind: string;
  klass: NeedleClass;
  encoding: string;
  value: string;
}

function needleSet(entries: Array<{ kind: string; klass: NeedleClass; value: string }>): Needle[] {
  const needles: Needle[] = [];
  for (const entry of entries) {
    if (entry.value === '') continue;
    for (const [encoding, value] of variantsOf(entry.value)) {
      needles.push({ kind: entry.kind, klass: entry.klass, encoding, value });
    }
  }
  return needles;
}

/** The columns whose job it is to hold the token hash and the two MACs (docs/phase-3.md section 1). */
const HASH_AND_MAC_COLUMNS = [
  'vault_access_capabilities.authorization_mac',
  'vault_access_capabilities.token_hash',
  'vault_access_capabilities.token_mac',
];

interface Haystack {
  label: string;
  /** The `table.column` this text came from, when it came from one. */
  column: string | null;
  text: string;
}

interface Hit {
  haystack: string;
  kind: string;
  encoding: string;
}

/** Hits by haystack label, needle kind and encoding. Never returns a secret. */
function findHits(
  haystacks: Haystack[],
  needles: Needle[],
  options: { excludeHashMacColumns: boolean },
): Hit[] {
  const hits: Hit[] = [];
  for (const haystack of haystacks) {
    const excluded =
      options.excludeHashMacColumns && HASH_AND_MAC_COLUMNS.includes(haystack.column ?? '');
    for (const needle of needles) {
      if (excluded && needle.klass === 'hashmac') continue;
      if (needle.klass === 'client' && haystack.label.startsWith('api responses')) continue;
      if (haystack.text.includes(needle.value)) {
        hits.push({ haystack: haystack.label, kind: needle.kind, encoding: needle.encoding });
      }
    }
  }
  return hits;
}

const describeHits = (hits: Hit[]): string[] =>
  [...new Set(hits.map((hit) => `${hit.haystack} :: ${hit.kind} (${hit.encoding})`))].sort();

interface ColumnInfo {
  table: string;
  column: string;
  type: string;
}

async function allColumns(): Promise<ColumnInfo[]> {
  const rows = await jsonRows(
    `select c.table_name as "table", c.column_name as "column", c.data_type as "type" from information_schema.columns c join information_schema.tables t on t.table_schema = c.table_schema and t.table_name = c.table_name where c.table_schema = 'public' and t.table_type = 'BASE TABLE' order by 1, 2`,
  );
  return rows as ColumnInfo[];
}

interface DatabaseText {
  haystacks: Haystack[];
  tables: number;
  columns: number;
  rows: number;
  cells: number;
}

/** Every column of every table as text, one haystack per column (bytea also as hex, utf8, latin1). */
async function databaseColumns(): Promise<DatabaseText> {
  const columns = await allColumns();
  const tables = [...new Set(columns.map((entry) => entry.table))];
  const haystacks: Haystack[] = [];
  let rows = 0;
  let cells = 0;
  for (const table of tables) {
    rows += await count(`select count(*) from "${table}"`);
    const out = await psql(
      `select coalesce(json_object_agg(key, vals), '{}'::json) from (select key, json_agg(value) as vals from "${table}" t, json_each_text(row_to_json(t)) group by key) q`,
    );
    const byColumn = JSON.parse(out) as Record<string, Array<string | null>>;
    for (const entry of columns.filter((candidate) => candidate.table === table)) {
      const values = (byColumn[entry.column] ?? []).filter(
        (value): value is string => value !== null,
      );
      cells += values.length;
      const column = `${table}.${entry.column}`;
      if (entry.type === 'bytea') {
        const buffers = values.map((value) => Buffer.from(value.replace(/^\\x/, ''), 'hex'));
        haystacks.push(
          {
            label: `db:${column}(hex)`,
            column,
            text: buffers.map((b) => b.toString('hex')).join('\n'),
          },
          {
            label: `db:${column}(utf8)`,
            column,
            text: buffers.map((b) => b.toString('utf8')).join('\n'),
          },
          {
            label: `db:${column}(latin1)`,
            column,
            text: buffers.map((b) => b.toString('latin1')).join('\n'),
          },
        );
      } else {
        haystacks.push({ label: `db:${column}`, column, text: values.join('\n') });
      }
    }
  }
  return { haystacks, tables: tables.length, columns: columns.length, rows, cells };
}

function countLines(text: string): number {
  return text === '' ? 0 : text.split('\n').length;
}

/** The value of the owner's `aab_session` cookie (without the name). */
function dashboardSessionValue(): string {
  return (S.cookie.split(';')[0] ?? '').replace(/^aab_session=/, '');
}

function currentNeedles(
  capabilityRows: Loose[],
  options: { withHashesAndMacs: boolean },
): { needles: Needle[]; counts: Record<string, number> } {
  const entries: Array<{ kind: string; klass: NeedleClass; value: string }> = [];
  const tokens = new Set([...T.tokens, ...(T.proxy?.tokens ?? [])]);
  for (const token of tokens) entries.push({ kind: 'raw token', klass: 'token', value: token });
  for (const [label, value] of T.canaries) {
    entries.push({ kind: `plaintext: ${label}`, klass: 'plain', value });
  }
  // What the owner, the demo and the dashboard session hold: none of it may reach a log, an audit
  // event, a job row or a column. (The API's responses carry the session cookie and CSRF token
  // back to their own client, see NeedleClass.)
  entries.push(
    { kind: 'demo password (alice)', klass: 'plain', value: S.passwords.alice },
    { kind: 'demo password (bob)', klass: 'plain', value: S.passwords.bob },
    { kind: 'owner password', klass: 'plain', value: S.passwords.owner },
    { kind: 'dashboard session cookie', klass: 'client', value: dashboardSessionValue() },
    { kind: 'dashboard CSRF token', klass: 'client', value: S.csrf },
  );
  let hashes = 0;
  let tokenMacs = 0;
  let authorizationMacs = 0;
  if (options.withHashesAndMacs) {
    for (const row of capabilityRows) {
      if (row.token_hash !== null) {
        hashes += 1;
        entries.push({ kind: 'token hash', klass: 'hashmac', value: row.token_hash });
      }
      if (row.token_mac !== null) {
        tokenMacs += 1;
        entries.push({ kind: 'token MAC', klass: 'hashmac', value: row.token_mac });
      }
      authorizationMacs += 1;
      entries.push({ kind: 'authorization MAC', klass: 'hashmac', value: row.authorization_mac });
    }
  }
  return {
    needles: needleSet(entries),
    counts: {
      tokens: tokens.size,
      canaries: T.canaries.size,
      'client values': 5,
      'token hashes': hashes,
      'token MACs': tokenMacs,
      'authorization MACs': authorizationMacs,
    },
  };
}

/** Every process log, in the shapes the scan reads them. */
function processLogs(): Haystack[] {
  const logs = logHaystacks();
  return [
    { label: 'log: api', column: null, text: logs['api stdout/stderr'] ?? '' },
    { label: 'log: worker (supervisor)', column: null, text: logs['worker stdout/stderr'] ?? '' },
    { label: 'log: vault', column: null, text: logs['vault stdout/stderr'] ?? '' },
    { label: 'log: demo', column: null, text: S.demo?.text() ?? '' },
  ];
}

/* ------------------------------------------------------------------ the test */

let activeProxy: VaultProxy | null = null;

describe.skipIf(!ENABLED)('Phase 3 end-to-end: the vault in the path of every read', () => {
  beforeAll(async () => {
    await prepareEnvironment('Phase 3');
    activeProxy = new VaultProxy(S.socketDir);
    await activeProxy.start();
    T.proxy = activeProxy;
  }, 120_000);

  afterAll(async () => {
    // A paused worker must not outlive the test.
    try {
      if (S.worker !== null) process.kill(S.worker.pid, 'SIGCONT');
    } catch {
      // Gone.
    }
    await activeProxy?.stop().catch(() => undefined);
    await teardownEnvironment('Phase 3', 'phase3');
    process.stdout.write(`\nPhase 3 e2e timings: ${JSON.stringify(T.timings, null, 2)}\n`);
    process.stdout.write(`Phase 3 e2e revocation outcomes:\n  ${T.revokedRead}\n  ${T.liveRead}\n`);
  }, 90_000);

  /* ============================================================ 0 */
  step(
    '0. setup through the API (stack start through the proxy, application, two connections, one agent)',
    async () => {
      expect(T.proxy).not.toBeNull();
      // The worker runs with its default lease here and in steps 1 to 3a: a stall under load cannot
      // cost it a lease in the middle of a real login. Step 3b restarts it with a short lease.
      await setupStack({ workerSocket: T.proxy?.socketPath ?? '' });
      expect(S.worker?.text()).toContain('supervisor started');
      S.aliceOrders = demoOrdersOf(ALICE);
      S.bobOrders = demoOrdersOf(BOB);
    },
    { critical: true },
  );

  /* ============================================================ 1 */
  step(
    '1. real login and read through the vault',
    async () => {
      for (const [key, username, password] of [
        ['alice', ALICE, S.passwords.alice],
        ['bob', BOB, S.passwords.bob],
      ] as const) {
        await loginAs(S.conn[key], username, password);
        expect(
          await count(
            `select count(*) from audit_events where event_type = 'vault.secret_stored' and connection_id = '${S.conn[key]}'`,
          ),
        ).toBe(1);
        const secrets = await jsonRows(
          `select status, active_version_id is not null as has_active from vault_secrets where connection_id = '${S.conn[key]}'`,
        );
        expect(secrets).toEqual([{ status: 'active', has_active: true }]);
        await grant(S.conn[key], 'orders.list');
        await grant(S.conn[key], 'orders.get');
      }

      const readsBefore = await secretReads(`connection_id = '${S.conn.alice}'`);
      const response = await execute(S.conn.alice, 'orders.list', { limit: 100 });
      expect(response.status).toBe(200);
      expect(response.json.status).toBe('succeeded');
      const orders = response.json.result.orders as Loose[];
      expect(new Set(orders.map((order) => order.id as string))).toEqual(S.aliceOrders);

      // The read really went through the vault: issue and consume are on the capability row, the
      // audit chain has the read, and the worker's requests passed the proxy.
      const rows = await jsonRows(
        `select * from vault_access_capabilities where job_id = '${response.json.jobId}'`,
      );
      expect(rows).toHaveLength(1);
      const row = rows[0] as Loose;
      expect(row.purpose).toBe('read');
      expect(row.operation).toBe('orders.list');
      expect(row.connection_id).toBe(S.conn.alice);
      expect(row.secret_version).toBe(1);
      expect(row.token_hash).toMatch(/^[0-9a-f]{64}$/);
      expect(row.token_mac).toMatch(/^[0-9a-f]{64}$/);
      expect(row.authorization_mac).toMatch(/^[0-9a-f]{64}$/);
      expect(row.used_at).not.toBeNull();
      expect(row.revoked_at).toBeNull();
      expect(await secretReads(`connection_id = '${S.conn.alice}'`)).toBe(readsBefore + 1);
      expect(
        await count(
          `select count(*) from audit_events where event_type = 'vault.capability_issued' and connection_id = '${S.conn.alice}' and metadata->>'jobId' = '${response.json.jobId}'`,
        ),
      ).toBe(1);
      const operations = T.proxy?.operations ?? [];
      expect(operations).toEqual(
        expect.arrayContaining([
          'hello',
          'completeLogin',
          'issueAccessCapability',
          'readForWorker',
        ]),
      );
      expect(T.proxy?.tokens.size).toBeGreaterThanOrEqual(3);
      expect(await rejections()).toEqual([]);
      expect(S.vault?.text()).toContain('vault listening');
    },
    { critical: true },
  );

  /* ============================================================ 2 */
  step(
    '2. worker asks the vault for an unrelated connection (P3-5, AT-009, VA-12, VS-3, VS-5)',
    async () => {
      const workerPid = S.worker?.pid ?? 0;
      process.kill(workerPid, 'SIGSTOP'); // the test is the supervisor for this step
      try {
        const tampered: string[] = [];

        /* Bob's own read as the supervisor: the plaintext Bob's connection can really yield. */
        const bobJob = await queuedJob(S.conn.bob, 'orders.list', { limit: 5 });
        await claim(bobJob);
        const bobToken = await issued(bobJob);
        const bobRead = await vaultCall(
          'supervisor',
          'readForWorker',
          readParams(bobJob, bobToken),
        );
        expect(bobRead.ok).toBe(true);
        expect(bobRead.result.secretType).toBe('session_snapshot');
        learnCanaries('bob', bobRead.result.plaintext as string);
        await endJob(bobJob);
        const bobSecret = T.canaries.get('bob storage state (JSON)') ?? '';
        expect(bobSecret).toContain('cookies');

        /* Job A of Alice, with a token: wrong connection, operation, job and purpose. */
        const jobA = await queuedJob(S.conn.alice, 'orders.list', { limit: 5 });
        const jobB = await queuedJob(S.conn.alice, 'orders.list', { limit: 5 });
        await claim(jobA);
        await claim(jobB);
        const tokenA = await issued(jobA);
        const ids = { jobId: jobA.jobId, capabilityId: jobA.capabilityId };
        const unusedBefore = await capabilityRow(jobA.capabilityId);
        expect(unusedBefore.used_at).toBeNull();

        await expectRefused(
          'job A token for connection B (an unrelated connection)',
          'binding_mismatch',
          () =>
            vaultCall(
              'supervisor',
              'readForWorker',
              readParams(jobA, tokenA, { connectionId: S.conn.bob }),
            ),
          ids,
        );
        await expectRefused(
          'job A token for another operation',
          'binding_mismatch',
          () =>
            vaultCall(
              'supervisor',
              'readForWorker',
              readParams(jobA, tokenA, { operation: 'orders.get' }),
            ),
          ids,
        );
        await expectRefused(
          'job A token for job B',
          'binding_mismatch',
          () =>
            vaultCall(
              'supervisor',
              'readForWorker',
              readParams(jobA, tokenA, { jobId: jobB.jobId }),
            ),
          ids,
        );
        await expectRefused(
          'job A read token presented as a login completion (another purpose)',
          'binding_mismatch',
          () =>
            vaultCall('supervisor', 'completeLogin', {
              token: tokenA,
              jobId: jobA.jobId,
              connectionId: S.conn.alice,
              plaintext: Buffer.from('{"cookies":[],"origins":[]}').toString('base64url'),
              externalAccountHint: null,
              sessionExpiresAt: null,
            }),
          ids,
        );
        // Four refusals consumed nothing: the capability row is what it was.
        expect(await capabilityRow(jobA.capabilityId)).toEqual(unusedBefore);
        expect(
          await secretReads(`metadata->>'jobId' = '${jobA.jobId}'`),
          'no read was audited for the refused presentations',
        ).toBe(0);
        // Positive control: the same token, with its own bindings, opens the session.
        const readA = await vaultCall('supervisor', 'readForWorker', readParams(jobA, tokenA));
        expect(readA.ok, 'the same token with the right bindings').toBe(true);
        learnCanaries('alice', readA.result.plaintext as string);
        expect(readA.result.secretVersion).toBe(1);
        const jobRow = (
          await jsonRows(`select arguments_hash from execution_jobs where id = '${jobA.jobId}'`)
        )[0] as Loose;
        expect(readA.result.argumentsHash).toBe(jobRow.arguments_hash);
        // Bob's session never came back for Alice's token.
        for (const text of T.refusedResponses) {
          expect(text).not.toContain(bobSecret);
          for (const [label, value] of T.canaries) expect(text, label).not.toContain(value);
        }
        // And the spent token is refused as used.
        await expectRefused(
          'job A token a second time',
          'used',
          () => vaultCall('supervisor', 'readForWorker', readParams(jobA, tokenA)),
          ids,
        );
        await endJob(jobA);
        await endJob(jobB);

        /* Another secret version: the bound version is no longer the active one. */
        const jobV = await queuedJob(S.conn.alice, 'orders.list', { limit: 5 });
        await claim(jobV);
        const tokenV = await issued(jobV);
        expect((await capabilityRow(jobV.capabilityId)).secret_version).toBe(1);
        const secretId = (
          (
            await jsonRows(`select id from vault_secrets where connection_id = '${S.conn.alice}'`)
          )[0] as Loose
        ).id as string;
        const v1Id = (
          (
            await jsonRows(
              `select id from vault_secret_versions where secret_id = '${secretId}' and version = 1`,
            )
          )[0] as Loose
        ).id as string;
        let v2Id = '';
        try {
          // A second version (a copy of the sealed bytes, which would not open as version 2) made
          // the active one: the vault must refuse on the binding, before it opens anything.
          v2Id = await psql(
            `insert into vault_secret_versions (secret_id, version, algorithm, ciphertext, nonce, auth_tag, wrapped_dek, kek_version, aad_version) select secret_id, 2, algorithm, ciphertext, nonce, auth_tag, wrapped_dek, kek_version, aad_version from vault_secret_versions where id = '${v1Id}' returning id`,
          );
          v2Id = v2Id.split('\n')[0] as string;
          await psql(
            `update vault_secrets set active_version_id = '${v2Id}' where id = '${secretId}'`,
          );
          tampered.push('active secret version');
          await expectRefused(
            'job V token (bound to version 1) after the active version became 2',
            'secret_not_active',
            () => vaultCall('supervisor', 'readForWorker', readParams(jobV, tokenV)),
            { jobId: jobV.jobId, capabilityId: jobV.capabilityId },
          );
        } finally {
          await psql(
            `update vault_secrets set active_version_id = '${v1Id}' where id = '${secretId}'`,
          );
          if (v2Id !== '') await psql(`delete from vault_secret_versions where id = '${v2Id}'`);
        }
        expect((await capabilityRow(jobV.capabilityId)).used_at).toBeNull();
        const readV = await vaultCall('supervisor', 'readForWorker', readParams(jobV, tokenV));
        expect(readV.ok, 'the same token once version 1 is active again').toBe(true);
        await endJob(jobV);

        /* Another worker or attempt: at issue, and at read after the job moved. */
        const jobW = await queuedJob(S.conn.alice, 'orders.list', { limit: 5 });
        await claim(jobW, SUPERVISOR_WORKER, 1);
        const idsW = { jobId: jobW.jobId, capabilityId: jobW.capabilityId };
        await expectRefused(
          'issue for another worker than the one running the job',
          'binding_mismatch',
          () => issue(jobW, { workerId: 'e2e-impostor' }),
          idsW,
        );
        await expectRefused(
          'issue for another attempt than the one running',
          'binding_mismatch',
          () => issue(jobW, { attempt: 2 }),
          idsW,
        );
        expect(
          (await capabilityRow(jobW.capabilityId)).token_hash,
          'no token after refused issues',
        ).toBeNull();
        const tokenW = await issued(jobW);
        try {
          await psql(
            `update execution_jobs set worker_id = 'e2e-other-worker' where id = '${jobW.jobId}'`,
          );
          tampered.push('job worker');
          await expectRefused(
            'job W token after the job moved to another worker',
            'binding_mismatch',
            () => vaultCall('supervisor', 'readForWorker', readParams(jobW, tokenW)),
            idsW,
          );
        } finally {
          await psql(
            `update execution_jobs set worker_id = '${SUPERVISOR_WORKER}' where id = '${jobW.jobId}'`,
          );
        }
        try {
          await psql(`update execution_jobs set attempt_count = 2 where id = '${jobW.jobId}'`);
          tampered.push('job attempt');
          await expectRefused(
            'job W token after the job moved to another attempt',
            'binding_mismatch',
            () => vaultCall('supervisor', 'readForWorker', readParams(jobW, tokenW)),
            idsW,
          );
        } finally {
          await psql(`update execution_jobs set attempt_count = 1 where id = '${jobW.jobId}'`);
        }
        expect((await capabilityRow(jobW.capabilityId)).used_at).toBeNull();
        const readW = await vaultCall('supervisor', 'readForWorker', readParams(jobW, tokenW));
        expect(readW.ok, 'the same token on its own worker and attempt').toBe(true);
        await endJob(jobW);

        /* VS-5: a supervisor cannot get a token for a job the API did not authorize. */
        const jobX = await queuedJob(S.conn.alice, 'orders.list', { limit: 5 });
        const jobY = await queuedJob(S.conn.alice, 'orders.list', { limit: 5 });
        await claim(jobX);
        await claim(jobY);
        const capabilitiesBefore = await count('select count(*) from vault_access_capabilities');
        const unknownCapability = '00000000-0000-4000-8000-0000000000e5';
        await expectRefused(
          'issue for a capability the API never created (unknown id)',
          'unknown_token',
          () => issue(jobX, { capabilityId: unknownCapability }),
          { jobId: jobX.jobId, capabilityId: null },
        );
        expect(await count('select count(*) from vault_access_capabilities')).toBe(
          capabilitiesBefore,
        );
        await expectRefused(
          'issue with the capability of another job',
          'binding_mismatch',
          () => issue(jobX, { capabilityId: jobY.capabilityId }),
          { jobId: jobY.jobId, capabilityId: jobY.capabilityId },
        );
        // A job whose claim did not come from an authorization (capability_ref cleared).
        try {
          await psql(`update execution_jobs set capability_ref = null where id = '${jobX.jobId}'`);
          tampered.push('job capability reference');
          await expectRefused(
            'issue for a job that points at no authorization',
            'binding_mismatch',
            () => issue(jobX),
            { jobId: jobX.jobId, capabilityId: jobX.capabilityId },
          );
        } finally {
          await psql(
            `update execution_jobs set capability_ref = '${jobX.capabilityId}' where id = '${jobX.jobId}'`,
          );
        }
        // An authorization edited by a database writer (here: its expiry, one second earlier): the MAC no longer fits.
        const original = (await capabilityRow(jobY.capabilityId)).expires_at as string;
        try {
          await psql(
            `update vault_access_capabilities set expires_at = expires_at - interval '1 second' where id = '${jobY.capabilityId}'`,
          );
          tampered.push('authorization expiry');
          await expectRefused(
            'issue for an authorization edited by a database writer (MAC)',
            'integrity',
            () => issue(jobY),
            { jobId: jobY.jobId, capabilityId: jobY.capabilityId },
          );
        } finally {
          await psql(
            `update vault_access_capabilities set expires_at = '${original}' where id = '${jobY.capabilityId}'`,
          );
        }
        for (const job of [jobX, jobY]) {
          expect(
            (await capabilityRow(job.capabilityId)).token_hash,
            'no token for an unauthorized job',
          ).toBeNull();
        }
        await endJob(jobX);
        await endJob(jobY);

        expect(tampered).toEqual([
          'active secret version',
          'job worker',
          'job attempt',
          'job capability reference',
          'authorization expiry',
        ]);
        // Every refusal above is on the audit chain with the reason the test expected; nothing
        // else was refused (the real worker was paused, the real jobs did not run).
        const reasons = (await rejections()).map((event) => event.reason);
        expect(reasons.filter((reason) => reason === 'binding_mismatch')).toHaveLength(10);
        expect(reasons.filter((reason) => reason === 'secret_not_active')).toHaveLength(1);
        expect(reasons.filter((reason) => reason === 'used')).toHaveLength(1);
        expect(reasons.filter((reason) => reason === 'unknown_token')).toHaveLength(1);
        expect(reasons.filter((reason) => reason === 'integrity')).toHaveLength(1);
        expect(reasons).toHaveLength(14);
        expect(
          await count(
            `select count(*) from audit_events where event_type = 'vault.secret_read' and connection_id = '${S.conn.alice}'`,
          ),
        ).toBe(4); // step 1's read and the reads of jobs A, V and W; none for any refusal
      } finally {
        process.kill(workerPid, 'SIGCONT');
      }
      // The worker is alive again: a real read works.
      const again = await execute(S.conn.alice, 'orders.list', { limit: 100 });
      expect(again.json.status).toBe('succeeded');
    },
    { critical: true },
  );

  /* ============================================================ 3 */
  step(
    '3. revocation during a running job',
    async () => {
      const proxy = T.proxy as VaultProxy;
      const connectionId = S.conn.bob;

      /* (a) between the token issue and the consume, held by the proxy */
      const readsBefore = await secretReads(`connection_id = '${connectionId}'`);
      const requestsBefore = demoRequests().length;
      const rejectionsBefore = (await rejections()).length;
      const forwardedBefore = proxy.forwardedReads;
      proxy.arm();
      const pendingA = execute(connectionId, 'orders.list', { limit: 100 });
      await waitFor(() => proxy.heldCount > 0, 60_000, 'the worker to ask the vault to read');
      expect(proxy.heldCount, 'exactly one readForWorker line is held').toBe(1);
      const held = (
        await jsonRows(
          `select j.id as job_id, j.status, c.id as capability_id, c.token_hash is not null as issued, c.used_at, c.revoked_at from execution_jobs j join vault_access_capabilities c on c.id = j.capability_ref where j.connection_id = '${connectionId}' and j.status = 'running'`,
        )
      )[0] as Loose;
      expect(held, 'a running job whose token is issued and not yet consumed').toMatchObject({
        status: 'running',
        issued: true,
        used_at: null,
        revoked_at: null,
      });
      const revokedAt = Date.now();
      const revoke = await api('POST', `/connections/${connectionId}/revoke`);
      expect(revoke.status).toBe(200);
      expect(revoke.json.status).toBe('revoked');
      proxy.release();
      const responseA = await pendingA;
      T.timings['3a revoke to job end ms'] = Date.now() - revokedAt;
      const newReasons = (await rejections()).slice(rejectionsBefore);
      // The point of 3a is that the VAULT judged the token: the held readForWorker line was
      // forwarded after the revocation committed and was refused as `revoked`. If the job had been
      // cancelled before the line reached the vault (the other branch), the vault would never have
      // judged the token: that is a failure here, not an equally good outcome.
      const forwardedReads = proxy.forwardedReads - forwardedBefore;
      expect(
        forwardedReads,
        `3a took the cancel branch: the held readForWorker line was not forwarded to the vault (forwarded ${forwardedReads}, job ended ${String(responseA.json.status)}, rejections ${JSON.stringify(newReasons.map((event) => event.reason))}); the vault did not judge the token`,
      ).toBe(1);
      expect(
        newReasons.map((event) => event.reason),
        '3a: exactly one rejection, the vault refusing the held token as revoked',
      ).toEqual(['revoked']);
      expect(responseA.status).toBe(200);
      expect(['cancelled', 'failed']).toContain(responseA.json.status);
      expect(responseA.json.result).toBeNull();
      if (responseA.json.status === 'failed')
        expect(responseA.json.error.code).toBe('vault_denied');
      const capabilityA = await capabilityRow(held.capability_id as string);
      expect(capabilityA.used_at, 'the token was never consumed').toBeNull();
      expect(capabilityA.revoked_at).not.toBeNull();
      expect(capabilityA.revoked_reason).toBe('connection_revoked');
      expect(await secretReads(`connection_id = '${connectionId}'`)).toBe(readsBefore);
      expect(demoRequests().length, 'the browser never ran').toBe(requestsBefore);
      const secrets = await jsonRows(
        `select status, active_version_id from vault_secrets where connection_id = '${connectionId}'`,
      );
      expect(secrets).toEqual([{ status: 'revoked', active_version_id: null }]);
      expect(await versionsFor(connectionId)).toBe(0);
      T.revokedRead = `3a: job ${String(held.job_id)} ended ${String(responseA.json.status)}; held readForWorker forwarded ${forwardedReads}, vault rejection events after the revoke: ${JSON.stringify(newReasons.map((event) => event.reason))} (vault branch)`;

      /* (b) after the consume, while the browser holds the session: the browser is frozen */
      // Only here the worker runs with a short lease (its real AAB_WORKER_LEASE_MS, minimum 5 s): its
      // heartbeat, which is also when it looks at the cancel flag of a running job, then fires every
      // 2 s instead of 20 s. Restart it: the old one and its sandboxes must be gone first.
      const oldWorkerPid = S.worker?.pid ?? 0;
      await S.worker?.stop();
      expect(S.worker?.exit).toEqual({ code: 0, signal: null });
      S.oldWorkerLogs.push(S.worker?.text() ?? '');
      expect(pidGone(oldWorkerPid), 'the old worker is gone').toBe(true);
      expect(
        [...procTable()]
          .filter(
            ([pid, info]) => pid !== process.pid && info.argv.join(' ').includes(S.runtimeDir),
          )
          .map(([pid]) => pid),
        'no sandbox or process of the old worker is left',
      ).toEqual([]);
      await startWorker(proxy.socketPath, { AAB_WORKER_LEASE_MS: '6000' });
      const worker = S.worker?.pid ?? 0;
      S.pids.worker = worker;
      expect(worker).not.toBe(oldWorkerPid);
      expect(
        new RegExp(`"workerId":"worker-[^"]*-${worker}-`).test(S.worker?.text() ?? ''),
        'the new worker identifies itself',
      ).toBe(true);

      const second = await newConnection('Revocation target (e2e)');
      T.extraRevokeConnection = second;
      await loginAs(second, ALICE, S.passwords.alice);
      await grant(second, 'orders.list');
      const demoBefore = demoRequests().length;
      let requestsFrozen: number;
      const pendingB = execute(second, 'orders.list', { limit: 100 });
      let settled = false;
      void pendingB.then(
        () => (settled = true),
        () => (settled = true),
      );
      // Freezes everything below the worker (the sandbox, the runner driving the page and every
      // browser process), again and again for a moment so late children are caught too. The
      // worker itself keeps running: it is the one that has to notice the revocation.
      const frozen = S.watchPids;
      frozen.clear();
      const freeze = (): void => {
        const { table } = browserTree(worker);
        for (const pid of table.keys()) {
          if (frozen.has(pid) || ancestorsOf(pid, table, worker) === null) continue;
          try {
            process.kill(pid, 'SIGSTOP');
            frozen.add(pid);
            writeWatchSpec(); // the watchdog resumes and kills these if this process dies
          } catch {
            // Gone.
          }
        }
      };
      let running: Loose;
      try {
        while (!settled && browserTree(worker).chromium.length === 0) await sleep(20);
        for (let round = 0; round < 15; round += 1) {
          freeze();
          await sleep(100);
        }
        expect(frozen.size, 'the sandbox of the running job was caught and frozen').toBeGreaterThan(
          2,
        );
        expect(settled, 'the job had not finished when it was frozen').toBe(false);
        await sleep(1_000);
        running = (
          await jsonRows(
            `select j.id, j.status, c.id as capability_id, c.used_at, c.revoked_at from execution_jobs j join vault_access_capabilities c on c.id = j.capability_ref where j.connection_id = '${second}' and j.kind = 'operation'`,
          )
        )[0] as Loose;
        expect(running.status).toBe('running');
        expect(running.used_at, 'the session was already read by the worker').not.toBeNull();
        requestsFrozen = demoRequests().length;
        const readsB = await secretReads(`connection_id = '${second}'`);
        expect(readsB).toBe(1);
        const revokeB = await api('POST', `/connections/${second}/revoke`);
        expect(revokeB.status).toBe(200);
        expect(revokeB.json.status).toBe('revoked');
        const revokeCommitted = Date.now();
        await waitFor(
          async () => {
            const status = await psql(
              `select status from execution_jobs where id = '${String(running.id)}'`,
            );
            return !['running', 'queued'].includes(status);
          },
          90_000,
          'the revoked job to end',
          200,
        );
        T.timings['3b revoke to job end ms'] = Date.now() - revokeCommitted;
        // Nothing has resumed these processes. A stopped process cannot exit by itself, so each one
        // that is gone now was killed by the worker's heartbeat ending the job and taking the
        // sandbox down. (A pid that is gone, or a zombie waiting to be reaped, counts as exited.)
        await waitFor(
          () => [...frozen].every((pid) => pidGone(pid)),
          30_000,
          'every frozen process to exit while still stopped',
          200,
        ).catch(() => undefined);
        const survivors = [...frozen].filter((pid) => !pidGone(pid));
        expect(
          survivors,
          `frozen processes still alive when the job had ended (killed by nobody): ${survivors.length} of ${frozen.size}`,
        ).toEqual([]);
        T.timings['3b frozen processes killed'] = frozen.size;
      } finally {
        // Whatever happened above: nothing stays stopped. Resume, give the worker a moment to take
        // its sandbox down, then kill what is still alive.
        for (const pid of frozen) {
          try {
            process.kill(pid, 'SIGCONT');
          } catch {
            // Gone.
          }
        }
        const until = Date.now() + 5_000;
        while (Date.now() < until && [...frozen].some((pid) => !pidGone(pid))) await sleep(100);
        for (const pid of frozen) {
          if (pidGone(pid)) continue;
          try {
            process.kill(pid, 'SIGKILL');
          } catch {
            // Gone.
          }
        }
        frozen.clear();
        writeWatchSpec();
      }
      const responseB = await pendingB;
      expect(['cancelled', 'failed']).toContain(responseB.json.status);
      expect(responseB.json.result).toBeNull();
      if (responseB.json.status === 'failed')
        expect(['vault_denied', 'cancelled']).toContain(responseB.json.error.code);
      await sleep(1_000);
      expect(
        demoRequests().length,
        'no request reached the demo with that session after it was frozen, so none after the revocation committed',
      ).toBe(requestsFrozen);
      expect(requestsFrozen).toBeGreaterThanOrEqual(demoBefore);
      const secretsB = await jsonRows(
        `select status, active_version_id from vault_secrets where connection_id = '${second}'`,
      );
      expect(secretsB).toEqual([{ status: 'revoked', active_version_id: null }]);
      expect(await versionsFor(second)).toBe(0);
      expect(await secretReads(`connection_id = '${second}'`)).toBe(1);
      expect((await connectionOf(second)).status).toBe('revoked');
      T.liveRead = `3b: job ${String(running.id)} ended ${String(responseB.json.status)} after the revoke committed`;
      // The real worker is still serving: a read on a live connection works.
      const alive = await execute(S.conn.alice, 'orders.list', { limit: 100 });
      expect(alive.json.status).toBe('succeeded');
    },
    { critical: true },
  );

  /* ============================================================ 4 */
  step(
    '4. no token, MAC or plaintext in logs, responses, audit or any column (P3-15, VS-16)',
    async () => {
      // Quiet the stack first: nothing may still be running.
      expect(
        await count(`select count(*) from execution_jobs where status in ('queued', 'running')`),
      ).toBe(0);

      /* The sessions of every login and read the worker did (seen in transit by the proxy), the
       * session of step 3b's connection among them, are canaries too. */
      const sessionNames = new Map([
        [S.conn.alice, 'alice login'],
        [S.conn.bob, 'bob login'],
        [T.extraRevokeConnection, 'step 3b'],
      ]);
      expect(
        T.proxy?.sessions.get(T.extraRevokeConnection)?.size ?? 0,
        'step 3b session seen',
      ).toBeGreaterThanOrEqual(1);
      for (const [connectionId, plaintexts] of T.proxy?.sessions ?? []) {
        const name = sessionNames.get(connectionId) ?? `connection ${connectionId.slice(0, 8)}`;
        [...plaintexts].forEach((plaintext, index) => learnCanaries(`${name} ${index}`, plaintext));
      }
      expect([...T.canaries.keys()].some((label) => /^step 3b 0 cookie /.test(label))).toBe(true);
      for (const secret of [
        S.passwords.alice,
        S.passwords.bob,
        S.passwords.owner,
        S.csrf,
        dashboardSessionValue(),
      ]) {
        expect(secret.length).toBeGreaterThanOrEqual(8);
      }

      /* The vault's refusal paths, so its log has something to say (it runs at debug level, like
       * the worker). A real token is used on purpose: if the vault ever logged a request's params,
       * the scan below would find it. */
      const realToken = [...T.tokens][0] as string;
      const someJob = (
        await jsonRows(
          `select id, connection_id from execution_jobs order by created_at desc limit 1`,
        )
      )[0] as Loose;
      const logBefore = countLines(S.vault?.text() ?? '');
      const refusedByRole = [
        await vaultCall('api', 'readForWorker', {
          token: realToken,
          jobId: someJob.id,
          connectionId: someJob.connection_id,
          operation: 'orders.list',
        }),
        await vaultCall('supervisor', 'rewrap', { jobId: someJob.id }),
      ];
      for (const response of refusedByRole) {
        expect(isPlainForbidden(response), 'a request for an operation the role may not call').toBe(
          true,
        );
        T.refusedResponses.push(JSON.stringify(response));
      }
      // A line longer than the cap, never ended: the vault answers once and closes the connection.
      const oversized = await vaultRaw('api', 'x'.repeat(80 * 1024));
      T.refusedResponses.push(oversized);
      expect(oversized).not.toContain('plaintext');
      await waitFor(
        () => /vault connection closed/.test(S.vault?.text() ?? ''),
        15_000,
        'the vault to log the closed connection',
      );
      const capabilityRows = await jsonRows(
        'select id, token_hash, token_mac, authorization_mac from vault_access_capabilities',
      );
      const withHashes = currentNeedles(capabilityRows, { withHashesAndMacs: true });

      // The inputs exist and are not trivial.
      expect(T.canaries.size).toBeGreaterThanOrEqual(6);
      for (const value of T.canaries.values()) expect(value.length).toBeGreaterThanOrEqual(8);
      expect([...T.canaries.keys()].some((label) => /^alice cookie /.test(label))).toBe(true);
      expect([...T.canaries.keys()].some((label) => /^bob cookie /.test(label))).toBe(true);
      expect(withHashes.counts['tokens']).toBeGreaterThanOrEqual(8);
      expect(withHashes.counts['token hashes']).toBeGreaterThanOrEqual(8);
      expect(withHashes.counts['token MACs']).toBeGreaterThanOrEqual(8);
      expect(withHashes.counts['authorization MACs']).toBeGreaterThanOrEqual(8);
      expect(withHashes.needles.length).toBeGreaterThan(300);
      // A token the real worker presented (seen only in the proxy) is among the needles.
      const workerTokens = [...(T.proxy?.tokens ?? [])].filter((token) => !T.tokens.has(token));
      expect(workerTokens.length).toBeGreaterThanOrEqual(3);

      /* haystacks */
      const logs = processLogs();
      const responses: Haystack = {
        label: 'api responses (bodies and headers)',
        column: null,
        text: S.httpBodies.join('\n'),
      };
      const audit: Haystack = {
        label: 'audit events (metadata)',
        column: null,
        text: await psql('select metadata::text from audit_events'),
      };
      const jobs: Haystack = {
        label: 'job rows',
        column: null,
        text: await psql('select row_to_json(j)::text from execution_jobs j'),
      };
      const database = await databaseColumns();
      const refusals: Haystack = {
        label: 'vault answers to refused requests',
        column: null,
        text: T.refusedResponses.join('\n'),
      };
      const haystacks = [...logs, responses, refusals, audit, jobs, ...database.haystacks];
      const logLines = logs.reduce((sum, log) => sum + countLines(log.text), 0);
      for (const log of logs) {
        expect(countLines(log.text), `${log.label} has lines`).toBeGreaterThanOrEqual(3);
      }
      // The vault log is not vacuous: besides its start-up lines it holds the request-path lines
      // of the refusals triggered above (warn level) and of everything before them.
      const vaultLines = (logs.find((log) => log.label === 'log: vault')?.text ?? '').split('\n');
      const requestPathLines = vaultLines.filter((line) =>
        /"event":"vault\.(request_refused|connection_closed|capability_rejected)"|vault request (refused|failed)/.test(
          line,
        ),
      );
      expect(
        requestPathLines.filter(
          (line) => line.includes('"operation":"readForWorker"') && line.includes('"role":"api"'),
        ).length,
        'the vault refused readForWorker on the api socket and said so',
      ).toBe(1);
      expect(
        requestPathLines.filter(
          (line) => line.includes('"operation":"rewrap"') && line.includes('"role":"supervisor"'),
        ).length,
        'the vault refused rewrap on the supervisor socket and said so',
      ).toBe(1);
      expect(
        requestPathLines.filter((line) => line.includes('vault.connection_closed')).length,
      ).toBeGreaterThanOrEqual(1);
      expect(requestPathLines.length, 'request-path lines in the vault log').toBeGreaterThanOrEqual(
        3,
      );
      expect(
        countLines(S.vault?.text() ?? '') - logBefore,
        'lines the refusals added',
      ).toBeGreaterThanOrEqual(3);
      expect(vaultLines.length, 'lines in the vault log').toBeGreaterThanOrEqual(
        VAULT_LOG_MIN_LINES,
      );
      expect(logLines).toBeGreaterThan(200);
      expect(S.httpBodies.length).toBeGreaterThan(50);
      expect(responses.text.length).toBeGreaterThan(10_000);
      expect(audit.text.split('\n').length).toBeGreaterThan(50);
      expect(jobs.text.split('\n').length).toBeGreaterThan(8);
      expect(database.tables).toBeGreaterThanOrEqual(15);
      expect(database.columns).toBeGreaterThan(100);
      expect(database.rows).toBeGreaterThan(100);
      expect(database.cells).toBeGreaterThan(500);

      /* the scanner finds what is there (positive controls, every encoding) */
      const controlValues = [
        ...[...T.canaries.values()].slice(0, 3),
        ...[...T.canaries]
          .filter(([label]) => /^step 3b /.test(label))
          .map(([, value]) => value)
          .slice(0, 3),
        S.passwords.alice,
        S.passwords.owner,
        S.csrf,
        dashboardSessionValue(),
      ];
      expect(controlValues.length).toBeGreaterThanOrEqual(10);
      for (const needle of controlValues) {
        for (const [encoding, variant] of variantsOf(needle)) {
          const control = findHits(
            [{ label: 'control', column: null, text: `xx ${variant} yy` }],
            needleSet([{ kind: 'control', klass: 'plain', value: needle }]),
            { excludeHashMacColumns: false },
          );
          expect(
            control.map((hit) => hit.encoding),
            `control ${encoding}`,
          ).toContain(encoding);
        }
      }
      /* positive controls for the new forms: a token's 32 bytes as hex, base64 and raw characters */
      const sampleToken = [...T.tokens][0] as string;
      const sampleBytes = Buffer.from(sampleToken, 'base64url');
      expect(sampleBytes.length).toBe(32);
      for (const [encoding, text] of [
        ['token bytes as hex', sampleBytes.toString('hex')],
        ['token bytes as HEX', sampleBytes.toString('hex').toUpperCase()],
        ['token bytes as base64', sampleBytes.toString('base64')],
        ['token bytes as latin1', sampleBytes.toString('latin1')],
      ] as const) {
        expect(
          findHits(
            [{ label: 'control', column: null, text: `xx ${text} yy` }],
            needleSet([{ kind: 'control', klass: 'token', value: sampleToken }]),
            { excludeHashMacColumns: false },
          ).map((hit) => hit.encoding),
          `control ${encoding}`,
        ).toContain(encoding);
      }
      /* the dashboard values: found everywhere but in the API's own responses, which do carry the CSRF token */
      const clientControl = needleSet([{ kind: 'control', klass: 'client', value: S.csrf }]);
      expect(responses.text, 'the API answered the login with the CSRF token').toContain(S.csrf);
      expect(
        findHits([{ label: 'log: control', column: null, text: `xx ${S.csrf}` }], clientControl, {
          excludeHashMacColumns: false,
        }).length,
        'a CSRF token in a log is found',
      ).toBeGreaterThan(0);
      expect(
        findHits(
          [{ label: 'api responses (control)', column: null, text: S.csrf }],
          clientControl,
          { excludeHashMacColumns: false },
        ),
        'the exclusion covers the API responses only',
      ).toEqual([]);
      const embedded = Buffer.from(
        `${'x'.repeat(7)}${[...T.canaries.values()][2] as string}tail`,
      ).toString('base64');
      expect(
        findHits(
          [{ label: 'control', column: null, text: embedded }],
          needleSet([
            { kind: 'control', klass: 'plain', value: [...T.canaries.values()][2] as string },
          ]),
          { excludeHashMacColumns: false },
        ).length,
        'a value inside a longer base64 text',
      ).toBeGreaterThan(0);

      /* where the token hashes and MACs really are: exactly the three capability columns */
      const columnsWithHashesOrMacs = new Set(
        findHits(
          database.haystacks,
          withHashes.needles.filter((needle) => needle.klass === 'hashmac'),
          { excludeHashMacColumns: false },
        ).map((hit) => hit.haystack),
      );
      expect(
        [...columnsWithHashesOrMacs].sort(),
        'the only columns that hold a token hash or a MAC',
      ).toEqual(HASH_AND_MAC_COLUMNS.map((column) => `db:${column}`).sort());
      const allNames = (await allColumns()).map((entry) => `${entry.table}.${entry.column}`);
      for (const column of HASH_AND_MAC_COLUMNS) expect(allNames).toContain(column);

      /* the scan: every needle, every haystack; the three columns are excluded for hashes and MACs only */
      const hits = findHits(haystacks, withHashes.needles, { excludeHashMacColumns: true });
      expect(describeHits(hits), 'secrets found (haystack :: kind (encoding))').toEqual([]);
      // Outside the excluded columns the hashes and MACs are searched in the logs and responses too.
      expect(
        withHashes.needles.filter((needle) => needle.klass === 'hashmac').length,
      ).toBeGreaterThan(100);
      T.timings['scan: needles'] = withHashes.needles.length;
      T.timings['scan: haystacks'] = haystacks.length;
      T.timings['scan: log lines'] = logLines;
      T.timings['scan: tables'] = database.tables;
      T.timings['scan: columns'] = database.columns;
      T.timings['scan: rows'] = database.rows;
      T.timings['scan: cells'] = database.cells;
    },
  );

  /* ============================================================ 5 */
  step('5. a database dump contains no plaintext session and no live token (P3-16)', async () => {
    const { stdout } = await run(
      path.join(PG_BIN, 'pg_dump'),
      ['-h', PG_DIR, '-p', PG_PORT, '--no-owner', '--format=plain', S.dbName],
      { env: { PATH: '/usr/bin' }, maxBuffer: 512 * 1024 * 1024 },
    );
    const dump = stdout;
    expect(dump.length).toBeGreaterThan(20_000);
    // It is a dump of everything: every table has its schema and its rows.
    const tables = (await allColumns()).map((entry) => entry.table);
    for (const table of new Set(tables)) {
      expect(dump, `CREATE TABLE for ${table}`).toContain(`CREATE TABLE public.${table} `);
    }
    expect(dump).toContain('COPY public.vault_secret_versions ');
    expect(dump).toContain('COPY public.vault_access_capabilities ');
    expect(countLines(dump)).toBeGreaterThan(300);

    /* no plaintext in any encoding, no raw token in any encoding */
    const capabilityRows = await jsonRows(
      'select id, token_hash, token_mac, authorization_mac from vault_access_capabilities',
    );
    const live = currentNeedles(capabilityRows, { withHashesAndMacs: false });
    expect(live.counts['canaries']).toBeGreaterThanOrEqual(6);
    expect(live.counts['tokens']).toBeGreaterThanOrEqual(8);
    const dumpHaystack: Haystack = { label: 'pg_dump', column: null, text: dump };
    // The dump of a bytea column is hex text; look at its bytes too.
    const dumpBytes: Haystack = {
      label: 'pg_dump (decoded bytea)',
      column: null,
      text: decodeByteaHex(dump),
    };
    expect(
      describeHits(
        findHits([dumpHaystack, dumpBytes], live.needles, { excludeHashMacColumns: false }),
      ),
    ).toEqual([]);
    // The control: the dump does hold what the database holds by design.
    const designed = currentNeedles(capabilityRows, { withHashesAndMacs: true });
    const designedHits = findHits(
      [dumpHaystack],
      designed.needles.filter((needle) => needle.klass === 'hashmac' && needle.encoding === 'raw'),
      { excludeHashMacColumns: false },
    );
    expect(new Set(designedHits.map((hit) => hit.kind))).toEqual(
      new Set(['token hash', 'token MAC', 'authorization MAC']),
    );

    /* every stored version is ciphertext with wrapped-key bytes */
    const versions = await jsonRows(
      `select id, secret_id, version, length(ciphertext) as ciphertext_bytes, length(wrapped_dek) as wrapped_key_bytes, length(nonce) as nonce_bytes, length(auth_tag) as tag_bytes from vault_secret_versions`,
    );
    expect(versions.length).toBeGreaterThanOrEqual(1);
    for (const row of versions) {
      expect(row.ciphertext_bytes, `ciphertext of version ${String(row.id)}`).toBeGreaterThan(0);
      expect(row.wrapped_key_bytes, `wrapped key of version ${String(row.id)}`).toBeGreaterThan(0);
      expect(row.nonce_bytes).toBeGreaterThan(0);
      expect(row.tag_bytes).toBeGreaterThan(0);
    }
    expect(
      await count(
        `select count(*) from vault_secret_versions where octet_length(ciphertext) = 0 or octet_length(wrapped_dek) = 0`,
      ),
    ).toBe(0);
    // The ciphertext is not the plaintext in any encoding.
    const stored = await jsonRows(
      `select encode(ciphertext, 'hex') as c, encode(wrapped_dek, 'hex') as w from vault_secret_versions`,
    );
    const aliceJson = T.canaries.get('alice storage state (JSON)') as string;
    expect(aliceJson.length).toBeGreaterThan(50);
    // AES-GCM keeps the length: the stored bytes are as long as the session but are not it.
    expect(stored.map((row) => (row.c as string).length / 2)).toContain(
      Buffer.byteLength(aliceJson),
    );

    /* a token hash from the dump, presented as a token at the socket, is refused */
    const hashLines = dump
      .split('\n')
      .filter((line) => /^[0-9a-f-]{36}\t/.test(line))
      .flatMap((line) => line.split('\t').filter((field) => /^[0-9a-f]{64}$/.test(field)));
    const knownHashes = new Set(capabilityRows.map((row) => row.token_hash as string | null));
    const hashFromDump = hashLines.find((hash) => knownHashes.has(hash));
    expect(hashFromDump, 'a token hash read out of the dump').toBeDefined();
    const jobForBait = (
      await jsonRows(
        `select j.id as job_id, j.connection_id from execution_jobs j order by j.created_at desc limit 1`,
      )
    )[0] as Loose;
    const before = await rejections();
    // As written in the dump (64 hex characters): not even the shape of a token.
    const asHex = await vaultCall('supervisor', 'readForWorker', {
      token: hashFromDump,
      jobId: jobForBait.job_id,
      connectionId: jobForBait.connection_id,
      operation: 'orders.list',
    });
    expect(asHex.ok).toBe(false);
    expect(['malformed', 'validation_failed']).toContain(asHex.error.code);
    expect(JSON.stringify(asHex)).not.toContain('plaintext');
    expect((await rejections()).length).toBe(before.length);
    // The same 32 bytes in the shape of a token (43 base64url characters): refused as unknown.
    const asToken = Buffer.from(hashFromDump as string, 'hex').toString('base64url');
    expect(asToken).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const usedBefore = await count(
      'select count(*) from vault_access_capabilities where used_at is not null',
    );
    const response = await vaultCall('supervisor', 'readForWorker', {
      token: asToken,
      jobId: jobForBait.job_id,
      connectionId: jobForBait.connection_id,
      operation: 'orders.list',
    });
    expect(isPlainForbidden(response)).toBe(true);
    const after = await rejections();
    expect(after.length - before.length).toBe(1);
    expect((after[after.length - 1] as Rejected).reason).toBe('unknown_token');
    expect(
      await count('select count(*) from vault_access_capabilities where used_at is not null'),
    ).toBe(usedBefore);
    // And through the completion path, which takes a plaintext.
    const login = await vaultCall('supervisor', 'completeLogin', {
      token: asToken,
      jobId: jobForBait.job_id,
      connectionId: jobForBait.connection_id,
      plaintext: Buffer.from('{"cookies":[],"origins":[]}').toString('base64url'),
      externalAccountHint: null,
      sessionExpiresAt: null,
    });
    expect(isPlainForbidden(login)).toBe(true);
    T.timings['dump bytes'] = dump.length;
    T.timings['dump lines'] = countLines(dump);
  });
});

/** The bytes of every `\x...` hex value in a plain pg_dump, as latin1 text, so raw bytes can be searched. */
function decodeByteaHex(dump: string): string {
  const parts: string[] = [];
  for (const match of dump.matchAll(/\\\\x([0-9a-f]+)/g)) {
    parts.push(Buffer.from(match[1] as string, 'hex').toString('latin1'));
    parts.push(Buffer.from(match[1] as string, 'hex').toString('utf8'));
  }
  return parts.join('\n');
}
