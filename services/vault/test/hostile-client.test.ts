import { connect } from 'node:net';
import type { Socket } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  VAULT_MAX_LINE_BYTES,
  VAULT_MAX_SUPERVISOR_LINE_BYTES,
  VAULT_OPERATION_ROLES,
  VAULT_OPERATIONS,
  VAULT_ROLES,
} from '@aab/contracts';
import type { VaultOperation, VaultRole } from '@aab/contracts';
import { hashToken } from '@aab/crypto';
import {
  auditEvents,
  b64url,
  CANARY,
  capabilityRowOf,
  dumpAllTables,
  ok,
  prepare,
  readParams,
  seedSealedOperation,
  seedTenant,
  sleep,
  startService,
} from './service-helpers.js';
import type { Prepared, SealedOperation, Service, Tenant } from './service-helpers.js';

/*
 * B6a: a hostile client per role. Each one talks to its own socket of the real vault (real
 * operations, PGlite) and tries what ADR-014 section 1, 2 and 4 say must fail: operations of the
 * other roles, role-selecting and unknown fields, oversized lines, non-plain JSON, many and slow
 * connections, and a request after a protocol error on the same connection. Every refusal must
 * leave the database as it was, carry no secret data, and leave the other sockets serving.
 * The resource tests are bounded (caps of 6, timeouts of 0.6 s, a few seconds each).
 */

interface Reply {
  lines: string[];
  closed: boolean;
}

/** Every line a hostile connection received, for the leak scan. */
const hostileLines: string[] = [];

/**
 * Sends raw bytes and collects the response lines. It stops `settleMs` after the last line that
 * arrived, when the peer closes, or after `waitMs` at the latest.
 */
function converse(
  path: string,
  bytes: string | Buffer,
  options: { waitMs?: number; settleMs?: number; endAfterWrite?: boolean } = {},
): Promise<Reply> {
  const waitMs = options.waitMs ?? 1500;
  const settleMs = options.settleMs ?? 150;
  return new Promise((resolve, reject) => {
    const socket = connect(path);
    let data = '';
    let closed = false;
    let done = false;
    let settle: NodeJS.Timeout | undefined;
    const finish = () => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      clearTimeout(settle);
      socket.destroy();
      const lines = data.split('\n').filter((line) => line !== '');
      hostileLines.push(...lines);
      resolve({ lines, closed });
    };
    const timer = setTimeout(finish, waitMs);
    socket.on('connect', () => {
      socket.write(bytes);
      if (options.endAfterWrite === true) socket.end();
    });
    socket.on('data', (chunk) => {
      data += chunk.toString('utf8');
      if (data.includes('\n')) {
        clearTimeout(settle);
        settle = setTimeout(finish, settleMs);
      }
    });
    socket.on('close', () => {
      closed = true;
      finish();
    });
    socket.on('error', (error) => {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === 'EPIPE' || code === 'ECONNRESET') return;
      clearTimeout(timer);
      reject(error);
    });
  });
}

/**
 * A slow sender: one byte of a request every `intervalMs`, so the connection is never idle, for at
 * most `maxMs`. The vault must end it by the line timeout, not wait for the line to finish.
 */
function drip(
  path: string,
  intervalMs: number,
  maxMs: number,
): Promise<Reply & { sentBytes: number }> {
  return new Promise((resolve, reject) => {
    const socket = connect(path);
    const text = '{"id":"drip","operation":"hello","params":{"protocolVersion":1}}';
    let data = '';
    let closed = false;
    let sent = 0;
    let done = false;
    const timers: NodeJS.Timeout[] = [];
    const finish = () => {
      if (done) return;
      done = true;
      for (const timer of timers) clearTimeout(timer);
      clearInterval(ticker);
      socket.destroy();
      const lines = data.split('\n').filter((line) => line !== '');
      hostileLines.push(...lines);
      resolve({ lines, closed, sentBytes: sent });
    };
    const ticker = setInterval(() => {
      // Never the last byte or a newline: the request is never complete.
      if (sent < text.length - 1 && !socket.destroyed) socket.write(text[sent++]!);
    }, intervalMs);
    timers.push(setTimeout(finish, maxMs));
    socket.on('data', (chunk) => {
      data += chunk.toString('utf8');
    });
    socket.on('close', () => {
      closed = true;
      finish();
    });
    socket.on('error', (error) => {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === 'EPIPE' || code === 'ECONNRESET') return;
      reject(error);
    });
  });
}

const json = (line: string | undefined): Record<string, unknown> =>
  JSON.parse(line ?? 'null') as Record<string, unknown>;
const request = (body: Record<string, unknown>): string => `${JSON.stringify(body)}\n`;
const MALFORMED = { ok: false, error: { code: 'malformed' } };
const FORBIDDEN = { ok: false, error: { code: 'forbidden' } };

let service: Service;
let tenant: Tenant;
beforeAll(async () => {
  service = await startService();
  tenant = await seedTenant(service.repos, 'hostile');
});
afterAll(async () => {
  await service.cleanup();
});

/** A job with an authorization and a live, unused token: the bait every hostile client wants. */
async function bait(): Promise<{ op: SealedOperation; prepared: Prepared }> {
  const op = await seedSealedOperation(service, tenant);
  return { op, prepared: await prepare(service, op) };
}

/** Valid, real parameters for every operation, for the bait. */
function paramsFor(
  operation: VaultOperation,
  b: { op: SealedOperation; prepared: Prepared },
): Record<string, unknown> {
  switch (operation) {
    case 'hello':
      return { protocolVersion: 1 };
    case 'authorizeJobAccess':
      return { jobId: b.op.jobId, ttlSeconds: 600 };
    case 'issueAccessCapability':
      return {
        capabilityId: b.prepared.capabilityId,
        jobId: b.op.jobId,
        workerId: b.prepared.workerId,
        attempt: 1,
        ttlSeconds: 30,
      };
    case 'readForWorker':
      return readParams(b.prepared);
    case 'completeLogin':
      return {
        token: b.prepared.token,
        jobId: b.op.jobId,
        connectionId: b.op.connectionId,
        plaintext: b64url('{"cookies":[],"origins":[]}'),
        externalAccountHint: null,
        sessionExpiresAt: null,
      };
    case 'status':
      return {};
    case 'rewrap':
      return { batchSize: 1, maxBatches: 1 };
    case 'kekRetirementCheck':
      return { kekVersion: 1 };
  }
}

/** Every table except the audit log, as text: what a refused request must not change. */
async function stateDump(): Promise<string> {
  const dump = await dumpAllTables(service);
  return JSON.stringify(
    [...dump.entries()]
      .filter(([table]) => table !== 'audit_events')
      .sort(([a], [b]) => a.localeCompare(b)),
  );
}

async function refusedEvents(): Promise<number> {
  return (await auditEvents(service, tenant.organization.id, 'vault.request_refused')).length;
}

function assertNoSecretData(b: { op: SealedOperation; prepared: Prepared }): void {
  const all = hostileLines.join('\n');
  expect(all).not.toContain(CANARY);
  expect(all).not.toContain(Buffer.from(b.op.plaintext).toString('base64url'));
  expect(all).not.toContain(b.prepared.token);
  expect(all).not.toContain(hashToken(b.prepared.token));
}

/** The vault still answers on every socket (hello needs no database) and in the same role again. */
async function expectServingEverySocket(): Promise<void> {
  for (const role of VAULT_ROLES) {
    const reply = await converse(
      service.vault.sockets[role],
      request({ id: `alive-${role}`, operation: 'hello', params: { protocolVersion: 1 } }),
      { waitMs: 3000 },
    );
    expect(json(reply.lines[0])).toMatchObject({ id: `alive-${role}`, ok: true, result: { role } });
  }
}

const ALLOWED_REAL: Record<VaultRole, VaultOperation> = {
  api: 'status',
  supervisor: 'readForWorker',
  admin: 'status',
};

describe.each(VAULT_ROLES)('hostile client on the %s socket', (role) => {
  const path = () => service.vault.sockets[role];
  const forbiddenOperations = VAULT_OPERATIONS.filter(
    (operation) => !VAULT_OPERATION_ROLES[operation].includes(role),
  );

  it('every operation not allowed for the role is forbidden, audited where it names a job, counted where it does not, and changes nothing', async () => {
    const b = await bait();
    const before = await stateDump();
    const refusedBefore = await refusedEvents();
    const counters = ok(await service.rpc('admin', 'status', {}))['counters'] as Record<
      string,
      number
    >;
    let withJob = 0;
    for (const operation of forbiddenOperations) {
      const params = paramsFor(operation, b);
      if (typeof params['jobId'] === 'string') withJob += 1;
      const reply = await converse(path(), request({ id: `f-${operation}`, operation, params }));
      expect(reply.lines, operation).toHaveLength(1);
      expect(json(reply.lines[0]), `${role} -> ${operation}`).toEqual({
        id: `f-${operation}`,
        ...FORBIDDEN,
      });
    }
    expect(forbiddenOperations.length).toBeGreaterThan(0);
    // Role, operation, request id and job only: a refusal that names a job is on its chain, the
    // rest are counted (ADR-014 section 10: a known gap, not a silent one).
    expect(await refusedEvents()).toBe(refusedBefore + withJob);
    const after = ok(await service.rpc('admin', 'status', {}))['counters'] as Record<
      string,
      number
    >;
    expect(after['refusedUnattributed']).toBe(
      counters['refusedUnattributed']! + (forbiddenOperations.length - withJob),
    );
    for (const event of (
      await auditEvents(service, tenant.organization.id, 'vault.request_refused')
    ).slice(refusedBefore)) {
      expect(event['metadata']).toMatchObject({ role });
    }
    expect(await stateDump()).toBe(before);
    assertNoSecretData(b);
    // The bait token was in those requests and is still unused.
    expect((await capabilityRowOf(service, b.prepared.capabilityId))['used_at']).toBeNull();
    await expectServingEverySocket();
  });

  it('role-selecting and unknown fields, at the top level and in params, are malformed on every operation, before the role check', async () => {
    const b = await bait();
    const before = await stateDump();
    const refusedBefore = await refusedEvents();
    const operations: VaultOperation[] = ['hello', ALLOWED_REAL[role], forbiddenOperations[0]!];
    const extras: Array<[string, unknown]> = [
      ['role', 'admin'],
      ['role', 'api'],
      ['role', 'supervisor'],
      ['role', 5],
      ['roles', ['admin']],
      ['as', 'admin'],
      ['caller', 'api'],
      ['uid', 0],
      ['socket', 'admin'],
      ['extra', 1],
    ];
    let sent = 0;
    for (const operation of operations) {
      for (const [field, value] of extras) {
        // A forbidden operation is refused for its role before its params are looked at (the next
        // test), so a field in its params is only malformed for the operations the role may call.
        const places = (
          VAULT_OPERATION_ROLES[operation].includes(role) ? ['top', 'params'] : ['top']
        ) as Array<'top' | 'params'>;
        for (const place of places) {
          const params = paramsFor(operation, b);
          const body: Record<string, unknown> = { id: `x${sent}`, operation, params };
          if (place === 'top') body[field] = value;
          else (body['params'] as Record<string, unknown>)[field] = value;
          const reply = await converse(path(), request(body));
          sent += 1;
          expect(reply.lines, JSON.stringify([operation, field, place])).toHaveLength(1);
          expect(json(reply.lines[0])).toEqual({ id: body['id'], ...MALFORMED });
        }
      }
    }
    expect(sent).toBe(extras.length * (2 * 2 + 1));
    // Malformed is decided before the role: a smuggled field earns no `vault.request_refused`.
    expect(await refusedEvents()).toBe(refusedBefore);
    expect(await stateDump()).toBe(before);
    assertNoSecretData(b);
    expect((await capabilityRowOf(service, b.prepared.capabilityId))['used_at']).toBeNull();
  });

  it('a forbidden operation with unknown fields in params is forbidden, not malformed: the role is checked before the schema', async () => {
    const operation = forbiddenOperations[0]!;
    const reply = await converse(
      path(),
      request({ id: 'late', operation, params: { surprise: { nested: [1, 2, 3] } } }),
    );
    expect(json(reply.lines[0])).toEqual({ id: 'late', ...FORBIDDEN });
  });

  it('non-plain, poisoned and malformed JSON is answered malformed (or closes the connection), never with data', async () => {
    const b = await bait();
    const before = await stateDump();
    const goodParams = paramsFor(ALLOWED_REAL[role], b);
    const base = { id: 'p', operation: ALLOWED_REAL[role], params: goodParams };
    const text = JSON.stringify(base);
    const deepArray = `${'['.repeat(5000)}${']'.repeat(5000)}`;
    const deepObject = `${'{"a":'.repeat(2000)}1${'}'.repeat(2000)}`;
    const lines: Array<[string, string | Buffer]> = [
      [
        '__proto__ at the top',
        `{"id":"p","operation":"hello","params":{"protocolVersion":1},"__proto__":{"role":"admin"}}\n`,
      ],
      [
        '__proto__ in params',
        `{"id":"p","operation":"hello","params":{"protocolVersion":1,"__proto__":{"role":"admin"}}}\n`,
      ],
      [
        'constructor in params',
        `{"id":"p","operation":"hello","params":{"protocolVersion":1,"constructor":{"prototype":{"role":"admin"}}}}\n`,
      ],
      [
        'prototype in params',
        `{"id":"p","operation":"hello","params":{"protocolVersion":1,"prototype":{}}}\n`,
      ],
      [
        '__proto__ deep inside a valid request',
        `${text.slice(0, -1)},"deep":{"a":{"b":{"__proto__":1}}}}\n`,
      ],
      ['deeply nested arrays', `${deepArray}\n`],
      ['deeply nested objects', `${deepObject}\n`],
      [
        'deep nesting inside params',
        `{"id":"p","operation":"hello","params":{"protocolVersion":1,"x":${deepArray}}}\n`,
      ],
      ['truncated JSON', `${text.slice(0, text.length - 5)}\n`],
      ['trailing garbage', `${text} trailing\n`],
      ['a byte order mark', `${String.fromCharCode(0xfeff)}${text}\n`],
      ['a NUL byte', `{"id":"p"\u0000,"operation":"hello"}\n`],
      [
        'invalid UTF-8',
        Buffer.concat([
          Buffer.from('{"id":"p","operation":"'),
          Buffer.from([0xff, 0xfe, 0xc3]),
          Buffer.from('"}\n'),
        ]),
      ],
      [
        'a lone surrogate in the id',
        `{"id":"p\\ud800","operation":"hello","params":{"protocolVersion":1}}\n`,
      ],
      ['a number as the whole request', '1e999\n'],
      ['an array of requests (a batch)', `[${text},${text}]\n`],
      ['a string holding a request', `${JSON.stringify(text)}\n`],
      ['a null params', `{"id":"p","operation":"hello","params":null}\n`],
      ['a prototype-named operation', `{"id":"p","operation":"__proto__","params":{}}\n`],
    ];
    for (const [name, bytes] of lines) {
      const reply = await converse(path(), bytes);
      expect(reply.lines.length, name).toBeLessThanOrEqual(1);
      if (reply.lines.length === 1) {
        const answer = json(reply.lines[0]);
        expect(answer, name).toMatchObject(MALFORMED);
        expect(Object.keys(answer).sort(), name).toEqual(['error', 'id', 'ok']);
      } else {
        // No answer is allowed only when the connection was closed.
        expect(reply.closed, name).toBe(true);
      }
    }
    expect(await stateDump()).toBe(before);
    assertNoSecretData(b);
    expect(Object.prototype.hasOwnProperty.call(Object.prototype, 'role')).toBe(false);
    expect(({} as Record<string, unknown>)['role']).toBeUndefined();
    expect((await capabilityRowOf(service, b.prepared.capabilityId))['used_at']).toBeNull();
    await expectServingEverySocket();
  });

  it('an oversized line is answered malformed once, the connection is closed, and the vault keeps serving', async () => {
    const limit = role === 'supervisor' ? VAULT_MAX_SUPERVISOR_LINE_BYTES : VAULT_MAX_LINE_BYTES;
    const b = await bait();
    const before = await stateDump();
    // The oversized line, then a valid request for the bait in the same write: never processed.
    const follow = request({
      id: 'after',
      operation: ALLOWED_REAL[role],
      params: paramsFor(ALLOWED_REAL[role], b),
    });
    const reply = await converse(path(), `${'a'.repeat(limit + 1)}\n${follow}`, { waitMs: 5000 });
    expect(reply.lines).toHaveLength(1);
    expect(json(reply.lines[0])).toEqual({ id: null, ...MALFORMED });
    expect(reply.closed).toBe(true);
    // The same line without its newline, streamed past the limit: closed too.
    const streamed = await converse(path(), 'b'.repeat(limit + 1), { waitMs: 5000 });
    expect(streamed.closed).toBe(true);
    expect(streamed.lines.length).toBeLessThanOrEqual(1);
    expect(await stateDump()).toBe(before);
    assertNoSecretData(b);
    expect((await capabilityRowOf(service, b.prepared.capabilityId))['used_at']).toBeNull();
    await expectServingEverySocket();
  }, 60_000);

  it('a request after a protocol error: a malformed line keeps the connection, a framing error ends it and what is queued behind it is never run', async () => {
    const b = await bait();
    const before = await stateDump();
    const hello = request({ id: 'h', operation: 'hello', params: { protocolVersion: 1 } });
    const real = request({
      id: 'r',
      operation: ALLOWED_REAL[role],
      params: paramsFor(ALLOWED_REAL[role], b),
    });

    // 1. Ordinary refusals are soft: the next request on the same connection is answered.
    const soft = await converse(
      path(),
      `{not json\n${request({ id: 'm', operation: 'nope', params: {} })}${request({
        id: 'f',
        operation: forbiddenOperations[0]!,
        params: paramsFor(forbiddenOperations[0]!, b),
      })}${hello}`,
      { settleMs: 800 },
    );
    expect(soft.lines.map((line) => json(line)['id'])).toEqual([null, 'm', 'f', 'h']);
    expect(json(soft.lines[2])).toMatchObject(FORBIDDEN);
    expect(json(soft.lines[3])).toMatchObject({ ok: true });

    // 2. An empty line is a framing error: one malformed answer, then the connection is closed
    //    and the valid requests behind it (hello and the real one) are not answered or run.
    const empty = await converse(path(), `\n${hello}${real}`);
    expect(empty.lines).toHaveLength(1);
    expect(json(empty.lines[0])).toEqual({ id: null, ...MALFORMED });
    expect(empty.closed).toBe(true);

    // 3. Valid requests first, then a framing error in the same write: the earlier ones are
    //    answered, the ones after the error are not.
    const mixed = await converse(path(), `${hello}\n${hello}${real}`);
    expect(mixed.lines.map((line) => json(line)['id'])).toEqual(['h', null]);
    expect(json(mixed.lines[1])).toMatchObject(MALFORMED);

    expect(await stateDump()).toBe(before);
    assertNoSecretData(b);
    expect((await capabilityRowOf(service, b.prepared.capabilityId))['used_at']).toBeNull();
    await expectServingEverySocket();
  });

  it('after all of that the role still works for its own operations', async () => {
    if (role === 'supervisor') {
      const b = await bait();
      const read = ok(await service.rpc('supervisor', 'readForWorker', readParams(b.prepared)));
      expect(Buffer.from(read['plaintext'] as string, 'base64url').toString('utf8')).toBe(
        b.op.plaintext,
      );
    } else {
      expect(ok(await service.rpc(role, 'status', {}))).toHaveProperty('kekVersions');
    }
  });
});

describe('many, slow and half-open connections (bounded, tight limits)', () => {
  let tight: Service;
  const CAP = 6;
  beforeAll(async () => {
    const limits = Object.fromEntries(
      VAULT_ROLES.map((role) => [
        role,
        { maxConnections: CAP, idleTimeoutMs: 600, requestTimeoutMs: 600, closeGraceMs: 300 },
      ]),
    ) as Record<
      VaultRole,
      {
        maxConnections: number;
        idleTimeoutMs: number;
        requestTimeoutMs: number;
        closeGraceMs: number;
      }
    >;
    tight = await startService({ limits });
  });
  afterAll(async () => {
    await tight.cleanup();
  });

  const helloLine = request({ id: 'h', operation: 'hello', params: { protocolVersion: 1 } });

  const open = (path: string): Promise<Socket> =>
    new Promise((resolve, reject) => {
      const socket = connect(path);
      socket.once('connect', () => resolve(socket));
      socket.once('error', reject);
    });

  const alive = async (role: VaultRole) => {
    const reply = await converse(tight.vault.sockets[role], helloLine, { waitMs: 3000 });
    return json(reply.lines[0]);
  };

  it.each(VAULT_ROLES)(
    'a flood of connections on the %s socket is capped, answered service_unavailable and closed, and the other sockets keep serving',
    async (role) => {
      const held: Socket[] = [];
      try {
        for (let i = 0; i < CAP; i += 1) held.push(await open(tight.vault.sockets[role]));
        // The cap is reached: every further connection gets one answer and is closed.
        for (let i = 0; i < 4; i += 1) {
          const reply = await converse(tight.vault.sockets[role], '', { waitMs: 3000 });
          expect(reply.lines).toHaveLength(1);
          expect(json(reply.lines[0])).toEqual({
            id: null,
            ...{ ok: false, error: { code: 'service_unavailable' } },
          });
          expect(reply.closed).toBe(true);
        }
        // Another role is untouched by this role's flood, and its real operations still work.
        for (const other of VAULT_ROLES.filter((candidate) => candidate !== role)) {
          expect(await alive(other)).toMatchObject({ ok: true, result: { role: other } });
        }
        expect(ok(await tight.rpc(role === 'api' ? 'admin' : 'api', 'status', {}))).toHaveProperty(
          'kekVersions',
        );
      } finally {
        for (const socket of held) socket.destroy();
      }
      // Recovery: once the hostile connections are gone, the role answers again.
      const until = Date.now() + 5000;
      let answer = await alive(role);
      while (answer['ok'] !== true && Date.now() < until) {
        await sleep(100);
        answer = await alive(role);
      }
      expect(answer).toMatchObject({ ok: true, result: { role } });
      // No descriptor is left behind by the flood.
      const settle = Date.now() + 5000;
      while (tight.vault.servers[role].connections.size > 0 && Date.now() < settle) await sleep(50);
      expect(tight.vault.servers[role].connections.size).toBe(0);
      expect(tight.vault.servers[role].refusedConnections.size).toBe(0);
    },
    30_000,
  );

  it.each(VAULT_ROLES)(
    'idle, slow and half-open clients on the %s socket are closed by the vault, process nothing, and do not block the other connections',
    async (role) => {
      const path = tight.vault.sockets[role];
      const dumpBefore = JSON.stringify([...(await dumpAllTables(tight)).entries()]);

      // Idle: connects and says nothing.
      const idle = converse(path, '', { waitMs: 4000 });
      // Slowloris: one byte every 150 ms, never idle. The line must complete within the request timeout.
      const slow = drip(path, 150, 4000);
      // Half-open: half a request, then the client closes its sending side and keeps listening.
      const half = converse(
        path,
        '{"id":"half","operation":"hello","params":{"protocolVersion":1}',
        {
          waitMs: 4000,
          endAfterWrite: true,
        },
      );
      // While those are open, a well-behaved client on the same socket is answered promptly.
      expect(await alive(role)).toMatchObject({ ok: true, result: { role } });
      const [idleReply, slowReply, halfReply] = await Promise.all([idle, slow, half]);
      expect(idleReply.closed).toBe(true);
      expect(idleReply.lines).toEqual([]);
      expect(slowReply.closed).toBe(true);
      // Ended by the line timeout (0.6 s), long before the 62 bytes could have been dripped (9 s).
      expect(slowReply.sentBytes).toBeLessThan(15);
      // Nothing that was half sent was answered as if it were a whole request.
      for (const reply of [slowReply, halfReply]) {
        expect(reply.closed).toBe(true);
        for (const line of reply.lines) expect(json(line)).toMatchObject(MALFORMED);
      }
      expect(JSON.stringify([...(await dumpAllTables(tight)).entries()])).toBe(dumpBefore);
      const settle = Date.now() + 5000;
      while (tight.vault.servers[role].connections.size > 0 && Date.now() < settle) await sleep(50);
      expect(tight.vault.servers[role].connections.size).toBe(0);
      for (const other of VAULT_ROLES) expect(await alive(other)).toMatchObject({ ok: true });
    },
    30_000,
  );
});
