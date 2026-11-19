import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  VAULT_MAX_LINE_BYTES,
  VAULT_OPERATION_ROLES,
  VAULT_OPERATIONS,
  VAULT_ROLES,
  VaultResponse,
} from '@aab/contracts';
import type { VaultOperation, VaultRole } from '@aab/contracts';
import { VAULT_SERVICE_VERSION } from '../src/version.js';
import { call, exchange, openSocket, startTestVault, waitClosed } from './helpers.js';
import type { Harness } from './helpers.js';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

const UUID = '3f1c2b0e-8a54-4a52-9d57-0e1c2d3e4f50';
const TOKEN = 'B'.repeat(43);

/** A valid `params` object for every operation. */
const VALID_PARAMS: Record<VaultOperation, Record<string, unknown>> = {
  hello: { protocolVersion: 1 },
  authorizeJobAccess: { jobId: UUID, ttlSeconds: 600 },
  issueAccessCapability: {
    capabilityId: UUID,
    jobId: UUID,
    workerId: 'worker-1',
    attempt: 1,
    ttlSeconds: 30,
  },
  readForWorker: { token: TOKEN, jobId: UUID, connectionId: UUID, operation: 'orders.list' },
  completeLogin: {
    token: TOKEN,
    jobId: UUID,
    connectionId: UUID,
    plaintext: 'e30',
    externalAccountHint: null,
    sessionExpiresAt: null,
  },
  status: {},
  rewrap: { batchSize: 10, maxBatches: 1 },
  kekRetirementCheck: { kekVersion: 1 },
};

let harness: Harness;
beforeEach(async () => {
  harness = await startTestVault();
});
afterEach(async () => {
  await harness.cleanup();
});

const request = (role: VaultRole, body: Record<string, unknown>) =>
  call(harness.vault.sockets[role], body);

describe('hello', () => {
  it('returns version, isolation, the socket role, the key directory and the KEK version', async () => {
    for (const role of VAULT_ROLES) {
      const reply = await request(role, {
        id: 'h1',
        operation: 'hello',
        params: { protocolVersion: 1 },
      });
      expect(reply).toEqual({
        id: 'h1',
        ok: true,
        result: {
          protocolVersion: 1,
          serviceVersion: VAULT_SERVICE_VERSION,
          isolation: 'shared-uid',
          role,
          keyDirectory: harness.kekDir,
          currentKekVersion: 1,
        },
      });
      expect(VaultResponse.safeParse(reply).success).toBe(true);
    }
  });

  it('keeps the reported service version equal to package.json', async () => {
    const pkg = JSON.parse(
      await readFile(join(import.meta.dirname, '..', 'package.json'), 'utf8'),
    ) as { version: string };
    expect(VAULT_SERVICE_VERSION).toBe(pkg.version);
  });

  it('refuses another protocol version', async () => {
    const reply = await request('api', {
      id: 'h2',
      operation: 'hello',
      params: { protocolVersion: 2 },
    });
    expect(reply).toEqual({ id: 'h2', ok: false, error: { code: 'malformed' } });
  });
});

describe('role comes from the socket only (P3-2)', () => {
  it('refuses every operation not allowed for the socket role with forbidden, and audits it', async () => {
    const refused: Array<Record<string, unknown>> = [];
    await harness.cleanup();
    harness = await startTestVault({}, { onRequestRefused: (event) => refused.push({ ...event }) });
    let count = 0;
    for (const role of VAULT_ROLES) {
      for (const operation of VAULT_OPERATIONS) {
        if (VAULT_OPERATION_ROLES[operation].includes(role)) continue;
        count += 1;
        const reply = await request(role, {
          id: `r${count}`,
          operation,
          params: VALID_PARAMS[operation],
        });
        expect(reply, `${role} -> ${operation}`).toEqual({
          id: `r${count}`,
          ok: false,
          error: { code: 'forbidden' },
        });
      }
    }
    // api: 5 not allowed, supervisor: 4, admin: 4
    expect(count).toBe(13);
    expect(refused).toHaveLength(13);
    const logged = harness.log
      .records()
      .filter((record) => record['event'] === 'vault.request_refused');
    expect(logged).toHaveLength(13);
    expect(logged[0]).toMatchObject({
      level: 40,
      role: expect.any(String),
      operation: expect.any(String),
    });
  });

  it('refuses before validating parameters: a forbidden operation reveals nothing about its schema', async () => {
    const reply = await request('api', { id: 'a', operation: 'readForWorker', params: {} });
    expect(reply).toEqual({ id: 'a', ok: false, error: { code: 'forbidden' } });
  });

  it('answers an allowed operation with not_implemented in B2a, after role and schema checks', async () => {
    for (const role of VAULT_ROLES) {
      for (const operation of VAULT_OPERATIONS) {
        if (operation === 'hello' || !VAULT_OPERATION_ROLES[operation].includes(role)) continue;
        const reply = await request(role, {
          id: 'n',
          operation,
          params: VALID_PARAMS[operation],
        });
        expect(reply, `${role} -> ${operation}`).toEqual({
          id: 'n',
          ok: false,
          error: { code: 'not_implemented' },
        });
        // Bad parameters never reach the stub.
        const bad = await request(role, { id: 'b', operation, params: { nope: true } });
        expect(bad, `${role} -> ${operation} bad params`).toEqual({
          id: 'b',
          ok: false,
          error: { code: 'malformed' },
        });
      }
    }
  });

  it('treats a role field as malformed, at the top level and inside params, on every socket', async () => {
    for (const role of VAULT_ROLES) {
      for (const claimed of VAULT_ROLES) {
        const top = await request(role, {
          id: 't',
          operation: 'hello',
          params: { protocolVersion: 1 },
          role: claimed,
        });
        expect(top).toEqual({ id: 't', ok: false, error: { code: 'malformed' } });
        const inner = await request(role, {
          id: 'i',
          operation: 'hello',
          params: { protocolVersion: 1, role: claimed },
        });
        expect(inner).toEqual({ id: 'i', ok: false, error: { code: 'malformed' } });
      }
    }
    // A role field cannot be used to reach an operation the socket may not call.
    const smuggled = await request('supervisor', {
      id: 's',
      operation: 'authorizeJobAccess',
      params: { jobId: UUID, ttlSeconds: 600 },
      role: 'api',
    });
    expect(smuggled).toEqual({ id: 's', ok: false, error: { code: 'malformed' } });
    const plain = await request('supervisor', {
      id: 's2',
      operation: 'authorizeJobAccess',
      params: { jobId: UUID, ttlSeconds: 600 },
    });
    expect(plain).toEqual({ id: 's2', ok: false, error: { code: 'forbidden' } });
  });

  it('answers an unknown operation, including prototype names, with malformed', async () => {
    for (const operation of ['nope', 'toString', 'constructor', 'hasOwnProperty', 'HELLO', '']) {
      const reply = await request('admin', { id: 'u', operation, params: {} });
      expect(reply, operation).toEqual({ id: 'u', ok: false, error: { code: 'malformed' } });
    }
  });
});

describe('framing and input hardening', () => {
  const api = () => harness.vault.sockets.api;

  it('answers invalid JSON with malformed and keeps the connection usable', async () => {
    const socket = await openSocket(api());
    const lines: string[] = [];
    socket.on('data', (chunk) => lines.push(...chunk.toString().split('\n').filter(Boolean)));
    socket.write('{not json\n');
    socket.write(
      `${JSON.stringify({ id: 'ok', operation: 'hello', params: { protocolVersion: 1 } })}\n`,
    );
    await new Promise((resolve) => setTimeout(resolve, 200));
    socket.destroy();
    expect(JSON.parse(lines[0] ?? '{}')).toEqual({
      id: null,
      ok: false,
      error: { code: 'malformed' },
    });
    expect(JSON.parse(lines[1] ?? '{}')).toMatchObject({ id: 'ok', ok: true });
  });

  it('answers requests in order when several arrive in one write', async () => {
    const socket = await openSocket(api());
    const lines: string[] = [];
    socket.on('data', (chunk) => lines.push(...chunk.toString().split('\n').filter(Boolean)));
    const body = [1, 2, 3]
      .map((n) =>
        JSON.stringify({ id: `p${n}`, operation: 'hello', params: { protocolVersion: 1 } }),
      )
      .join('\n');
    socket.write(`${body}\n`);
    await new Promise((resolve) => setTimeout(resolve, 200));
    socket.destroy();
    expect(lines.map((line) => (JSON.parse(line) as { id: string }).id)).toEqual([
      'p1',
      'p2',
      'p3',
    ]);
  });

  it('refuses an empty line, arrays, scalars and null as malformed', async () => {
    for (const raw of ['\n', '[]\n', '5\n', '"hello"\n', 'null\n', 'true\n', '{}\n']) {
      const line = await exchange(api(), raw);
      expect(JSON.parse(line ?? '{}'), JSON.stringify(raw)).toEqual({
        id: null,
        ok: false,
        error: { code: 'malformed' },
      });
    }
  });

  it('refuses __proto__, constructor and prototype keys anywhere, even where zod would drop them', async () => {
    const poisoned = [
      '{"id":"p","operation":"hello","params":{"protocolVersion":1},"__proto__":{"role":"admin"}}',
      '{"id":"p","operation":"hello","params":{"protocolVersion":1,"__proto__":{"x":1}}}',
      '{"id":"p","operation":"hello","params":{"protocolVersion":1,"constructor":{"prototype":{}}}}',
      '{"id":"p","operation":"hello","params":{"protocolVersion":1,"prototype":1}}',
      '{"id":"p","operation":"status","params":{"a":{"b":{"__proto__":1}}}}',
    ];
    for (const raw of poisoned) {
      const line = await exchange(api(), `${raw}\n`);
      expect(JSON.parse(line ?? '{}'), raw).toEqual({
        id: 'p',
        ok: false,
        error: { code: 'malformed' },
      });
    }
    expect(({} as Record<string, unknown>)['role']).toBeUndefined();
  });

  it('refuses extra fields, a missing params, a bad id and wrong types', async () => {
    const bad: Array<Record<string, unknown>> = [
      { id: 'e', operation: 'hello', params: { protocolVersion: 1 }, extra: 1 },
      { id: 'e', operation: 'hello', params: { protocolVersion: 1, extra: 1 } },
      { id: 'e', operation: 'hello' },
      { id: 'e', operation: 'hello', params: null },
      { id: 'e', operation: 'hello', params: [] },
      { id: 'e', operation: 5, params: {} },
      { operation: 'hello', params: { protocolVersion: 1 } },
      { id: 'has space', operation: 'hello', params: { protocolVersion: 1 } },
      { id: 'x'.repeat(65), operation: 'hello', params: { protocolVersion: 1 } },
      { id: 5, operation: 'hello', params: { protocolVersion: 1 } },
    ];
    for (const body of bad) {
      const reply = await request('api', body);
      expect(reply['ok'], JSON.stringify(body)).toBe(false);
      expect(reply['error'], JSON.stringify(body)).toEqual({ code: 'malformed' });
      // The id is echoed only when it is a well-formed identifier.
      const id = body['id'];
      expect(reply['id']).toBe(
        typeof id === 'string' && /^[A-Za-z0-9._-]{1,64}$/.test(id) ? id : null,
      );
    }
  });

  it('never echoes request values in an error', async () => {
    const reply = await request('api', {
      id: 'e1',
      operation: 'authorizeJobAccess',
      params: { jobId: 'secret-looking-value', ttlSeconds: 'also-secret' },
    });
    expect(reply).toEqual({ id: 'e1', ok: false, error: { code: 'malformed' } });
    const text = JSON.stringify(reply);
    expect(text).not.toContain('secret-looking-value');
    expect(text).not.toContain('also-secret');
  });

  it('closes a connection that sends a line over the limit, after one malformed answer', async () => {
    const socket = await openSocket(api());
    const received: string[] = [];
    socket.on('data', (chunk) => received.push(chunk.toString()));
    socket.on('error', () => undefined);
    socket.write(`${'a'.repeat(VAULT_MAX_LINE_BYTES + 1)}\n`);
    expect(await waitClosed(socket)).toBe(true);
    expect(JSON.parse(received.join('').trim())).toEqual({
      id: null,
      ok: false,
      error: { code: 'malformed' },
    });
  });

  it('closes a connection that streams an unterminated line past the limit', async () => {
    const socket = await openSocket(api());
    socket.on('error', () => undefined);
    const chunk = 'a'.repeat(16 * 1024);
    for (let sent = 0; sent <= VAULT_MAX_LINE_BYTES + 16 * 1024; sent += chunk.length) {
      if (socket.destroyed) break;
      socket.write(chunk);
      await new Promise((resolve) => setImmediate(resolve));
    }
    expect(await waitClosed(socket)).toBe(true);
  });

  it('accepts a line exactly at the limit on the api socket as far as framing goes', async () => {
    // Over the schema (ids are 64 characters at most), so malformed, but not a framing refusal:
    // the connection stays open for the next request.
    const socket = await openSocket(api());
    const lines: string[] = [];
    socket.on('data', (chunk) => lines.push(...chunk.toString().split('\n').filter(Boolean)));
    const prefix = '{"id":"big","operation":"hello","params":{"protocolVersion":1},"pad":"';
    const padLength = VAULT_MAX_LINE_BYTES - prefix.length - 2;
    socket.write(`${prefix}${'x'.repeat(padLength)}"}\n`);
    socket.write(
      `${JSON.stringify({ id: 'next', operation: 'hello', params: { protocolVersion: 1 } })}\n`,
    );
    await new Promise((resolve) => setTimeout(resolve, 300));
    socket.destroy();
    expect(JSON.parse(lines[0] ?? '{}')).toEqual({
      id: 'big',
      ok: false,
      error: { code: 'malformed' },
    });
    expect(JSON.parse(lines[1] ?? '{}')).toMatchObject({ id: 'next', ok: true });
  });

  it('allows larger lines on the supervisor socket only', async () => {
    const big = `${JSON.stringify({ id: 'sup', operation: 'hello', params: { protocolVersion: 1 }, pad: 'x'.repeat(200 * 1024) })}\n`;
    const supervisor = await exchange(harness.vault.sockets.supervisor, big);
    expect(JSON.parse(supervisor ?? '{}')).toEqual({
      id: 'sup',
      ok: false,
      error: { code: 'malformed' },
    });
    // Same line on the api socket is a framing refusal: connection closed, id null.
    const api = await exchange(harness.vault.sockets.api, big);
    expect(JSON.parse(api ?? '{}')).toEqual({ id: null, ok: false, error: { code: 'malformed' } });
  });
});

describe('connection and time limits', () => {
  it('closes idle connections', async () => {
    await harness.cleanup();
    harness = await startTestVault({ idleTimeoutMs: 1_000 });
    const socket = await openSocket(harness.vault.sockets.api);
    socket.on('error', () => undefined);
    const started = Date.now();
    expect(await waitClosed(socket, 5_000)).toBe(true);
    expect(Date.now() - started).toBeGreaterThanOrEqual(900);
  });

  it('closes a connection that never finishes a line', async () => {
    await harness.cleanup();
    harness = await startTestVault({ requestTimeoutMs: 300, idleTimeoutMs: 60_000 });
    const socket = await openSocket(harness.vault.sockets.api);
    socket.on('error', () => undefined);
    const received: string[] = [];
    socket.on('data', (chunk) => received.push(chunk.toString()));
    // One byte every 100 ms keeps the connection from idling, never completes the line.
    const timer = setInterval(() => socket.write('{'), 100);
    expect(await waitClosed(socket, 5_000)).toBe(true);
    clearInterval(timer);
    expect(received.join('')).toContain('"malformed"');
  });

  // Changed in the B2 review fixes (fix 3): the old test pinned "answer service_unavailable at the
  // timer", which tells a client "failed" for work that may still commit. The database limits end
  // work first (statement and lock timeouts, see handler-timeouts.test.ts); the timer is a last
  // resort that closes the connection and claims no outcome.
  it('closes, without claiming an outcome, a request that outlives the request timeout', async () => {
    await harness.cleanup();
    harness = await startTestVault(
      { requestTimeoutMs: 200 },
      {
        handlers: {
          ...(await import('../src/handlers.js')).DEFAULT_HANDLERS,
          status: () => new Promise(() => undefined),
        },
      },
    );
    const socket = await openSocket(harness.vault.sockets.api);
    const lines: string[] = [];
    socket.on('data', (chunk) => lines.push(...chunk.toString().split('\n').filter(Boolean)));
    socket.on('error', () => undefined);
    socket.write(`${JSON.stringify({ id: 'slow', operation: 'status', params: {} })}\n`);
    expect(await waitClosed(socket, 2_000)).toBe(true);
    expect(lines).toEqual([]);
  });

  it('answers and closes connections over the per-role cap, and recovers when others close', async () => {
    await harness.cleanup();
    harness = await startTestVault({ maxConnectionsPerRole: 3 });
    const path = harness.vault.sockets.api;
    const held = await Promise.all([openSocket(path), openSocket(path), openSocket(path)]);
    for (const socket of held) socket.on('error', () => undefined);
    // Let the server register all three before the fourth arrives.
    await new Promise((resolve) => setTimeout(resolve, 100));
    const over: string[] = [];
    const extras = [];
    for (let i = 0; i < 5; i += 1) {
      const extra = await openSocket(path);
      extra.on('error', () => undefined);
      extra.on('data', (chunk) => over.push(chunk.toString()));
      extras.push(extra);
    }
    for (const extra of extras) expect(await waitClosed(extra)).toBe(true);
    expect(over).toHaveLength(5);
    for (const text of over) {
      expect(JSON.parse(text.trim())).toEqual({
        id: null,
        ok: false,
        error: { code: 'service_unavailable' },
      });
    }
    // Held connections still work, and the cap is per role: another role is unaffected.
    const first = held[0];
    expect(first).toBeDefined();
    const other = await call(harness.vault.sockets.supervisor, {
      id: 'o',
      operation: 'hello',
      params: { protocolVersion: 1 },
    });
    expect(other['ok']).toBe(true);
    for (const socket of held) socket.destroy();
    await new Promise((resolve) => setTimeout(resolve, 100));
    const again = await call(path, {
      id: 'again',
      operation: 'hello',
      params: { protocolVersion: 1 },
    });
    expect(again['ok']).toBe(true);
  });
});

describe('handler failures', () => {
  it('turns an unexpected throw into internal_error with no detail, and logs type only', async () => {
    await harness.cleanup();
    harness = await startTestVault(
      {},
      {
        handlers: {
          ...(await import('../src/handlers.js')).DEFAULT_HANDLERS,
          status: () => Promise.reject(new Error('password=hunter2 token=abc')),
        },
      },
    );
    const reply = await call(harness.vault.sockets.api, {
      id: 'f',
      operation: 'status',
      params: {},
    });
    expect(reply).toEqual({ id: 'f', ok: false, error: { code: 'internal_error' } });
    const text = harness.log.text();
    expect(text).toContain('vault request failed');
    expect(text).not.toContain('hunter2');
    expect(text).not.toContain('token=abc');
  });

  it('refuses a handler result that does not match its schema', async () => {
    await harness.cleanup();
    harness = await startTestVault(
      {},
      {
        handlers: {
          ...(await import('../src/handlers.js')).DEFAULT_HANDLERS,
          status: () => Promise.resolve({ leaked: 'plaintext' } as never),
        },
      },
    );
    const reply = await call(harness.vault.sockets.api, {
      id: 'f',
      operation: 'status',
      params: {},
    });
    expect(reply).toEqual({ id: 'f', ok: false, error: { code: 'internal_error' } });
  });
});
