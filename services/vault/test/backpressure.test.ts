import { connect } from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
import { VAULT_ROLES } from '@aab/contracts';
import { DEFAULT_HANDLERS } from '../src/handlers.js';
import { defaultLimits, DEFAULT_CONCURRENT_HANDLERS } from '../src/server.js';
import { call, openSocket, startTestVault, waitClosed } from './helpers.js';
import type { Harness } from './helpers.js';

/*
 * A client that sends and never reads must not make the vault buffer without bound (B2 review
 * fix 1), a connection over the cap must not hold a descriptor forever (fix 2), a long line must
 * not cost quadratic work (fix 7), and handler concurrency is capped per role (fix 3).
 */

let harness: Harness | undefined;
afterEach(async () => {
  await harness?.cleanup();
  harness = undefined;
});

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));
const HELLO = `${JSON.stringify({ id: 'h', operation: 'hello', params: { protocolVersion: 1 } })}\n`;

const serverWritable = (h: Harness, role: 'api' | 'supervisor' | 'admin' = 'api') => {
  let total = 0;
  for (const socket of h.vault.servers[role].connections) total += socket.writableLength;
  return total;
};
const openServerConnections = (h: Harness, role: 'api' | 'supervisor' | 'admin' = 'api') =>
  new Promise<number>((resolve, reject) =>
    h.vault.servers[role].server.getConnections((error, count) =>
      error ? reject(error) : resolve(count),
    ),
  );

async function waitFor(condition: () => boolean | Promise<boolean>, ms: number): Promise<boolean> {
  const until = Date.now() + ms;
  while (Date.now() < until) {
    if (await condition()) return true;
    await sleep(25);
  }
  return condition();
}

describe('amplification: a client that sends and never reads (fix 1)', () => {
  it('closes a connection that sends empty lines instead of answering each one', async () => {
    harness = await startTestVault();
    const socket = await openSocket(harness.vault.sockets.api);
    socket.on('error', () => undefined);
    socket.pause(); // never read a response
    const chunk = Buffer.alloc(256 * 1024, 0x0a);
    let peak = 0;
    for (let i = 0; i < 16 && !socket.destroyed; i += 1) {
      socket.write(chunk);
      await sleep(20);
      peak = Math.max(peak, serverWritable(harness));
    }
    // The server answers the first empty line as malformed and closes: nothing piles up.
    expect(await waitFor(() => harness!.vault.servers.api.connections.size === 0, 2_000)).toBe(
      true,
    );
    expect(peak).toBeLessThan(64 * 1024);
    expect(await openServerConnections(harness)).toBe(0);
    socket.destroy();
    // The other roles are unaffected, during and after.
    for (const role of ['supervisor', 'admin'] as const) {
      expect(
        await call(harness.vault.sockets[role], {
          id: 'x',
          operation: 'hello',
          params: { protocolVersion: 1 },
        }),
      ).toMatchObject({ ok: true });
    }
  });

  it('pauses reading while the peer does not drain, keeps the buffer bounded, then closes the connection', async () => {
    harness = await startTestVault(
      {},
      {
        limits: {
          api: {
            writeBufferSoftBytes: 32 * 1024,
            writeBufferHardBytes: 128 * 1024,
            writeGraceMs: 400,
            writeStallMs: 800,
            maxInFlightPerConnection: 10_000,
          },
        },
      },
    );
    const socket = await openSocket(harness.vault.sockets.api);
    socket.on('error', () => undefined);
    socket.pause();
    let peak = 0;
    const sampler = setInterval(() => {
      peak = Math.max(peak, serverWritable(harness!));
    }, 2);
    let otherRoleAnswers = 0;
    for (let i = 0; i < 20_000 && !socket.destroyed; i += 1) {
      socket.write(HELLO);
      if (i % 20 === 0) await new Promise((resolve) => setImmediate(resolve));
      if (i % 2_000 === 0) {
        const reply = await call(harness.vault.sockets.supervisor, {
          id: 'o',
          operation: 'hello',
          params: { protocolVersion: 1 },
        });
        if (reply['ok'] === true) otherRoleAnswers += 1;
      }
    }
    // The stalled connection is destroyed by the server, not left to grow.
    expect(await waitFor(() => harness!.vault.servers.api.connections.size === 0, 5_000)).toBe(
      true,
    );
    clearInterval(sampler);
    // One response is ~230 bytes; the buffer never gets near what 20,000 of them would be (4.6 MB).
    expect(peak).toBeLessThan(256 * 1024);
    expect(otherRoleAnswers).toBeGreaterThan(0);
    socket.destroy();
    for (const role of VAULT_ROLES) {
      expect(
        await call(harness.vault.sockets[role], {
          id: 'after',
          operation: 'hello',
          params: { protocolVersion: 1 },
        }),
      ).toMatchObject({ ok: true });
    }
  });

  it('answers once and closes when more requests are in flight on a connection than allowed', async () => {
    harness = await startTestVault();
    const socket = await openSocket(harness.vault.sockets.api);
    const lines: string[] = [];
    socket.on('data', (chunk) => lines.push(...chunk.toString().split('\n').filter(Boolean)));
    socket.on('error', () => undefined);
    socket.write(HELLO.repeat(10));
    expect(await waitClosed(socket, 3_000)).toBe(true);
    const replies = lines.map((line) => JSON.parse(line) as Record<string, unknown>);
    expect(replies.filter((reply) => reply['ok'] === true)).toHaveLength(4);
    expect(replies.filter((reply) => reply['ok'] === false)).toEqual([
      { id: null, ok: false, error: { code: 'service_unavailable' } },
    ]);
  });

  it('keeps the earlier requests of a chunk and closes at the empty line', async () => {
    harness = await startTestVault();
    const socket = await openSocket(harness.vault.sockets.api);
    const lines: string[] = [];
    socket.on('data', (chunk) => lines.push(...chunk.toString().split('\n').filter(Boolean)));
    socket.on('error', () => undefined);
    socket.write(`${HELLO}\n${HELLO}`);
    expect(await waitClosed(socket, 3_000)).toBe(true);
    const replies = lines.map((line) => JSON.parse(line) as Record<string, unknown>);
    expect(replies).toHaveLength(2);
    expect(replies[0]).toMatchObject({ id: 'h', ok: true });
    expect(replies[1]).toEqual({ id: null, ok: false, error: { code: 'malformed' } });
  });
});

describe('connections over the cap do not leak descriptors (fix 2)', () => {
  it('destroys over-cap connections whose clients never close', async () => {
    harness = await startTestVault(
      {},
      { limits: { api: { maxConnections: 1, idleTimeoutMs: 60_000, closeGraceMs: 500 } } },
    );
    const keep = await openSocket(harness.vault.sockets.api);
    await sleep(50);
    const extra = [];
    const answers: string[] = [];
    for (let i = 0; i < 20; i += 1) {
      const socket = connect({ path: harness.vault.sockets.api, allowHalfOpen: true });
      socket.on('error', () => undefined);
      socket.on('data', (chunk) => answers.push(chunk.toString()));
      extra.push(socket);
    }
    try {
      // Every refused caller got its answer ...
      expect(await waitFor(() => answers.length >= 20, 2_000)).toBe(true);
      expect(answers.every((text) => text.includes('service_unavailable'))).toBe(true);
      // ... and the server closed them although the clients never did.
      expect(await waitFor(async () => (await openServerConnections(harness!)) === 1, 3_000)).toBe(
        true,
      );
      expect(harness.vault.servers.api.refusedConnections.size).toBe(0);
      // The accepted connection is untouched.
      keep.write(HELLO);
      await sleep(100);
      expect(keep.destroyed).toBe(false);
    } finally {
      for (const socket of extra) socket.destroy();
      keep.destroy();
    }
  });
});

describe('framing is linear (fix 7)', () => {
  it('completes a multi-megabyte line sent in small chunks within a time bound', async () => {
    harness = await startTestVault();
    const socket = await openSocket(harness.vault.sockets.supervisor);
    socket.on('error', () => undefined);
    const received: string[] = [];
    socket.on('data', (chunk) => received.push(chunk.toString()));
    const prefix = '{"id":"slow","operation":"hello","params":{"protocolVersion":1},"pad":"';
    const body = `${prefix}${'x'.repeat(3_800_000)}"}\n`;
    const started = Date.now();
    const size = 256;
    for (let offset = 0; offset < body.length; offset += size) {
      socket.write(body.slice(offset, offset + size));
      await new Promise((resolve) => setImmediate(resolve));
    }
    expect(await waitFor(() => received.join('').includes('\n'), 30_000)).toBe(true);
    const elapsed = Date.now() - started;
    socket.destroy();
    expect(JSON.parse(received.join('').split('\n')[0]!)).toMatchObject({ id: 'slow', ok: false });
    // ~15,000 chunks of 256 bytes: linear work takes about half a second; re-joining and
    // rescanning the whole line per chunk took ten seconds on the same machine.
    expect(elapsed).toBeLessThan(4_000);
  });
});

describe('handlers run at most N at a time per role (fix 3)', () => {
  it('has the default caps and the longer admin request timeout', () => {
    expect(DEFAULT_CONCURRENT_HANDLERS).toEqual({ api: 4, supervisor: 8, admin: 1 });
    const config = {
      maxConnectionsPerRole: 16,
      idleTimeoutMs: 60_000,
      requestTimeoutMs: 10_000,
      adminRequestTimeoutMs: 120_000,
    };
    expect(defaultLimits('api', config)).toMatchObject({
      maxConcurrentHandlers: 4,
      requestTimeoutMs: 10_000,
      writeBufferSoftBytes: 1024 * 1024,
      writeBufferHardBytes: 4 * 1024 * 1024,
      maxInFlightPerConnection: 4,
    });
    expect(defaultLimits('supervisor', config)).toMatchObject({
      maxConcurrentHandlers: 8,
      requestTimeoutMs: 10_000,
    });
    expect(defaultLimits('admin', config)).toMatchObject({
      maxConcurrentHandlers: 1,
      requestTimeoutMs: 120_000,
    });
  });

  it('queues the requests of every connection behind the cap, and answers them all', async () => {
    let running = 0;
    let peak = 0;
    const waiting: Array<() => void> = [];
    harness = await startTestVault(
      {},
      {
        limits: { api: { maxConcurrentHandlers: 2 } },
        handlers: {
          ...DEFAULT_HANDLERS,
          status: async () => {
            running += 1;
            peak = Math.max(peak, running);
            await new Promise<void>((resolve) => waiting.push(resolve));
            running -= 1;
            return {
              isolation: 'shared-uid' as const,
              kekVersions: [1],
              currentKekVersion: 1,
              versionsByKek: {},
              missingKekVersions: [],
              counters: {},
            };
          },
        },
      },
    );
    const replies = Array.from({ length: 6 }, (_, i) =>
      call(harness!.vault.sockets.api, { id: `s${i}`, operation: 'status', params: {} }),
    );
    // hello never waits for a slot, even with both slots taken.
    expect(await waitFor(() => running === 2, 2_000)).toBe(true);
    expect(
      await call(harness.vault.sockets.api, {
        id: 'hi',
        operation: 'hello',
        params: { protocolVersion: 1 },
      }),
    ).toMatchObject({ ok: true });
    for (let i = 0; i < 6; i += 1) {
      await waitFor(() => waiting.length > 0, 2_000);
      waiting.shift()!();
      await sleep(30);
    }
    const results = await Promise.all(replies);
    expect(results.every((reply) => reply['ok'] === true)).toBe(true);
    expect(peak).toBe(2);
  });

  it('closes without an answer when a request outlives its timeout, and the slot stays held until the handler settles', async () => {
    let started = 0;
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    harness = await startTestVault(
      { requestTimeoutMs: 300 },
      {
        limits: { api: { maxConcurrentHandlers: 1 } },
        handlers: {
          ...DEFAULT_HANDLERS,
          status: async () => {
            started += 1;
            await gate;
            return {
              isolation: 'shared-uid' as const,
              kekVersions: [1],
              currentKekVersion: 1,
              versionsByKek: {},
              missingKekVersions: [],
              counters: {},
            };
          },
        },
      },
    );
    const first = await openSocket(harness.vault.sockets.api);
    const firstData: string[] = [];
    first.on('data', (chunk) => firstData.push(chunk.toString()));
    first.on('error', () => undefined);
    first.write(`${JSON.stringify({ id: 'a', operation: 'status', params: {} })}\n`);
    const second = await openSocket(harness.vault.sockets.api);
    const secondData: string[] = [];
    second.on('data', (chunk) => secondData.push(chunk.toString()));
    second.on('error', () => undefined);
    second.write(`${JSON.stringify({ id: 'b', operation: 'status', params: {} })}\n`);
    // Both time out: the first is running, the second never got the slot. Neither is told an outcome.
    expect(await waitClosed(first, 3_000)).toBe(true);
    expect(await waitClosed(second, 3_000)).toBe(true);
    expect(firstData.join('')).toBe('');
    expect(secondData.join('')).toBe('');
    expect(started).toBe(1);
    // Once the first handler settles the abandoned second request must not start.
    release();
    await sleep(200);
    expect(started).toBe(1);
  });
});
