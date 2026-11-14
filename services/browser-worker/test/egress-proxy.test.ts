import { existsSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import http from 'node:http';
import type { IncomingHttpHeaders } from 'node:http';
import net from 'node:net';
import type { AddressInfo } from 'node:net';
import path from 'node:path';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createEgressProxy, stripHopByHop, vetAddresses } from '../src/egress/proxy.js';
import type { EgressDecision, EgressProxy, EgressResolver } from '../src/egress/proxy.js';
import { defaultRuntimeBaseDir, ensureRuntimeBaseDir } from '../src/sandbox/runtime-dir.js';

let upstream: http.Server;
let upstreamPort: number;
let lastHeaders: IncomingHttpHeaders = {};
let upgradeTarget: net.Server;
let upgradePort: number;
let dir: string;

beforeAll(async () => {
  upstream = http.createServer((request, response) => {
    lastHeaders = request.headers;
    response.writeHead(200, {
      'content-type': 'text/plain',
      'proxy-authenticate': 'Basic',
      'x-hop': 'secret',
      connection: 'x-hop',
    });
    response.end(`ok ${request.method} ${request.url}`);
  });
  await new Promise<void>((resolve) => upstream.listen(0, '127.0.0.1', resolve));
  upstreamPort = (upstream.address() as AddressInfo).port;
  // A raw TCP echo server stands in for a TLS or WebSocket endpoint behind CONNECT.
  upgradeTarget = net.createServer((socket) => socket.pipe(socket));
  await new Promise<void>((resolve) => upgradeTarget.listen(0, '127.0.0.1', resolve));
  upgradePort = (upgradeTarget.address() as AddressInfo).port;
  const base = defaultRuntimeBaseDir();
  await ensureRuntimeBaseDir(base);
  dir = await mkdtemp(path.join(base, 't-'));
});

afterAll(async () => {
  upstream.closeAllConnections();
  await new Promise((resolve) => upstream.close(resolve));
  await new Promise((resolve) => upgradeTarget.close(resolve));
  await rm(dir, { recursive: true, force: true });
});

let proxy: EgressProxy;
let decisions: EgressDecision[];
let socketPath: string;
let counter = 0;

async function startProxy(
  allowedOrigins: string[],
  resolver?: EgressResolver,
  limits?: Parameters<typeof createEgressProxy>[0]['limits'],
): Promise<void> {
  counter += 1;
  socketPath = path.join(dir, `p${counter}.sock`);
  proxy = await createEgressProxy({
    socketPath,
    allowedOrigins,
    ...(resolver === undefined ? {} : { resolver }),
    ...(limits === undefined ? {} : { limits }),
    onDecision: (decision) => decisions.push(decision),
  });
}

beforeEach(() => {
  decisions = [];
});
afterEach(async () => {
  await proxy?.close();
});

/** Sends raw bytes to the proxy and collects everything until the connection closes. */
function raw(payload: string, waitMs = 400): Promise<string> {
  return new Promise((resolve) => {
    const socket = net.connect(socketPath);
    let data = '';
    socket.on('data', (chunk) => (data += chunk.toString()));
    socket.on('error', () => resolve(data));
    socket.on('close', () => resolve(data));
    socket.write(payload);
    setTimeout(() => socket.destroy(), waitMs);
  });
}

const statusOf = (response: string): string => response.split('\r\n', 1)[0] ?? '';

describe('egress proxy: absolute-URI requests', () => {
  it('forwards a request to an allowed http origin and strips proxy and hop-by-hop headers', async () => {
    const origin = `http://127.0.0.1:${upstreamPort}`;
    await startProxy([origin]);
    const response = await raw(
      `GET ${origin}/path?q=1 HTTP/1.1\r\nHost: 127.0.0.1:${upstreamPort}\r\n` +
        'Proxy-Authorization: Basic c2VjcmV0\r\nProxy-Connection: keep-alive\r\n' +
        'Connection: close, X-Remove-Me\r\nX-Remove-Me: 1\r\nTE: trailers\r\nCookie: a=b\r\n\r\n',
    );
    expect(statusOf(response)).toBe('HTTP/1.1 200 OK');
    expect(response).toContain('ok GET /path?q=1');
    expect(lastHeaders['proxy-authorization']).toBeUndefined();
    expect(lastHeaders['proxy-connection']).toBeUndefined();
    expect(lastHeaders['x-remove-me']).toBeUndefined();
    expect(lastHeaders['te']).toBeUndefined();
    expect(lastHeaders['cookie']).toBe('a=b');
    expect(lastHeaders['host']).toBe(`127.0.0.1:${upstreamPort}`);
    // Nothing identifying is added.
    expect(lastHeaders['via']).toBeUndefined();
    expect(lastHeaders['x-forwarded-for']).toBeUndefined();
    // Response hop-by-hop headers are stripped too.
    expect(response.toLowerCase()).not.toContain('proxy-authenticate');
    expect(response.toLowerCase()).not.toContain('x-hop');
    expect(decisions).toEqual([{ origin, decision: 'allow', reason: 'allowed' }]);
  });

  it.each([
    ['another port', (port: number) => `http://127.0.0.1:${port + 1}/`],
    ['another host', (port: number) => `http://localhost:${port}/`],
    ['an https absolute URI', (port: number) => `https://127.0.0.1:${port}/`],
    ['a public host', () => 'http://example.com/'],
    ['a metadata address', () => 'http://169.254.169.254/latest/meta-data/'],
  ])('refuses %s with 403 and closes', async (_label, url) => {
    await startProxy([`http://127.0.0.1:${upstreamPort}`]);
    const response = await raw(`GET ${url(upstreamPort)} HTTP/1.1\r\nHost: x\r\n\r\n`);
    expect(statusOf(response)).toBe('HTTP/1.1 403 Forbidden');
    expect(decisions[0]?.decision).toBe('deny');
  });

  it('refuses an origin-form request', async () => {
    await startProxy([`http://127.0.0.1:${upstreamPort}`]);
    const response = await raw('GET /path HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n');
    expect(statusOf(response)).toBe('HTTP/1.1 400 Bad Request');
    expect(decisions[0]).toEqual({
      origin: '(not-absolute)',
      decision: 'deny',
      reason: 'bad_request',
    });
  });

  it('checks each request on a kept-alive connection on its own', async () => {
    const origin = `http://127.0.0.1:${upstreamPort}`;
    await startProxy([origin]);
    const response = await raw(
      `GET ${origin}/a HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n` +
        'GET http://example.com/b HTTP/1.1\r\nHost: example.com\r\n\r\n',
      600,
    );
    expect(response).toContain('ok GET /a');
    expect(response).toContain('403 Forbidden');
    expect(decisions.map((d) => d.decision).sort()).toEqual(['allow', 'deny']);
  });

  it('handles default ports when comparing origins', async () => {
    const resolver: EgressResolver = async () => ['127.0.0.1'];
    await startProxy(['http://localhost'], resolver, { connectTimeoutMs: 300 });
    // Same origin spelled with an explicit default port is the same origin.
    await raw('GET http://localhost:80/x HTTP/1.1\r\nHost: localhost\r\n\r\n');
    expect(decisions[0]?.origin).toBe('http://localhost');
    expect(decisions[0]?.reason).not.toBe('origin_not_allowed');
  });

  it('refuses a request head over the size limit', async () => {
    await startProxy([`http://127.0.0.1:${upstreamPort}`], undefined, { maxHeaderBytes: 1024 });
    const response = await raw(
      `GET http://127.0.0.1:${upstreamPort}/ HTTP/1.1\r\nX-Big: ${'a'.repeat(4000)}\r\n\r\n`,
    );
    expect(response).toMatch(/^HTTP\/1\.1 4\d\d/);
    expect(lastHeaders['x-big']).toBeUndefined();
  });

  it('refuses an Upgrade sent as an absolute-URI request', async () => {
    const origin = `http://127.0.0.1:${upstreamPort}`;
    await startProxy([origin]);
    const response = await raw(
      `GET ${origin}/ws HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n`,
    );
    expect(statusOf(response)).toBe('HTTP/1.1 403 Forbidden');
    expect(decisions[0]).toMatchObject({ decision: 'deny', reason: 'upgrade_refused' });
  });
});

describe('egress proxy: CONNECT', () => {
  it('tunnels to an allowed host:port (how Chromium carries TLS and WebSockets)', async () => {
    await startProxy([`http://127.0.0.1:${upgradePort}`]);
    const response = await raw(
      `CONNECT 127.0.0.1:${upgradePort} HTTP/1.1\r\nHost: 127.0.0.1:${upgradePort}\r\n\r\nping`,
    );
    expect(response.startsWith('HTTP/1.1 200 Connection Established\r\n\r\n')).toBe(true);
    expect(response.endsWith('ping')).toBe(true);
    expect(decisions[0]).toMatchObject({ decision: 'allow' });
  });

  it.each([
    ['another port', (port: number) => `127.0.0.1:${port + 1}`],
    ['another host', (port: number) => `localhost:${port}`],
    ['a missing port', () => '127.0.0.1'],
    ['a path', (port: number) => `127.0.0.1:${port}/x`],
    ['userinfo', (port: number) => `user@127.0.0.1:${port}`],
  ])('refuses %s', async (_label, authority) => {
    await startProxy([`http://127.0.0.1:${upgradePort}`]);
    const response = await raw(`CONNECT ${authority(upgradePort)} HTTP/1.1\r\nHost: x\r\n\r\n`);
    expect(statusOf(response)).toMatch(/^HTTP\/1\.1 40[03]/);
    expect(decisions[0]?.decision).toBe('deny');
  });

  it('refuses CONNECT to a private address for a public origin', async () => {
    await startProxy(['https://app.example.test'], async () => ['10.0.0.8']);
    const response = await raw('CONNECT app.example.test:443 HTTP/1.1\r\nHost: x\r\n\r\n');
    expect(statusOf(response)).toBe('HTTP/1.1 403 Forbidden');
    expect(decisions[0]).toEqual({
      origin: 'https://app.example.test',
      decision: 'deny',
      reason: 'address_not_allowed',
    });
  });
});

describe('egress proxy: address checks', () => {
  it('re-resolves on every request, so a rebinding answer is refused', async () => {
    const answers = [['127.0.0.1'], ['93.184.216.34']];
    const resolver: EgressResolver = async () => answers.shift() ?? [];
    const origin = `http://localhost:${upstreamPort}`;
    await startProxy([origin], resolver);
    const first = await raw(`GET ${origin}/one HTTP/1.1\r\nHost: localhost\r\n\r\n`);
    const second = await raw(`GET ${origin}/two HTTP/1.1\r\nHost: localhost\r\n\r\n`);
    expect(first).toContain('ok GET /one');
    expect(statusOf(second)).toBe('HTTP/1.1 403 Forbidden');
    expect(decisions).toEqual([
      { origin, decision: 'allow', reason: 'allowed' },
      { origin, decision: 'deny', reason: 'address_not_allowed' },
    ]);
  });

  it('connects to the vetted address, not the name', async () => {
    // The name resolves (in our fake DNS) to loopback; Node's resolver is never consulted.
    const origin = `http://app.localhost:${upstreamPort}`;
    await startProxy([origin], async () => ['127.0.0.1']);
    const response = await raw(`GET ${origin}/n HTTP/1.1\r\nHost: app.localhost\r\n\r\n`);
    expect(response).toContain('ok GET /n');
    expect(lastHeaders['host']).toBe(`app.localhost:${upstreamPort}`);
  });

  it.each([
    [['127.0.0.1'], 'address_not_allowed'],
    [['10.0.0.1'], 'address_not_allowed'],
    [['8.8.8.8', '192.168.1.1'], 'address_not_allowed'],
    [['::ffff:10.0.0.1'], 'address_not_allowed'],
    [['::ffff:127.0.0.1'], 'address_not_allowed'],
    [['fd00::1'], 'address_not_allowed'],
    [['fe80::1'], 'address_not_allowed'],
    [['100.64.1.1'], 'address_not_allowed'],
    [['169.254.169.254'], 'address_not_allowed'],
    [['224.0.0.1'], 'address_not_allowed'],
    [['0.0.0.0'], 'address_not_allowed'],
    [[], 'resolve_failed'],
  ])('a public origin answering %j is refused (%s)', async (answers, reason) => {
    const result = await vetAddresses('app.example.test', async () => answers);
    expect(result).toEqual({ ok: false, reason });
  });

  it('a public origin answering only global addresses passes', async () => {
    const result = await vetAddresses('app.example.test', async () => ['8.8.8.8', '2606:4700::1']);
    expect(result).toEqual({ ok: true, addresses: ['8.8.8.8', '2606:4700::1'] });
  });

  it('a loopback origin must resolve only to loopback', async () => {
    expect(await vetAddresses('localhost', async () => ['127.0.0.1', '::1'])).toMatchObject({
      ok: true,
    });
    expect(await vetAddresses('localhost', async () => ['127.0.0.1', '8.8.8.8'])).toMatchObject({
      ok: false,
      reason: 'address_not_allowed',
    });
    expect(await vetAddresses('[::1]', async () => ['8.8.8.8'])).toMatchObject({ ok: true });
  });

  it('treats a resolver failure as a refusal', async () => {
    const result = await vetAddresses('app.example.test', async () => {
      throw new Error('ENOTFOUND');
    });
    expect(result).toEqual({ ok: false, reason: 'resolve_failed' });
  });
});

describe('egress proxy: lifecycle and limits', () => {
  it('close() tears down open tunnels and removes the socket file', async () => {
    await startProxy([`http://127.0.0.1:${upgradePort}`]);
    const socket = net.connect(socketPath);
    socket.on('error', () => undefined);
    socket.write(`CONNECT 127.0.0.1:${upgradePort} HTTP/1.1\r\nHost: x\r\n\r\n`);
    await new Promise((resolve) => socket.once('data', resolve));
    const closed = new Promise((resolve) => socket.once('close', resolve));
    await proxy.close();
    await closed;
    expect(existsSync(socketPath)).toBe(false);
  });

  it('closes idle connections', async () => {
    await startProxy([`http://127.0.0.1:${upgradePort}`], undefined, { idleTimeoutMs: 200 });
    const socket = net.connect(socketPath);
    const start = Date.now();
    await new Promise((resolve) => socket.once('close', resolve));
    expect(Date.now() - start).toBeLessThan(2_000);
  });

  it('bounds concurrent connections', async () => {
    await startProxy([`http://127.0.0.1:${upgradePort}`], undefined, { maxConnections: 2 });
    const sockets = [0, 1, 2, 3].map(() => {
      const socket = net.connect(socketPath);
      socket.on('error', () => undefined);
      return socket;
    });
    await new Promise((resolve) => setTimeout(resolve, 300));
    expect(decisions.filter((d) => d.reason === 'too_many_connections').length).toBe(2);
    for (const socket of sockets) socket.destroy();
  });

  it('rejects allowed origins that are not canonical', async () => {
    await expect(
      createEgressProxy({ socketPath: path.join(dir, 'bad.sock'), allowedOrigins: ['http://x/'] }),
    ).rejects.toThrow();
    await expect(
      createEgressProxy({ socketPath: path.join(dir, 'bad.sock'), allowedOrigins: [] }),
    ).rejects.toThrow();
  });
});

describe('stripHopByHop', () => {
  it('removes connection-named, hop-by-hop and proxy headers only', () => {
    expect(
      stripHopByHop({
        connection: 'keep-alive, X-Foo',
        'x-foo': '1',
        'keep-alive': 'timeout=5',
        'transfer-encoding': 'chunked',
        upgrade: 'h2c',
        'proxy-authorization': 'x',
        'proxy-anything': 'x',
        cookie: 'session=1',
        accept: 'text/html',
      }),
    ).toEqual({ cookie: 'session=1', accept: 'text/html' });
  });
});
