import { lookup } from 'node:dns/promises';
import { unlink } from 'node:fs/promises';
import http from 'node:http';
import type { IncomingHttpHeaders, IncomingMessage, OutgoingHttpHeaders } from 'node:http';
import net from 'node:net';
import type { Socket } from 'node:net';
import type { Duplex } from 'node:stream';
import { isLoopbackHost } from '@aab/contracts';
import { classifyAddress } from './ip-ranges.js';

/*
 * The per-job egress proxy (ADR-013). It runs in the supervisor, listens on a Unix socket that
 * is bound into the sandbox, and is the sandbox's only way out.
 *
 * - `http:` origins: absolute-URI requests (`GET http://host:port/path HTTP/1.1`), forwarded
 *   request by request, each checked on its own even on a kept-alive connection.
 * - `https:` origins and WebSockets: `CONNECT host:port`, then an opaque tunnel. Chromium sends
 *   every WebSocket (ws: and wss:) through CONNECT, so WebSockets to an allowed origin work.
 *   An `Upgrade` sent as an absolute-URI request is refused with 403.
 *
 * Only the origin, the decision and a reason code are ever reported. Headers and bodies carry
 * the session cookie and are never logged.
 */

export type EgressReason =
  | 'allowed'
  | 'bad_request'
  | 'scheme_not_allowed'
  | 'origin_not_allowed'
  | 'resolve_failed'
  | 'address_not_allowed'
  | 'upstream_failed'
  | 'upgrade_refused'
  | 'too_many_connections';

export interface EgressDecision {
  /** Normalized origin of the attempt, or a placeholder when none could be parsed. */
  readonly origin: string;
  readonly decision: 'allow' | 'deny';
  readonly reason: EgressReason;
}

/** Returns every address for a host name. Injectable so tests can simulate DNS answers. */
export type EgressResolver = (hostname: string) => Promise<readonly string[]>;

export const systemResolver: EgressResolver = async (hostname) => {
  const answers = await lookup(hostname, { all: true, verbatim: true });
  return answers.map((answer) => answer.address);
};

export interface EgressLimits {
  /** Largest request head accepted from the browser. */
  readonly maxHeaderBytes: number;
  /** A client or tunnel with no traffic for this long is closed. */
  readonly idleTimeoutMs: number;
  /** Concurrent client connections on the Unix socket. */
  readonly maxConnections: number;
  readonly connectTimeoutMs: number;
}

export const DEFAULT_EGRESS_LIMITS: EgressLimits = {
  maxHeaderBytes: 32 * 1024,
  idleTimeoutMs: 60_000,
  maxConnections: 64,
  connectTimeoutMs: 10_000,
};

export interface EgressProxyOptions {
  readonly socketPath: string;
  /** The job's allowed origins, already in canonical `Origin` form. */
  readonly allowedOrigins: readonly string[];
  readonly resolver?: EgressResolver;
  readonly limits?: Partial<EgressLimits>;
  readonly onDecision?: (decision: EgressDecision) => void;
}

export interface EgressProxy {
  readonly socketPath: string;
  /** Tears down every open connection and removes the socket file. Idempotent. */
  close(): Promise<void>;
}

interface AllowedTarget {
  readonly origin: string;
  readonly protocol: 'http:' | 'https:';
  /** Hostname as the URL parser reports it (IPv6 literals in brackets). */
  readonly hostname: string;
  readonly port: number;
}

const HOP_BY_HOP = new Set([
  'connection',
  'keep-alive',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
  'http2-settings',
]);

/** Removes hop-by-hop headers, every `Proxy-*` header and anything named in `Connection`. */
export function stripHopByHop(headers: IncomingHttpHeaders): OutgoingHttpHeaders {
  const named = new Set<string>();
  const connection = headers['connection'];
  for (const value of Array.isArray(connection) ? connection : [connection ?? '']) {
    for (const token of value.split(',')) {
      const name = token.trim().toLowerCase();
      if (name !== '') named.add(name);
    }
  }
  const result: OutgoingHttpHeaders = {};
  for (const [name, value] of Object.entries(headers)) {
    const lower = name.toLowerCase();
    if (value === undefined) continue;
    if (HOP_BY_HOP.has(lower) || named.has(lower) || lower.startsWith('proxy-')) continue;
    result[lower] = value;
  }
  return result;
}

function defaultPort(protocol: string): number {
  return protocol === 'https:' ? 443 : 80;
}

function toTarget(origin: string): AllowedTarget | null {
  let url: URL;
  try {
    url = new URL(origin);
  } catch {
    return null;
  }
  if (url.origin !== origin) return null;
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
  return {
    origin,
    protocol: url.protocol,
    hostname: url.hostname,
    port: url.port === '' ? defaultPort(url.protocol) : Number(url.port),
  };
}

/** Strips brackets from an IPv6 literal hostname. */
function bareHost(hostname: string): string {
  return hostname.startsWith('[') && hostname.endsWith(']') ? hostname.slice(1, -1) : hostname;
}

/** Keeps logged origins short and printable whatever the page asked for. */
function displayOrigin(value: string): string {
  const clean = value.replace(/[^\x21-\x7e]/g, '?');
  return clean.length > 200 ? `${clean.slice(0, 200)}...` : clean;
}

export type AddressVetting =
  | { readonly ok: true; readonly addresses: readonly string[] }
  | { readonly ok: false; readonly reason: 'resolve_failed' | 'address_not_allowed' };

/**
 * Resolves a target and applies spec §3.2: a loopback origin must resolve only to loopback
 * addresses; any other origin only to globally routable ones. Every answer must pass.
 */
export async function vetAddresses(
  hostname: string,
  resolver: EgressResolver,
): Promise<AddressVetting> {
  const host = bareHost(hostname);
  let addresses: readonly string[];
  if (net.isIP(host) !== 0) {
    addresses = [host];
  } else {
    try {
      addresses = await resolver(host);
    } catch {
      return { ok: false, reason: 'resolve_failed' };
    }
  }
  if (addresses.length === 0) return { ok: false, reason: 'resolve_failed' };
  const wanted = isLoopbackHost(hostname) ? 'loopback' : 'global';
  for (const address of addresses) {
    if (classifyAddress(address) !== wanted) return { ok: false, reason: 'address_not_allowed' };
  }
  return { ok: true, addresses };
}

function connectFirst(
  addresses: readonly string[],
  port: number,
  timeoutMs: number,
): Promise<Socket> {
  return new Promise((resolve, reject) => {
    let index = 0;
    const attempt = (): void => {
      const address = addresses[index];
      if (address === undefined) {
        reject(new Error('no address connected'));
        return;
      }
      index += 1;
      const socket = net.connect({ host: address, port });
      const timer = setTimeout(() => socket.destroy(new Error('connect timeout')), timeoutMs);
      socket.once('connect', () => {
        clearTimeout(timer);
        socket.removeAllListeners('error');
        resolve(socket);
      });
      socket.once('error', () => {
        clearTimeout(timer);
        socket.destroy();
        attempt();
      });
    };
    attempt();
  });
}

function refuse(socket: Duplex, status: 400 | 403 | 502 | 503): void {
  const text = { 400: 'Bad Request', 403: 'Forbidden', 502: 'Bad Gateway', 503: 'Unavailable' }[
    status
  ];
  if (!socket.destroyed && socket.writable) {
    socket.end(`HTTP/1.1 ${status} ${text}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n`);
  }
  setTimeout(() => socket.destroy(), 1_000).unref();
}

export async function createEgressProxy(options: EgressProxyOptions): Promise<EgressProxy> {
  const limits: EgressLimits = { ...DEFAULT_EGRESS_LIMITS, ...options.limits };
  const resolver = options.resolver ?? systemResolver;
  const targets = options.allowedOrigins
    .map(toTarget)
    .filter((target): target is AllowedTarget => target !== null);
  if (targets.length !== options.allowedOrigins.length || targets.length === 0) {
    throw new Error('egress proxy needs at least one origin, all in canonical form');
  }
  const httpTargets = new Map(
    targets.filter((target) => target.protocol === 'http:').map((t) => [t.origin, t]),
  );
  // CONNECT is accepted for the host:port of any allowed origin. For an http: origin this is
  // what Chromium uses for WebSockets; the destination is the same host and port either way.
  const tunnelTargets = new Map(targets.map((t) => [`${t.hostname}:${t.port}`, t]));

  const sockets = new Set<Duplex>();
  let closed = false;

  const track = (socket: Duplex): void => {
    sockets.add(socket);
    socket.once('close', () => sockets.delete(socket));
  };

  const report = (origin: string, decision: 'allow' | 'deny', reason: EgressReason): void => {
    try {
      options.onDecision?.({ origin: displayOrigin(origin), decision, reason });
    } catch {
      // A failing observer must not change the decision.
    }
  };

  const server = http.createServer({
    maxHeaderSize: limits.maxHeaderBytes,
    requestTimeout: 0,
    headersTimeout: Math.min(limits.idleTimeoutMs, 30_000),
    keepAliveTimeout: limits.idleTimeoutMs,
    // Nothing is decided from these, but keep Node from normalizing paths behind our back.
    joinDuplicateHeaders: false,
  });
  server.maxConnections = limits.maxConnections;

  server.on('connection', (socket: Socket) => {
    track(socket);
    socket.setTimeout(limits.idleTimeoutMs, () => socket.destroy());
  });
  server.on('drop', () => report('(connection)', 'deny', 'too_many_connections'));
  server.on('clientError', (_error, socket: Duplex) => {
    report('(unparseable)', 'deny', 'bad_request');
    refuse(socket, 400);
  });

  server.on('request', (request: IncomingMessage, response: http.ServerResponse) => {
    void handleRequest(request, response);
  });

  async function handleRequest(
    request: IncomingMessage,
    response: http.ServerResponse,
  ): Promise<void> {
    const deny = (origin: string, reason: EgressReason, status: 400 | 403 | 502 = 403): void => {
      report(origin, 'deny', reason);
      response.shouldKeepAlive = false;
      response.writeHead(status, { 'content-length': '0', connection: 'close' });
      response.end();
      request.socket.once('finish', () => request.socket.destroy());
      setTimeout(() => request.socket.destroy(), 1_000).unref();
    };

    let url: URL;
    try {
      url = new URL(request.url ?? '');
    } catch {
      deny('(not-absolute)', 'bad_request', 400);
      return;
    }
    if (url.protocol !== 'http:') {
      deny(`${url.protocol}//`, 'scheme_not_allowed');
      return;
    }
    if (url.username !== '' || url.password !== '') {
      deny(url.origin, 'bad_request', 400);
      return;
    }
    const target = httpTargets.get(url.origin);
    if (target === undefined) {
      deny(url.origin, 'origin_not_allowed');
      return;
    }
    const vetting = await vetAddresses(target.hostname, resolver);
    if (!vetting.ok) {
      deny(target.origin, vetting.reason);
      return;
    }

    let upstreamSocket: Socket;
    try {
      upstreamSocket = await connectFirst(vetting.addresses, target.port, limits.connectTimeoutMs);
    } catch {
      deny(target.origin, 'upstream_failed', 502);
      return;
    }
    if (closed) {
      upstreamSocket.destroy();
      return;
    }
    track(upstreamSocket);
    upstreamSocket.setTimeout(limits.idleTimeoutMs, () => upstreamSocket.destroy());
    report(target.origin, 'allow', 'allowed');

    const headers = stripHopByHop(request.headers);
    // The Host header names the origin, never the vetted address.
    headers['host'] = url.host;
    const upstream = http.request({
      method: request.method,
      path: `${url.pathname}${url.search}`,
      headers,
      // No agent: with a createConnection and no agent, Node uses exactly this socket.
      createConnection: () => upstreamSocket,
      setHost: false,
    });
    upstream.on('response', (upstreamResponse) => {
      const responseHeaders = stripHopByHop(upstreamResponse.headers);
      response.writeHead(upstreamResponse.statusCode ?? 502, responseHeaders);
      upstreamResponse.pipe(response);
    });
    upstream.on('error', () => {
      if (!response.headersSent) {
        response.writeHead(502, { 'content-length': '0', connection: 'close' });
        response.end();
      } else {
        response.destroy();
      }
    });
    request.on('aborted', () => upstream.destroy());
    response.on('close', () => upstreamSocket.destroy());
    request.pipe(upstream);
  }

  server.on('upgrade', (_request: IncomingMessage, socket: Duplex) => {
    report('(upgrade)', 'deny', 'upgrade_refused');
    refuse(socket, 403);
  });

  server.on('connect', (request: IncomingMessage, clientSocket: Duplex, head: Buffer) => {
    void handleConnect(request, clientSocket, head);
  });

  async function handleConnect(
    request: IncomingMessage,
    clientSocket: Duplex,
    head: Buffer,
  ): Promise<void> {
    const authority = request.url ?? '';
    let parsed: URL | null;
    try {
      parsed = new URL(`https://${authority}`);
    } catch {
      parsed = null;
    }
    // The authority must be exactly host:port with nothing else, and the port explicit.
    const explicitPort = /:(\d{1,5})$/.exec(authority)?.[1];
    if (
      parsed === null ||
      explicitPort === undefined ||
      parsed.pathname !== '/' ||
      parsed.search !== '' ||
      parsed.username !== '' ||
      parsed.password !== '' ||
      `${parsed.hostname}:${explicitPort}` !== authority.toLowerCase()
    ) {
      report('(connect)', 'deny', 'bad_request');
      refuse(clientSocket, 400);
      return;
    }
    const key = `${parsed.hostname}:${Number(explicitPort)}`;
    const target = tunnelTargets.get(key);
    if (target === undefined) {
      report(`connect://${key}`, 'deny', 'origin_not_allowed');
      refuse(clientSocket, 403);
      return;
    }
    const vetting = await vetAddresses(target.hostname, resolver);
    if (!vetting.ok) {
      report(target.origin, 'deny', vetting.reason);
      refuse(clientSocket, 403);
      return;
    }
    let upstream: Socket;
    try {
      upstream = await connectFirst(vetting.addresses, target.port, limits.connectTimeoutMs);
    } catch {
      report(target.origin, 'deny', 'upstream_failed');
      refuse(clientSocket, 502);
      return;
    }
    if (closed || clientSocket.destroyed) {
      upstream.destroy();
      return;
    }
    track(upstream);
    report(target.origin, 'allow', 'allowed');
    upstream.setTimeout(limits.idleTimeoutMs, () => upstream.destroy());
    clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    if (head.length > 0) upstream.write(head);
    upstream.pipe(clientSocket);
    clientSocket.pipe(upstream);
    upstream.on('error', () => clientSocket.destroy());
    clientSocket.on('error', () => upstream.destroy());
    upstream.on('close', () => clientSocket.destroy());
    clientSocket.on('close', () => upstream.destroy());
  }

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(options.socketPath, () => {
      server.off('error', reject);
      resolve();
    });
  });

  return {
    socketPath: options.socketPath,
    async close(): Promise<void> {
      if (closed) return;
      closed = true;
      const done = new Promise<void>((resolve) => server.close(() => resolve()));
      for (const socket of sockets) socket.destroy();
      server.closeAllConnections();
      await done;
      await unlink(options.socketPath).catch(() => undefined);
    },
  };
}
