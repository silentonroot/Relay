import { mkdtemp, rm } from 'node:fs/promises';
import { createServer } from 'node:net';
import type { Server, Socket } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { VAULT_PROTOCOL_VERSION } from '@aab/contracts';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createVaultClient, VaultCallError, vaultSocketPath } from '../src/index.js';

const JOB_ID = '8a1b6f5e-3c47-4b0e-9d52-0f1c2e3d4a5b';
const CAPABILITY_ID = '1b2c3d4e-5f60-4718-8293-a4b5c6d7e8f9';

type Responder = (
  request: { id: string; operation: string; params: unknown },
  socket: Socket,
) => void;

describe('vault client', () => {
  let dir: string;
  let server: Server;
  let socketPath: string;
  let respond: Responder;
  const sockets = new Set<Socket>();

  beforeEach(async () => {
    dir = await mkdtemp(join(process.env['XDG_RUNTIME_DIR'] ?? tmpdir(), 'aab-vc-'));
    socketPath = join(dir, 'vault.sock');
    respond = () => undefined;
    server = createServer((socket) => {
      sockets.add(socket);
      socket.on('close', () => sockets.delete(socket));
      let buffer = '';
      socket.on('data', (chunk) => {
        buffer += chunk.toString('utf8');
        const end = buffer.indexOf('\n');
        if (end === -1) return;
        respond(JSON.parse(buffer.slice(0, end)) as never, socket);
      });
      socket.on('error', () => undefined);
    });
    await new Promise<void>((resolve) => server.listen(socketPath, resolve));
  });

  afterEach(async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await rm(dir, { recursive: true, force: true });
  });

  const authorize = (client = createVaultClient({ socketPath, timeoutMs: 400 })) =>
    client.call('authorizeJobAccess', { jobId: JOB_ID, ttlSeconds: 600 });
  const reply = (socket: Socket, body: unknown) => socket.write(`${JSON.stringify(body)}\n`);
  const kindOf = async (promise: Promise<unknown>) => {
    const error = await promise.then(
      () => null,
      (caught: unknown) => caught,
    );
    expect(error).toBeInstanceOf(VaultCallError);
    const failure = error as VaultCallError;
    return `${failure.kind}:${failure.code}`;
  };

  it('returns a validated result', async () => {
    respond = (request, socket) => {
      expect(request.operation).toBe('authorizeJobAccess');
      expect(request.params).toEqual({ jobId: JOB_ID, ttlSeconds: 600 });
      reply(socket, {
        id: request.id,
        ok: true,
        result: { capabilityId: CAPABILITY_ID, expiresAt: '2026-03-01T09:10:00.000Z' },
      });
    };
    await expect(authorize()).resolves.toEqual({
      capabilityId: CAPABILITY_ID,
      expiresAt: '2026-03-01T09:10:00.000Z',
    });
  });

  it('builds the socket path of a role', () => {
    expect(vaultSocketPath('/run/aab-vault', 'api')).toBe('/run/aab-vault/api/vault.sock');
  });

  it('maps a refusal to denied and a vault failure to unavailable', async () => {
    const answers: [string, string][] = [
      ['forbidden', 'denied:forbidden'],
      ['not_found', 'denied:not_found'],
      ['validation_failed', 'denied:validation_failed'],
      ['conflict', 'denied:conflict'],
      ['malformed', 'denied:malformed'],
      ['service_unavailable', 'unavailable:service_unavailable'],
      ['internal_error', 'unavailable:internal_error'],
      ['not_implemented', 'unavailable:not_implemented'],
    ];
    for (const [code, expected] of answers) {
      respond = (request, socket) => reply(socket, { id: request.id, ok: false, error: { code } });
      expect(await kindOf(authorize()), code).toBe(expected);
    }
  });

  it('is unavailable when nothing listens on the socket', async () => {
    const client = createVaultClient({ socketPath: join(dir, 'missing.sock'), timeoutMs: 400 });
    expect(await kindOf(authorize(client))).toBe('unavailable:unreachable');
  });

  it('times out when the vault never answers', async () => {
    respond = () => undefined;
    const started = Date.now();
    expect(await kindOf(authorize(createVaultClient({ socketPath, timeoutMs: 150 })))).toBe(
      'unavailable:timeout',
    );
    expect(Date.now() - started).toBeLessThan(2_000);
  });

  it('is unavailable when the connection closes without an answer', async () => {
    respond = (_request, socket) => socket.end();
    expect(await kindOf(authorize())).toBe('unavailable:closed');
  });

  it('treats a malformed reply as unavailable', async () => {
    const replies: [string, (request: { id: string }, socket: Socket) => void][] = [
      ['not json', (_r, socket) => socket.write('this is not json\n')],
      ['not an object', (_r, socket) => socket.write('[1,2]\n')],
      [
        'unknown field',
        (r, socket) =>
          reply(socket, {
            id: r.id,
            ok: true,
            result: { capabilityId: CAPABILITY_ID, expiresAt: '2026-03-01T09:10:00.000Z' },
            extra: 1,
          }),
      ],
      [
        'result that fails its schema',
        (r, socket) => reply(socket, { id: r.id, ok: true, result: { capabilityId: 'nope' } }),
      ],
      [
        'result with an extra field',
        (r, socket) =>
          reply(socket, {
            id: r.id,
            ok: true,
            result: {
              capabilityId: CAPABILITY_ID,
              expiresAt: '2026-03-01T09:10:00.000Z',
              token: 'x',
            },
          }),
      ],
      [
        'error code outside the list',
        (r, socket) => reply(socket, { id: r.id, ok: false, error: { code: 'teapot' } }),
      ],
      [
        'answer to another request',
        (_r, socket) =>
          reply(socket, {
            id: 'someone-else',
            ok: true,
            result: { capabilityId: CAPABILITY_ID, expiresAt: '2026-03-01T09:10:00.000Z' },
          }),
      ],
    ];
    for (const [label, answer] of replies) {
      respond = (request, socket) => answer(request, socket);
      expect(await kindOf(authorize()), label).toBe('unavailable:bad_response');
    }
  });

  it('refuses an oversize reply without buffering it', async () => {
    respond = (_request, socket) => {
      socket.write('x'.repeat(10_000));
    };
    const client = createVaultClient({ socketPath, timeoutMs: 1_000, maxResponseBytes: 2_048 });
    expect(await kindOf(authorize(client))).toBe('unavailable:oversize');
  });

  it('reads a reply that arrives in several chunks', async () => {
    respond = (request, socket) => {
      const text = `${JSON.stringify({
        id: request.id,
        ok: true,
        result: { capabilityId: CAPABILITY_ID, expiresAt: '2026-03-01T09:10:00.000Z' },
      })}\n`;
      socket.write(text.slice(0, 20));
      setTimeout(() => socket.write(text.slice(20)), 20);
    };
    await expect(authorize()).resolves.toMatchObject({ capabilityId: CAPABILITY_ID });
  });

  it('refuses to send a request that fails the contracts schema', async () => {
    let seen = false;
    respond = () => {
      seen = true;
    };
    const client = createVaultClient({ socketPath, timeoutMs: 400 });
    const bad = client.call('authorizeJobAccess', { jobId: JOB_ID, ttlSeconds: 5 });
    expect(await kindOf(bad)).toBe('denied:invalid_request');
    const extra = client.call('hello', {
      protocolVersion: VAULT_PROTOCOL_VERSION,
      role: 'admin',
    } as never);
    expect(await kindOf(extra)).toBe('denied:invalid_request');
    expect(seen).toBe(false);
  });

  it('puts nothing from the request or the reply into the error', async () => {
    respond = (request, socket) =>
      reply(socket, { id: request.id, ok: false, error: { code: 'forbidden' } });
    const error = (await authorize().catch((caught: unknown) => caught)) as VaultCallError;
    expect(error.message).not.toContain(JOB_ID);
    expect(Object.keys(error).sort()).toEqual(['code', 'kind', 'name']);
  });

  it('rejects a timeout that is not a positive integer', () => {
    expect(() => createVaultClient({ socketPath, timeoutMs: 0 })).toThrow(RangeError);
    expect(() => createVaultClient({ socketPath, maxResponseBytes: 1.5 })).toThrow(RangeError);
  });
});
