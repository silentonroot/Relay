import { mkdtemp, rm } from 'node:fs/promises';
import { createServer } from 'node:net';
import type { Server, Socket } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

/**
 * A stand-in for the vault's api socket: answers `hello` as configured and everything else
 * through `handle`. It speaks the line protocol only; it has no key, no database and no role
 * logic of its own. Tests that need the real operations start the real vault instead.
 */
export interface FakeVault {
  socketPath: string;
  /** Every request received, in order. */
  requests: { id: string; operation: string; params: unknown }[];
  close(): Promise<void>;
}

export interface FakeVaultOptions {
  hello?: Partial<{
    role: string;
    isolation: string;
    keyDirectory: string;
    currentKekVersion: number;
  }>;
  /** Answers every other operation: an `ok` result or an error code. Default: service_unavailable. */
  handle?: (operation: string, params: unknown) => { result: unknown } | { error: string } | 'hang';
}

export async function startFakeVault(options: FakeVaultOptions = {}): Promise<FakeVault> {
  const dir = await mkdtemp(join(process.env['XDG_RUNTIME_DIR'] ?? tmpdir(), 'aab-fv-'));
  const socketPath = join(dir, 'vault.sock');
  const requests: FakeVault['requests'] = [];
  const sockets = new Set<Socket>();
  const server: Server = createServer((socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    socket.on('error', () => undefined);
    let buffer = '';
    socket.on('data', (chunk) => {
      buffer += chunk.toString('utf8');
      const end = buffer.indexOf('\n');
      if (end === -1) return;
      const request = JSON.parse(buffer.slice(0, end)) as FakeVault['requests'][number];
      buffer = buffer.slice(end + 1);
      requests.push(request);
      let answer: { result: unknown } | { error: string } | 'hang';
      if (request.operation === 'hello') {
        answer = {
          result: {
            protocolVersion: 1,
            serviceVersion: '0.0.0',
            isolation: 'shared-uid',
            role: 'api',
            keyDirectory: '/nonexistent/aab-keys',
            currentKekVersion: 1,
            ...options.hello,
          },
        };
      } else {
        answer = options.handle?.(request.operation, request.params) ?? {
          error: 'service_unavailable',
        };
      }
      if (answer === 'hang') return;
      socket.write(
        `${JSON.stringify(
          'result' in answer
            ? { id: request.id, ok: true, result: answer.result }
            : { id: request.id, ok: false, error: { code: answer.error } },
        )}\n`,
      );
    });
  });
  await new Promise<void>((resolve) => server.listen(socketPath, resolve));
  return {
    socketPath,
    requests,
    async close() {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await rm(dir, { recursive: true, force: true });
    },
  };
}
