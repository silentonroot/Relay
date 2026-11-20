import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import type { VaultClient } from '@aab/vault-client';
import { createVaultGateway, VaultStartupRefusal } from '../src/vault/gateway.js';

/*
 * B3 review L1 and L4: in separate-uid mode the API must not be able to connect to another
 * role's socket (they sit beside its own), and a vault that turns out wrong is reported once.
 */
const hello = (role: string) =>
  ({
    protocolVersion: 1,
    serviceVersion: '0.0.0',
    isolation: 'separate-uid',
    role,
    keyDirectory: '/nonexistent/aab-keys',
    currentKekVersion: 1,
  }) as never;

const clientFor = (role: string): VaultClient => ({ call: async () => hello(role) }) as VaultClient;

describe('the API gateway and the other roles sockets', () => {
  const cleanups: Array<() => void> = [];
  afterEach(() => {
    for (const cleanup of cleanups.splice(0)) cleanup();
  });

  /** `<root>/<role>/vault.sock` for each role; the listed roles really listen. */
  async function layout(listening: string[]) {
    const parent = process.env['XDG_RUNTIME_DIR'] ?? '/tmp';
    const root = mkdtempSync(path.join(parent, 'aab-gw-'));
    const servers: net.Server[] = [];
    for (const role of ['api', 'supervisor', 'admin']) {
      mkdirSync(path.join(root, role));
      if (!listening.includes(role)) continue;
      const server = net.createServer((socket) => socket.end());
      await new Promise<void>((resolve) =>
        server.listen(path.join(root, role, 'vault.sock'), resolve),
      );
      servers.push(server);
    }
    cleanups.push(() => {
      for (const server of servers) server.close();
      rmSync(root, { recursive: true, force: true });
    });
    return path.join(root, 'api', 'vault.sock');
  }

  it('refuses to start when a sibling role socket accepts a connection (separate-uid)', async () => {
    const socketPath = await layout(['api', 'admin']);
    const reasons: string[] = [];
    const gateway = createVaultGateway({
      socketPath,
      isolation: 'separate-uid',
      client: clientFor('api'),
      onRefused: (reason) => reasons.push(reason),
    });
    const error = await gateway.verify().catch((e: unknown) => e);
    expect(error).toBeInstanceOf(VaultStartupRefusal);
    expect((error as Error).message).toContain('admin-role socket');
    expect(gateway.state()).toBe('refused');
    // Told once, and the refusal is permanent.
    await gateway.verify().catch(() => undefined);
    expect(reasons).toHaveLength(1);
  });

  it('starts when no other role socket accepts a connection', async () => {
    const socketPath = await layout(['api']);
    const gateway = createVaultGateway({
      socketPath,
      isolation: 'separate-uid',
      client: clientFor('api'),
    });
    await expect(gateway.verify()).resolves.toBeUndefined();
    expect(gateway.state()).toBe('ready');
  });

  it('does not probe sibling sockets in shared-uid mode', async () => {
    const socketPath = await layout(['api', 'admin', 'supervisor']);
    const gateway = createVaultGateway({
      socketPath,
      isolation: 'shared-uid',
      client: {
        call: async () => ({ ...(hello('api') as object), isolation: 'shared-uid' }),
      } as never,
    });
    await expect(gateway.verify()).resolves.toBeUndefined();
  });

  it('reports a wrong role once', async () => {
    const socketPath = await layout(['api']);
    const reasons: string[] = [];
    const gateway = createVaultGateway({
      socketPath,
      isolation: 'separate-uid',
      client: clientFor('admin'),
      onRefused: (reason) => reasons.push(reason),
    });
    await gateway.verify().catch(() => undefined);
    await gateway.verify().catch(() => undefined);
    expect(reasons).toEqual([expect.stringContaining('role other than api')]);
  });
});
