import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { Routes } from '@aab/contracts';
import type { ConnectionStatus } from '@aab/contracts';
import { schema } from '@aab/database';
import type { DatabaseHandle } from '@aab/database';
import { createVaultGateway } from '../src/vault/gateway.js';
import type { VaultGateway } from '../src/vault/gateway.js';
import { makeKekDir, makeSocketDir, removeDir } from '../../vault/test/helpers.js';
import { startService } from '../../vault/test/service-helpers.js';
import type { Service } from '../../vault/test/service-helpers.js';
import type { Harness, SignedIn } from './helpers.js';
import { path } from './helpers.js';

/*
 * Test support: a REAL vault (the real operations, temporary sockets, a temporary key directory)
 * started on the same in-memory database as the API under test, and the API's gateway to its
 * api-role socket. Only the vault touches keys; the API side of the tests never does.
 */

export interface RealVault {
  service: Service;
  gateway: VaultGateway;
  stop(): Promise<void>;
}

export async function startRealVault(database: DatabaseHandle): Promise<RealVault> {
  const socketDir = await makeSocketDir();
  const kekDir = await makeKekDir();
  const service = await startService({ reuse: { dbHandle: database, kekDir, socketDir } });
  const gateway = createVaultGateway({
    socketPath: service.vault.sockets.api,
    isolation: 'shared-uid',
    timeoutMs: 5_000,
  });
  return {
    service,
    gateway,
    async stop() {
      await service.stop().catch(() => undefined);
      await removeDir(socketDir);
      await removeDir(join(kekDir, '..'));
    },
  };
}

export interface World {
  agentId: string;
  connectionId: string;
}

/** Registers the Northstar application and returns its id. */
export async function registerApplication(h: Harness, session: SignedIn): Promise<string> {
  const response = await h.inject({
    method: 'POST',
    url: path(Routes.applicationsRegister),
    headers: session.headers,
    payload: {
      adapterId: 'northstar',
      adapterVersion: '0.1.0',
      name: 'Northstar',
      allowedOrigins: ['https://northstar.example.test'],
      authModes: ['browser_session'],
    },
  });
  return response.json<{ id: string }>().id;
}

/** An agent with an allow grant for `orders.list` on a new connection in `status`. */
export async function newWorld(
  h: Harness,
  session: SignedIn,
  applicationId: string,
  status: ConnectionStatus = 'active',
): Promise<World> {
  const post = (url: string, payload: object) =>
    h.inject({ method: 'POST', url, headers: session.headers, payload });
  const tag = randomUUID().slice(0, 8);
  const scope = { organizationId: session.organizationId, userId: session.userId };
  const connectionId = (
    await post(path(Routes.connections), { applicationId, displayName: `Connection ${tag}` })
  ).json<{ id: string }>().id;
  const agentId = (
    await post(path(Routes.agents), { name: `Agent ${tag}`, clientIdentity: `client-${tag}` })
  ).json<{ id: string }>().id;
  if (status !== 'created') {
    for (const step of ['authentication_required', 'authenticating', 'active'] as const) {
      await h.repos.connections.transitionStatus(scope, connectionId, { to: step });
    }
  }
  const grant = await post(path(Routes.agentGrants, { id: agentId }), {
    connectionId,
    operation: 'orders.list',
  });
  if (grant.statusCode !== 201) throw new Error(`grant failed: ${grant.body}`);
  return { agentId, connectionId };
}

export const executeFor = (h: Harness, session: SignedIn, world: World) =>
  h.inject({
    method: 'POST',
    url: path(Routes.operationsExecute),
    headers: session.headers,
    payload: {
      agentId: world.agentId,
      connectionId: world.connectionId,
      operation: 'orders.list',
      arguments: {},
      idempotencyKey: `key-${randomUUID()}`,
    },
  });

export const capabilityRows = async (h: Harness) =>
  h.database.db.select().from(schema.vaultAccessCapabilities);
