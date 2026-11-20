import { Routes, VAULT_KEY_PROTECTION_STATEMENT, VaultKeyStatus } from '@aab/contracts';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createVaultGateway } from '../src/vault/gateway.js';
import { startFakeVault } from './fake-vault.js';
import type { FakeVault } from './fake-vault.js';
import type { Harness, SignedIn } from './helpers.js';
import {
  createHarness,
  expectError,
  expectNoSecretLeaks,
  login,
  path,
  seedOwner,
  seedTenant,
} from './helpers.js';

const owner = { email: 'owner@example.test', password: 'vault status owner password' };
const member = { email: 'member@example.test', password: 'vault status member password' };

const STATUS = {
  isolation: 'shared-uid',
  kekVersions: [1, 2],
  currentKekVersion: 2,
  versionsByKek: { '1': 3, '2': 7 },
  missingKekVersions: [],
  counters: { internalFailures: 0, rejectedAudited: 4 },
};

describe('GET /vault/status', () => {
  let vault: FakeVault;
  let withVault: Harness;
  let withoutVault: Harness;
  let ownerSession: SignedIn;
  let memberSession: SignedIn;
  let plainSession: SignedIn;

  beforeAll(async () => {
    vault = await startFakeVault({
      hello: { currentKekVersion: 2 },
      handle: (operation) => (operation === 'status' ? { result: STATUS } : { error: 'forbidden' }),
    });
    withVault = await createHarness({
      vault: createVaultGateway({
        socketPath: vault.socketPath,
        isolation: 'shared-uid',
        timeoutMs: 500,
      }),
    });
    await seedOwner(withVault, owner);
    await seedTenant(withVault, member, 'Member Org', 'member');
    ownerSession = await login(withVault, owner);
    memberSession = await login(withVault, member);

    withoutVault = await createHarness();
    await seedOwner(withoutVault, owner);
    plainSession = await login(withoutVault, owner);
  }, 60_000);

  afterAll(async () => {
    await expectNoSecretLeaks(withVault);
    await withVault.close();
    await withoutVault.close();
    await vault.close();
  });

  it('gives the owner the vault status, metadata only', async () => {
    const response = await withVault.inject({
      method: 'GET',
      url: path(Routes.vaultStatus),
      headers: { cookie: ownerSession.cookie },
    });
    expect(response.statusCode, response.body).toBe(200);
    expect(VaultKeyStatus.parse(response.json())).toEqual({
      ...STATUS,
      protectionStatement: VAULT_KEY_PROTECTION_STATEMENT,
    });
    // hello first (the start-up check), then status; the API asked as itself and nothing else.
    expect(vault.requests.map((request) => request.operation)).toEqual(['hello', 'status']);
  });

  it('is for owners only', async () => {
    const before = vault.requests.length;
    expectError(
      await withVault.inject({
        method: 'GET',
        url: path(Routes.vaultStatus),
        headers: { cookie: memberSession.cookie },
      }),
      403,
      'forbidden',
    );
    expect(vault.requests.length).toBe(before);
  });

  it('is a 503 without a vault, and when the vault stops answering', async () => {
    expectError(
      await withoutVault.inject({
        method: 'GET',
        url: path(Routes.vaultStatus),
        headers: { cookie: plainSession.cookie },
      }),
      503,
      'service_unavailable',
    );
    const down = await createHarness({
      vault: createVaultGateway({
        socketPath: '/nonexistent/aab-vault/api/vault.sock',
        isolation: 'shared-uid',
        timeoutMs: 300,
      }),
    });
    try {
      await seedOwner(down, owner);
      const session = await login(down, owner);
      const body = expectError(
        await down.inject({
          method: 'GET',
          url: path(Routes.vaultStatus),
          headers: { cookie: session.cookie },
        }),
        503,
        'service_unavailable',
      );
      expect(JSON.stringify(body)).not.toContain('nonexistent');
    } finally {
      await down.close();
    }
  });
});
