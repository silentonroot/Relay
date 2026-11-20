import { createHash, randomBytes, randomUUID } from 'node:crypto';
import {
  CapabilityRejectionReason,
  ConnectionVaultMetadata,
  CSRF_HEADER,
  DeleteStoredSessionResult,
  OperationJob,
  RevokeCapabilitiesResult,
  Routes,
  SESSION_SNAPSHOT_SECRET_TYPE,
  VAULT_DASHBOARD_RESPONSE_SCHEMAS,
  VAULT_KEY_PROTECTION_STATEMENT,
  VaultKeyStatus,
} from '@aab/contracts';
import { schema } from '@aab/database';
import type { DatabaseHandle } from '@aab/database';
import { createTestDatabase, sql } from '@aab/database/testing';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { walkJson, walkSchema } from '../../../packages/contracts/test/forbidden-fields.js';
import { createVaultGateway } from '../src/vault/gateway.js';
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
import { executeFor, newWorld, registerApplication, startRealVault } from './vault-world.js';
import type { RealVault, World } from './vault-world.js';

/*
 * Step B5a: the vault metadata reads and the two lifecycle actions, against a REAL vault (for
 * capability authorizations and the key status) on the database the API shares with it.
 */

const owner = { email: 'owner@example.test', password: 'vault dashboard owner password' };
const admin = { email: 'admin@example.test', password: 'vault dashboard admin password' };
const member = { email: 'member@example.test', password: 'vault dashboard member password' };
const stranger = { email: 'stranger@example.test', password: 'vault dashboard stranger password' };
const NO_VAULT_SOCKET = '/nonexistent/aab-vault/api/vault.sock';
const realClock = () => new Date();

// Synthetic stored-session canaries: none of these may appear in any response.
const CIPHERTEXT = 'synthetic-ciphertext-b5a-canary';
const WRAPPED_DEK = 'synthetic-wrapped-dek-b5a-canary';
const NONCE = randomBytes(12);
const AUTH_TAG = randomBytes(16);
const SEALED = {
  algorithm: 'aab-envelope-v1/aes-256-gcm',
  ciphertext: Buffer.from(CIPHERTEXT),
  nonce: NONCE,
  authTag: AUTH_TAG,
  wrappedDek: Buffer.from(WRAPPED_DEK),
  kekVersion: 1,
  aadVersion: 1,
} as const;

/** One sealed column value in every form a response could leak it in. */
const forms = (value: Buffer): string[] => [
  value.toString('utf8'),
  value.toString('base64'),
  value.toString('base64url'),
  value.toString('hex'),
  JSON.stringify(value), // Buffer-JSON: {"type":"Buffer","data":[...]}
  `[${[...value].join(',')}]`,
];

const sha256Hex = (value: string) => createHash('sha256').update(value, 'utf8').digest('hex');

describe('vault metadata and lifecycle actions (step B5a)', () => {
  let database: DatabaseHandle;
  let vault: RealVault;
  let h: Harness;
  /** Same database, a vault that is not there: the actions must not need it. */
  let down: Harness;
  let ownerSession: SignedIn;
  let ownerDown: SignedIn;
  let adminSession: SignedIn;
  let memberSession: SignedIn;
  let strangerSession: SignedIn;
  let applicationId: string;
  const scope = () => ({
    organizationId: ownerSession.organizationId,
    userId: ownerSession.userId,
  });

  beforeAll(async () => {
    database = await createTestDatabase();
    vault = await startRealVault(database);
    h = await createHarness({ vault: vault.gateway, clock: realClock, database });
    await seedOwner(h, owner);
    ownerSession = await login(h, owner);
    await seedTenant(h, admin, 'unused', 'admin', ownerSession.organizationId);
    await seedTenant(h, member, 'unused', 'member', ownerSession.organizationId);
    await seedTenant(h, stranger, 'Other Org', 'owner');
    adminSession = await login(h, admin);
    memberSession = await login(h, member);
    strangerSession = await login(h, stranger);
    applicationId = await registerApplication(h, ownerSession);
    down = await createHarness({
      vault: createVaultGateway({
        socketPath: NO_VAULT_SOCKET,
        isolation: 'shared-uid',
        timeoutMs: 100,
      }),
      clock: realClock,
      database,
    });
    ownerDown = await login(down, owner);
  }, 120_000);

  afterAll(async () => {
    await expectNoSecretLeaks(h);
    // Every response the suite recorded, vault routes or not, holds no sealed column value.
    const sealedValues = [SEALED.ciphertext, SEALED.nonce, SEALED.authTag, SEALED.wrappedDek];
    for (const response of [...h.responses, ...down.responses]) {
      for (const value of sealedValues.flatMap(forms)) {
        expect(response.body.includes(value), `sealed value in a response: ${value}`).toBe(false);
      }
    }
    await expectNoSecretLeaks(down);
    await down.close();
    await h.close();
    await vault.stop();
    await vault.service.dbHandle.close();
  });

  /* ------------------------------------------------------------ helpers */

  /** An active connection with a stored version, an agent with a grant, and one authorization. */
  async function seed(options: { stored?: boolean; authorize?: boolean } = {}) {
    const world: World = await newWorld(h, ownerSession, applicationId);
    let secretId: string | null = null;
    if (options.stored !== false) {
      const ensured = await h.repos.vault.ensureSecret({
        connectionId: world.connectionId,
        secretType: SESSION_SNAPSHOT_SECRET_TYPE,
        now: new Date(),
      });
      secretId = ensured.secretId;
      await h.repos.vault.putVersion({
        secretId,
        version: ensured.nextVersion,
        sealed: SEALED,
        now: new Date(),
      });
    }
    let jobId: string | null = null;
    let capabilityId: string | null = null;
    if (options.authorize !== false) {
      const response = await executeFor(h, ownerSession, world);
      expect(response.statusCode, response.body).toBe(202);
      jobId = OperationJob.parse(response.json()).jobId;
      capabilityId = (await capabilityRowsFor(world.connectionId))[0]!.id;
    }
    return { ...world, secretId, jobId, capabilityId };
  }

  const capabilityRowsFor = async (connectionId: string) =>
    (await h.database.db.select().from(schema.vaultAccessCapabilities)).filter(
      (row) => row.connectionId === connectionId,
    );
  const secretRowsFor = async (connectionId: string) =>
    (await h.database.db.select().from(schema.vaultSecrets)).filter(
      (row) => row.connectionId === connectionId,
    );
  const versionCount = async (connectionId: string) => {
    const secretIds = (await secretRowsFor(connectionId)).map((row) => row.id);
    return (await h.database.db.select().from(schema.vaultSecretVersions)).filter((row) =>
      secretIds.includes(row.secretId),
    ).length;
  };
  const connectionStatus = async (connectionId: string) =>
    (await h.repos.connections.get(scope(), connectionId))!.status;
  const eventTypes = async (connectionId: string) =>
    (await h.repos.audit.list(scope(), { limit: 200, connectionId })).items.map(
      (event) => event.eventType,
    );

  const get = (session: SignedIn, id: string, harness: Harness = h) =>
    harness.inject({
      method: 'GET',
      url: path(Routes.connectionVault, { id }),
      headers: { cookie: session.cookie },
    });
  const post = (
    route: string,
    session: SignedIn,
    id: string,
    headers: Record<string, string> = session.headers,
    harness: Harness = h,
  ) => harness.inject({ method: 'POST', url: path(route, { id }), headers });
  const deleteSession = (session: SignedIn, id: string, harness: Harness = h) =>
    post(Routes.connectionVaultDeleteSession, session, id, session.headers, harness);
  const revokeCapabilities = (session: SignedIn, id: string) =>
    post(Routes.connectionVaultRevokeCapabilities, session, id);

  /** Issues a token for the connection's authorized job, as the supervisor would. */
  async function issueToken(jobId: string, capabilityId: string) {
    const record = (await h.repos.capabilities.getAuthorization(capabilityId))!;
    await h.database.db.execute(
      sql`update execution_jobs set status = 'running', worker_id = 'worker-1', attempt_count = 1, lease_expires_at = now() + interval '60 seconds' where id = ${jobId}::uuid`,
    );
    const token = randomBytes(32).toString('base64url');
    const tokenHash = sha256Hex(token);
    const issued = await h.repos.capabilities.issueToken({
      capabilityId,
      jobId,
      workerId: 'worker-1',
      attempt: 1,
      tokenHash,
      tokenTtlSeconds: 30,
      now: new Date(),
      authorizationMac: record.authorizationMac,
      computeTokenMac: () => 'b'.repeat(64),
    });
    expect(issued).not.toBeNull();
    return tokenHash;
  }
  const consume = (tokenHash: string, world: { jobId: string | null; connectionId: string }) =>
    h.repos.capabilities.consumeRead({
      tokenHash,
      jobId: world.jobId!,
      connectionId: world.connectionId,
      operation: 'orders.list',
      now: new Date(),
    });

  /**
   * Every field name of the real JSON is metadata, no string value looks like a hash, a MAC or an
   * encoded blob, and no sealed column of any stored version (the synthetic values above and
   * every row now in the table) appears in any form.
   */
  async function expectMetadataOnly(body: string, minimumFields: number) {
    const walk = walkJson(JSON.parse(body));
    expect(walk.fields.length).toBeGreaterThanOrEqual(minimumFields);
    expect(walk.violations).toEqual([]);
    const rows = await h.database.db.select().from(schema.vaultSecretVersions);
    const sealed = [
      SEALED.ciphertext,
      SEALED.nonce,
      SEALED.authTag,
      SEALED.wrappedDek,
      ...rows.flatMap((row) => [row.ciphertext, row.nonce, row.authTag, row.wrappedDek]),
    ];
    for (const value of sealed.flatMap(forms)) {
      expect(body.includes(value), `sealed value in response: ${value}`).toBe(false);
    }
  }

  /**
   * No authorization MAC, token hash or token MAC of any capability row is in the body. With
   * `tokenFor` (a connection id) the test says a token was issued for that connection, and the
   * check refuses to pass unless that connection's row actually holds a token hash and a token
   * MAC to look for.
   */
  async function expectNoMacOrTokenHashIn(body: string, options: { tokenFor?: string } = {}) {
    const rows = await h.database.db.select().from(schema.vaultAccessCapabilities);
    expect(rows.length).toBeGreaterThan(0);
    let tokenValues = 0;
    for (const row of rows) {
      for (const value of [row.authorizationMac, row.tokenHash, row.tokenMac]) {
        if (value !== null)
          expect(body.includes(value), 'MAC or token hash in a response').toBe(false);
      }
      if (
        row.connectionId === options.tokenFor &&
        row.tokenHash !== null &&
        row.tokenMac !== null
      ) {
        tokenValues += 1;
      }
    }
    if (options.tokenFor !== undefined) expect(tokenValues).toBeGreaterThan(0);
  }

  const jobRow = async (jobId: string) =>
    (await h.database.db.select().from(schema.executionJobs)).find((row) => row.id === jobId)!;
  /** A second job (queued) on the world's connection, with its capability. */
  async function secondJob(world: World) {
    const response = await executeFor(h, ownerSession, world);
    expect(response.statusCode, response.body).toBe(202);
    const jobId = OperationJob.parse(response.json()).jobId;
    const capability = (await capabilityRowsFor(world.connectionId)).find(
      (row) => row.jobId === jobId,
    )!;
    return { jobId, capabilityId: capability.id };
  }

  /* ------------------------------------------------------------ the read */

  describe('GET /connections/:id/vault', () => {
    it('shows metadata for the owner: secret, version, key version, 24-hour counts', async () => {
      const w = await seed();
      const response = await get(ownerSession, w.connectionId);
      expect(response.statusCode, response.body).toBe(200);
      const body = ConnectionVaultMetadata.parse(response.json());
      expect(body).toMatchObject({
        connectionId: w.connectionId,
        connectionStatus: 'active',
        secrets: [
          {
            secretType: SESSION_SNAPSHOT_SECRET_TYPE,
            status: 'active',
            activeVersion: 1,
            kekVersion: 1,
            lastAccessedAt: null,
          },
        ],
        capabilities: { windowHours: 24, authorized: 1, used: 0, revoked: 0, rejected: [] },
      });
      await expectMetadataOnly(response.body, 10);
      await expectNoMacOrTokenHashIn(response.body);
    });

    it('counts rejections by reason, apart from each other', async () => {
      const w = await seed();
      const tokenHash = await issueToken(w.jobId!, w.capabilityId!);
      expect(await consume(tokenHash, w)).not.toBeNull();
      // The same token again: `used`. An unknown token: `unknown_token`.
      for (const hash of [tokenHash, sha256Hex('another token'), sha256Hex('and another')]) {
        const rejection = await h.repos.capabilities.describeForRejection({
          tokenHash: hash,
          jobId: w.jobId!,
          connectionId: w.connectionId,
          operation: 'orders.list',
          now: new Date(),
          purpose: 'read',
        });
        await h.repos.capabilities.recordRejection(rejection, {
          role: 'supervisor',
          now: new Date(),
        });
      }
      const response = await get(ownerSession, w.connectionId);
      const body = ConnectionVaultMetadata.parse(response.json());
      expect(body.capabilities).toMatchObject({ authorized: 1, used: 1, revoked: 0 });
      expect(body.capabilities.rejected).toEqual([
        { reason: 'unknown_token', count: 2 },
        { reason: 'used', count: 1 },
      ]);
      await expectMetadataOnly(response.body, 12);
      await expectNoMacOrTokenHashIn(response.body, { tokenFor: w.connectionId });
    });

    it('lists every rejection reason the enum has (a new reason cannot be silently dropped)', async () => {
      const w = await seed({ authorize: false });
      for (const reason of CapabilityRejectionReason.options) {
        await h.repos.audit.append({
          organizationId: ownerSession.organizationId,
          actorType: 'system',
          actorId: null,
          agentId: null,
          connectionId: w.connectionId,
          eventType: 'vault.capability_rejected',
          decision: 'deny',
          timestamp: new Date(),
          metadata: { reason },
        });
      }
      const body = ConnectionVaultMetadata.parse((await get(ownerSession, w.connectionId)).json());
      expect(body.capabilities.rejected.map((entry) => entry.reason).sort()).toEqual(
        [...CapabilityRejectionReason.options].sort(),
      );
      expect(body.capabilities.rejected.every((entry) => entry.count === 1)).toBe(true);
    });

    it('is 404 for another owner, another organization, a teammate of any role, and an unknown id', async () => {
      const w = await seed();
      const unknown = '00000000-0000-4000-8000-000000000000';
      for (const session of [strangerSession, adminSession, memberSession]) {
        expectError(await get(session, w.connectionId), 404, 'not_found');
      }
      const own = await get(ownerSession, unknown);
      expectError(own, 404, 'not_found');
      // The same body as an id that never existed: no sign that the connection is real.
      const foreign = await get(strangerSession, w.connectionId);
      expect(foreign.json().error.message).toBe(own.json().error.message);
    });

    it('is 401 without a session', async () => {
      const w = await seed({ authorize: false });
      expectError(
        await h.inject({
          method: 'GET',
          url: path(Routes.connectionVault, { id: w.connectionId }),
        }),
        401,
        'unauthenticated',
      );
    });

    it('shows a deleted secret with no version after the session is deleted', async () => {
      const w = await seed();
      expect((await deleteSession(ownerSession, w.connectionId)).statusCode).toBe(200);
      const body = ConnectionVaultMetadata.parse((await get(ownerSession, w.connectionId)).json());
      expect(body.connectionStatus).toBe('reconnect_required');
      expect(body.secrets).toEqual([
        {
          secretType: SESSION_SNAPSHOT_SECRET_TYPE,
          status: 'deleted',
          activeVersion: null,
          kekVersion: null,
          lastAccessedAt: null,
        },
      ]);
      expect(body.capabilities).toMatchObject({ authorized: 1, revoked: 1 });
    });
  });

  /* ------------------------------------------------------------ key status */

  describe('GET /vault/status', () => {
    it('gives the owner key versions, versions per key version, missing versions, isolation and the ADR-003 statement', async () => {
      await seed();
      const response = await h.inject({
        method: 'GET',
        url: path(Routes.vaultStatus),
        headers: { cookie: ownerSession.cookie },
      });
      expect(response.statusCode, response.body).toBe(200);
      const body = VaultKeyStatus.parse(response.json());
      expect(body.protectionStatement).toBe(VAULT_KEY_PROTECTION_STATEMENT);
      expect(body.kekVersions.length).toBeGreaterThan(0);
      expect(body.missingKekVersions).toEqual([]);
      expect(Object.keys(body.versionsByKek).length).toBeGreaterThan(0);
      expect(['separate-uid', 'shared-uid']).toContain(body.isolation);
      // The real status object, including the vault's own counter names (dynamic keys).
      await expectMetadataOnly(response.body, 8);
    });

    it('is owner-only (403 for admin and member) and 503 when the vault is down', async () => {
      for (const session of [adminSession, memberSession]) {
        expectError(
          await h.inject({
            method: 'GET',
            url: path(Routes.vaultStatus),
            headers: { cookie: session.cookie },
          }),
          403,
          'forbidden',
        );
      }
      expectError(
        await down.inject({
          method: 'GET',
          url: path(Routes.vaultStatus),
          headers: { cookie: ownerDown.cookie },
        }),
        503,
        'service_unavailable',
      );
    });
  });

  /* ------------------------------------------------------------ delete stored session */

  describe('POST /connections/:id/vault/delete-session', () => {
    it('is one transaction: versions gone, secret deleted, capabilities revoked, reconnect required, events written', async () => {
      const w = await seed();
      const tokenHash = await issueToken(w.jobId!, w.capabilityId!);
      expect(await versionCount(w.connectionId)).toBe(1);
      await h.repos.connections.recordSession(w.connectionId, {
        externalAccountHint: null,
        sessionExpiresAt: new Date(Date.now() + 86_400_000),
        lastVerifiedAt: new Date(),
      });
      expect(
        (await h.repos.connections.get(scope(), w.connectionId))!.sessionExpiresAt,
      ).not.toBeNull();

      const response = await deleteSession(ownerSession, w.connectionId);
      expect(response.statusCode, response.body).toBe(200);
      expect(DeleteStoredSessionResult.parse(response.json())).toEqual({
        connectionId: w.connectionId,
        connectionStatus: 'reconnect_required',
        versionsDeleted: 1,
        capabilitiesRevoked: 1,
        jobsCancelled: 1,
      });
      await expectMetadataOnly(response.body, 5);
      await expectNoMacOrTokenHashIn(response.body, { tokenFor: w.connectionId });

      expect(await versionCount(w.connectionId)).toBe(0);
      const [secret] = await secretRowsFor(w.connectionId);
      expect(secret).toMatchObject({ status: 'deleted', activeVersionId: null });
      const [capability] = await capabilityRowsFor(w.connectionId);
      expect(capability!.revokedAt).not.toBeNull();
      expect(capability!.revokedReason).toBe('session_deleted');
      expect(await connectionStatus(w.connectionId)).toBe('reconnect_required');
      expect((await h.repos.connections.get(scope(), w.connectionId))!.sessionExpiresAt).toBeNull();
      const events = (
        await h.repos.audit.list(scope(), { limit: 200, connectionId: w.connectionId })
      ).items;
      const byType = (type: string) => events.filter((event) => event.eventType === type);
      expect(byType('vault.secret_deleted')).toHaveLength(1);
      expect(byType('vault.secret_deleted')[0]).toMatchObject({
        actorType: 'user',
        actorId: ownerSession.userId,
        metadata: { versionsDeleted: 1, vaultEntryIds: [w.secretId] },
      });
      expect(byType('vault.capability_revoked')).toHaveLength(1);
      expect(byType('vault.capability_revoked')[0]).toMatchObject({
        actorType: 'user',
        metadata: { reason: 'session_deleted', count: 1 },
      });
      expect(
        byType('connection.status_changed').some(
          (event) => (event.metadata as { status?: string }).status === 'reconnect_required',
        ),
      ).toBe(true);
      // Nothing that was stored remains where a response or an event could carry it.
      expect(JSON.stringify(events).includes(CIPHERTEXT)).toBe(false);

      // A worker that held a token for the revoked capability is refused.
      expect(await consume(tokenHash, w)).toBeNull();
    });

    it("cancels the connection's jobs like revoking does: queued end cancelled, running are flagged, no capability is rejected", async () => {
      const w = await seed();
      const queuedAlso = await secondJob(w);
      // The first job runs (a token was issued for it); the second stays queued.
      await issueToken(w.jobId!, w.capabilityId!);
      expect((await jobRow(queuedAlso.jobId)).status).toBe('queued');

      const response = await deleteSession(ownerSession, w.connectionId);
      expect(response.statusCode, response.body).toBe(200);
      expect(DeleteStoredSessionResult.parse(response.json())).toMatchObject({
        capabilitiesRevoked: 2,
        jobsCancelled: 2,
      });

      const queued = await jobRow(queuedAlso.jobId);
      expect(queued).toMatchObject({ status: 'cancelled', errorCode: 'cancelled' });
      expect(queued.finishedAt).not.toBeNull();
      const running = await jobRow(w.jobId!);
      expect(running.status).toBe('running');
      expect(running.cancelRequestedAt).not.toBeNull();
      // Not `vault_denied`, and no rejection event for the owner's own action.
      for (const job of [queued, running]) expect(job.errorCode).not.toBe('vault_denied');
      const events = (
        await h.repos.audit.list(scope(), { limit: 200, connectionId: w.connectionId })
      ).items;
      expect(events.map((event) => event.eventType)).not.toContain('vault.capability_rejected');
      expect(
        events.find((event) => event.eventType === 'vault.secret_deleted')!.metadata,
      ).toMatchObject({ jobsCancelled: 2 });
    });

    it.each([
      ['authenticating', ['authenticating']],
      ['authentication_required', ['authenticating', 'authentication_required']],
    ] as const)('is 409 for a connection in %s, and nothing changes', async (status, steps) => {
      // A stored session and a capability exist, as after an earlier login, but the connection
      // is mid-login or waiting for one: it cannot move to reconnect_required.
      const w = await seed();
      for (const step of ['reconnect_required', ...steps] as const) {
        await h.repos.connections.transitionStatus(scope(), w.connectionId, { to: step });
      }
      expect(await connectionStatus(w.connectionId)).toBe(status);
      const before = {
        versions: await versionCount(w.connectionId),
        secrets: await secretRowsFor(w.connectionId),
        capabilities: await capabilityRowsFor(w.connectionId),
        events: await eventTypes(w.connectionId),
        job: await jobRow(w.jobId!),
      };
      expectError(await deleteSession(ownerSession, w.connectionId), 409, 'conflict');
      expect(await connectionStatus(w.connectionId)).toBe(status);
      expect(await versionCount(w.connectionId)).toBe(before.versions);
      expect(await secretRowsFor(w.connectionId)).toEqual(before.secrets);
      expect(await capabilityRowsFor(w.connectionId)).toEqual(before.capabilities);
      expect(await eventTypes(w.connectionId)).toEqual(before.events);
      expect(await jobRow(w.jobId!)).toEqual(before.job);
    });

    it('is 409 for a freshly created connection, and nothing changes', async () => {
      const w = await newWorld(h, ownerSession, applicationId, 'created');
      const events = await eventTypes(w.connectionId);
      expectError(await deleteSession(ownerSession, w.connectionId), 409, 'conflict');
      expect(await connectionStatus(w.connectionId)).toBe('created');
      expect(await secretRowsFor(w.connectionId)).toEqual([]);
      expect(await eventTypes(w.connectionId)).toEqual(events);
    });

    it('works while the vault is down', async () => {
      const w = await seed();
      const response = await deleteSession(ownerDown, w.connectionId, down);
      expect(response.statusCode, response.body).toBe(200);
      expect(await versionCount(w.connectionId)).toBe(0);
      expect(await connectionStatus(w.connectionId)).toBe('reconnect_required');
      expect((await capabilityRowsFor(w.connectionId))[0]!.revokedAt).not.toBeNull();
    });

    it('is 409 for a connection with no stored session, and leaves it exactly as it was (rollback)', async () => {
      const w = await seed({ stored: false, authorize: false });
      const refused = expectError(
        await deleteSession(ownerSession, w.connectionId),
        409,
        'conflict',
      );
      expect(refused.error.message).toBe('This connection has no stored session to delete.');
      // The transition to reconnect_required was part of the transaction and rolled back.
      expect(await connectionStatus(w.connectionId)).toBe('active');
      expect(await eventTypes(w.connectionId)).not.toContain('vault.secret_deleted');
    });

    it('is 409 twice in a row and for a revoked connection', async () => {
      const w = await seed();
      expect((await deleteSession(ownerSession, w.connectionId)).statusCode).toBe(200);
      const repeat = expectError(
        await deleteSession(ownerSession, w.connectionId),
        409,
        'conflict',
      );
      expect(repeat.error.message).toBe('This connection has no stored session to delete.');
      expect(
        (
          await h.repos.audit.list(scope(), { limit: 200, connectionId: w.connectionId })
        ).items.filter((event) => event.eventType === 'vault.secret_deleted'),
      ).toHaveLength(1);

      const revoked = await seed();
      expect(
        (
          await h.inject({
            method: 'POST',
            url: path(Routes.connectionRevoke, { id: revoked.connectionId }),
            headers: ownerSession.headers,
          })
        ).statusCode,
      ).toBe(200);
      const afterRevoke = expectError(
        await deleteSession(ownerSession, revoked.connectionId),
        409,
        'conflict',
      );
      // No internal state names in the message.
      expect(afterRevoke.error.message).not.toMatch(/revoked|reconnect_required/);
      expect(await connectionStatus(revoked.connectionId)).toBe('revoked');
      expect((await secretRowsFor(revoked.connectionId))[0]!.status).toBe('revoked');
    });

    it('revoking the connection also clears sessionExpiresAt', async () => {
      const w = await seed({ authorize: false });
      await h.repos.connections.recordSession(w.connectionId, {
        externalAccountHint: null,
        sessionExpiresAt: new Date(Date.now() + 86_400_000),
        lastVerifiedAt: new Date(),
      });
      const response = await h.inject({
        method: 'POST',
        url: path(Routes.connectionRevoke, { id: w.connectionId }),
        headers: ownerSession.headers,
      });
      expect(response.statusCode, response.body).toBe(200);
      expect((await h.repos.connections.get(scope(), w.connectionId))!.sessionExpiresAt).toBeNull();
    });

    it('is refused for everyone but the connection owner, and changes nothing', async () => {
      const w = await seed();
      // An owner-role or admin-role teammate does not widen scope: it is another user's connection.
      for (const session of [strangerSession, adminSession, memberSession]) {
        expectError(await deleteSession(session, w.connectionId), 404, 'not_found');
      }
      expectError(
        await deleteSession(ownerSession, '00000000-0000-4000-8000-000000000000'),
        404,
        'not_found',
      );
      expect(await connectionStatus(w.connectionId)).toBe('active');
      expect(await versionCount(w.connectionId)).toBe(1);
      expect((await secretRowsFor(w.connectionId))[0]!.status).toBe('active');
      expect((await capabilityRowsFor(w.connectionId))[0]!.revokedAt).toBeNull();
      expect(await eventTypes(w.connectionId)).not.toContain('vault.secret_deleted');
    });

    it('needs the CSRF token and a session', async () => {
      const w = await seed();
      expectError(
        await post(Routes.connectionVaultDeleteSession, ownerSession, w.connectionId, {
          cookie: ownerSession.cookie,
        }),
        403,
        'csrf_failed',
      );
      expectError(
        await post(Routes.connectionVaultDeleteSession, ownerSession, w.connectionId, {
          cookie: ownerSession.cookie,
          [CSRF_HEADER]: 'not-the-token',
        }),
        403,
        'csrf_failed',
      );
      expectError(
        await post(Routes.connectionVaultDeleteSession, ownerSession, w.connectionId, {}),
        401,
        'unauthenticated',
      );
      expect(await connectionStatus(w.connectionId)).toBe('active');
      expect(await versionCount(w.connectionId)).toBe(1);
    });

    it('a member who owns the connection may delete its session, like revoking it', async () => {
      // Connections belong to one user; the role does not matter, ownership does.
      const memberScope = {
        organizationId: memberSession.organizationId,
        userId: memberSession.userId,
      };
      const connection = await h.repos.connections.create(memberScope, {
        applicationId,
        displayName: 'Member connection',
      });
      for (const step of ['authentication_required', 'authenticating', 'active'] as const) {
        await h.repos.connections.transitionStatus(memberScope, connection.id, { to: step });
      }
      const ensured = await h.repos.vault.ensureSecret({
        connectionId: connection.id,
        secretType: SESSION_SNAPSHOT_SECRET_TYPE,
        now: new Date(),
      });
      await h.repos.vault.putVersion({
        secretId: ensured.secretId,
        version: 1,
        sealed: SEALED,
        now: new Date(),
      });
      // The organization owner cannot touch it.
      expectError(await deleteSession(ownerSession, connection.id), 404, 'not_found');
      expect((await deleteSession(memberSession, connection.id)).statusCode).toBe(200);
    });
  });

  /* ------------------------------------------------------------ revoke capabilities */

  describe('POST /connections/:id/vault/revoke-capabilities', () => {
    it('revokes the unused capabilities in one transaction and leaves the connection and the session alone', async () => {
      const w = await seed();
      const tokenHash = await issueToken(w.jobId!, w.capabilityId!);
      const response = await revokeCapabilities(ownerSession, w.connectionId);
      expect(response.statusCode, response.body).toBe(200);
      expect(RevokeCapabilitiesResult.parse(response.json())).toEqual({
        connectionId: w.connectionId,
        capabilitiesRevoked: 1,
        jobsCancelled: 0,
      });
      await expectMetadataOnly(response.body, 3);
      await expectNoMacOrTokenHashIn(response.body, { tokenFor: w.connectionId });

      const [capability] = await capabilityRowsFor(w.connectionId);
      expect(capability!.revokedAt).not.toBeNull();
      expect(capability!.revokedReason).toBe('owner_requested');
      // The connection and the stored session are untouched.
      expect(await connectionStatus(w.connectionId)).toBe('active');
      expect(await versionCount(w.connectionId)).toBe(1);
      expect((await secretRowsFor(w.connectionId))[0]!.status).toBe('active');
      const types = await eventTypes(w.connectionId);
      expect(types.filter((type) => type === 'vault.capability_revoked')).toHaveLength(1);
      expect(types).not.toContain('vault.secret_deleted');
      // Revoked: the token cannot be consumed, although the connection is still active.
      expect(await consume(tokenHash, w)).toBeNull();
    });

    it('cancels the queued jobs whose capability it revoked, leaves running jobs alone, and no capability is rejected', async () => {
      const w = await seed();
      const queuedAlso = await secondJob(w);
      await issueToken(w.jobId!, w.capabilityId!);
      // A queued job on ANOTHER connection must not be touched.
      const other = await seed();

      const response = await revokeCapabilities(ownerSession, w.connectionId);
      expect(response.statusCode, response.body).toBe(200);
      expect(RevokeCapabilitiesResult.parse(response.json())).toEqual({
        connectionId: w.connectionId,
        capabilitiesRevoked: 2,
        jobsCancelled: 1,
      });
      const queued = await jobRow(queuedAlso.jobId);
      expect(queued).toMatchObject({ status: 'cancelled', errorCode: 'cancelled' });
      const running = await jobRow(w.jobId!);
      expect(running.status).toBe('running');
      expect(running.cancelRequestedAt).toBeNull();
      expect((await jobRow(other.jobId!)).status).toBe('queued');
      const events = (
        await h.repos.audit.list(scope(), { limit: 200, connectionId: w.connectionId })
      ).items;
      expect(events.map((event) => event.eventType)).not.toContain('vault.capability_rejected');
      const revokedEvents = events.filter(
        (event) => event.eventType === 'vault.capability_revoked',
      );
      expect(revokedEvents).toHaveLength(1);
      expect(revokedEvents[0]!.metadata).toMatchObject({
        reason: 'owner_requested',
        count: 2,
        jobsCancelled: 1,
      });
    });

    it('control: the same token IS consumable when nothing was revoked', async () => {
      const w = await seed();
      const tokenHash = await issueToken(w.jobId!, w.capabilityId!);
      expect(await consume(tokenHash, w)).not.toBeNull();
    });

    it('revoking nothing is a 200 with a count of zero and still writes the event (count 0)', async () => {
      const w = await seed({ authorize: false });
      const response = await revokeCapabilities(ownerSession, w.connectionId);
      expect(response.statusCode, response.body).toBe(200);
      expect(RevokeCapabilitiesResult.parse(response.json())).toEqual({
        connectionId: w.connectionId,
        capabilitiesRevoked: 0,
        jobsCancelled: 0,
      });
      const events = (
        await h.repos.audit.list(scope(), { limit: 200, connectionId: w.connectionId })
      ).items.filter((event) => event.eventType === 'vault.capability_revoked');
      expect(events).toHaveLength(1);
      expect(events[0]).toMatchObject({
        actorType: 'user',
        actorId: ownerSession.userId,
        metadata: { reason: 'owner_requested', count: 0, capabilityIds: [], jobsCancelled: 0 },
      });
      // A second call leaves a second trace.
      await revokeCapabilities(ownerSession, w.connectionId);
      expect(
        (await eventTypes(w.connectionId)).filter((type) => type === 'vault.capability_revoked'),
      ).toHaveLength(2);
    });

    it('works while the vault is down', async () => {
      const w = await seed();
      const response = await post(
        Routes.connectionVaultRevokeCapabilities,
        ownerDown,
        w.connectionId,
        ownerDown.headers,
        down,
      );
      expect(response.statusCode, response.body).toBe(200);
      expect((await capabilityRowsFor(w.connectionId))[0]!.revokedAt).not.toBeNull();
    });

    it('is refused for everyone but the connection owner, and changes nothing', async () => {
      const w = await seed();
      for (const session of [strangerSession, adminSession, memberSession]) {
        expectError(await revokeCapabilities(session, w.connectionId), 404, 'not_found');
      }
      expectError(
        await revokeCapabilities(ownerSession, '00000000-0000-4000-8000-000000000000'),
        404,
        'not_found',
      );
      expect((await capabilityRowsFor(w.connectionId))[0]!.revokedAt).toBeNull();
      expect(await eventTypes(w.connectionId)).not.toContain('vault.capability_revoked');
    });

    it('needs the CSRF token and a session', async () => {
      const w = await seed();
      expectError(
        await post(Routes.connectionVaultRevokeCapabilities, ownerSession, w.connectionId, {
          cookie: ownerSession.cookie,
        }),
        403,
        'csrf_failed',
      );
      expectError(
        await post(Routes.connectionVaultRevokeCapabilities, ownerSession, w.connectionId, {}),
        401,
        'unauthenticated',
      );
      expect((await capabilityRowsFor(w.connectionId))[0]!.revokedAt).toBeNull();
    });
  });

  /* ------------------------------------------------------------ the schema rule */

  describe('the leak checks themselves (self-test: they must fail on a leak)', () => {
    it('expectMetadataOnly fails on every sealed column in every form, and on a key-looking value', async () => {
      await seed({ authorize: false });
      for (const value of [SEALED.ciphertext, SEALED.nonce, SEALED.authTag, SEALED.wrappedDek]) {
        // The raw (utf8) form of random bytes is not valid JSON text; the other forms are.
        const printable = value === SEALED.ciphertext || value === SEALED.wrappedDek;
        const independent = [
          value.toString('base64'),
          value.toString('base64url'),
          value.toString('hex'),
          JSON.stringify(value),
        ];
        for (const form of printable ? [value.toString('utf8'), ...independent] : independent) {
          const body = JSON.stringify({ note: `x ${form} y` });
          await expect(expectMetadataOnly(body, 1), form).rejects.toThrow();
        }
      }
      await expect(
        expectMetadataOnly(JSON.stringify({ note: 'ab'.repeat(32) }), 1),
      ).rejects.toThrow();
      await expect(expectMetadataOnly(JSON.stringify({ tokenHash: 'x' }), 1)).rejects.toThrow();
      await expectMetadataOnly(
        JSON.stringify({ id: randomUUID(), at: new Date().toISOString() }),
        2,
      );
    });

    it('expectNoMacOrTokenHashIn fails on a leaked token hash, token MAC or authorization MAC', async () => {
      const w = await seed();
      await issueToken(w.jobId!, w.capabilityId!);
      const [row] = (await capabilityRowsFor(w.connectionId))!;
      for (const value of [row!.tokenHash!, row!.tokenMac!, row!.authorizationMac]) {
        await expect(
          expectNoMacOrTokenHashIn(`{"a":"${value}"}`, { tokenFor: w.connectionId }),
        ).rejects.toThrow();
      }
      await expectNoMacOrTokenHashIn('{"a":"clean"}', { tokenFor: w.connectionId });
      // No token was issued for this connection: the check refuses to pass vacuously.
      const noToken = await seed();
      await expect(
        expectNoMacOrTokenHashIn('{"a":"clean"}', { tokenFor: noToken.connectionId }),
      ).rejects.toThrow();
    });
  });

  describe('the response schemas the routes serve', () => {
    it('are the schemas the forbidden-field test walks, and none has a forbidden field', () => {
      const walked = Object.values(VAULT_DASHBOARD_RESPONSE_SCHEMAS).map(walkSchema);
      expect(walked.reduce((total, walk) => total + walk.fields.length, 0)).toBeGreaterThanOrEqual(
        25,
      );
      for (const walk of walked) expect(walk.violations).toEqual([]);
    });

    it('every vault route serves exactly its entry in VAULT_DASHBOARD_RESPONSE_SCHEMAS (same object)', () => {
      const expected: Record<string, keyof typeof VAULT_DASHBOARD_RESPONSE_SCHEMAS> = {
        'GET /v1/vault/status': 'vaultStatus',
        'GET /v1/connections/:id/vault': 'connectionVault',
        'POST /v1/connections/:id/vault/delete-session': 'deleteStoredSession',
        'POST /v1/connections/:id/vault/revoke-capabilities': 'revokeCapabilities',
      };
      const isVaultRoute = (url: string) =>
        url.startsWith('/v1/vault') || /^\/v1\/connections\/:id\/vault(\/|$)/.test(url);
      const routes = h.app.routeTable.filter(
        (route) => isVaultRoute(route.url) && route.method !== 'HEAD',
      );
      // No vault route is missing from the table, and the table lists no route that is not there.
      expect(routes.map((route) => `${route.method} ${route.url}`).sort()).toEqual(
        Object.keys(expected).sort(),
      );
      for (const route of routes) {
        const key = expected[`${route.method} ${route.url}`]!;
        expect(route.responseSchemas['200'], `${route.method} ${route.url}`).toBe(
          VAULT_DASHBOARD_RESPONSE_SCHEMAS[key],
        );
      }
      // Every table entry is served by some route.
      expect(Object.values(expected).sort()).toEqual(
        Object.keys(VAULT_DASHBOARD_RESPONSE_SCHEMAS).sort(),
      );
    });
  });
});
