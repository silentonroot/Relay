import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { VAULT_MAX_PLAINTEXT_BYTES } from '@aab/contracts';
import { rowsOf } from '../../../packages/database/src/client.js';
import { inspectStorageState, MAX_SESSION_LIFETIME_MS } from '../src/operations.js';
import {
  auditEvents,
  b64url,
  capabilityRowOf,
  completeParams,
  errorCode,
  ok,
  openStored,
  prepare,
  seedLoginJob,
  seedTenant,
  sql,
  startService,
  storageStateJson,
} from './service-helpers.js';
import type { Service } from './service-helpers.js';

/*
 * B2 review fix 8: the vault does not seal anything that is not a Playwright storage state, and
 * does not record an expiry it cannot stand behind. (The supervisor still filters by origin;
 * docs/phase-3.md B3 lists what it must keep doing.)
 */

let service: Service;
beforeAll(async () => {
  service = await startService();
});
afterAll(async () => {
  await service.cleanup();
});

describe('inspectStorageState', () => {
  const buf = (value: unknown) => Buffer.from(JSON.stringify(value), 'utf8');
  it('accepts cookies and origins arrays and counts them', () => {
    expect(
      inspectStorageState(
        buf({ cookies: [{ name: 'a' }, { name: 'b' }], origins: [{ origin: 'x' }] }),
      ),
    ).toEqual({ cookieCount: 2, originCount: 1 });
    expect(inspectStorageState(buf({ cookies: [], origins: [{ origin: 'x' }] }))).toEqual({
      cookieCount: 0,
      originCount: 1,
    });
  });

  it('refuses empty, oversized, non-JSON and wrongly shaped input', () => {
    const problem = (input: Buffer) => (inspectStorageState(input) as { problem: string }).problem;
    expect(problem(Buffer.alloc(0))).toBe('empty');
    expect(problem(Buffer.alloc(VAULT_MAX_PLAINTEXT_BYTES + 1, 0x20))).toBe('too_large');
    expect(problem(Buffer.from('not json'))).toBe('not_json');
    expect(problem(buf({ cookies: [], origins: [] }))).toBe('empty_state');
    for (const wrong of [
      [],
      5,
      null,
      'x',
      {},
      { cookies: [] },
      { origins: [] },
      { cookies: {}, origins: [] },
      { cookies: [], origins: 'x' },
      { cookies: [1], origins: [] },
      { cookies: [null], origins: [] },
      { cookies: [[]], origins: [] },
    ]) {
      expect(problem(buf(wrong)), JSON.stringify(wrong)).toBe('shape');
    }
  });
});

describe('completeLogin sanity checks', () => {
  async function login(label: string) {
    const tenant = await seedTenant(service.repos, label);
    const fixture = await seedLoginJob(service, tenant);
    return { tenant, fixture, prepared: await prepare(service, fixture) };
  }

  it('refuses a state that is not JSON, not the storage-state shape, or empty, and keeps the capability', async () => {
    const { tenant, fixture, prepared } = await login('sanity-bad');
    for (const bad of ['not json at all', '[]', '{"cookies":[]}', '{"cookies":[],"origins":[]}']) {
      const response = await service.rpc(
        'supervisor',
        'completeLogin',
        completeParams(prepared, bad),
      );
      expect(errorCode(response), bad).toBe('validation_failed');
    }
    // Nothing was sealed, the capability is unspent, and a good state still completes the login.
    expect(await openStored(service, tenant, fixture.connectionId)).toBeNull();
    expect((await capabilityRowOf(service, prepared.capabilityId))['used_at']).toBeNull();
    ok(
      await service.rpc(
        'supervisor',
        'completeLogin',
        completeParams(prepared, storageStateJson()),
      ),
    );
    expect(await openStored(service, tenant, fixture.connectionId)).toBe(storageStateJson());
  });

  it('refuses an expiry in the past', async () => {
    const { prepared } = await login('sanity-past');
    const response = await service.rpc(
      'supervisor',
      'completeLogin',
      completeParams(prepared, storageStateJson(), {
        sessionExpiresAt: '2020-01-01T00:00:00.000Z',
      }),
    );
    expect(errorCode(response)).toBe('validation_failed');
    expect((await capabilityRowOf(service, prepared.capabilityId))['used_at']).toBeNull();
  });

  it('bounds a far-future expiry to 400 days', async () => {
    const { tenant, fixture, prepared } = await login('sanity-future');
    const before = Date.now();
    ok(
      await service.rpc(
        'supervisor',
        'completeLogin',
        completeParams(prepared, storageStateJson(), {
          sessionExpiresAt: '2999-01-01T00:00:00.000Z',
        }),
      ),
    );
    const row = rowsOf(
      await service.db.execute(
        sql`select session_expires_at from connections where id = ${fixture.connectionId}::uuid`,
      ),
    )[0]!;
    const stored = new Date(row['session_expires_at'] as string).getTime();
    expect(stored).toBeGreaterThanOrEqual(before + MAX_SESSION_LIFETIME_MS - 1_000);
    expect(stored).toBeLessThanOrEqual(Date.now() + MAX_SESSION_LIFETIME_MS + 1_000);
    const completed = await auditEvents(
      service,
      tenant.organization.id,
      'connection.auth_completed',
    );
    const metadata = completed[0]!['metadata'] as { sessionExpiresAt: string };
    expect(new Date(metadata.sessionExpiresAt).getTime()).toBe(stored);
  });

  it('records the origin count and the Phase 2 snapshot version in the audit event', async () => {
    const { tenant, prepared } = await login('sanity-audit');
    const state = JSON.stringify({
      cookies: [{ name: 'a' }, { name: 'b' }],
      origins: [{ origin: 'http://localhost', localStorage: [] }],
    });
    ok(await service.rpc('supervisor', 'completeLogin', completeParams(prepared, state)));
    const stored = await auditEvents(service, tenant.organization.id, 'vault.secret_stored');
    expect(stored).toHaveLength(1);
    expect(stored[0]!['metadata']).toMatchObject({
      entryVersion: 1,
      snapshotVersion: 1,
      originCount: 1,
      role: 'supervisor',
    });
    expect(stored[0]!['actor_type']).toBe('system');
    void b64url;
  });
});
