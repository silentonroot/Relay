import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  auditEvents,
  CANARY,
  hasPostgres,
  isPlainForbidden,
  prepare,
  readParams,
  rejectedReasons,
  seedSealedOperation,
  seedTenant,
  startService,
} from './service-helpers.js';
import type { Service } from './service-helpers.js';

/*
 * B6a, VS-2 and P3-4 on PostgreSQL: the vault's own pool has several real connections, so 20
 * simultaneous redemptions of one token over the supervisor socket really run in parallel
 * transactions (PGlite serialises them; capability-consume.test.ts covers that case). Skipped
 * without AAB_TEST_DATABASE_URL.
 */

let service: Service;
beforeAll(async () => {
  if (hasPostgres())
    // The default cap is 16 connections per role: 20 clients at once need room, or the surplus
    // is answered at the cap (a different, also correct, refusal) instead of reaching the consume.
    service = await startService({
      postgres: true,
      limits: { supervisor: { maxConnections: 32 } },
    });
});
afterAll(async () => {
  if (hasPostgres()) await service.cleanup();
});

describe.runIf(hasPostgres())('P3-4 / VS-2 on PostgreSQL, through the supervisor socket', () => {
  it('redeems a capability exactly once under 20 simultaneous redemptions', async () => {
    const tenant = await seedTenant(service.repos, 'pg-race');
    const op = await seedSealedOperation(service, tenant);
    const prepared = await prepare(service, op);
    const responses = await Promise.all(
      Array.from({ length: 20 }, () =>
        service.rpc('supervisor', 'readForWorker', readParams(prepared)),
      ),
    );
    const winners = responses.filter((response) => response['ok'] === true);
    expect(winners).toHaveLength(1);
    expect(
      Buffer.from((winners[0]!['result'] as { plaintext: string }).plaintext, 'base64url').toString(
        'utf8',
      ),
    ).toBe(op.plaintext);
    const losers = responses.filter((response) => response['ok'] !== true);
    expect(losers).toHaveLength(19);
    for (const loser of losers) {
      expect(isPlainForbidden(loser), JSON.stringify(loser)).toBe(true);
      expect(JSON.stringify(loser)).not.toContain(CANARY);
    }
    expect(await auditEvents(service, tenant.organization.id, 'vault.secret_read')).toHaveLength(1);
    expect(await rejectedReasons(service, tenant.organization.id)).toEqual(Array(19).fill('used'));
  });
});
