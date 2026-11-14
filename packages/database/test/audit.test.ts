import { verifyChain } from '@aab/audit';
import { AuditEvent } from '@aab/contracts';
import { sql } from 'drizzle-orm';
import type { SQL } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { rowsOf } from '../src/client.js';
import { createRepositories, InvalidCursorError, ValidationError } from '../src/index.js';
import type { DatabaseHandle, Repositories } from '../src/index.js';
import { openTestDb, seedTenant } from './helpers.js';
import type { Tenant } from './helpers.js';

// Obviously fake. Nothing here is a real credential.
const FAKE_SECRET = 'synthetic-not-a-real-secret';

let handle: DatabaseHandle;
let repositories: Repositories;

beforeAll(async () => {
  handle = await openTestDb();
  repositories = createRepositories(handle.db);
});

afterAll(async () => {
  await handle.close();
});

function appendFor(tenant: Tenant, metadata: unknown = {}) {
  return repositories.audit.append({
    organizationId: tenant.organization.id,
    actorType: 'user',
    actorId: tenant.user.id,
    eventType: 'connection.created',
    metadata,
  });
}

async function allEvents(tenant: Tenant): Promise<AuditEvent[]> {
  const page = await repositories.audit.list(tenant.scope, { limit: 200 });
  return page.items.slice().reverse();
}

describe('audit.append', () => {
  it('starts a chain at sequence 1 and links each event to the previous one', async () => {
    const tenant = await seedTenant(repositories, 'audit-chain');
    const first = await appendFor(tenant, { step: 1 });
    const second = await appendFor(tenant, { step: 2 });

    expect(AuditEvent.safeParse(first).success).toBe(true);
    expect(first).toMatchObject({ sequence: 1, previousHash: null, decision: 'not_applicable' });
    expect(second).toMatchObject({ sequence: 2, previousHash: first.eventHash });
    expect(await repositories.audit.verify(tenant.scope)).toEqual({
      ok: true,
      count: 2,
      head: { organizationId: tenant.organization.id, sequence: 2, eventHash: second.eventHash },
    });
  });

  it('keeps one independent chain per organization', async () => {
    const one = await seedTenant(repositories, 'audit-one');
    const two = await seedTenant(repositories, 'audit-two');
    await appendFor(one);
    await appendFor(two);
    await appendFor(one);
    expect((await allEvents(one)).map((event) => event.sequence)).toEqual([1, 2]);
    expect((await allEvents(two)).map((event) => event.sequence)).toEqual([1]);
  });

  it('produces a gapless, verifiable chain from 25 concurrent appends', async () => {
    const tenant = await seedTenant(repositories, 'audit-concurrent');
    const appended = await Promise.all(
      Array.from({ length: 25 }, (_, index) => appendFor(tenant, { index })),
    );
    expect(new Set(appended.map((event) => event.id)).size).toBe(25);

    const events = await allEvents(tenant);
    expect(events.map((event) => event.sequence)).toEqual(
      Array.from({ length: 25 }, (_, i) => i + 1),
    );
    expect(verifyChain(events)).toMatchObject({ ok: true, count: 25 });
    expect(await repositories.audit.verify(tenant.scope)).toMatchObject({ ok: true, count: 25 });
  });

  it('redacts secrets before they reach the database', async () => {
    const tenant = await seedTenant(repositories, 'audit-redact');
    const event = await appendFor(tenant, {
      displayName: 'kept',
      password: FAKE_SECRET,
      request: { headers: { Cookie: FAKE_SECRET, accept: 'text/html' } },
      attempts: [{ sessionId: FAKE_SECRET }],
      note: `Bearer ${FAKE_SECRET}`,
    });
    expect(event.metadata).toEqual({
      displayName: 'kept',
      password: '[REDACTED]',
      request: { headers: { Cookie: '[REDACTED]', accept: 'text/html' } },
      attempts: [{ sessionId: '[REDACTED]' }],
      note: '[REDACTED]',
    });

    const stored = rowsOf(
      await handle.db.execute(
        sql`select metadata::text as metadata from audit_events where id = ${event.id}`,
      ),
    );
    expect(String(stored[0]!.metadata)).not.toContain(FAKE_SECRET);
    expect(await repositories.audit.verify(tenant.scope)).toMatchObject({ ok: true });
  });

  it('hashes metadata that survives the jsonb round trip unchanged', async () => {
    const tenant = await seedTenant(repositories, 'audit-roundtrip');
    await appendFor(tenant, {
      zeta: 1,
      alpha: { nested: [1.5, -0, 1e21, 1e-7, 123456789012345680000], flag: false, none: null },
      unicode: 'naïve — ☃ 𝄞',
      escapes: 'quote " backslash \\ newline \n tab \t',
      empty: { object: {}, array: [] },
      when: new Date('2026-11-11T00:00:00.000Z'),
    });
    expect(await repositories.audit.verify(tenant.scope)).toMatchObject({ ok: true, count: 1 });
  });

  it('rejects malformed events', async () => {
    const tenant = await seedTenant(repositories, 'audit-invalid');
    const base = {
      organizationId: tenant.organization.id,
      actorType: 'user' as const,
      eventType: 'agent.created' as const,
    };
    const invalid = [
      { ...base, organizationId: 'not-a-uuid' },
      { ...base, eventType: 'made.up' },
      { ...base, actorType: 'alien' },
      { ...base, decision: 'perhaps' },
      { ...base, connectionId: 'not-a-uuid' },
    ];
    for (const input of invalid) {
      await expect(repositories.audit.append(input as never)).rejects.toBeInstanceOf(
        ValidationError,
      );
    }
    expect(await allEvents(tenant)).toEqual([]);
  });

  it('exposes no way to update or delete events', () => {
    expect(Object.keys(repositories.audit).sort()).toEqual(['append', 'list', 'verify']);
  });
});

describe('audit.verify', () => {
  async function chainOf(label: string, length: number): Promise<Tenant> {
    const tenant = await seedTenant(repositories, label);
    for (let index = 0; index < length; index += 1) await appendFor(tenant, { index });
    return tenant;
  }
  const org = (tenant: Tenant) => tenant.organization.id;

  /**
   * Edits the table the way a privileged administrator (table owner or superuser) would have
   * to: the append-only trigger from migration 0002 must be disabled first. It is re-enabled
   * in the same transaction, so later tests see it active again.
   */
  async function tamper(statement: SQL): Promise<void> {
    await handle.db.transaction(async (tx) => {
      await tx.execute(sql`alter table audit_events disable trigger audit_events_no_update_delete`);
      await tx.execute(statement);
      await tx.execute(sql`alter table audit_events enable trigger audit_events_no_update_delete`);
    });
  }

  it('accepts an empty trail', async () => {
    const tenant = await seedTenant(repositories, 'audit-empty');
    expect(await repositories.audit.verify(tenant.scope)).toEqual({
      ok: true,
      count: 0,
      head: null,
    });
  });

  it('detects a row whose metadata was edited directly in SQL', async () => {
    const tenant = await chainOf('audit-tamper-metadata', 5);
    await tamper(
      sql`update audit_events set metadata = '{"index": 99}' where organization_id = ${org(tenant)} and sequence = 3`,
    );
    expect(await repositories.audit.verify(tenant.scope)).toMatchObject({
      ok: false,
      sequence: 3,
      reason: 'event_hash_mismatch',
      verifiedCount: 2,
    });
  });

  it('detects an edited decision, actor and timestamp', async () => {
    for (const [label, statement] of [
      ['decision', sql`decision = 'allow'`],
      ['actor', sql`actor_id = gen_random_uuid()`],
      ['timestamp', sql`timestamp = timestamp + interval '1 second'`],
      ['type', sql`event_type = 'connection.revoked'`],
    ] as const) {
      const tenant = await chainOf(`audit-tamper-${label}`, 3);
      await tamper(
        sql`update audit_events set ${statement} where organization_id = ${org(tenant)} and sequence = 2`,
      );
      expect(await repositories.audit.verify(tenant.scope)).toMatchObject({
        ok: false,
        sequence: 2,
        reason: 'event_hash_mismatch',
      });
    }
  });

  it('detects a deleted event', async () => {
    const tenant = await chainOf('audit-delete', 5);
    await tamper(
      sql`delete from audit_events where organization_id = ${org(tenant)} and sequence = 3`,
    );
    expect(await repositories.audit.verify(tenant.scope)).toMatchObject({
      ok: false,
      sequence: 4,
      reason: 'sequence_gap',
      verifiedCount: 2,
    });
  });

  it('detects a deleted first event', async () => {
    const tenant = await chainOf('audit-delete-head', 3);
    await tamper(
      sql`delete from audit_events where organization_id = ${org(tenant)} and sequence = 1`,
    );
    expect(await repositories.audit.verify(tenant.scope)).toMatchObject({
      ok: false,
      sequence: 2,
      reason: 'unexpected_start',
    });
  });

  it('detects a forged previous hash', async () => {
    const tenant = await chainOf('audit-forge', 3);
    await tamper(
      sql`update audit_events set previous_hash = ${'f'.repeat(64)} where organization_id = ${org(tenant)} and sequence = 3`,
    );
    expect(await repositories.audit.verify(tenant.scope)).toMatchObject({
      ok: false,
      sequence: 3,
      reason: 'previous_hash_mismatch',
    });
  });

  it('refuses a second event with an existing sequence number', async () => {
    const tenant = await chainOf('audit-duplicate', 2);
    await expect(
      handle.db.execute(
        sql`insert into audit_events (id, organization_id, sequence, timestamp, actor_type, event_type, decision, metadata, previous_hash, event_hash)
            select gen_random_uuid(), organization_id, sequence, timestamp, actor_type, event_type, decision, metadata, previous_hash, event_hash
            from audit_events where organization_id = ${org(tenant)} and sequence = 2`,
      ),
    ).rejects.toThrow();
  });
});

describe('audit.list', () => {
  it('returns newest first, pages by cursor and applies filters', async () => {
    const tenant = await seedTenant(repositories, 'audit-list');
    const connectionId = '44444444-4444-4444-8444-444444444444';
    const agentId = '55555555-5555-4555-8555-555555555555';
    for (let index = 0; index < 5; index += 1) {
      await repositories.audit.append({
        organizationId: tenant.organization.id,
        actorType: index % 2 === 0 ? 'user' : 'agent',
        actorId: tenant.user.id,
        agentId: index % 2 === 0 ? null : agentId,
        connectionId: index < 2 ? connectionId : null,
        eventType: index === 4 ? 'policy.evaluated' : 'connection.status_changed',
        decision: index === 4 ? 'deny' : 'not_applicable',
        metadata: { index },
      });
    }

    const firstPage = await repositories.audit.list(tenant.scope, { limit: 2 });
    expect(firstPage.items.map((event) => event.sequence)).toEqual([5, 4]);
    expect(firstPage.nextCursor).not.toBeNull();
    const secondPage = await repositories.audit.list(tenant.scope, {
      limit: 2,
      cursor: firstPage.nextCursor!,
    });
    expect(secondPage.items.map((event) => event.sequence)).toEqual([3, 2]);
    const lastPage = await repositories.audit.list(tenant.scope, {
      limit: 2,
      cursor: secondPage.nextCursor!,
    });
    expect(lastPage.items.map((event) => event.sequence)).toEqual([1]);
    expect(lastPage.nextCursor).toBeNull();

    const byConnection = await repositories.audit.list(tenant.scope, { connectionId });
    expect(byConnection.items.map((event) => event.sequence)).toEqual([2, 1]);
    const byAgent = await repositories.audit.list(tenant.scope, { agentId });
    expect(byAgent.items.map((event) => event.sequence)).toEqual([4, 2]);
    const byType = await repositories.audit.list(tenant.scope, { eventType: 'policy.evaluated' });
    expect(byType.items).toMatchObject([{ sequence: 5, decision: 'deny' }]);
    const combined = await repositories.audit.list(tenant.scope, { agentId, connectionId });
    expect(combined.items.map((event) => event.sequence)).toEqual([2]);

    expect((await repositories.audit.list(tenant.scope, { agentId: 'not-a-uuid' })).items).toEqual(
      [],
    );
    await expect(
      repositories.audit.list(tenant.scope, { cursor: 'garbage' }),
    ).rejects.toBeInstanceOf(InvalidCursorError);
  });
});

describe('audit_events append-only trigger (F-7)', () => {
  // Drizzle wraps the driver error; the trigger's message is on its cause.
  const APPEND_ONLY_REJECTION = {
    cause: { message: expect.stringMatching(/audit_events is append-only/) as unknown },
  };

  // The trigger is defence in depth, not immutability: a table owner or superuser can still
  // disable it (as `tamper` above does). These tests prove ordinary statements are refused.
  async function seeded(label: string): Promise<Tenant> {
    const tenant = await seedTenant(repositories, label);
    await appendFor(tenant, { index: 0 });
    await appendFor(tenant, { index: 1 });
    return tenant;
  }

  it('is installed on a freshly migrated database', async () => {
    const rows = rowsOf(
      await handle.db.execute(
        sql`select tgname from pg_trigger where tgrelid = 'audit_events'::regclass and not tgisinternal and tgenabled <> 'D' order by tgname`,
      ),
    );
    expect(rows.map((row) => row.tgname)).toEqual([
      'audit_events_no_truncate',
      'audit_events_no_update_delete',
    ]);
  });

  it('rejects a plain UPDATE and leaves the row and chain intact', async () => {
    const tenant = await seeded('audit-trigger-update');
    await expect(
      handle.db.execute(
        sql`update audit_events set metadata = '{"index": 99}' where organization_id = ${tenant.organization.id}`,
      ),
    ).rejects.toMatchObject(APPEND_ONLY_REJECTION);
    expect((await allEvents(tenant)).map((event) => event.metadata)).toEqual([
      { index: 0 },
      { index: 1 },
    ]);
    expect(await repositories.audit.verify(tenant.scope)).toMatchObject({ ok: true, count: 2 });
  });

  it('rejects a plain DELETE', async () => {
    const tenant = await seeded('audit-trigger-delete');
    await expect(
      handle.db.execute(
        sql`delete from audit_events where organization_id = ${tenant.organization.id}`,
      ),
    ).rejects.toMatchObject(APPEND_ONLY_REJECTION);
    expect(await allEvents(tenant)).toHaveLength(2);
  });

  it('rejects TRUNCATE', async () => {
    const tenant = await seeded('audit-trigger-truncate');
    await expect(handle.db.execute(sql`truncate audit_events`)).rejects.toMatchObject(
      APPEND_ONLY_REJECTION,
    );
    expect(await allEvents(tenant)).toHaveLength(2);
  });

  it('still accepts new events', async () => {
    const tenant = await seeded('audit-trigger-insert');
    await appendFor(tenant, { index: 2 });
    expect(await repositories.audit.verify(tenant.scope)).toMatchObject({ ok: true, count: 3 });
  });
});
