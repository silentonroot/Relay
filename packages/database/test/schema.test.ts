import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  ActorType,
  ApprovalMode,
  AuditDecision,
  ConnectionStatus,
  EntityStatus,
  GrantEffect,
  JobErrorCode,
  JobKind,
  JobStatus,
  MembershipRole,
} from '@aab/contracts';
import { sql } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { rowsOf } from '../src/client.js';
import { createRepositories, migrate, MIGRATIONS_FOLDER, schema } from '../src/index.js';
import type { DatabaseHandle, Repositories } from '../src/index.js';
import { openTestDb, seedApplication, seedTenant } from './helpers.js';
import type { Tenant } from './helpers.js';

let handle: DatabaseHandle;
let repositories: Repositories;
let tenant: Tenant;

beforeAll(async () => {
  handle = await openTestDb();
  repositories = createRepositories(handle.db);
  tenant = await seedTenant(repositories, 'schema');
});

afterAll(async () => {
  await handle.close();
});

describe('migrations', () => {
  it('creates every Phase 1 and Phase 2 table on a fresh database', async () => {
    const rows = rowsOf(
      await handle.db.execute(
        sql`select table_name from information_schema.tables where table_schema = 'public' order by table_name`,
      ),
    );
    expect(rows.map((row) => row.table_name)).toEqual([
      'agent_grants',
      'agents',
      'application_definitions',
      'audit_events',
      'connection_status_events',
      'connections',
      'execution_jobs',
      'memberships',
      'operation_requests',
      'organizations',
      'user_sessions',
      'users',
      'vault_secret_versions',
      'vault_secrets',
    ]);
  });

  it('does not create tables that belong to later phases', async () => {
    const rows = rowsOf(
      await handle.db.execute(
        sql`select table_name from information_schema.tables where table_schema = 'public' and (table_name like 'approval%' or table_name like 'workflow%' or table_name like 'vault_access%')`,
      ),
    );
    expect(rows).toEqual([]);
  });

  it('applies every journal entry, including the hand-written trigger migration', async () => {
    const journal = JSON.parse(
      readFileSync(join(MIGRATIONS_FOLDER, 'meta', '_journal.json'), 'utf8'),
    ) as { entries: { tag: string }[] };
    expect(journal.entries.map((entry) => entry.tag)).toEqual([
      '0000_phase1_foundation',
      '0001_owner_scoped_agent_identity',
      '0002_audit_events_append_only',
      '0003_phase2_execution',
    ]);
    const applied = rowsOf(
      await handle.db.execute(sql`select count(*)::int as n from drizzle.__drizzle_migrations`),
    );
    expect(applied[0]!.n).toBe(journal.entries.length);

    const triggers = rowsOf(
      await handle.db.execute(
        sql`select tgname from pg_trigger where tgrelid = 'audit_events'::regclass and not tgisinternal order by tgname`,
      ),
    );
    expect(triggers.map((row) => row.tgname)).toEqual([
      'audit_events_no_truncate',
      'audit_events_no_update_delete',
    ]);
  });

  it('makes agent client identities unique per owner, not per organization', async () => {
    const rows = rowsOf(
      await handle.db.execute(
        sql`select indexname, indexdef from pg_indexes where tablename = 'agents' and indexdef like '%client_identity%'`,
      ),
    );
    expect(rows).toHaveLength(1);
    expect(rows[0]!.indexname).toBe('agents_owner_client_identity_unique');
    expect(String(rows[0]!.indexdef)).toContain('(owner_user_id, client_identity)');
  });

  it('is idempotent', async () => {
    expect(await migrate(handle.db)).toEqual({ applied: 0 });
  });
});

describe('schema enum lists', () => {
  it('match @aab/contracts exactly', () => {
    expect(schema.ENTITY_STATUSES).toEqual(EntityStatus.options);
    expect(schema.MEMBERSHIP_ROLES).toEqual(MembershipRole.options);
    expect(schema.CONNECTION_STATUSES).toEqual(ConnectionStatus.options);
    expect(schema.GRANT_EFFECTS).toEqual(GrantEffect.options);
    expect(schema.APPROVAL_MODES).toEqual(ApprovalMode.options);
    expect(schema.ACTOR_TYPES).toEqual(ActorType.options);
    expect(schema.AUDIT_DECISIONS).toEqual(AuditDecision.options);
    expect(schema.JOB_KINDS).toEqual(JobKind.options);
    expect(schema.JOB_STATUSES).toEqual(JobStatus.options);
    expect(schema.JOB_ERROR_CODES).toEqual(JobErrorCode.options);
  });
});

describe('database constraints', () => {
  const org = () => tenant.organization.id;
  const user = () => tenant.user.id;

  it('reject status, role, effect and decision values outside the contracts enums', async () => {
    const application = await seedApplication(repositories, tenant.scope, '9.0.0');
    const connection = await repositories.connections.create(tenant.scope, {
      applicationId: application.id,
      displayName: 'constraint probe',
    });
    const agent = await repositories.agents.create(tenant.scope, {
      name: 'constraint probe',
      clientIdentity: 'constraint-probe',
    });

    const invalidWrites = [
      sql`insert into organizations (name, status) values ('x', 'deleted')`,
      sql`update users set status = 'banned' where id = ${user()}`,
      sql`update memberships set role = 'superuser' where user_id = ${user()}`,
      sql`update application_definitions set status = 'archived' where id = ${application.id}`,
      sql`update connections set status = 'connected' where id = ${connection.id}`,
      sql`update agents set status = 'paused' where id = ${agent.id}`,
      sql`insert into connection_status_events (connection_id, from_status, to_status, actor_type) values (${connection.id}, 'created', 'bogus', 'user')`,
      sql`insert into connection_status_events (connection_id, from_status, to_status, actor_type) values (${connection.id}, 'bogus', 'active', 'user')`,
      sql`insert into connection_status_events (connection_id, to_status, actor_type) values (${connection.id}, 'active', 'robot')`,
      sql`insert into agent_grants (agent_id, connection_id, operation, effect, constraints, approval_mode) values (${agent.id}, ${connection.id}, 'orders.list', 'maybe', '{}', 'none')`,
      sql`insert into agent_grants (agent_id, connection_id, operation, effect, constraints, approval_mode) values (${agent.id}, ${connection.id}, 'orders.list', 'allow', '{}', 'sometimes')`,
      sql`insert into agent_grants (agent_id, connection_id, operation, effect, constraints, approval_mode) values (${agent.id}, ${connection.id}, 'orders.list', 'allow', '[]', 'none')`,
      sql`insert into audit_events (id, organization_id, sequence, timestamp, actor_type, event_type, decision, metadata, event_hash) values (gen_random_uuid(), ${org()}, 1, now(), 'user', 'agent.created', 'perhaps', '{}', ${'a'.repeat(64)})`,
      sql`insert into audit_events (id, organization_id, sequence, timestamp, actor_type, event_type, decision, metadata, event_hash) values (gen_random_uuid(), ${org()}, 1, now(), 'alien', 'agent.created', 'allow', '{}', ${'a'.repeat(64)})`,
      sql`insert into audit_events (id, organization_id, sequence, timestamp, actor_type, event_type, decision, metadata, event_hash) values (gen_random_uuid(), ${org()}, 1, now(), 'user', 'agent.created', 'allow', '{}', 'not-a-hash')`,
      sql`insert into audit_events (id, organization_id, sequence, timestamp, actor_type, event_type, decision, metadata, event_hash) values (gen_random_uuid(), ${org()}, 0, now(), 'user', 'agent.created', 'allow', '{}', ${'a'.repeat(64)})`,
      sql`insert into audit_events (id, organization_id, sequence, timestamp, actor_type, event_type, decision, metadata, previous_hash, event_hash) values (gen_random_uuid(), ${org()}, 1, now(), 'user', 'agent.created', 'allow', '{}', ${'b'.repeat(64)}, ${'a'.repeat(64)})`,
    ];
    for (const statement of invalidWrites) {
      await expect(handle.db.execute(statement)).rejects.toThrow();
    }
  });

  it('reject mixed-case emails and dangling foreign keys', async () => {
    await expect(
      handle.db.execute(
        sql`insert into users (email, password_hash) values ('Mixed@Synthetic.test', 'x')`,
      ),
    ).rejects.toThrow();
    await expect(
      handle.db.execute(
        sql`insert into agents (organization_id, owner_user_id, name, client_identity) values (gen_random_uuid(), ${user()}, 'x', 'dangling')`,
      ),
    ).rejects.toThrow();
  });
});
