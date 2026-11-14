import {
  Agent,
  AgentGrant,
  ApplicationDefinition,
  Connection,
  Organization,
  User,
} from '@aab/contracts';
import { sql } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  ConflictError,
  createRepositories,
  InvalidCursorError,
  InvalidTransitionError,
  NotFoundError,
  ValidationError,
} from '../src/index.js';
import type { DatabaseHandle, Repositories } from '../src/index.js';
import {
  openTestDb,
  seedApplication,
  seedTenant,
  SYNTHETIC_PASSWORD_HASH,
  UNKNOWN_ID,
} from './helpers.js';
import type { Tenant } from './helpers.js';

let handle: DatabaseHandle;
let repositories: Repositories;
let tenant: Tenant;

beforeAll(async () => {
  handle = await openTestDb();
  repositories = createRepositories(handle.db);
  tenant = await seedTenant(repositories, 'crud');
});

afterAll(async () => {
  await handle.close();
});

const hour = 60 * 60 * 1000;

describe('users and organizations', () => {
  it('creates users with a lowercased email and returns only the DTO', async () => {
    const user = await repositories.users.create({
      email: '  Mixed.Case@Synthetic.TEST ',
      passwordHash: SYNTHETIC_PASSWORD_HASH,
    });
    expect(User.safeParse(user).success).toBe(true);
    expect(user.email).toBe('mixed.case@synthetic.test');
    expect(Object.keys(user).sort()).toEqual(['createdAt', 'email', 'id', 'status', 'updatedAt']);
    expect(JSON.stringify(user)).not.toContain(SYNTHETIC_PASSWORD_HASH);
  });

  it('reports a duplicate email as a conflict, whatever its casing', async () => {
    const attempt = repositories.users.create({
      email: tenant.user.email.toUpperCase(),
      passwordHash: SYNTHETIC_PASSWORD_HASH,
    });
    await expect(attempt).rejects.toBeInstanceOf(ConflictError);
    await expect(attempt).rejects.toMatchObject({ code: 'conflict' });
  });

  it('finds a user for login with the hash and memberships', async () => {
    const record = await repositories.users.findForLogin(tenant.user.email.toUpperCase());
    expect(record).not.toBeNull();
    expect(record!.user).toEqual(tenant.user);
    expect(record!.passwordHash).toBe(SYNTHETIC_PASSWORD_HASH);
    expect(record!.memberships).toHaveLength(1);
    expect(record!.memberships[0]!.role).toBe('owner');
    expect(Organization.safeParse(record!.memberships[0]!.organization).success).toBe(true);
    expect(await repositories.users.findForLogin('nobody@synthetic.test')).toBeNull();
  });

  it('replaces a password hash, optionally only while the old hash is still stored', async () => {
    const user = await repositories.users.create({
      email: 'rehash@synthetic.test',
      passwordHash: SYNTHETIC_PASSWORD_HASH,
    });
    const next = `${SYNTHETIC_PASSWORD_HASH}-next`;
    const later = `${SYNTHETIC_PASSWORD_HASH}-later`;
    const hashOf = async () => (await repositories.users.findForLogin(user.email))!.passwordHash;

    // Compare-and-swap with a stale expected hash changes nothing.
    expect(
      await repositories.users.updatePasswordHash(user.id, next, { expectedHash: 'stale' }),
    ).toBe(false);
    expect(await hashOf()).toBe(SYNTHETIC_PASSWORD_HASH);

    expect(
      await repositories.users.updatePasswordHash(user.id, next, {
        expectedHash: SYNTHETIC_PASSWORD_HASH,
      }),
    ).toBe(true);
    expect(await hashOf()).toBe(next);

    expect(await repositories.users.updatePasswordHash(user.id, later)).toBe(true);
    expect(await hashOf()).toBe(later);
    // Other users are untouched.
    expect((await repositories.users.findForLogin(tenant.user.email))!.passwordHash).toBe(
      SYNTHETIC_PASSWORD_HASH,
    );

    expect(await repositories.users.updatePasswordHash(UNKNOWN_ID, next)).toBe(false);
    expect(await repositories.users.updatePasswordHash('not-a-uuid', next)).toBe(false);
    await expect(repositories.users.updatePasswordHash(user.id, '')).rejects.toBeInstanceOf(
      ValidationError,
    );
  });

  it('reports a duplicate membership as a conflict', async () => {
    await expect(
      repositories.organizations.addMember({
        organizationId: tenant.organization.id,
        userId: tenant.user.id,
        role: 'member',
      }),
    ).rejects.toBeInstanceOf(ConflictError);
  });
});

describe('bootstrapLocalOwner', () => {
  it('creates org, user and owner membership once, then refuses', async () => {
    const fresh = await openTestDb();
    try {
      const freshRepositories = createRepositories(fresh.db);
      const input = {
        email: 'Owner@Synthetic.test',
        passwordHash: SYNTHETIC_PASSWORD_HASH,
        organizationName: 'Local',
      };
      const result = await freshRepositories.organizations.bootstrapLocalOwner(input);
      expect(result.user.email).toBe('owner@synthetic.test');
      expect(result.membership).toEqual({
        organizationId: result.organization.id,
        userId: result.user.id,
        role: 'owner',
      });

      await expect(
        freshRepositories.organizations.bootstrapLocalOwner({
          ...input,
          email: 'second@synthetic.test',
        }),
      ).rejects.toBeInstanceOf(ConflictError);
      expect(await freshRepositories.users.findForLogin('second@synthetic.test')).toBeNull();
    } finally {
      await fresh.close();
    }
  });

  it('lets only one of several simultaneous bootstraps win', async () => {
    const fresh = await openTestDb();
    try {
      const freshRepositories = createRepositories(fresh.db);
      const results = await Promise.allSettled(
        Array.from({ length: 5 }, (_, i) =>
          freshRepositories.organizations.bootstrapLocalOwner({
            email: `racer-${i}@synthetic.test`,
            passwordHash: SYNTHETIC_PASSWORD_HASH,
            organizationName: `Race ${i}`,
          }),
        ),
      );
      expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
    } finally {
      await fresh.close();
    }
  });
});

describe('sessions', () => {
  const sessionInput = (suffix: string, expiresAt = new Date(Date.now() + hour)) => ({
    userId: tenant.user.id,
    organizationId: tenant.organization.id,
    tokenHash: `token-hash-${suffix}`,
    csrfTokenHash: `csrf-hash-${suffix}`,
    expiresAt,
  });

  it('creates a session and resolves it by token hash', async () => {
    const session = await repositories.sessions.create(sessionInput('a'));
    expect(JSON.stringify(session)).not.toContain('token-hash-a');

    const valid = await repositories.sessions.findValid('token-hash-a');
    expect(valid).not.toBeNull();
    expect(valid!.session.id).toBe(session.id);
    expect(valid!.user).toEqual(tenant.user);
    expect(valid!.organization).toEqual(tenant.organization);
    expect(valid!.role).toBe('owner');
    expect(valid!.csrfTokenHash).toBe('csrf-hash-a');
    expect(JSON.stringify(valid)).not.toContain(SYNTHETIC_PASSWORD_HASH);
    expect(JSON.stringify(valid)).not.toContain('token-hash-a');
  });

  it('does not resolve unknown, expired or revoked sessions', async () => {
    expect(await repositories.sessions.findValid('no-such-hash')).toBeNull();
    expect(await repositories.sessions.findValid('')).toBeNull();

    await repositories.sessions.create(sessionInput('expired', new Date(Date.now() - 1000)));
    expect(await repositories.sessions.findValid('token-hash-expired')).toBeNull();

    await repositories.sessions.create(sessionInput('clock'));
    expect(
      await repositories.sessions.findValid('token-hash-clock', new Date(Date.now() + 2 * hour)),
    ).toBeNull();

    const revoked = await repositories.sessions.create(sessionInput('revoked'));
    expect(await repositories.sessions.revoke(revoked.id)).toBe(true);
    expect(await repositories.sessions.revoke(revoked.id)).toBe(false);
    expect(await repositories.sessions.findValid('token-hash-revoked')).toBeNull();
  });

  it('records last seen time', async () => {
    const session = await repositories.sessions.create(sessionInput('touch'));
    const seenAt = new Date(Date.now() + 5000);
    await repositories.sessions.touch(session.id, seenAt);
    const valid = await repositories.sessions.findValid('token-hash-touch');
    expect(valid!.session.lastSeenAt).toBe(seenAt.toISOString());
  });

  it('rejects a duplicate token hash and a non-member', async () => {
    await repositories.sessions.create(sessionInput('dup'));
    await expect(repositories.sessions.create(sessionInput('dup'))).rejects.toBeInstanceOf(
      ConflictError,
    );

    const other = await seedTenant(repositories, 'session-other');
    await expect(
      repositories.sessions.create({
        ...sessionInput('cross'),
        organizationId: other.organization.id,
      }),
    ).rejects.toBeInstanceOf(NotFoundError);
    await expect(
      repositories.sessions.create({ ...sessionInput('bad-id'), userId: 'not-a-uuid' }),
    ).rejects.toBeInstanceOf(NotFoundError);
  });

  it('stops resolving sessions when the user is disabled, and revokes them all', async () => {
    const member = await seedTenant(repositories, 'session-disable');
    const input = (suffix: string) => ({
      userId: member.user.id,
      organizationId: member.organization.id,
      tokenHash: `disable-token-${suffix}`,
      csrfTokenHash: `disable-csrf-${suffix}`,
      expiresAt: new Date(Date.now() + hour),
    });
    await repositories.sessions.create(input('1'));
    await repositories.sessions.create(input('2'));
    expect(await repositories.sessions.findValid('disable-token-1')).not.toBeNull();

    await handle.db.execute(sql`update users set status = 'disabled' where id = ${member.user.id}`);
    expect(await repositories.sessions.findValid('disable-token-1')).toBeNull();
    await expect(repositories.sessions.create(input('3'))).rejects.toBeInstanceOf(NotFoundError);

    await handle.db.execute(sql`update users set status = 'active' where id = ${member.user.id}`);
    expect(await repositories.sessions.revokeAllForUser(member.user.id)).toBe(2);
    expect(await repositories.sessions.findValid('disable-token-1')).toBeNull();
    expect(await repositories.sessions.findValid('disable-token-2')).toBeNull();
  });
});

describe('applications', () => {
  it('registers, gets and lists', async () => {
    const application = await seedApplication(repositories, tenant.scope, '1.0.0');
    expect(ApplicationDefinition.safeParse(application).success).toBe(true);
    expect(application.organizationId).toBe(tenant.organization.id);
    expect(await repositories.applications.get(tenant.scope, application.id)).toEqual(application);
    const page = await repositories.applications.list(tenant.scope);
    expect(page.items.map((item) => item.id)).toContain(application.id);
  });

  it('rejects a duplicate adapter version and invalid origins', async () => {
    await expect(seedApplication(repositories, tenant.scope, '1.0.0')).rejects.toBeInstanceOf(
      ConflictError,
    );
    await expect(
      repositories.applications.register(tenant.scope, {
        adapterId: 'northstar',
        adapterVersion: '2.0.0',
        name: 'Wildcard',
        allowedOrigins: ['https://*.example.com'],
        authModes: ['browser_session'],
      }),
    ).rejects.toBeInstanceOf(ValidationError);
  });

  it('returns null for unknown and malformed ids', async () => {
    expect(await repositories.applications.get(tenant.scope, UNKNOWN_ID)).toBeNull();
    expect(await repositories.applications.get(tenant.scope, "' or 1=1 --")).toBeNull();
  });
});

describe('connections', () => {
  it('creates in status created with a history row, gets and lists', async () => {
    const application = await seedApplication(repositories, tenant.scope, '1.1.0');
    const connection = await repositories.connections.create(tenant.scope, {
      applicationId: application.id,
      displayName: 'Primary',
      externalAccountHint: 'a***@synthetic.test',
    });
    expect(Connection.safeParse(connection).success).toBe(true);
    expect(connection).toMatchObject({
      ownerUserId: tenant.user.id,
      organizationId: tenant.organization.id,
      status: 'created',
      statusReason: null,
      lastVerifiedAt: null,
      externalAccountHint: 'a***@synthetic.test',
    });
    expect(await repositories.connections.get(tenant.scope, connection.id)).toEqual(connection);
    expect((await repositories.connections.list(tenant.scope)).items).toContainEqual(connection);
    expect(
      await repositories.connections.listStatusEvents(tenant.scope, connection.id),
    ).toMatchObject([
      { fromStatus: null, toStatus: 'created', actorType: 'user', actorId: tenant.user.id },
    ]);
  });

  it('allows several accounts on one application but not a duplicate name', async () => {
    const application = await seedApplication(repositories, tenant.scope, '1.2.0');
    const input = { applicationId: application.id, displayName: 'Account A' };
    await repositories.connections.create(tenant.scope, input);
    await repositories.connections.create(tenant.scope, { ...input, displayName: 'Account B' });
    const duplicate = repositories.connections.create(tenant.scope, input);
    await expect(duplicate).rejects.toBeInstanceOf(ConflictError);
    await expect(duplicate).rejects.toMatchObject({
      constraint: 'connections_owner_application_name_unique',
    });
  });

  it('rejects an unknown application and a disabled one', async () => {
    await expect(
      repositories.connections.create(tenant.scope, {
        applicationId: UNKNOWN_ID,
        displayName: 'Nowhere',
      }),
    ).rejects.toBeInstanceOf(NotFoundError);

    const application = await seedApplication(repositories, tenant.scope, '1.3.0');
    await handle.db.execute(
      sql`update application_definitions set status = 'disabled' where id = ${application.id}`,
    );
    await expect(
      repositories.connections.create(tenant.scope, {
        applicationId: application.id,
        displayName: 'Disabled app',
      }),
    ).rejects.toBeInstanceOf(ConflictError);
  });

  it('walks the lifecycle, recording every transition', async () => {
    const application = await seedApplication(repositories, tenant.scope, '1.4.0');
    const { id } = await repositories.connections.create(tenant.scope, {
      applicationId: application.id,
      displayName: 'Lifecycle',
    });
    const move = (to: Parameters<typeof repositories.connections.transitionStatus>[2]['to']) =>
      repositories.connections.transitionStatus(tenant.scope, id, { to });

    await move('authentication_required');
    await move('authenticating');
    const active = await move('active');
    expect(active.status).toBe('active');
    expect(active.lastVerifiedAt).not.toBeNull();

    const expired = await repositories.connections.transitionStatus(tenant.scope, id, {
      to: 'expired',
      reason: 'session check failed',
      actor: { type: 'worker', id: null },
    });
    expect(expired).toMatchObject({ status: 'expired', statusReason: 'session check failed' });
    expect(expired.lastVerifiedAt).toBe(active.lastVerifiedAt);

    const events = await repositories.connections.listStatusEvents(tenant.scope, id);
    expect(events!.map((event) => [event.fromStatus, event.toStatus])).toEqual([
      [null, 'created'],
      ['created', 'authentication_required'],
      ['authentication_required', 'authenticating'],
      ['authenticating', 'active'],
      ['active', 'expired'],
    ]);
    expect(events!.at(-1)).toMatchObject({
      reason: 'session check failed',
      actorType: 'worker',
      actorId: null,
    });
  });

  it('rejects invalid transitions without changing anything', async () => {
    const application = await seedApplication(repositories, tenant.scope, '1.5.0');
    const { id } = await repositories.connections.create(tenant.scope, {
      applicationId: application.id,
      displayName: 'Invalid',
    });
    const attempt = repositories.connections.transitionStatus(tenant.scope, id, { to: 'active' });
    await expect(attempt).rejects.toBeInstanceOf(InvalidTransitionError);
    await expect(attempt).rejects.toMatchObject({
      code: 'invalid_transition',
      from: 'created',
      to: 'active',
    });
    expect((await repositories.connections.get(tenant.scope, id))!.status).toBe('created');
    expect(await repositories.connections.listStatusEvents(tenant.scope, id)).toHaveLength(1);
  });

  it('treats revoked as terminal', async () => {
    const application = await seedApplication(repositories, tenant.scope, '1.6.0');
    const { id } = await repositories.connections.create(tenant.scope, {
      applicationId: application.id,
      displayName: 'Revoke me',
    });
    const revoked = await repositories.connections.revoke(tenant.scope, id, {
      reason: 'no longer used',
    });
    expect(revoked).toMatchObject({ status: 'revoked', statusReason: 'no longer used' });

    for (const to of ['authenticating', 'active', 'authentication_required', 'revoked'] as const) {
      await expect(
        repositories.connections.transitionStatus(tenant.scope, id, { to }),
      ).rejects.toBeInstanceOf(InvalidTransitionError);
    }
    expect((await repositories.connections.get(tenant.scope, id))!.status).toBe('revoked');
  });

  it('lets exactly one of two conflicting concurrent transitions succeed', async () => {
    const application = await seedApplication(repositories, tenant.scope, '1.7.0');
    const { id } = await repositories.connections.create(tenant.scope, {
      applicationId: application.id,
      displayName: 'Race',
    });
    await repositories.connections.transitionStatus(tenant.scope, id, {
      to: 'authentication_required',
    });
    await repositories.connections.transitionStatus(tenant.scope, id, { to: 'authenticating' });

    // From `authenticating`, each of these makes the other invalid.
    const results = await Promise.allSettled([
      repositories.connections.transitionStatus(tenant.scope, id, { to: 'active' }),
      repositories.connections.transitionStatus(tenant.scope, id, {
        to: 'authentication_required',
      }),
    ]);
    const rejected = results.filter((result) => result.status === 'rejected');
    expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
    expect(rejected).toHaveLength(1);
    expect(rejected[0]!.reason).toBeInstanceOf(InvalidTransitionError);
    expect(await repositories.connections.listStatusEvents(tenant.scope, id)).toHaveLength(4);
  });
});

describe('agents', () => {
  it('creates, gets, lists and disables', async () => {
    const agent = await repositories.agents.create(tenant.scope, {
      name: 'Order assistant',
      clientIdentity: 'order-assistant',
    });
    expect(Agent.safeParse(agent).success).toBe(true);
    expect(agent).toMatchObject({ ownerUserId: tenant.user.id, status: 'active' });
    expect(await repositories.agents.get(tenant.scope, agent.id)).toEqual(agent);
    expect((await repositories.agents.list(tenant.scope)).items).toContainEqual(agent);

    const disabled = await repositories.agents.disable(tenant.scope, agent.id);
    expect(disabled.status).toBe('disabled');
    expect((await repositories.agents.disable(tenant.scope, agent.id)).status).toBe('disabled');
  });

  it('rejects a duplicate client identity and an unknown agent', async () => {
    const input = { name: 'Dup', clientIdentity: 'dup-identity' };
    await repositories.agents.create(tenant.scope, input);
    await expect(repositories.agents.create(tenant.scope, input)).rejects.toBeInstanceOf(
      ConflictError,
    );
    await expect(repositories.agents.disable(tenant.scope, UNKNOWN_ID)).rejects.toBeInstanceOf(
      NotFoundError,
    );
  });

  it('pages through a list without gaps or repeats', async () => {
    const pager = await seedTenant(repositories, 'pager');
    const created = [];
    for (let i = 0; i < 5; i += 1) {
      created.push(
        await repositories.agents.create(pager.scope, {
          name: `Agent ${i}`,
          clientIdentity: `pager-${i}`,
        }),
      );
    }
    const seen: string[] = [];
    let cursor: string | undefined;
    let pages = 0;
    do {
      const page = await repositories.agents.list(pager.scope, { limit: 2, cursor });
      expect(page.items.length).toBeLessThanOrEqual(2);
      seen.push(...page.items.map((item) => item.id));
      cursor = page.nextCursor ?? undefined;
      pages += 1;
    } while (cursor !== undefined && pages < 10);
    expect(pages).toBe(3);
    // The list order is (created_at desc, id desc). Agents created within the same
    // millisecond tie on created_at, which happens on a fast real server.
    const expected = created
      .slice()
      .sort((x, y) => y.createdAt.localeCompare(x.createdAt) || y.id.localeCompare(x.id))
      .map((agent) => agent.id);
    expect(seen).toEqual(expected);
  });

  it('rejects a cursor it did not issue', async () => {
    for (const cursor of ['garbage', Buffer.from('{"t":"x","id":"y"}').toString('base64url')]) {
      await expect(repositories.agents.list(tenant.scope, { cursor })).rejects.toBeInstanceOf(
        InvalidCursorError,
      );
    }
  });
});

describe('grants', () => {
  async function fixture(label: string) {
    const application = await seedApplication(repositories, tenant.scope, `2.0.0-${label}`);
    const connection = await repositories.connections.create(tenant.scope, {
      applicationId: application.id,
      displayName: `Grant target ${label}`,
    });
    const agent = await repositories.agents.create(tenant.scope, {
      name: `Grant agent ${label}`,
      clientIdentity: `grant-agent-${label}`,
    });
    return { connection, agent };
  }

  it('creates with defaults, lists and returns contract-shaped grants', async () => {
    const { connection, agent } = await fixture('defaults');
    const grant = await repositories.grants.create(tenant.scope, agent.id, {
      connectionId: connection.id,
      operation: 'orders.list',
    });
    expect(AgentGrant.safeParse(grant).success).toBe(true);
    expect(grant).toMatchObject({
      agentId: agent.id,
      connectionId: connection.id,
      effect: 'allow',
      approvalMode: 'none',
      constraints: {},
      expiresAt: null,
      revokedAt: null,
    });

    const expiresAt = new Date(Date.now() + hour).toISOString();
    const constrained = await repositories.grants.create(tenant.scope, agent.id, {
      connectionId: connection.id,
      operation: 'orders.applyApprovedUpdate',
      approvalMode: 'required',
      constraints: { maxResults: 50, resourceIds: ['NS-1001'] },
      expiresAt,
    });
    expect(constrained).toMatchObject({
      approvalMode: 'required',
      constraints: { maxResults: 50, resourceIds: ['NS-1001'] },
      expiresAt,
    });

    const page = await repositories.grants.listForAgent(tenant.scope, agent.id);
    expect(page.items.map((item) => item.id).sort()).toEqual([grant.id, constrained.id].sort());
  });

  it('rejects unknown constraint keys, bad operation names and past expiry', async () => {
    const { connection, agent } = await fixture('validation');
    const base = { connectionId: connection.id, operation: 'orders.list' };
    const invalid = [
      { ...base, constraints: { maxResult: 50 } },
      { ...base, constraints: { maxResults: -1 } },
      { ...base, operation: 'orders.*' },
      { ...base, operation: 'orders' },
      { ...base, effect: 'maybe' },
      { ...base, expiresAt: new Date(Date.now() - hour).toISOString() },
      { ...base, somethingElse: true },
    ];
    for (const input of invalid) {
      await expect(
        repositories.grants.create(tenant.scope, agent.id, input as never),
      ).rejects.toBeInstanceOf(ValidationError);
    }
    expect((await repositories.grants.listForAgent(tenant.scope, agent.id)).items).toEqual([]);
  });

  it('refuses grants for a disabled agent or a revoked connection', async () => {
    const disabledCase = await fixture('disabled-agent');
    await repositories.agents.disable(tenant.scope, disabledCase.agent.id);
    await expect(
      repositories.grants.create(tenant.scope, disabledCase.agent.id, {
        connectionId: disabledCase.connection.id,
        operation: 'orders.list',
      }),
    ).rejects.toBeInstanceOf(ConflictError);

    const revokedCase = await fixture('revoked-connection');
    await repositories.connections.revoke(tenant.scope, revokedCase.connection.id);
    await expect(
      repositories.grants.create(tenant.scope, revokedCase.agent.id, {
        connectionId: revokedCase.connection.id,
        operation: 'orders.list',
      }),
    ).rejects.toBeInstanceOf(ConflictError);
  });

  it('revokes by timestamp, keeps the row, and is idempotent', async () => {
    const { connection, agent } = await fixture('revoke');
    const grant = await repositories.grants.create(tenant.scope, agent.id, {
      connectionId: connection.id,
      operation: 'orders.get',
    });
    const first = await repositories.grants.revoke(tenant.scope, agent.id, grant.id);
    expect(first.changed).toBe(true);
    const revoked = first.grant;
    expect(revoked.revokedAt).not.toBeNull();
    expect(await repositories.grants.revoke(tenant.scope, agent.id, grant.id)).toEqual({
      grant: revoked,
      changed: false,
    });

    const page = await repositories.grants.listForAgent(tenant.scope, agent.id);
    expect(page.items).toEqual([revoked]);

    const other = await fixture('revoke-other-agent');
    await expect(
      repositories.grants.revoke(tenant.scope, other.agent.id, grant.id),
    ).rejects.toBeInstanceOf(NotFoundError);
    await expect(
      repositories.grants.revoke(tenant.scope, agent.id, UNKNOWN_ID),
    ).rejects.toBeInstanceOf(NotFoundError);
  });

  it('reports a repeated revocation even when both calls use the same clock reading', async () => {
    const { connection, agent } = await fixture('revoke-fixed-clock');
    const grant = await repositories.grants.create(tenant.scope, agent.id, {
      connectionId: connection.id,
      operation: 'orders.get',
    });
    const fixed = new Date(Date.now() + hour);
    const first = await repositories.grants.revoke(tenant.scope, agent.id, grant.id, fixed);
    const second = await repositories.grants.revoke(tenant.scope, agent.id, grant.id, fixed);
    expect(first).toMatchObject({ changed: true, grant: { revokedAt: fixed.toISOString() } });
    expect(second).toEqual({ grant: first.grant, changed: false });
  });

  it('returns exactly the non-revoked grants of one agent, connection and operation', async () => {
    const { connection, agent } = await fixture('evaluation');
    const sibling = await fixture('evaluation-sibling');
    const base = { connectionId: connection.id, operation: 'orders.list' };

    const allow = await repositories.grants.create(tenant.scope, agent.id, base);
    const deny = await repositories.grants.create(tenant.scope, agent.id, {
      ...base,
      effect: 'deny',
    });
    const expiring = await repositories.grants.create(tenant.scope, agent.id, {
      ...base,
      expiresAt: new Date(Date.now() + hour).toISOString(),
    });
    const revoked = await repositories.grants.create(tenant.scope, agent.id, base);
    await repositories.grants.revoke(tenant.scope, agent.id, revoked.id);
    // Same agent, other operation; same agent, other connection; other agent, same connection.
    await repositories.grants.create(tenant.scope, agent.id, { ...base, operation: 'orders.get' });
    await repositories.grants.create(tenant.scope, agent.id, {
      ...base,
      connectionId: sibling.connection.id,
    });
    await repositories.grants.create(tenant.scope, sibling.agent.id, base);

    const key = { agentId: agent.id, connectionId: connection.id, operation: 'orders.list' };
    const grants = await repositories.grants.listForEvaluation(key);
    expect(grants.map((grant) => grant.id).sort()).toEqual([allow.id, deny.id, expiring.id].sort());

    // Still returned after it expires: expiry is the policy engine's call.
    await handle.db.execute(
      sql`update agent_grants set expires_at = now() - interval '1 hour' where id = ${expiring.id}`,
    );
    expect(await repositories.grants.listForEvaluation(key)).toHaveLength(3);

    expect(
      await repositories.grants.listForEvaluation({ ...key, operation: 'orders.delete' }),
    ).toEqual([]);
    expect(await repositories.grants.listForEvaluation({ ...key, agentId: 'not-a-uuid' })).toEqual(
      [],
    );
    expect(
      await repositories.grants.listForEvaluation({ ...key, operation: "x' or '1'='1" }),
    ).toEqual([]);
  });

  it('returns policy-engine-ready AgentGrant DTOs with ISO-string timestamps', async () => {
    const { connection, agent } = await fixture('evaluation-dto');
    const base = { connectionId: connection.id, operation: 'orders.list' };
    const expiresAt = new Date(Date.now() + hour).toISOString();
    await repositories.grants.create(tenant.scope, agent.id, base);
    await repositories.grants.create(tenant.scope, agent.id, {
      ...base,
      effect: 'deny',
      approvalMode: 'required',
      constraints: { maxResults: 10 },
      expiresAt,
    });

    const grants = await repositories.grants.listForEvaluation({
      agentId: agent.id,
      connectionId: connection.id,
      operation: 'orders.list',
    });
    expect(grants).toHaveLength(2);
    for (const grant of grants) {
      // parse throws on a Date or any other non-ISO value; the result must equal the input.
      expect(AgentGrant.parse(grant)).toEqual(grant);
      expect(typeof grant.createdAt).toBe('string');
      expect(typeof grant.updatedAt).toBe('string');
      expect(grant.revokedAt).toBeNull();
    }
    const [plain, withExpiry] = grants;
    expect(plain!.expiresAt).toBeNull();
    expect(withExpiry!.expiresAt).toBe(expiresAt);
    expect(withExpiry!.constraints).toEqual({ maxResults: 10 });
  });
});

describe('transaction', () => {
  it('rolls back every repository write when the work throws', async () => {
    const before = await repositories.audit.list(tenant.scope);
    await expect(
      repositories.transaction(async (tx) => {
        await tx.agents.create(tenant.scope, { name: 'Ghost', clientIdentity: 'ghost-agent' });
        await tx.audit.append({
          organizationId: tenant.organization.id,
          actorType: 'user',
          actorId: tenant.user.id,
          eventType: 'agent.created',
        });
        throw new Error('abort');
      }),
    ).rejects.toThrow('abort');

    const agents = await repositories.agents.list(tenant.scope, { limit: 200 });
    expect(agents.items.some((agent) => agent.clientIdentity === 'ghost-agent')).toBe(false);
    expect((await repositories.audit.list(tenant.scope)).items).toEqual(before.items);
  });

  it('commits a change together with its audit event', async () => {
    const agent = await repositories.transaction(async (tx) => {
      const created = await tx.agents.create(tenant.scope, {
        name: 'Committed',
        clientIdentity: 'committed-agent',
      });
      await tx.audit.append({
        organizationId: tenant.organization.id,
        actorType: 'user',
        actorId: tenant.user.id,
        agentId: created.id,
        eventType: 'agent.created',
      });
      return created;
    });
    expect(await repositories.agents.get(tenant.scope, agent.id)).not.toBeNull();
    const events = await repositories.audit.list(tenant.scope, { agentId: agent.id });
    expect(events.items).toHaveLength(1);
  });
});
