import type { Membership, MembershipRole, Organization, User } from '@aab/contracts';
import { and, eq, gt, isNull, sql } from 'drizzle-orm';
import type { Db } from '../client.js';
import { ConflictError, NotFoundError, translateDbErrors, ValidationError } from '../errors.js';
import { memberships, organizations, users, userSessions } from '../schema.js';
import { isUuid, toMembership, toOrganization, toUser } from '../support.js';

function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

/* ---------------------------------------------------------------- users */

export interface CreateUserInput {
  email: string;
  /** Already hashed by @aab/crypto. This package never sees a plaintext password. */
  passwordHash: string;
}

/**
 * INTERNAL record for the login path only. It carries the password hash, so it must never be
 * serialized into an API response or a log line. Everything else uses the `User` DTO.
 */
export interface LoginRecord {
  user: User;
  passwordHash: string;
  memberships: { organization: Organization; role: MembershipRole }[];
}

export function createUserRepository(db: Db) {
  return {
    async create(input: CreateUserInput): Promise<User> {
      if (input.passwordHash === '') throw new ValidationError('passwordHash is required');
      return translateDbErrors('user', async () => {
        const [row] = await db
          .insert(users)
          .values({ email: normalizeEmail(input.email), passwordHash: input.passwordHash })
          .returning();
        return toUser(row!);
      });
    },

    /**
     * Looks a user up by email for password verification. Returns disabled users too, so the
     * caller can spend the same hashing time on every attempt; check `user.status` afterwards.
     */
    async findForLogin(email: string): Promise<LoginRecord | null> {
      const [row] = await db
        .select()
        .from(users)
        .where(eq(users.email, normalizeEmail(email)))
        .limit(1);
      if (row === undefined) return null;

      const memberRows = await db
        .select({ organization: organizations, role: memberships.role })
        .from(memberships)
        .innerJoin(organizations, eq(organizations.id, memberships.organizationId))
        .where(eq(memberships.userId, row.id))
        .orderBy(memberships.createdAt);

      return {
        user: toUser(row),
        passwordHash: row.passwordHash,
        memberships: memberRows.map((member) => ({
          organization: toOrganization(member.organization),
          role: member.role,
        })),
      };
    },

    /**
     * Replaces a user's password hash (for example a rehash with stronger parameters after a
     * successful login). Pass `expectedHash` to make it a compare-and-swap: the update applies
     * only while the stored hash is still that value, so a concurrent password change is never
     * overwritten. Returns whether a row was updated.
     */
    async updatePasswordHash(
      userId: string,
      passwordHash: string,
      options: { expectedHash?: string; now?: Date } = {},
    ): Promise<boolean> {
      if (passwordHash === '') throw new ValidationError('passwordHash is required');
      if (!isUuid(userId)) return false;
      const rows = await db
        .update(users)
        .set({ passwordHash, updatedAt: options.now ?? new Date() })
        .where(
          options.expectedHash === undefined
            ? eq(users.id, userId)
            : and(eq(users.id, userId), eq(users.passwordHash, options.expectedHash)),
        )
        .returning({ id: users.id });
      return rows.length > 0;
    },
  };
}

/* ---------------------------------------------------------------- organizations */

export interface BootstrapLocalOwnerInput {
  email: string;
  passwordHash: string;
  organizationName: string;
}

export interface BootstrapLocalOwnerResult {
  user: User;
  organization: Organization;
  membership: Membership;
}

export function createOrganizationRepository(db: Db) {
  return {
    async create(input: { name: string }): Promise<Organization> {
      return translateDbErrors('organization', async () => {
        const [row] = await db
          .insert(organizations)
          .values({ name: input.name.trim() })
          .returning();
        return toOrganization(row!);
      });
    },

    async addMember(input: {
      organizationId: string;
      userId: string;
      role: MembershipRole;
    }): Promise<Membership> {
      if (!isUuid(input.organizationId)) throw new NotFoundError('organization');
      if (!isUuid(input.userId)) throw new NotFoundError('user');
      return translateDbErrors('membership', async () => {
        const [row] = await db.insert(memberships).values(input).returning();
        return toMembership(row!);
      });
    },

    /**
     * First-run setup: creates the single local organization, its owner and the membership in
     * one transaction. Refuses once any user exists, so it cannot be replayed to mint a second
     * owner. Concurrent calls are serialized by an advisory lock.
     */
    async bootstrapLocalOwner(input: BootstrapLocalOwnerInput): Promise<BootstrapLocalOwnerResult> {
      if (input.passwordHash === '') throw new ValidationError('passwordHash is required');
      return translateDbErrors('local owner', () =>
        db.transaction(async (tx) => {
          await tx.execute(sql`select pg_advisory_xact_lock(hashtextextended('aab.bootstrap', 0))`);
          const existing = await tx.select({ id: users.id }).from(users).limit(1);
          if (existing.length > 0) {
            throw new ConflictError(
              'a user already exists; bootstrap is only for an empty database',
            );
          }
          const [organization] = await tx
            .insert(organizations)
            .values({ name: input.organizationName.trim() })
            .returning();
          const [user] = await tx
            .insert(users)
            .values({ email: normalizeEmail(input.email), passwordHash: input.passwordHash })
            .returning();
          const [membership] = await tx
            .insert(memberships)
            .values({ organizationId: organization!.id, userId: user!.id, role: 'owner' })
            .returning();
          return {
            user: toUser(user!),
            organization: toOrganization(organization!),
            membership: toMembership(membership!),
          };
        }),
      );
    },
  };
}

/* ---------------------------------------------------------------- sessions */

export interface CreateSessionInput {
  userId: string;
  organizationId: string;
  /** Hash of the session token. The token itself is never stored. */
  tokenHash: string;
  /** Hash of the CSRF token bound to this session. */
  csrfTokenHash: string;
  expiresAt: Date;
}

export interface SessionRecord {
  id: string;
  userId: string;
  organizationId: string;
  expiresAt: string;
  lastSeenAt: string;
  createdAt: string;
}

/** A live session with the identity it authenticates. `csrfTokenHash` is for comparison only. */
export interface ValidSession {
  session: SessionRecord;
  user: User;
  organization: Organization;
  role: MembershipRole;
  csrfTokenHash: string;
}

function toSessionRecord(row: typeof userSessions.$inferSelect): SessionRecord {
  return {
    id: row.id,
    userId: row.userId,
    organizationId: row.organizationId,
    expiresAt: row.expiresAt.toISOString(),
    lastSeenAt: row.lastSeenAt.toISOString(),
    createdAt: row.createdAt.toISOString(),
  };
}

export function createSessionRepository(db: Db) {
  return {
    /** Fails with NotFoundError unless the user is an active member of the active organization. */
    async create(input: CreateSessionInput): Promise<SessionRecord> {
      if (!isUuid(input.userId) || !isUuid(input.organizationId)) {
        throw new NotFoundError('membership');
      }
      if (input.tokenHash === '' || input.csrfTokenHash === '') {
        throw new ValidationError('token hashes are required');
      }
      return translateDbErrors('session', () =>
        db.transaction(async (tx) => {
          const [member] = await tx
            .select({ userId: memberships.userId })
            .from(memberships)
            .innerJoin(users, eq(users.id, memberships.userId))
            .innerJoin(organizations, eq(organizations.id, memberships.organizationId))
            .where(
              and(
                eq(memberships.userId, input.userId),
                eq(memberships.organizationId, input.organizationId),
                eq(users.status, 'active'),
                eq(organizations.status, 'active'),
              ),
            )
            .limit(1);
          if (member === undefined) throw new NotFoundError('membership');

          const [row] = await tx
            .insert(userSessions)
            .values({
              userId: input.userId,
              organizationId: input.organizationId,
              tokenHash: input.tokenHash,
              csrfTokenHash: input.csrfTokenHash,
              expiresAt: input.expiresAt,
            })
            .returning();
          return toSessionRecord(row!);
        }),
      );
    },

    /**
     * Resolves a session token hash to its identity. Returns null when the session is unknown,
     * expired or revoked, or when the user, organization or membership is no longer active.
     */
    async findValid(tokenHash: string, now: Date = new Date()): Promise<ValidSession | null> {
      if (tokenHash === '') return null;
      const [row] = await db
        .select({
          session: userSessions,
          user: users,
          organization: organizations,
          role: memberships.role,
        })
        .from(userSessions)
        .innerJoin(users, eq(users.id, userSessions.userId))
        .innerJoin(organizations, eq(organizations.id, userSessions.organizationId))
        .innerJoin(
          memberships,
          and(
            eq(memberships.userId, userSessions.userId),
            eq(memberships.organizationId, userSessions.organizationId),
          ),
        )
        .where(
          and(
            eq(userSessions.tokenHash, tokenHash),
            isNull(userSessions.revokedAt),
            gt(userSessions.expiresAt, now),
            eq(users.status, 'active'),
            eq(organizations.status, 'active'),
          ),
        )
        .limit(1);
      if (row === undefined) return null;
      return {
        session: toSessionRecord(row.session),
        user: toUser(row.user),
        organization: toOrganization(row.organization),
        role: row.role,
        csrfTokenHash: row.session.csrfTokenHash,
      };
    },

    async touch(sessionId: string, now: Date = new Date()): Promise<void> {
      if (!isUuid(sessionId)) return;
      await db
        .update(userSessions)
        .set({ lastSeenAt: now })
        .where(and(eq(userSessions.id, sessionId), isNull(userSessions.revokedAt)));
    },

    /** Idempotent. Returns whether a live session was revoked by this call. */
    async revoke(sessionId: string, now: Date = new Date()): Promise<boolean> {
      if (!isUuid(sessionId)) return false;
      const rows = await db
        .update(userSessions)
        .set({ revokedAt: now })
        .where(and(eq(userSessions.id, sessionId), isNull(userSessions.revokedAt)))
        .returning({ id: userSessions.id });
      return rows.length > 0;
    },

    /** Revokes every live session of a user. Returns how many were revoked. */
    async revokeAllForUser(userId: string, now: Date = new Date()): Promise<number> {
      if (!isUuid(userId)) return 0;
      const rows = await db
        .update(userSessions)
        .set({ revokedAt: now })
        .where(and(eq(userSessions.userId, userId), isNull(userSessions.revokedAt)))
        .returning({ id: userSessions.id });
      return rows.length;
    },
  };
}
