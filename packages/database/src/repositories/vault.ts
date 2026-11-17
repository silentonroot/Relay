import { AuditEventType } from '@aab/contracts';
import { and, asc, eq, gt, inArray, lt, ne, sql } from 'drizzle-orm';
import type { Db } from '../client.js';
import { rowsOf } from '../client.js';
import { ConflictError, NotFoundError, translateDbErrors, ValidationError } from '../errors.js';
import { connections, vaultSecrets, vaultSecretVersions } from '../schema.js';
import { isUuid, isValidScope } from '../support.js';
import type { Scope } from '../support.js';
import { createAuditRepository } from './audit.js';

/**
 * One encrypted secret version, as produced by `sealSecret` in @aab/crypto. Declared here
 * because this package never imports key handling code; the shapes are identical.
 */
export interface SealedSecretRecord {
  algorithm: string;
  ciphertext: Buffer;
  nonce: Buffer;
  authTag: Buffer;
  wrappedDek: Buffer;
  kekVersion: number;
  aadVersion: number;
}

export interface EnsuredSecret {
  secretId: string;
  /** One more than the highest version ever used for this secret. */
  nextVersion: number;
}

export type SecretStatus = 'pending' | 'active' | 'deleted' | 'revoked';

export interface ActiveSecret {
  secretId: string;
  version: number;
  sealed: SealedSecretRecord;
}

/** What the dashboard may know about a stored secret. Never ciphertext. */
/** One version that still wraps its key under a KEK version below the target (B4). */
export interface RewrapCandidate {
  versionId: string;
  secretId: string;
  secretType: string;
  connectionId: string;
  organizationId: string;
  ownerUserId: string;
  version: number;
  kekVersion: number;
  aadVersion: number;
  /** Only the wrapped key: rewrapping never needs the ciphertext. */
  wrappedDek: Buffer;
}

export interface RewrapVersionInput {
  versionId: string;
  /** The `kek_version` and `wrapped_dek` the caller read; the update requires both unchanged. */
  fromKekVersion: number;
  expectedWrappedDek: Buffer;
  toKekVersion: number;
  newWrappedDek: Buffer;
  now: Date;
}

export interface SecretDescription {
  id: string;
  secretType: string;
  status: SecretStatus;
  activeVersion: number | null;
  kekVersion: number | null;
  lastAccessedAt: string | null;
}

async function describeConnection(db: Db, connectionId: string): Promise<SecretDescription[]> {
  if (!isUuid(connectionId)) return [];
  const rows = await db
    .select({
      id: vaultSecrets.id,
      secretType: vaultSecrets.secretType,
      status: vaultSecrets.status,
      lastAccessedAt: vaultSecrets.lastAccessedAt,
      version: vaultSecretVersions.version,
      kekVersion: vaultSecretVersions.kekVersion,
    })
    .from(vaultSecrets)
    .leftJoin(vaultSecretVersions, eq(vaultSecretVersions.id, vaultSecrets.activeVersionId))
    .where(eq(vaultSecrets.connectionId, connectionId))
    .orderBy(vaultSecrets.secretType);
  return rows.map((row) => ({
    id: row.id,
    secretType: row.secretType,
    status: row.status,
    activeVersion: row.version,
    kekVersion: row.kekVersion,
    lastAccessedAt: row.lastAccessedAt === null ? null : row.lastAccessedAt.toISOString(),
  }));
}

/**
 * Ciphertext storage for the vault. Plaintext and keys never reach this package: callers seal
 * before `putVersion` and open after `getActive`.
 */
export function createVaultRepository(db: Db) {
  return {
    /**
     * Finds or creates the secret row (status `pending` when new) and says which version
     * number the next write should use. Numbers are never reused, even after deletion.
     * NotFoundError for an unknown connection, ConflictError for a `revoked` one.
     */
    async ensureSecret(input: {
      connectionId: string;
      secretType: string;
      now: Date;
    }): Promise<EnsuredSecret> {
      if (!isUuid(input.connectionId)) throw new NotFoundError('connection');
      return translateDbErrors('secret', () =>
        db.transaction(async (tx) => {
          // The connection first (the lock order of ADR-014 section 7). A revoked connection gets
          // no secret row and no version number, whatever state its old secrets were left in.
          const [connection] = await tx
            .select({ status: connections.status })
            .from(connections)
            .where(eq(connections.id, input.connectionId))
            .limit(1)
            .for('share');
          if (connection === undefined) throw new NotFoundError('connection');
          if (connection.status === 'revoked') throw new ConflictError('connection is revoked');
          await tx
            .insert(vaultSecrets)
            .values({
              connectionId: input.connectionId,
              secretType: input.secretType,
              createdAt: input.now,
              updatedAt: input.now,
            })
            .onConflictDoNothing({ target: [vaultSecrets.connectionId, vaultSecrets.secretType] });
          const [row] = await tx
            .select({ id: vaultSecrets.id, lastVersion: vaultSecrets.lastVersion })
            .from(vaultSecrets)
            .where(
              and(
                eq(vaultSecrets.connectionId, input.connectionId),
                eq(vaultSecrets.secretType, input.secretType),
              ),
            )
            .limit(1);
          return { secretId: row!.id, nextVersion: row!.lastVersion + 1 };
        }),
      );
    },

    /**
     * Stores a version, makes it the active one, marks the secret `active` and deletes every
     * other version, all in one transaction. ConflictError when `version` was already used
     * (stored or deleted) for this secret, when the secret or its connection is `revoked`
     * (terminal; a trigger repeats the secret rule), or, when `expectedActiveVersion` is given, when the active version is
     * no longer that number (0 means "none"): the pointer moves only from the version bound at
     * issue (ADR-014 section 7, P3-9). NotFoundError for an unknown secret. Without
     * `expectedActiveVersion` the call behaves as in Phase 2, apart from the `revoked` refusal.
     * The caller appends `vault.secret_stored` in the same transaction.
     */
    async putVersion(input: {
      secretId: string;
      version: number;
      sealed: SealedSecretRecord;
      now: Date;
      expectedActiveVersion?: number | undefined;
    }): Promise<void> {
      if (!isUuid(input.secretId)) throw new NotFoundError('secret');
      if (
        input.expectedActiveVersion !== undefined &&
        (!Number.isSafeInteger(input.expectedActiveVersion) || input.expectedActiveVersion < 0)
      ) {
        throw new ValidationError('invalid secret version', [
          { path: 'expectedActiveVersion', message: 'expected a non-negative integer' },
        ]);
      }
      await translateDbErrors('secret version', () =>
        db.transaction(async (tx) => {
          // Connection before secret (ADR-014 section 7). Between `connections.revoke` and the
          // `deleteForConnection` that follows it the secret is not `revoked` yet; the
          // connection's own status closes that window.
          const [owner] = await tx
            .select({ connectionId: vaultSecrets.connectionId })
            .from(vaultSecrets)
            .where(eq(vaultSecrets.id, input.secretId))
            .limit(1);
          if (owner === undefined) throw new NotFoundError('secret');
          const [connection] = await tx
            .select({ status: connections.status })
            .from(connections)
            .where(eq(connections.id, owner.connectionId))
            .limit(1)
            .for('share');
          if (connection?.status === 'revoked') throw new ConflictError('connection is revoked');
          const [secret] = await tx
            .select({
              id: vaultSecrets.id,
              lastVersion: vaultSecrets.lastVersion,
              status: vaultSecrets.status,
              activeVersionId: vaultSecrets.activeVersionId,
              activeVersion: vaultSecretVersions.version,
            })
            .from(vaultSecrets)
            .leftJoin(vaultSecretVersions, eq(vaultSecretVersions.id, vaultSecrets.activeVersionId))
            .where(eq(vaultSecrets.id, input.secretId))
            .limit(1)
            .for('update', { of: vaultSecrets });
          if (secret === undefined) throw new NotFoundError('secret');
          if (secret.status === 'revoked') throw new ConflictError('secret is revoked');
          if (input.version <= secret.lastVersion) {
            throw new ConflictError('secret version already used');
          }
          if (
            input.expectedActiveVersion !== undefined &&
            (secret.activeVersion ?? 0) !== input.expectedActiveVersion
          ) {
            throw new ConflictError('secret version changed');
          }

          const [version] = await tx
            .insert(vaultSecretVersions)
            .values({
              secretId: secret.id,
              version: input.version,
              algorithm: input.sealed.algorithm,
              ciphertext: input.sealed.ciphertext,
              nonce: input.sealed.nonce,
              authTag: input.sealed.authTag,
              wrappedDek: input.sealed.wrappedDek,
              kekVersion: input.sealed.kekVersion,
              aadVersion: input.sealed.aadVersion,
              createdAt: input.now,
            })
            .returning({ id: vaultSecretVersions.id });
          // Compare-and-set: the pointer moves only from the version this call read under the
          // row lock, and never on a revoked secret.
          const moved = await tx
            .update(vaultSecrets)
            .set({
              activeVersionId: version!.id,
              status: 'active',
              lastVersion: input.version,
              updatedAt: input.now,
            })
            .where(
              and(
                eq(vaultSecrets.id, secret.id),
                ne(vaultSecrets.status, 'revoked'),
                secret.activeVersionId === null
                  ? sql`${vaultSecrets.activeVersionId} is null`
                  : eq(vaultSecrets.activeVersionId, secret.activeVersionId),
              ),
            )
            .returning({ id: vaultSecrets.id });
          if (moved.length !== 1) throw new ConflictError('secret version changed');
          await tx
            .delete(vaultSecretVersions)
            .where(
              and(
                eq(vaultSecretVersions.secretId, secret.id),
                ne(vaultSecretVersions.id, version!.id),
              ),
            );
        }),
      );
    },

    /** The ciphertext of the active version, or null unless the secret's status is `active`. */
    async getActive(connectionId: string, secretType: string): Promise<ActiveSecret | null> {
      if (!isUuid(connectionId)) return null;
      const [row] = await db
        .select({ secretId: vaultSecrets.id, version: vaultSecretVersions })
        .from(vaultSecrets)
        .innerJoin(vaultSecretVersions, eq(vaultSecretVersions.id, vaultSecrets.activeVersionId))
        .where(
          and(
            eq(vaultSecrets.connectionId, connectionId),
            eq(vaultSecrets.secretType, secretType),
            eq(vaultSecrets.status, 'active'),
          ),
        )
        .limit(1);
      if (row === undefined) return null;
      return {
        secretId: row.secretId,
        version: row.version.version,
        sealed: {
          algorithm: row.version.algorithm,
          ciphertext: row.version.ciphertext,
          nonce: row.version.nonce,
          authTag: row.version.authTag,
          wrappedDek: row.version.wrappedDek,
          kekVersion: row.version.kekVersion,
          aadVersion: row.version.aadVersion,
        },
      };
    },

    async touchAccessed(secretId: string, now: Date): Promise<void> {
      if (!isUuid(secretId)) return;
      await db
        .update(vaultSecrets)
        .set({ lastAccessedAt: now, updatedAt: now })
        .where(eq(vaultSecrets.id, secretId));
    },

    /**
     * Removes every ciphertext row of the connection and clears the active pointers. The
     * secrets become `revoked` (terminal) when the connection is `revoked`, so a revoked
     * connection's secret can never be written or read again, and `deleted` otherwise ("delete
     * stored session"). The metadata rows stay, with their version counters. Takes the
     * connection row FOR NO KEY UPDATE before the secret rows (the lock order of ADR-014
     * section 7); inside the revocation transaction the lock is already held. Returns the number
     * of version rows deleted. Capability revocation is `capabilities.revokeForConnection`,
     * which `connections.revoke` calls itself; this function leaves capabilities alone.
     */
    async deleteForConnection(connectionId: string, now: Date): Promise<number> {
      if (!isUuid(connectionId)) return 0;
      return db.transaction(async (tx) => {
        const [connection] = await tx
          .select({ status: connections.status })
          .from(connections)
          .where(eq(connections.id, connectionId))
          .limit(1)
          .for('no key update');
        const secrets = await tx
          .select({ id: vaultSecrets.id })
          .from(vaultSecrets)
          .where(eq(vaultSecrets.connectionId, connectionId))
          .for('update');
        if (secrets.length === 0) return 0;
        const deleted = await tx
          .delete(vaultSecretVersions)
          .where(
            inArray(
              vaultSecretVersions.secretId,
              secrets.map((secret) => secret.id),
            ),
          )
          .returning({ id: vaultSecretVersions.id });
        await tx
          .update(vaultSecrets)
          .set({
            // A revoked secret stays revoked whatever the connection says now (terminal).
            status:
              connection?.status === 'revoked'
                ? 'revoked'
                : sql`case when ${vaultSecrets.status} = 'revoked' then 'revoked' else 'deleted' end`,
            activeVersionId: null,
            updatedAt: now,
          })
          .where(eq(vaultSecrets.connectionId, connectionId));
        return deleted.length;
      });
    },

    /**
     * The exact bound version's ciphertext, or null when that version number is not the
     * secret's active version (or the secret is not `active`). The vault reads it in the
     * transaction of the consume that bound it (ADR-014 section 6).
     */
    async getVersion(secretId: string, version: number): Promise<ActiveSecret | null> {
      if (!isUuid(secretId) || !Number.isSafeInteger(version)) return null;
      const [row] = await db
        .select({ secretId: vaultSecrets.id, version: vaultSecretVersions })
        .from(vaultSecrets)
        .innerJoin(vaultSecretVersions, eq(vaultSecretVersions.id, vaultSecrets.activeVersionId))
        .where(
          and(
            eq(vaultSecrets.id, secretId),
            eq(vaultSecrets.status, 'active'),
            eq(vaultSecretVersions.version, version),
          ),
        )
        .limit(1);
      if (row === undefined) return null;
      return {
        secretId: row.secretId,
        version: row.version.version,
        sealed: {
          algorithm: row.version.algorithm,
          ciphertext: row.version.ciphertext,
          nonce: row.version.nonce,
          authTag: row.version.authTag,
          wrappedDek: row.version.wrappedDek,
          kekVersion: row.version.kekVersion,
          aadVersion: row.version.aadVersion,
        },
      };
    },

    /**
     * Rewrap (ADR-014 section 7): ONE conditional UPDATE of exactly two columns, `wrapped_dek`
     * and `kek_version`, of a version row, only while `kek_version` and `wrapped_dek` still hold
     * what the caller read and the secret and its connection are not `revoked`. It inserts no
     * row, changes no status and never touches the ciphertext, nonce, tag or any other column.
     * Takes the connection FOR SHARE first, like a read. Returns false (skipped) when no row
     * matched: replaced, deleted, revoked or already rewrapped. Appends `vault.secret_rewrapped`
     * in the same transaction when it changed a row.
     */
    async rewrapVersion(input: RewrapVersionInput): Promise<boolean> {
      if (
        !isUuid(input.versionId) ||
        !Number.isSafeInteger(input.fromKekVersion) ||
        input.fromKekVersion < 1 ||
        !Number.isSafeInteger(input.toKekVersion) ||
        input.toKekVersion < 1 ||
        input.toKekVersion === input.fromKekVersion ||
        !Buffer.isBuffer(input.expectedWrappedDek) ||
        !Buffer.isBuffer(input.newWrappedDek) ||
        input.newWrappedDek.length === 0
      ) {
        throw new ValidationError('invalid rewrap', [{ path: 'input', message: 'invalid rewrap' }]);
      }
      return translateDbErrors('secret version', () =>
        db.transaction(async (tx) => {
          const [owner] = await tx
            .select({ connectionId: vaultSecrets.connectionId })
            .from(vaultSecretVersions)
            .innerJoin(vaultSecrets, eq(vaultSecrets.id, vaultSecretVersions.secretId))
            .where(eq(vaultSecretVersions.id, input.versionId))
            .limit(1);
          if (owner === undefined) return false;
          await tx
            .select({ id: connections.id })
            .from(connections)
            .where(eq(connections.id, owner.connectionId))
            .for('share');

          const rows = rowsOf(
            await tx.execute(sql`
              update vault_secret_versions as v
              set wrapped_dek = ${input.newWrappedDek}, kek_version = ${input.toKekVersion}::int
              from vault_secrets as s, connections as k
              where v.id = ${input.versionId}::uuid
                and v.kek_version = ${input.fromKekVersion}::int
                and v.wrapped_dek = ${input.expectedWrappedDek}
                and s.id = v.secret_id
                and s.status <> 'revoked'
                and k.id = s.connection_id
                and k.status <> 'revoked'
              returning v.secret_id, v.version, s.connection_id, k.organization_id`),
          );
          if (rows[0] === undefined) return false;
          await createAuditRepository(tx).append({
            organizationId: String(rows[0].organization_id),
            actorType: 'system',
            actorId: null,
            connectionId: String(rows[0].connection_id),
            eventType: AuditEventType.parse('vault.secret_rewrapped'),
            timestamp: input.now,
            metadata: {
              connectionId: String(rows[0].connection_id),
              vaultEntryId: String(rows[0].secret_id),
              entryVersion: Number(rows[0].version),
              keyVersionFrom: input.fromKekVersion,
              keyVersionTo: input.toKekVersion,
            },
          });
          return true;
        }),
      );
    },

    /**
     * Versions whose key is wrapped under a KEK version below `belowKekVersion`, for a rewrap
     * batch: oldest id first, after `afterVersionId`, at most `limit` (1 to 500). Skips secrets and
     * connections that are `revoked`. Returns the wrapped key and the identity the AAD needs,
     * never the ciphertext.
     */
    async listForRewrap(input: {
      belowKekVersion: number;
      limit: number;
      afterVersionId?: string | undefined;
    }): Promise<RewrapCandidate[]> {
      if (
        !Number.isSafeInteger(input.belowKekVersion) ||
        input.belowKekVersion < 2 ||
        !Number.isSafeInteger(input.limit) ||
        input.limit < 1 ||
        input.limit > 500 ||
        (input.afterVersionId !== undefined && !isUuid(input.afterVersionId))
      ) {
        throw new ValidationError('invalid rewrap listing', [
          { path: 'input', message: 'invalid rewrap listing' },
        ]);
      }
      const rows = await db
        .select({
          versionId: vaultSecretVersions.id,
          secretId: vaultSecrets.id,
          secretType: vaultSecrets.secretType,
          connectionId: connections.id,
          organizationId: connections.organizationId,
          ownerUserId: connections.ownerUserId,
          version: vaultSecretVersions.version,
          kekVersion: vaultSecretVersions.kekVersion,
          aadVersion: vaultSecretVersions.aadVersion,
          wrappedDek: vaultSecretVersions.wrappedDek,
        })
        .from(vaultSecretVersions)
        .innerJoin(vaultSecrets, eq(vaultSecrets.id, vaultSecretVersions.secretId))
        .innerJoin(connections, eq(connections.id, vaultSecrets.connectionId))
        .where(
          and(
            lt(vaultSecretVersions.kekVersion, input.belowKekVersion),
            ne(vaultSecrets.status, 'revoked'),
            ne(connections.status, 'revoked'),
            input.afterVersionId === undefined
              ? undefined
              : gt(vaultSecretVersions.id, input.afterVersionId),
          ),
        )
        .orderBy(asc(vaultSecretVersions.id))
        .limit(input.limit);
      return rows;
    },

    /** How many stored versions each KEK version still wraps (installation level, no scope). */
    async countByKekVersion(): Promise<{ kekVersion: number; versions: number }[]> {
      const rows = await db
        .select({
          kekVersion: vaultSecretVersions.kekVersion,
          versions: sql<number>`count(*)::int`,
        })
        .from(vaultSecretVersions)
        .groupBy(vaultSecretVersions.kekVersion)
        .orderBy(asc(vaultSecretVersions.kekVersion));
      return rows.map((row) => ({ kekVersion: row.kekVersion, versions: Number(row.versions) }));
    },

    /** Metadata for every secret of the connection. Unscoped, for the broker's own use. */
    describeForConnection(connectionId: string): Promise<SecretDescription[]> {
      return describeConnection(db, connectionId);
    },

    /**
     * Dashboard (B5): metadata of the secrets of one connection in the caller's scope (owner
     * and organization). NotFoundError for a connection outside it, whoever owns it. Never
     * ciphertext.
     */
    async describeForOwner(scope: Scope, connectionId: string): Promise<SecretDescription[]> {
      if (!isValidScope(scope) || !isUuid(connectionId)) throw new NotFoundError('connection');
      const [owned] = await db
        .select({ id: connections.id })
        .from(connections)
        .where(
          and(
            eq(connections.id, connectionId),
            eq(connections.organizationId, scope.organizationId),
            eq(connections.ownerUserId, scope.userId),
          ),
        )
        .limit(1);
      if (owned === undefined) throw new NotFoundError('connection');
      return describeConnection(db, connectionId);
    },
  };
}
