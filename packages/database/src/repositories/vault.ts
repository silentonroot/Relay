import { and, eq, inArray, ne } from 'drizzle-orm';
import type { Db } from '../client.js';
import { ConflictError, NotFoundError, translateDbErrors } from '../errors.js';
import { vaultSecrets, vaultSecretVersions } from '../schema.js';
import { isUuid } from '../support.js';

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

export interface ActiveSecret {
  secretId: string;
  version: number;
  sealed: SealedSecretRecord;
}

/** What the dashboard may know about a stored secret. Never ciphertext. */
export interface SecretDescription {
  id: string;
  secretType: string;
  status: 'pending' | 'active' | 'deleted';
  activeVersion: number | null;
  kekVersion: number | null;
  lastAccessedAt: string | null;
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
     */
    async ensureSecret(input: {
      connectionId: string;
      secretType: string;
      now: Date;
    }): Promise<EnsuredSecret> {
      if (!isUuid(input.connectionId)) throw new NotFoundError('connection');
      return translateDbErrors('secret', async () => {
        await db
          .insert(vaultSecrets)
          .values({
            connectionId: input.connectionId,
            secretType: input.secretType,
            createdAt: input.now,
            updatedAt: input.now,
          })
          .onConflictDoNothing({ target: [vaultSecrets.connectionId, vaultSecrets.secretType] });
        const [row] = await db
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
      });
    },

    /**
     * Stores a version, makes it the active one, marks the secret `active` and deletes every
     * other version, all in one transaction. ConflictError when `version` was already used
     * (stored or deleted) for this secret; NotFoundError for an unknown secret.
     */
    async putVersion(input: {
      secretId: string;
      version: number;
      sealed: SealedSecretRecord;
      now: Date;
    }): Promise<void> {
      if (!isUuid(input.secretId)) throw new NotFoundError('secret');
      await translateDbErrors('secret version', () =>
        db.transaction(async (tx) => {
          const [secret] = await tx
            .select({ id: vaultSecrets.id, lastVersion: vaultSecrets.lastVersion })
            .from(vaultSecrets)
            .where(eq(vaultSecrets.id, input.secretId))
            .limit(1)
            .for('update');
          if (secret === undefined) throw new NotFoundError('secret');
          if (input.version <= secret.lastVersion) {
            throw new ConflictError('secret version already used');
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
          await tx
            .update(vaultSecrets)
            .set({
              activeVersionId: version!.id,
              status: 'active',
              lastVersion: input.version,
              updatedAt: input.now,
            })
            .where(eq(vaultSecrets.id, secret.id));
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
     * Revocation: removes every ciphertext row of the connection and marks its secrets
     * `deleted`. The metadata rows stay, with their version counters. Returns the number of
     * version rows deleted.
     */
    async deleteForConnection(connectionId: string, now: Date): Promise<number> {
      if (!isUuid(connectionId)) return 0;
      return db.transaction(async (tx) => {
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
          .set({ status: 'deleted', activeVersionId: null, updatedAt: now })
          .where(eq(vaultSecrets.connectionId, connectionId));
        return deleted.length;
      });
    },

    /** Metadata for every secret of the connection. */
    async describeForConnection(connectionId: string): Promise<SecretDescription[]> {
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
    },
  };
}
