import {
  CapabilityRejectionReason,
  ConnectionVaultMetadata,
  DeleteStoredSessionResult,
  IdParams,
  RevokeCapabilitiesResult,
  Routes,
  VAULT_KEY_PROTECTION_STATEMENT,
  VaultKeyStatus,
} from '@aab/contracts';
import { InvalidTransitionError } from '@aab/database';
import { auditAsUser } from '../audit.js';
import { authOf } from '../auth/session.js';
import type { AppContext } from '../context.js';
import { AppError, conflict, notFound } from '../errors.js';
import type { ZodApp } from '../types.js';

const NO_STORED_SESSION = 'This connection has no stored session to delete.';

/**
 * Stable order for the rejection counts, so a response does not depend on row order. Derived
 * from the enum: a new reason is listed (at the end) without a second edit to forget.
 */
const REJECTION_ORDER: readonly CapabilityRejectionReason[] = CapabilityRejectionReason.options;

/**
 * The vault's `status` for the owner's dashboard (ADR-014 section 12). The `api` role may call
 * it; it holds KEK version numbers, counts and counters, never a key, a token or a secret. Only
 * the organization's owner sees it: the installation's key state is not a member's business.
 * A vault that cannot be reached is a 503 with the usual error body and no detail of why.
 *
 * The per-connection routes follow the connection routes: every read and write takes the scope
 * of the session, so another owner's connection is a 404 like one that does not exist, and the
 * two actions are open to every role for the connections the caller owns, as revoking a
 * connection is. They need no vault: removing authority needs no key (ADR-014 section 7).
 */
export function registerVaultRoutes(app: ZodApp, ctx: AppContext) {
  app.get(
    Routes.vaultStatus,
    { schema: { response: { 200: VaultKeyStatus } } },
    async (request) => {
      if (authOf(request).session.role !== 'owner') {
        throw new AppError(403, 'forbidden', 'Only owners can see the vault status.');
      }
      if (ctx.vault === undefined) {
        throw new AppError(503, 'service_unavailable', 'The vault is not available.');
      }
      try {
        const status = await ctx.vault.status();
        return { ...status, protectionStatement: VAULT_KEY_PROTECTION_STATEMENT };
      } catch (error) {
        request.log.warn(
          { errorName: error instanceof Error ? error.name : 'unknown' },
          'vault status unavailable',
        );
        throw new AppError(503, 'service_unavailable', 'The vault is not available.');
      }
    },
  );

  /* ------------------------------------------------------------ per connection */

  app.get(
    Routes.connectionVault,
    { schema: { params: IdParams, response: { 200: ConnectionVaultMetadata } } },
    async (request) => {
      const scope = authOf(request).scope;
      const connection = await ctx.repos.connections.get(scope, request.params.id);
      if (connection === null) throw notFound();
      // Both reads re-check the scope themselves and answer NotFound for a foreign connection.
      const secrets = await ctx.repos.vault.describeForOwner(scope, connection.id);
      const summary = await ctx.repos.capabilities.summarizeLast24Hours(scope, connection.id);
      return {
        connectionId: connection.id,
        connectionStatus: connection.status,
        secrets: secrets.map((secret) => ({
          secretType: secret.secretType,
          status: secret.status,
          activeVersion: secret.activeVersion,
          kekVersion: secret.kekVersion,
          lastAccessedAt: secret.lastAccessedAt,
        })),
        capabilities: {
          windowHours: 24 as const,
          authorized: summary.authorized,
          used: summary.used,
          revoked: summary.revoked,
          rejected: REJECTION_ORDER.flatMap((reason) => {
            const count = summary.rejectedByReason[reason] ?? 0;
            return count > 0 ? [{ reason, count }] : [];
          }),
        },
      };
    },
  );

  // "Delete stored session" (ADR-014 section 7): one transaction. The connection row is locked
  // first (the transition), then the versions go, the secrets become `deleted`, the unused
  // capabilities are revoked and the connection needs a new login. Nothing here asks the vault.
  app.post(
    Routes.connectionVaultDeleteSession,
    { schema: { params: IdParams, response: { 200: DeleteStoredSessionResult } } },
    async (request) => {
      const auth = authOf(request);
      const now = ctx.clock();
      return ctx.repos.transaction(async (tx) => {
        // Takes the connection FOR UPDATE and refuses an invalid transition with 409: a revoked
        // connection, or one that cannot move to `reconnect_required` (for example, a repeat).
        // `clearSessionExpiry`: the connection no longer holds a session that expires later.
        const updated = await tx.connections
          .transitionStatus(auth.scope, request.params.id, {
            to: 'reconnect_required',
            reason: 'stored session deleted',
            clearSessionExpiry: true,
          })
          .catch((error: unknown) => {
            if (!(error instanceof InvalidTransitionError)) throw error;
            // A repeat (already reconnect_required) has no stored session left to delete; other
            // states (revoked, mid-login) cannot have theirs deleted now. No state names leak.
            throw conflict(
              error.from === 'reconnect_required'
                ? NO_STORED_SESSION
                : "The stored session cannot be deleted in the connection's current state.",
            );
          });
        const secretsBefore = await tx.vault.describeForConnection(updated.id);
        const stored = secretsBefore.filter((secret) => secret.activeVersion !== null);
        // Nothing stored: a conflict, and the transition above rolls back with it.
        if (stored.length === 0) throw conflict(NO_STORED_SESSION);
        const versionsDeleted = await tx.vault.deleteForConnection(updated.id, now);
        // `vault.capability_revoked` is appended by the repository when any changed.
        const revoked = await tx.capabilities.revokeForConnection({
          connectionId: updated.id,
          reason: 'session_deleted',
          now,
          actor: { type: 'user', id: auth.scope.userId },
        });
        // Lock order, as revoking a connection: connection, secrets, capabilities, then jobs.
        // Queued jobs end `cancelled` and running ones are flagged, so no worker later claims a
        // job whose capability this action revoked and trips `vault.capability_rejected`
        // (the theft signal) for the owner's own action.
        const cancelled = await tx.jobs.cancelForConnection(updated.id, now);
        await auditAsUser(tx, auth.scope, now, {
          eventType: 'connection.status_changed',
          connectionId: updated.id,
          metadata: {
            connectionId: updated.id,
            displayName: updated.displayName,
            status: updated.status,
            reason: 'stored_session_deleted',
          },
        });
        await auditAsUser(tx, auth.scope, now, {
          eventType: 'vault.secret_deleted',
          connectionId: updated.id,
          metadata: {
            connectionId: updated.id,
            vaultEntryIds: stored.map((secret) => secret.id),
            versionsDeleted,
            jobsCancelled: cancelled.length,
            reason: 'owner_deleted_session',
          },
        });
        return {
          connectionId: updated.id,
          connectionStatus: updated.status,
          versionsDeleted,
          capabilitiesRevoked: revoked.revoked,
          jobsCancelled: cancelled.length,
        };
      });
    },
  );

  // "Revoke outstanding capabilities": the unused authorizations and tokens of the connection die;
  // the connection and its stored session stay as they are.
  app.post(
    Routes.connectionVaultRevokeCapabilities,
    { schema: { params: IdParams, response: { 200: RevokeCapabilitiesResult } } },
    async (request) => {
      const auth = authOf(request);
      const now = ctx.clock();
      return ctx.repos.transaction(async (tx) => {
        const connection = await tx.connections.get(auth.scope, request.params.id);
        if (connection === null) throw notFound();
        // Queued jobs whose capability this call revokes are cancelled in the same transaction
        // (after the capabilities, as revoking a connection orders them), so no worker claims a
        // job and trips `vault.capability_rejected` for the owner's own action. Running jobs are
        // left alone: their read was already consumed.
        let jobsCancelled = 0;
        const revoked = await tx.capabilities.revokeForConnection({
          connectionId: connection.id,
          reason: 'owner_requested',
          now,
          actor: { type: 'user', id: auth.scope.userId },
          onRevoked: async (capabilityIds) => {
            const cancelled = await tx.jobs.cancelQueuedForCapabilities(
              connection.id,
              capabilityIds,
              now,
            );
            jobsCancelled = cancelled.length;
            return { jobsCancelled };
          },
        });
        // Every owner action leaves a trace: the repository wrote the event when something was
        // revoked; with nothing to revoke this writes the same event with a count of 0.
        if (revoked.revoked === 0) {
          await auditAsUser(tx, auth.scope, now, {
            eventType: 'vault.capability_revoked',
            connectionId: connection.id,
            metadata: {
              connectionId: connection.id,
              reason: 'owner_requested',
              count: 0,
              capabilityIds: [],
              jobsCancelled: 0,
            },
          });
        }
        return {
          connectionId: connection.id,
          capabilitiesRevoked: revoked.revoked,
          jobsCancelled,
        };
      });
    },
  );
}
