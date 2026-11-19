import { randomUUID } from 'node:crypto';
import {
  AuditEventType,
  SESSION_SNAPSHOT_SECRET_TYPE,
  VAULT_MAX_PLAINTEXT_BYTES,
} from '@aab/contracts';
import type { CapabilityRejectionReason, VaultOperation, VaultRole } from '@aab/contracts';
import { generateToken, hashToken, openSecret, rewrapSecret, sealSecret } from '@aab/crypto';
import type { SecretAad } from '@aab/crypto';
import { authorizationWindow, ConflictError, NotFoundError, ValidationError } from '@aab/database';
import type { CapabilityRecord, Repositories } from '@aab/database';
import type { Logger } from 'pino';
import { helloHandler, VaultOperationError } from './handlers.js';
import type { Handler, VaultContext, VaultHandlers } from './handlers.js';
import { errorFacts } from './logging.js';
import { authorizationMac, tokenMac, verifyAuthorizationMac, verifyTokenMac } from './mac.js';
import type { VaultKeys } from './keys.js';

/*
 * The vault operations of ADR-014 section 4. This module is the only caller of the repository
 * functions that decide access (`capabilities.*`, `vault.putVersion`, `vault.getVersion`,
 * `vault.rewrapVersion`; "B2 must guarantee" in docs/phase-3.md).
 *
 * Rules every operation follows:
 *  - Every repository call gets a fresh `clock()` taken immediately before it; no time comes from
 *    a request or an earlier step.
 *  - A refused capability answers `forbidden` and nothing else. The reason goes to the audit
 *    event `vault.capability_rejected` only (P3-12).
 *  - An internal failure (database down, key missing, a bug) answers `service_unavailable`, is
 *    logged as `vault request failed` (error type and code only) and writes NO rejection event.
 *  - Nothing here logs a token, a MAC, a hash, a key or plaintext.
 */

export interface VaultCounters {
  /** Rejections that resolved to no organization (cannot be put on a chain): logged and counted. */
  rejectedUnattributed: number;
  /** Role-refused requests that resolved to no organization, or were rate limited. */
  refusedUnattributed: number;
  /** Rejections written to a chain since the vault started. */
  rejectedAudited: number;
  /** Requests that failed internally (service_unavailable). */
  internalFailures: number;
  /** Rejection events not appended because their organization was over its per-minute limit. */
  rejectedRateLimited: number;
}

export function newCounters(): VaultCounters {
  return {
    rejectedUnattributed: 0,
    refusedUnattributed: 0,
    rejectedAudited: 0,
    internalFailures: 0,
    rejectedRateLimited: 0,
  };
}

/** `vault.capability_rejected` appends per organization per window (as `refusals.ts`). */
export const REJECTION_WINDOW_MS = 60_000;
export const REJECTIONS_PER_WINDOW = 60;
/** Most rows one `rewrap` call processes; the admin command calls again while rows remain. */
export const REWRAP_MAX_ROWS_PER_CALL = 500;
/** The largest batch `listForRewrap` is asked for. */
export const REWRAP_MAX_BATCH = 500;
/** A session is never recorded as valid for longer than a browser keeps a cookie (400 days). */
export const MAX_SESSION_LIFETIME_MS = 400 * 24 * 60 * 60 * 1000;

export interface OperationDeps {
  repositories: Repositories;
  keys: VaultKeys;
  logger: Logger;
  counters: VaultCounters;
  /** Wall clock; tests may replace it. Called immediately before every repository call. */
  clock?: () => Date;
  /** Test-only seam for the crash-safety test: called after each rewrapped row. */
  afterRewrapRow?: (rewrappedSoFar: number) => void | Promise<void>;
  /** Rows one `rewrap` call may process (default `REWRAP_MAX_ROWS_PER_CALL`); tests lower it. */
  rewrapMaxRowsPerCall?: number;
  /** Rejection events per organization per minute (default `REJECTIONS_PER_WINDOW`). */
  rejectionsPerWindow?: number;
}

/**
 * Checks a decoded `completeLogin` payload before anything is sealed: JSON of the Playwright
 * storage-state shape (`cookies` and `origins` arrays of objects), within the size cap, not empty.
 * The supervisor filters by origin before it sends (docs/phase-3.md B3); the vault does not trust that.
 */
export function inspectStorageState(
  plaintext: Buffer,
): { problem: string } | { cookieCount: number; originCount: number } {
  if (plaintext.length === 0) return { problem: 'empty' };
  if (plaintext.length > VAULT_MAX_PLAINTEXT_BYTES) return { problem: 'too_large' };
  let value: unknown;
  try {
    value = JSON.parse(plaintext.toString('utf8'));
  } catch {
    return { problem: 'not_json' };
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return { problem: 'shape' };
  }
  const { cookies, origins } = value as Record<string, unknown>;
  const isObjectList = (list: unknown): list is Array<Record<string, unknown>> =>
    Array.isArray(list) &&
    list.every((entry) => typeof entry === 'object' && entry !== null && !Array.isArray(entry));
  if (!isObjectList(cookies) || !isObjectList(origins)) return { problem: 'shape' };
  if (cookies.length === 0 && origins.length === 0) return { problem: 'empty_state' };
  return { cookieCount: cookies.length, originCount: origins.length };
}

const SECRET_TYPE = SESSION_SNAPSHOT_SECRET_TYPE;

function normalizeHint(hint: string | null): string | null {
  const trimmed = hint?.trim().slice(0, 120);
  return trimmed ? trimmed : null;
}

/** Outcome of the transactional part of a redemption. */
type Redemption<T> =
  | { kind: 'ok'; value: T }
  /** The consume matched no row: nothing changed, label and audit it in a separate transaction. */
  | { kind: 'unconsumed' }
  /** The consume committed together with a `vault.capability_rejected` event. */
  | { kind: 'rejected' };

export function createHandlers(deps: OperationDeps): VaultHandlers {
  const { repositories: repos, keys, logger, counters } = deps;
  const clock = deps.clock ?? (() => new Date());
  let rewrapRunning = false;
  const rewrapMaxRows = deps.rewrapMaxRowsPerCall ?? REWRAP_MAX_ROWS_PER_CALL;
  const rejectionsPerWindow = deps.rejectionsPerWindow ?? REJECTIONS_PER_WINDOW;
  const rejectionWindows = new Map<string, { start: number; count: number }>();

  /** Maps anything unexpected to `service_unavailable`, after logging its type and code. */
  function guard<Op extends VaultOperation>(operation: Op, handler: Handler<Op>): Handler<Op> {
    return async (context, params) => {
      try {
        return await handler(context, params);
      } catch (error) {
        if (error instanceof VaultOperationError) throw error;
        counters.internalFailures += 1;
        logger.error(
          { operation, role: context.role, ...errorFacts(error) },
          'vault request failed',
        );
        throw new VaultOperationError('service_unavailable');
      }
    };
  }

  async function recordRejectionFor(
    tx: Repositories,
    rejection: Parameters<Repositories['capabilities']['recordRejection']>[0],
    role: VaultRole,
  ): Promise<void> {
    // A caller that is refused in a loop must not fill an organization's chain: at most
    // `rejectionsPerWindow` appends per organization per minute, the overflow is logged and counted.
    const now = clock();
    const key = rejection.organizationId ?? '-';
    const nowMs = now.getTime();
    let window = rejectionWindows.get(key);
    if (window === undefined || nowMs - window.start >= REJECTION_WINDOW_MS) {
      if (rejectionWindows.size >= 4096) {
        for (const [other, entry] of rejectionWindows) {
          if (nowMs - entry.start >= REJECTION_WINDOW_MS) rejectionWindows.delete(other);
        }
      }
      window = { start: nowMs, count: 0 };
      rejectionWindows.set(key, window);
    }
    if (window.count >= rejectionsPerWindow) {
      counters.rejectedRateLimited += 1;
      logger.warn(
        { event: 'vault.capability_rejected', reason: rejection.reason, role, rateLimited: true },
        'capability rejection not appended: organization over its rejection rate limit',
      );
      return;
    }
    window.count += 1;
    const id = await tx.capabilities.recordRejection(rejection, { role, now });
    if (id === null) {
      counters.rejectedUnattributed += 1;
      logger.warn(
        { event: 'vault.capability_rejected', reason: rejection.reason, role },
        'capability rejection resolved to no organization; counted, not on a chain',
      );
    } else {
      counters.rejectedAudited += 1;
    }
  }

  /** A refusal where the consume matched nothing: label it and audit it in its own transaction. */
  async function rejectUnconsumed(
    purpose: 'read' | 'seal',
    role: VaultRole,
    input: { tokenHash: string; jobId: string; connectionId: string; operation: string | null },
  ): Promise<never> {
    const described = await repos.capabilities.describeForRejection({
      ...input,
      purpose,
      now: clock(),
    });
    await recordRejectionFor(repos, described, role);
    throw new VaultOperationError('forbidden');
  }

  function macKeyOf(row: CapabilityRecord) {
    return keys.macKey(row.macKekVersion);
  }

  // -------------------------------------------------------------------------------------------
  // authorizeJobAccess (api). The secret row (find or create, `pending` when new) is ensured first
  // in its own short transaction: `insertAuthorization` takes the agent lock before the connection
  // lock (ADR-014 section 7), and `ensureSecret` takes the connection lock, so running both in one
  // transaction would invert the lock order. A leftover `pending` row is inert. Then ONE
  // transaction (inside `insertAuthorization`): the authorization row with its MAC, the job's
  // `capability_ref` and `vault.capability_authorized` commit together or not at all.

  const authorizeJobAccess = guard('authorizeJobAccess', async (_context, params) => {
    try {
      const job = await repos.jobs.getInternal(params.jobId);
      if (job === null) throw new VaultOperationError('not_found');
      if (job.status !== 'queued' || job.capabilityRef !== null || job.cancelRequestedAt !== null) {
        throw new VaultOperationError('conflict');
      }
      const purpose = job.kind === 'operation' ? 'read' : 'seal';
      const ensured = await repos.vault.ensureSecret({
        connectionId: job.connectionId,
        secretType: SECRET_TYPE,
        now: clock(),
      });
      const capabilityId = randomUUID();
      const now = clock();
      const window = authorizationWindow(now, params.ttlSeconds);
      const { kekVersion, key } = keys.currentMacKey();
      const binding = {
        id: capabilityId,
        purpose,
        organizationId: job.organizationId,
        jobId: job.id,
        agentId: purpose === 'read' ? job.agentId : null,
        connectionId: job.connectionId,
        operation: purpose === 'read' ? job.operation : null,
        secretId: ensured.secretId,
        argumentsHash: purpose === 'read' ? job.argumentsHash : null,
        issuedAt: window.issuedAt,
        expiresAt: window.expiresAt,
      } as const;
      const created = await repos.capabilities.insertAuthorization({
        capabilityId,
        jobId: job.id,
        secretId: ensured.secretId,
        purpose,
        organizationId: binding.organizationId,
        agentId: binding.agentId,
        connectionId: binding.connectionId,
        operation: binding.operation,
        argumentsHash: binding.argumentsHash,
        now,
        ttlSeconds: params.ttlSeconds,
        authorizationMac: authorizationMac(key, binding),
        macKekVersion: kekVersion,
      });
      return { capabilityId: created.capabilityId, expiresAt: created.expiresAt };
    } catch (error) {
      if (error instanceof ConflictError) throw new VaultOperationError('conflict');
      if (error instanceof NotFoundError) throw new VaultOperationError('not_found');
      if (error instanceof ValidationError) throw new VaultOperationError('validation_failed');
      throw error;
    }
  });

  // -------------------------------------------------------------------------------------------
  // issueAccessCapability (supervisor): the authorization MAC is verified before the token is
  // generated; `issueToken` then sets the token and its MAC and appends `vault.capability_issued`
  // in one transaction. The raw token exists only in this function and the response.

  async function rejectIssue(
    params: { capabilityId: string; jobId: string; workerId: string; attempt: number },
    role: VaultRole,
    auth: CapabilityRecord | null,
    reason?: CapabilityRejectionReason,
  ): Promise<never> {
    const now = clock();
    let rejection;
    if (auth === null) {
      const job = await repos.jobs.getInternal(params.jobId);
      rejection = {
        reason: 'unknown_token' as CapabilityRejectionReason,
        organizationId: job?.organizationId ?? null,
        capabilityId: null,
        jobId: job?.id ?? null,
        connectionId: job?.connectionId ?? null,
        purpose: (job?.kind === 'login' ? 'seal' : 'read') as 'read' | 'seal',
      };
    } else {
      let label: CapabilityRejectionReason = reason ?? 'integrity';
      if (reason === undefined) {
        // Refused by the conditional UPDATE: label why, for the audit event only.
        const fresh = (await repos.capabilities.getAuthorization(auth.id)) ?? auth;
        const job = await repos.jobs.getInternal(auth.jobId);
        const connection = await repos.connections.getForExecution(auth.connectionId);
        const secrets = await repos.vault.describeForConnection(auth.connectionId);
        const secret = secrets.find((entry) => entry.id === auth.secretId);
        const expectedStatus = auth.purpose === 'read' ? 'active' : 'authenticating';
        if (fresh.revokedAt !== null) label = 'revoked';
        else if (fresh.tokenHash !== null || fresh.usedAt !== null) label = 'used';
        else if (new Date(fresh.expiresAt).getTime() <= now.getTime()) label = 'expired';
        else if (job === null || job.status !== 'running' || job.cancelRequestedAt !== null) {
          label = 'job_not_running';
        } else if (
          job.workerId !== params.workerId ||
          job.attemptCount !== params.attempt ||
          job.capabilityRef !== auth.id
        ) {
          label = 'binding_mismatch';
        } else if (connection?.connection.status !== expectedStatus)
          label = 'connection_not_active';
        else if (
          secret === undefined ||
          secret.status === 'revoked' ||
          secret.status === 'deleted'
        ) {
          label = 'secret_not_active';
        } else label = 'integrity';
      }
      rejection = {
        reason: label,
        organizationId: auth.organizationId,
        capabilityId: auth.id,
        jobId: auth.jobId,
        connectionId: auth.connectionId,
        purpose: auth.purpose,
      };
    }
    void now;
    await recordRejectionFor(repos, rejection, role);
    throw new VaultOperationError('forbidden');
  }

  const issueAccessCapability = guard('issueAccessCapability', async (context, params) => {
    const auth = await repos.capabilities.getAuthorization(params.capabilityId);
    if (auth === null) return rejectIssue(params, context.role, null);
    if (auth.jobId !== params.jobId)
      return rejectIssue(params, context.role, auth, 'binding_mismatch');
    const key = macKeyOf(auth);
    if (key === undefined) return rejectIssue(params, context.role, auth, 'key_unavailable');
    // A row inserted or edited by a database writer fails here, before any token exists.
    if (!verifyAuthorizationMac(key, auth)) {
      return rejectIssue(params, context.role, auth, 'integrity');
    }
    const token = generateToken();
    const issued = await repos.capabilities.issueToken({
      capabilityId: auth.id,
      jobId: params.jobId,
      workerId: params.workerId,
      attempt: params.attempt,
      tokenHash: hashToken(token),
      tokenTtlSeconds: params.ttlSeconds,
      now: clock(),
      authorizationMac: auth.authorizationMac,
      computeTokenMac: (row) => tokenMac(key, row),
    });
    if (issued === null) return rejectIssue(params, context.role, auth);
    return {
      token,
      tokenExpiresAt: issued.tokenExpiresAt!,
      secretVersion: issued.secretVersion!,
    };
  });

  // -------------------------------------------------------------------------------------------
  // readForWorker (supervisor): consume, version load, both MAC checks, open, `last_accessed_at`
  // and `vault.secret_read` in ONE transaction. A refusal after the consume (MAC, key, open)
  // commits the consume with `vault.capability_rejected` and nothing else (ADR-014 section 6: the
  // capability is spent). Any thrown error (database, audit append) rolls the consume back.

  const readForWorker = guard('readForWorker', async (context, params) => {
    const tokenHash = hashToken(params.token);
    const unconsumedInput = {
      tokenHash,
      jobId: params.jobId,
      connectionId: params.connectionId,
      operation: params.operation,
    };
    const outcome = await repos.transaction(
      async (
        tx,
      ): Promise<Redemption<{ plaintext: Buffer; row: CapabilityRecord; kek: number }>> => {
        const consumed = await tx.capabilities.consumeRead({ ...unconsumedInput, now: clock() });
        if (consumed === null) return { kind: 'unconsumed' };
        const reject = async (reason: CapabilityRejectionReason): Promise<Redemption<never>> => {
          await recordRejectionFor(
            tx,
            {
              reason,
              organizationId: consumed.organizationId,
              capabilityId: consumed.id,
              jobId: consumed.jobId,
              connectionId: consumed.connectionId,
              purpose: 'read',
            },
            context.role,
          );
          return { kind: 'rejected' };
        };

        const macKey = macKeyOf(consumed);
        if (macKey === undefined) return reject('key_unavailable');
        if (!verifyAuthorizationMac(macKey, consumed) || !verifyTokenMac(macKey, consumed)) {
          return reject('integrity');
        }
        const version = consumed.secretVersion;
        if (version === null || version < 1) return reject('integrity');
        const stored = await tx.vault.getVersion(consumed.secretId, version);
        if (stored === null) return reject('secret_not_active');
        const target = await tx.connections.getForExecution(consumed.connectionId);
        if (
          target === null ||
          target.connection.organizationId !== consumed.organizationId ||
          target.connection.id !== consumed.connectionId
        ) {
          return reject('integrity');
        }
        if (!keys.kekProvider.hasVersion(stored.sealed.kekVersion))
          return reject('key_unavailable');

        // The AAD comes from the connection row and the capability's binding, never from
        // columns stored beside the ciphertext.
        const aad: SecretAad = {
          organizationId: target.connection.organizationId,
          userId: target.connection.ownerUserId,
          connectionId: consumed.connectionId,
          secretId: consumed.secretId,
          secretType: SECRET_TYPE,
          secretVersion: version,
        };
        let plaintext: Buffer;
        try {
          plaintext = await openSecret({ sealed: stored.sealed, aad, kek: keys.kekProvider });
        } catch {
          return reject('integrity');
        }
        try {
          const now = clock();
          await tx.vault.touchAccessed(consumed.secretId, now);
          await tx.audit.append({
            organizationId: consumed.organizationId,
            actorType: 'system',
            actorId: null,
            agentId: consumed.agentId,
            connectionId: consumed.connectionId,
            eventType: AuditEventType.parse('vault.secret_read'),
            timestamp: clock(),
            metadata: {
              capabilityId: consumed.id,
              jobId: consumed.jobId,
              connectionId: consumed.connectionId,
              vaultEntryId: consumed.secretId,
              entryVersion: version,
              keyVersion: stored.sealed.kekVersion,
              workerId: consumed.workerId,
              attempt: consumed.attempt,
              role: context.role,
            },
          });
        } catch (error) {
          plaintext.fill(0);
          throw error;
        }
        return { kind: 'ok', value: { plaintext, row: consumed, kek: stored.sealed.kekVersion } };
      },
    );
    if (outcome.kind === 'unconsumed')
      return rejectUnconsumed('read', context.role, {
        ...unconsumedInput,
      });
    if (outcome.kind === 'rejected') throw new VaultOperationError('forbidden');
    const { plaintext, row, kek } = outcome.value;
    try {
      return {
        secretType: SESSION_SNAPSHOT_SECRET_TYPE,
        secretVersion: row.secretVersion!,
        kekVersion: kek,
        argumentsHash: row.argumentsHash,
        plaintext: plaintext.toString('base64url'),
      };
    } finally {
      plaintext.fill(0);
    }
  });

  // -------------------------------------------------------------------------------------------
  // completeLogin (supervisor): consume the seal capability, check both MACs, seal under a fresh
  // DEK and the active KEK, move the active pointer only from the version bound at issue, activate
  // the connection, record the session, append `vault.secret_stored` and
  // `connection.auth_completed` and complete the login job: ONE transaction. Anything that throws
  // rolls all of it back; the previous version stays the active one.

  const completeLogin = guard('completeLogin', async (context, params) => {
    const tokenHash = hashToken(params.token);
    const unconsumedInput = {
      tokenHash,
      jobId: params.jobId,
      connectionId: params.connectionId,
      operation: null,
    };
    const plaintext = Buffer.from(params.plaintext, 'base64url');
    try {
      const outcome = await repos.transaction(
        async (
          tx,
        ): Promise<Redemption<{ secretId: string; secretVersion: number; kekVersion: number }>> => {
          const consumed = await tx.capabilities.consumeSeal({ ...unconsumedInput, now: clock() });
          if (consumed === null) return { kind: 'unconsumed' };
          const reject = async (reason: CapabilityRejectionReason): Promise<Redemption<never>> => {
            await recordRejectionFor(
              tx,
              {
                reason,
                organizationId: consumed.organizationId,
                capabilityId: consumed.id,
                jobId: consumed.jobId,
                connectionId: consumed.connectionId,
                purpose: 'seal',
              },
              context.role,
            );
            return { kind: 'rejected' };
          };
          const macKey = macKeyOf(consumed);
          if (macKey === undefined) return reject('key_unavailable');
          if (!verifyAuthorizationMac(macKey, consumed) || !verifyTokenMac(macKey, consumed)) {
            return reject('integrity');
          }
          const bound = consumed.secretVersion;
          if (bound === null || bound < 0) return reject('integrity');

          const target = await tx.connections.getForExecution(consumed.connectionId);
          if (
            target === null ||
            target.connection.organizationId !== consumed.organizationId ||
            target.connection.status !== 'authenticating'
          ) {
            return reject('connection_not_active');
          }
          // Refused after the consume checks (only a capability holder learns anything) and
          // before anything is sealed: thrown, so the transaction rolls back and the capability
          // stays unspent for a corrected attempt.
          const inspected = inspectStorageState(plaintext);
          if ('problem' in inspected) {
            logger.warn(
              { operation: 'completeLogin', problem: inspected.problem },
              'storage state refused',
            );
            throw new VaultOperationError('validation_failed');
          }
          const now = clock();
          // Bounded: never in the past, never beyond what a browser keeps a cookie. The
          // supervisor derives the expiry from the state; the vault does not take it on trust.
          let sessionExpiresAt: Date | null = null;
          if (params.sessionExpiresAt !== null) {
            sessionExpiresAt = new Date(params.sessionExpiresAt);
            if (sessionExpiresAt.getTime() <= now.getTime()) {
              throw new VaultOperationError('validation_failed');
            }
            const latest = new Date(now.getTime() + MAX_SESSION_LIFETIME_MS);
            if (sessionExpiresAt.getTime() > latest.getTime()) sessionExpiresAt = latest;
          }
          const hint = normalizeHint(params.externalAccountHint);
          // A verified connection must not silently become a different account (as in Phase 2).
          if (
            target.connection.lastVerifiedAt !== null &&
            normalizeHint(target.connection.externalAccountHint) !== hint
          ) {
            throw new VaultOperationError('conflict');
          }

          const ensured = await tx.vault.ensureSecret({
            connectionId: consumed.connectionId,
            secretType: SECRET_TYPE,
            now: clock(),
          });
          if (ensured.secretId !== consumed.secretId) return reject('integrity');
          const version = ensured.nextVersion;
          const sealed = await sealSecret({
            plaintext,
            aad: {
              organizationId: target.connection.organizationId,
              userId: target.connection.ownerUserId,
              connectionId: consumed.connectionId,
              secretId: ensured.secretId,
              secretType: SECRET_TYPE,
              secretVersion: version,
            },
            kek: keys.kekProvider,
          });
          await tx.vault.putVersion({
            secretId: ensured.secretId,
            version,
            sealed,
            now: clock(),
            expectedActiveVersion: bound,
          });
          await tx.connections.transitionStatusInternal(consumed.connectionId, { to: 'active' });
          await tx.connections.recordSession(consumed.connectionId, {
            externalAccountHint: hint,
            sessionExpiresAt,
            lastVerifiedAt: now,
          });
          await tx.audit.append({
            organizationId: consumed.organizationId,
            actorType: 'system',
            actorId: null,
            connectionId: consumed.connectionId,
            eventType: AuditEventType.parse('vault.secret_stored'),
            timestamp: clock(),
            metadata: {
              capabilityId: consumed.id,
              jobId: consumed.jobId,
              connectionId: consumed.connectionId,
              vaultEntryId: ensured.secretId,
              entryVersion: version,
              // Phase 2 name for the same number, kept so existing audit queries still match.
              snapshotVersion: version,
              keyVersion: sealed.kekVersion,
              originCount: inspected.originCount,
              role: context.role,
            },
          });
          const event = await tx.audit.append({
            organizationId: consumed.organizationId,
            actorType: 'system',
            actorId: null,
            connectionId: consumed.connectionId,
            eventType: AuditEventType.parse('connection.auth_completed'),
            timestamp: clock(),
            metadata: {
              jobId: consumed.jobId,
              connectionId: consumed.connectionId,
              adapterId: target.application.adapterId,
              adapterVersion: target.application.adapterVersion,
              accountHintRecorded: hint !== null,
              sessionExpiresAt: sessionExpiresAt === null ? null : sessionExpiresAt.toISOString(),
            },
          });
          await tx.jobs.complete(consumed.jobId, consumed.workerId!, {
            status: 'succeeded',
            auditEventId: event.id,
            now: clock(),
          });
          return {
            kind: 'ok',
            value: {
              secretId: ensured.secretId,
              secretVersion: version,
              kekVersion: sealed.kekVersion,
            },
          };
        },
      );
      if (outcome.kind === 'unconsumed') {
        return await rejectUnconsumed('seal', context.role, unconsumedInput);
      }
      if (outcome.kind === 'rejected') throw new VaultOperationError('forbidden');
      return outcome.value;
    } catch (error) {
      // A moved active pointer, a revoked secret or connection, a job no longer held: refused
      // with a plain conflict (everything rolled back, nothing stored).
      if (error instanceof ConflictError) throw new VaultOperationError('conflict');
      throw error;
    } finally {
      plaintext.fill(0);
    }
  });

  // -------------------------------------------------------------------------------------------
  // status, rewrap, kekRetirementCheck

  async function versionCounts(): Promise<Map<number, number>> {
    const rows = await repos.vault.countByKekVersion();
    return new Map(rows.map((row) => [row.kekVersion, row.versions]));
  }

  const status = guard('status', async (context) => {
    const counts = await versionCounts();
    const loaded = new Set(keys.kekVersions);
    const versionsByKek: Record<string, number> = {};
    for (const [version, count] of counts) versionsByKek[String(version)] = count;
    return {
      isolation: context.isolation,
      kekVersions: keys.kekVersions,
      currentKekVersion: keys.currentKekVersion,
      versionsByKek,
      missingKekVersions: [...counts.keys()]
        .filter((version) => !loaded.has(version))
        .sort((a, b) => a - b),
      counters: {
        rejectedUnattributed: counters.rejectedUnattributed,
        refusedUnattributed: counters.refusedUnattributed,
        rejectedAudited: counters.rejectedAudited,
        internalFailures: counters.internalFailures,
        rejectedRateLimited: counters.rejectedRateLimited,
      },
    };
  });

  const rewrap = guard('rewrap', async (_context, params) => {
    // One rewrap at a time; the per-row compare-and-set makes overlap harmless anyway.
    if (rewrapRunning) throw new VaultOperationError('conflict');
    rewrapRunning = true;
    try {
      const target = keys.currentKekVersion;
      let rewrapped = 0;
      let skipped = 0;
      let failed = 0;
      let cursor: string | undefined;
      // The batch actually requested from the database: the cap applies to the comparison too,
      // or a batch size above it would stop after the first (short) batch.
      const batchLimit = Math.min(params.batchSize, REWRAP_MAX_BATCH);
      // One call does a bounded amount of work (a request must end inside its timeout); the
      // caller sees `remaining` and calls again.
      let processed = 0;
      for (let batch = 0; batch < params.maxBatches && target >= 2; batch += 1) {
        const candidates = await repos.vault.listForRewrap({
          belowKekVersion: target,
          limit: Math.min(batchLimit, rewrapMaxRows - processed),
          afterVersionId: cursor,
        });
        for (const candidate of candidates) {
          cursor = candidate.versionId;
          processed += 1;
          if (!keys.kekProvider.hasVersion(candidate.kekVersion)) {
            failed += 1;
            continue;
          }
          let wrapped;
          try {
            // Only the wrapped key is read; the ciphertext fields are never touched by a rewrap.
            wrapped = await rewrapSecret({
              sealed: {
                algorithm: 'aab-envelope-v1/aes-256-gcm',
                ciphertext: Buffer.alloc(0),
                nonce: Buffer.alloc(0),
                authTag: Buffer.alloc(0),
                wrappedDek: candidate.wrappedDek,
                kekVersion: candidate.kekVersion,
                aadVersion: candidate.aadVersion,
              },
              aad: {
                organizationId: candidate.organizationId,
                userId: candidate.ownerUserId,
                connectionId: candidate.connectionId,
                secretId: candidate.secretId,
                secretType: candidate.secretType,
                secretVersion: candidate.version,
              },
              from: keys.kekProvider,
              to: keys.kekProvider,
            });
          } catch {
            failed += 1;
            continue;
          }
          const changed = await repos.vault.rewrapVersion({
            versionId: candidate.versionId,
            fromKekVersion: candidate.kekVersion,
            expectedWrappedDek: candidate.wrappedDek,
            toKekVersion: wrapped.kekVersion,
            newWrappedDek: wrapped.wrappedDek,
            now: clock(),
          });
          if (changed) {
            rewrapped += 1;
            await deps.afterRewrapRow?.(rewrapped);
          } else {
            skipped += 1;
          }
        }
        if (candidates.length < batchLimit || processed >= rewrapMaxRows) break;
      }
      let remaining = 0;
      for (const [version, count] of await versionCounts()) {
        if (version < target) remaining += count;
      }
      return { rewrapped, skipped, failed, remaining };
    } finally {
      rewrapRunning = false;
    }
  });

  const kekRetirementCheck = guard('kekRetirementCheck', async (_context, params) => {
    const referencing = (await versionCounts()).get(params.kekVersion) ?? 0;
    // The current KEK wraps every new data key: never safe to remove while it is the current one.
    return {
      referencingVersions: referencing,
      safeToRemove: referencing === 0 && params.kekVersion !== keys.currentKekVersion,
    };
  });

  return {
    hello: helloHandler,
    authorizeJobAccess,
    issueAccessCapability,
    readForWorker,
    completeLogin,
    status,
    rewrap,
    kekRetirementCheck,
  };
}

export type { VaultContext };
