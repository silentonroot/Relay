import { z } from 'zod';
import { ConnectionStatus } from './enums.js';
import { CapabilityRejectionReason } from './entities.js';
import { IsoDateTime, Uuid } from './primitives.js';
import { StatusResult } from './vault.js';

/*
 * Dashboard responses about the vault (ADR-014 section 12, step B5). METADATA ONLY: nothing
 * here names or carries plaintext, ciphertext, a wrapped key, a token, a token hash or a MAC.
 * `packages/contracts/test/response-schemas.test.ts` walks every schema in
 * `VAULT_DASHBOARD_RESPONSE_SCHEMAS` and fails on a forbidden field name; a new response schema
 * for the vault must be added to that table.
 */

/** ADR-003, stated for the owner: what the key protects and what its loss means. */
export const VAULT_KEY_PROTECTION_STATEMENT =
  'The vault key encrypts every stored session, so a copy of the database alone yields only ' +
  'ciphertext. Whoever holds the key files can decrypt every stored session: back them up ' +
  'separately from the database. If the key files are lost, every stored session is ' +
  'unrecoverable and each connection must be reconnected; there is no back door and no key escrow.';

/** The vault's installation-level status plus the fixed statement of what its key protects. */
export const VaultKeyStatus = StatusResult.extend({
  protectionStatement: z.literal(VAULT_KEY_PROTECTION_STATEMENT),
});
export type VaultKeyStatus = z.infer<typeof VaultKeyStatus>;

export const VaultSecretStatus = z.enum(['pending', 'active', 'deleted', 'revoked']);

/** One stored secret of a connection: type, state, active version, which key wraps it. */
export const VaultSecretMetadata = z.strictObject({
  secretType: z.string().min(1).max(64),
  status: VaultSecretStatus,
  activeVersion: z.number().int().min(1).nullable(),
  kekVersion: z.number().int().min(1).nullable(),
  lastAccessedAt: IsoDateTime.nullable(),
});

export const VaultRejectionCount = z.strictObject({
  reason: CapabilityRejectionReason,
  count: z.number().int().min(0),
});

/** Counts over the last 24 hours (database clock). Rejections are kept apart by reason. */
export const VaultCapabilityActivity = z.strictObject({
  windowHours: z.literal(24),
  authorized: z.number().int().min(0),
  used: z.number().int().min(0),
  revoked: z.number().int().min(0),
  rejected: z.array(VaultRejectionCount),
});

export const ConnectionVaultMetadata = z.strictObject({
  connectionId: Uuid,
  connectionStatus: ConnectionStatus,
  secrets: z.array(VaultSecretMetadata),
  capabilities: VaultCapabilityActivity,
});
export type ConnectionVaultMetadata = z.infer<typeof ConnectionVaultMetadata>;

export const DeleteStoredSessionResult = z.strictObject({
  connectionId: Uuid,
  connectionStatus: ConnectionStatus,
  versionsDeleted: z.number().int().min(0),
  capabilitiesRevoked: z.number().int().min(0),
  /** Queued jobs cancelled and running jobs flagged for cancellation, as revoking does. */
  jobsCancelled: z.number().int().min(0),
});
export type DeleteStoredSessionResult = z.infer<typeof DeleteStoredSessionResult>;

export const RevokeCapabilitiesResult = z.strictObject({
  connectionId: Uuid,
  capabilitiesRevoked: z.number().int().min(0),
  /** Queued jobs whose capability was revoked, now cancelled. Running jobs are not touched. */
  jobsCancelled: z.number().int().min(0),
});
export type RevokeCapabilitiesResult = z.infer<typeof RevokeCapabilitiesResult>;

/** Every response schema of the step B5 vault routes, for the forbidden-field test. */
export const VAULT_DASHBOARD_RESPONSE_SCHEMAS = {
  vaultStatus: VaultKeyStatus,
  connectionVault: ConnectionVaultMetadata,
  deleteStoredSession: DeleteStoredSessionResult,
  revokeCapabilities: RevokeCapabilitiesResult,
} as const;
