import type { KeyObject } from 'node:crypto';
import { canonicalJson } from '@aab/contracts';
import { macSha256, verifyMac } from '@aab/crypto';
import type { CapabilityRecord } from '@aab/database';

/*
 * The capability MACs of ADR-014 section 6. Both are HMAC-SHA-256 over the canonical JSON of the
 * covered fields, under the key derived from one KEK version (`mac_kek_version` on the row; the
 * token MAC reuses it, so one row never needs two KEK versions). Each layout carries its own
 * label, so an authorization MAC can never be presented as a token MAC or the reverse.
 *
 * The authorization MAC covers: capability id, purpose, organization, job, agent, connection,
 * operation, secret id, arguments hash, issued_at and expires_at. The token MAC covers all of
 * those plus the token hash, worker id, attempt, bound secret version, token_issued_at and
 * token_expires_at. Timestamps are the ISO strings the repository returns (millisecond
 * precision, the same text `authorizationWindow` produced before the insert).
 */

export const AUTHORIZATION_MAC_LAYOUT = 'aab.vault.capability-authorization.v1';
export const TOKEN_MAC_LAYOUT = 'aab.vault.capability-token.v1';

/** The fields of the authorization MAC. Every field is always present (null when it has none). */
export interface AuthorizationMacFields {
  id: string;
  purpose: string;
  organizationId: string;
  jobId: string;
  agentId: string | null;
  connectionId: string;
  operation: string | null;
  secretId: string;
  argumentsHash: string | null;
  issuedAt: string;
  expiresAt: string;
}

function authorizationPayload(fields: AuthorizationMacFields): string {
  return canonicalJson({
    layout: AUTHORIZATION_MAC_LAYOUT,
    capabilityId: fields.id,
    purpose: fields.purpose,
    organizationId: fields.organizationId,
    jobId: fields.jobId,
    agentId: fields.agentId,
    connectionId: fields.connectionId,
    operation: fields.operation,
    secretId: fields.secretId,
    argumentsHash: fields.argumentsHash,
    issuedAt: fields.issuedAt,
    expiresAt: fields.expiresAt,
  });
}

function tokenPayload(row: CapabilityRecord): string {
  return canonicalJson({
    layout: TOKEN_MAC_LAYOUT,
    authorization: authorizationPayload(row),
    tokenHash: row.tokenHash,
    workerId: row.workerId,
    attempt: row.attempt,
    secretVersion: row.secretVersion,
    tokenIssuedAt: row.tokenIssuedAt,
    tokenExpiresAt: row.tokenExpiresAt,
  });
}

const HEX_MAC = /^[0-9a-f]{64}$/;

export function authorizationMac(key: KeyObject, fields: AuthorizationMacFields): string {
  return macSha256(key, authorizationPayload(fields)).toString('hex');
}

export function tokenMac(key: KeyObject, row: CapabilityRecord): string {
  return macSha256(key, tokenPayload(row)).toString('hex');
}

function verify(key: KeyObject, payload: string, mac: string | null): boolean {
  if (mac === null || !HEX_MAC.test(mac)) return false;
  return verifyMac(key, payload, Buffer.from(mac, 'hex'));
}

export function verifyAuthorizationMac(key: KeyObject, row: CapabilityRecord): boolean {
  return verify(key, authorizationPayload(row), row.authorizationMac);
}

/** A token MAC is only meaningful when the token fields are present. */
export function verifyTokenMac(key: KeyObject, row: CapabilityRecord): boolean {
  if (
    row.tokenHash === null ||
    row.workerId === null ||
    row.attempt === null ||
    row.secretVersion === null ||
    row.tokenIssuedAt === null ||
    row.tokenExpiresAt === null
  ) {
    return false;
  }
  return verify(key, tokenPayload(row), row.tokenMac);
}
