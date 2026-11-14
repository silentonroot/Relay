import type { ConnectionStatus } from './enums.js';

/**
 * Allowed connection status transitions (spec §5.2). `revoked` is terminal: a revoked
 * connection is never reactivated; the owner creates a new one instead.
 */
export const CONNECTION_TRANSITIONS: Readonly<
  Record<ConnectionStatus, readonly ConnectionStatus[]>
> = {
  created: ['authentication_required', 'revoked'],
  authentication_required: ['authenticating', 'revoked'],
  authenticating: ['active', 'authentication_required', 'revoked'],
  active: ['degraded', 'expired', 'reconnect_required', 'revoked'],
  degraded: ['active', 'expired', 'reconnect_required', 'revoked'],
  expired: ['reconnect_required', 'authenticating', 'revoked'],
  reconnect_required: ['authenticating', 'revoked'],
  revoked: [],
};

export function canTransitionConnection(from: ConnectionStatus, to: ConnectionStatus): boolean {
  return CONNECTION_TRANSITIONS[from].includes(to);
}

/** Statuses in which a worker may execute operations on the connection. */
export const EXECUTABLE_CONNECTION_STATUSES: readonly ConnectionStatus[] = ['active', 'degraded'];

export function isConnectionExecutable(status: ConnectionStatus): boolean {
  return EXECUTABLE_CONNECTION_STATUSES.includes(status);
}
