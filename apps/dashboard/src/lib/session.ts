import type { ConnectionStatus } from '@aab/contracts';

export type ExpiryLevel = 'none' | 'ok' | 'warn' | 'expired';

export interface ExpiryDescription {
  level: ExpiryLevel;
  text: string;
}

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

/** Under this much time left the dashboard shows a warning. */
export const EXPIRY_WARNING_MS = HOUR;

function plural(count: number, unit: string): string {
  return `${count} ${unit}${count === 1 ? '' : 's'}`;
}

/**
 * Plain-language session expiry. `nowMs` is passed in so the result is a pure function of its
 * inputs. Amounts round down: "expires in 3 hours" never promises more time than there is.
 * Exactly one hour left is not yet a warning; one millisecond less is.
 */
export function describeSessionExpiry(iso: string | null, nowMs: number): ExpiryDescription {
  if (iso === null) return { level: 'none', text: 'no expiry reported' };
  const at = new Date(iso).getTime();
  if (Number.isNaN(at)) return { level: 'none', text: 'no expiry reported' };

  const remaining = at - nowMs;
  if (remaining <= 0) return { level: 'expired', text: 'expired' };

  const level: ExpiryLevel = remaining < EXPIRY_WARNING_MS ? 'warn' : 'ok';
  if (remaining < MINUTE) return { level, text: 'expires in less than a minute' };
  if (remaining < HOUR) {
    return { level, text: `expires in ${plural(Math.floor(remaining / MINUTE), 'minute')}` };
  }
  if (remaining < DAY) {
    return { level, text: `expires in ${plural(Math.floor(remaining / HOUR), 'hour')}` };
  }
  return { level, text: `expires in ${plural(Math.floor(remaining / DAY), 'day')}` };
}

/** Statuses in which the broker holds no usable session, so an expiry would mean nothing. */
const NO_SESSION: readonly ConnectionStatus[] = [
  'created',
  'authentication_required',
  'authenticating',
  'revoked',
];

export function hasStoredSession(status: ConnectionStatus): boolean {
  return !NO_SESSION.includes(status);
}
