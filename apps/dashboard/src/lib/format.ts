import type { GrantConstraints, JsonValue } from '@aab/contracts';

const dateTimeFormat = new Intl.DateTimeFormat(undefined, {
  dateStyle: 'medium',
  timeStyle: 'short',
});

export function formatDateTime(iso: string): string {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? iso : dateTimeFormat.format(date);
}

export function shortId(id: string): string {
  return id.slice(0, 8);
}

/** Audit hashes are shown only as a short prefix: enough to compare, not to copy around. */
export function truncateHash(hash: string): string {
  return hash.length > 12 ? `${hash.slice(0, 12)}…` : hash;
}

/** `connection.status_changed` -> `Connection · status changed`. */
export function formatEventType(eventType: string): string {
  const [domain = '', action = ''] = eventType.split('.');
  const sentence = `${domain} · ${action.replaceAll('_', ' ')}`;
  return sentence.charAt(0).toUpperCase() + sentence.slice(1);
}

export function formatJsonValue(value: JsonValue): string {
  if (value === null) return 'none';
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return JSON.stringify(value);
}

function quote(value: string | number | boolean | null): string {
  return typeof value === 'string' ? `“${value}”` : String(value);
}

/** Plain-language lines for a grant's constraints. Empty when the grant is unconstrained. */
export function describeConstraints(constraints: GrantConstraints): string[] {
  const lines: string[] = [];
  if (constraints.maxResults !== undefined) {
    lines.push(`At most ${constraints.maxResults} results per call`);
  }
  for (const [argument, value] of Object.entries(constraints.argumentEquals ?? {})) {
    lines.push(`${argument} must equal ${quote(value)}`);
  }
  for (const [argument, values] of Object.entries(constraints.argumentOneOf ?? {})) {
    lines.push(`${argument} must be one of ${values.map(quote).join(', ')}`);
  }
  if (constraints.resourceIds !== undefined) {
    lines.push(`Only resources ${constraints.resourceIds.join(', ')}`);
  }
  return lines;
}
