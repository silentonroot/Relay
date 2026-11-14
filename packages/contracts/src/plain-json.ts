/**
 * Structural check for operation arguments and other JSON that crosses a trust boundary.
 *
 * Schema parsing alone is not enough: a parser may silently drop a `__proto__` key or follow a
 * cyclic reference, so the value that was judged by policy could differ from the value that is
 * later executed. Every boundary that accepts arguments (policy evaluation, the broker's execute
 * route, the worker) runs this check on the raw value first and rejects on any issue.
 */
export const MAX_JSON_DEPTH = 64;

export type PlainJsonIssue = 'not_json' | 'forbidden_key' | 'cyclic' | 'too_deep';

const FORBIDDEN_KEYS: ReadonlySet<string> = new Set(['__proto__', 'constructor', 'prototype']);

/** Returns null when `value` is plain, acyclic, bounded-depth JSON; otherwise the first issue. */
export function checkPlainJson(
  value: unknown,
  maxDepth: number = MAX_JSON_DEPTH,
): PlainJsonIssue | null {
  return walk(value, new Set<object>(), 0, maxDepth);
}

export function isPlainJson(value: unknown, maxDepth: number = MAX_JSON_DEPTH): boolean {
  return checkPlainJson(value, maxDepth) === null;
}

function walk(
  value: unknown,
  ancestors: Set<object>,
  depth: number,
  maxDepth: number,
): PlainJsonIssue | null {
  if (value === null) return null;

  switch (typeof value) {
    case 'boolean':
    case 'string':
      return null;
    case 'number':
      return Number.isFinite(value) ? null : 'not_json';
    case 'object':
      break;
    default:
      return 'not_json';
  }

  if (depth >= maxDepth) return 'too_deep';
  if (ancestors.has(value)) return 'cyclic';
  if (Object.getOwnPropertySymbols(value).length > 0) return 'not_json';

  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      for (let index = 0; index < value.length; index += 1) {
        if (!(index in value)) return 'not_json';
        const issue = walk(value[index], ancestors, depth + 1, maxDepth);
        if (issue !== null) return issue;
      }
      return null;
    }

    const prototype: unknown = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) return 'not_json';

    for (const key of Object.getOwnPropertyNames(value)) {
      if (FORBIDDEN_KEYS.has(key)) return 'forbidden_key';
      const issue = walk((value as Record<string, unknown>)[key], ancestors, depth + 1, maxDepth);
      if (issue !== null) return issue;
    }
    return null;
  } finally {
    ancestors.delete(value);
  }
}
