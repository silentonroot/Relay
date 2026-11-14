import { isLoopbackHost } from '@aab/contracts';
import { NavigationBlockedError } from './errors.js';
import type { NavigationBlockReason } from './errors.js';
import { matchesPathPattern } from './paths.js';
import type { ApplicationAdapter } from './types.js';

export type NavigationDecision =
  { readonly allowed: true } | { readonly allowed: false; readonly reason: NavigationBlockReason };

const blocked = (reason: NavigationBlockReason): NavigationDecision => ({ allowed: false, reason });

// Backslashes, whitespace and control characters are reinterpreted or silently removed by URL
// parsers, which is how "https://good.test\@evil.test" style confusion works.
// eslint-disable-next-line no-control-regex
const FORBIDDEN_CHARACTERS = /[\\\s\u0000-\u001f\u007f]/;
const ENCODED_DOT_OR_SEPARATOR = /%(?:2e|2f|5c)/i;

function hasTraversal(rawBeforeQuery: string): boolean {
  if (ENCODED_DOT_OR_SEPARATOR.test(rawBeforeQuery)) return true;
  return rawBeforeQuery.split('/').some((segment) => segment === '.' || segment === '..');
}

/**
 * Decides whether the worker may load `url` for this adapter. Apply it to every navigation
 * and to every redirect hop, with the same operation name.
 *
 * Allowed only when the URL is absolute and already in canonical form, carries no
 * credentials, uses https (or http on a loopback host), has an origin exactly equal to one of
 * the adapter's allowed origins, contains no dot segments, and, when an operation is given,
 * has a path matching one of that operation's allowed paths. Pass `null` as the operation
 * only for adapter-level flows such as the owner's interactive login.
 *
 * Query strings and fragments are not inspected.
 */
export function isNavigationAllowed(
  adapter: ApplicationAdapter,
  operationName: string | null,
  url: string,
): NavigationDecision {
  if (typeof url !== 'string' || url === '') return blocked('empty_url');
  if (FORBIDDEN_CHARACTERS.test(url)) return blocked('forbidden_characters');

  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return blocked('unparseable_url');
  }

  if (parsed.username !== '' || parsed.password !== '') return blocked('credentials_in_url');

  // The scheme is checked before the origin because `blob:https://host/...` reports the
  // origin of the embedded URL.
  const schemeAllowed =
    parsed.protocol === 'https:' ||
    (parsed.protocol === 'http:' && isLoopbackHost(parsed.hostname));
  if (!schemeAllowed) return blocked('scheme_not_allowed');

  const origin = parsed.origin;
  if (!adapter.allowedOrigins.includes(origin)) return blocked('origin_not_allowed');

  // Require the text itself to start with the canonical origin. This rejects spellings the
  // parser would normalize into an allowed origin (mixed-case hosts, default ports, missing
  // slashes), so the string that was checked is the string that gets loaded.
  const next = url.charAt(origin.length);
  if (!url.startsWith(origin) || !['', '/', '?', '#'].includes(next)) {
    return blocked('non_canonical_url');
  }

  const beforeQuery = url.split(/[?#]/, 1)[0] ?? '';
  if (hasTraversal(beforeQuery)) return blocked('path_traversal');

  if (operationName === null) return { allowed: true };

  const operation = Object.hasOwn(adapter.operations, operationName)
    ? adapter.operations[operationName]
    : undefined;
  if (operation === undefined) return blocked('unknown_operation');

  const pathAllowed = operation.allowedPaths.some((pattern) =>
    matchesPathPattern(pattern, parsed.pathname),
  );
  return pathAllowed ? { allowed: true } : blocked('path_not_allowed');
}

/** Throws NavigationBlockedError unless `isNavigationAllowed` allows the URL. */
export function assertNavigationAllowed(
  adapter: ApplicationAdapter,
  operationName: string | null,
  url: string,
): void {
  const decision = isNavigationAllowed(adapter, operationName, url);
  if (!decision.allowed) throw new NavigationBlockedError(decision.reason);
}
