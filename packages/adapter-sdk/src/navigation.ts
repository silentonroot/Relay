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
/**
 * A segment made only of dots, optionally followed by what some servers cut off before they
 * resolve it: a `;` path parameter (`..;`), a NUL or other control character, or whitespace.
 */
// eslint-disable-next-line no-control-regex
const DOT_SEGMENT = /^\.+(?:[;\s\u0000-\u001f\u0085\u180e\u200b-\u200d\u2060].*)?$/s;
/** Layers of percent-encoding the guard looks through; a path still encoded deeper is refused. */
const MAX_DECODE_ROUNDS = 3;
/** IIS-style `%uXXXX` escapes, which some servers decode to a UTF-16 unit. */
const UNICODE_ESCAPE = /%u[0-9a-f]{4}/i;

const encoder = new TextEncoder();
const strictDecoder = new TextDecoder('utf-8', { fatal: true });

/**
 * One layer of percent-decoding, as UTF-8. Every `%XX` becomes one byte and every other
 * character its UTF-8 bytes; the bytes must then be valid UTF-8. Returns null for invalid
 * UTF-8, which includes the overlong spellings of `.`, `/` and `\` (`%c0%ae`, `%c0%af`,
 * `%e0%80%ae`, `%f0%80%80%ae`, and every other use of the lead bytes `%c0`, `%c1`, `%e0%80..%9f`
 * and `%f0%80..%8f`): a lenient server could read those as the character they imitate. Never
 * throws; a lone `%` stays as it is.
 */
function utf8PercentDecode(text: string): string | null {
  const chunks: Uint8Array[] = [];
  for (const [index, part] of text.split(/(%[0-9a-f]{2})/i).entries()) {
    if (index % 2 === 1) chunks.push(Uint8Array.of(Number.parseInt(part.slice(1), 16)));
    else if (part !== '') chunks.push(encoder.encode(part));
  }
  const bytes = new Uint8Array(chunks.reduce((total, chunk) => total + chunk.length, 0));
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  try {
    return strictDecoder.decode(bytes);
  } catch {
    return null;
  }
}

/** True when some segment of `text` is a dot segment, or dots cut off by what follows them. */
const hasDotSegment = (text: string): boolean =>
  text.split(/[/\\]/).some((segment) => DOT_SEGMENT.test(segment));

/** Characters that a URL parser or server treats as an escape, dot or separator. */
const hasTraversalSpelling = (text: string): boolean =>
  ENCODED_DOT_OR_SEPARATOR.test(text) || UNICODE_ESCAPE.test(text) || hasDotSegment(text);

const separatorCount = (text: string): number => text.split(/[/\\]/).length - 1;

/**
 * True when the path, as written or after up to three rounds of percent-decoding, holds an
 * encoded dot or separator, an IIS `%u` escape, a dot segment, or bytes that are not valid
 * UTF-8. Servers and proxies differ in how often they decode, so `%252e%252e` is treated like
 * `%2e%2e`, and `%2e%2e` like `..`.
 *
 * Each round also looks at the text as a server that normalizes Unicode would see it (NFKC):
 * a fullwidth full stop, a one dot leader, a small full stop, a fullwidth solidus or reverse
 * solidus, or a dot followed by a no-break space become `.`, `/` or `\` there. The normalized
 * form must hold no dot segment and no separator that the decoded text did not.
 */
function hasTraversal(rawBeforeQuery: string): boolean {
  let text = rawBeforeQuery;
  for (let round = 0; ; round += 1) {
    if (hasTraversalSpelling(text)) return true;
    const decoded = utf8PercentDecode(text);
    if (decoded === null) return true;
    const normalized = decoded.normalize('NFKC');
    if (hasTraversalSpelling(decoded) || hasTraversalSpelling(normalized)) return true;
    if (separatorCount(normalized) > separatorCount(decoded)) return true;
    if (decoded === text) return false;
    if (round === MAX_DECODE_ROUNDS) return true;
    text = decoded;
  }
}

/**
 * Decides whether the worker may load `url` for this adapter. Apply it to every navigation
 * and to every redirect hop, with the same operation name.
 *
 * Allowed only when the URL is absolute and already in canonical form, carries no
 * credentials, uses https (or http on a loopback host), has an origin exactly equal to one of
 * the adapter's allowed origins, contains no dot segment, no encoded dot or separator, no `%u`
 * escape, no invalid or overlong UTF-8 and no Unicode lookalike of a dot or separator, even after
 * up to three rounds of percent-decoding (see `hasTraversal`), and, when an operation is given,
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
