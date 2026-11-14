/*
 * Path patterns for `OperationDefinition.allowedPaths`.
 *
 * A pattern is `/` or a sequence of `/segment` parts, where a segment is either a literal made
 * of URL-unreserved characters or a `:name` placeholder matching exactly one such segment.
 * Patterns are data, not regular expressions, so an adapter cannot widen the allowlist with a
 * careless `.*`.
 */

const UNRESERVED_SEGMENT = /^[A-Za-z0-9._~-]+$/;
const PLACEHOLDER = /^:[A-Za-z][A-Za-z0-9]*$/;

function isSafeSegment(segment: string): boolean {
  return UNRESERVED_SEGMENT.test(segment) && segment !== '.' && segment !== '..';
}

function segmentsOf(path: string): string[] | null {
  if (!path.startsWith('/')) return null;
  return path === '/' ? [] : path.slice(1).split('/');
}

export function isValidPathPattern(pattern: string): boolean {
  const segments = segmentsOf(pattern);
  if (segments === null) return false;
  return segments.every((segment) => PLACEHOLDER.test(segment) || isSafeSegment(segment));
}

/**
 * Whether a URL pathname matches a pattern. Matching is exact: no prefix matching, no
 * trailing-slash tolerance, and percent-encoded segments never match.
 */
export function matchesPathPattern(pattern: string, pathname: string): boolean {
  const expected = segmentsOf(pattern);
  const actual = segmentsOf(pathname);
  if (expected === null || actual === null || expected.length !== actual.length) return false;
  return expected.every((segment, index) => {
    const candidate = actual[index];
    if (candidate === undefined || !isSafeSegment(candidate)) return false;
    return PLACEHOLDER.test(segment) || segment === candidate;
  });
}
