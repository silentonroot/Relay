import { describe, expect, it } from 'vitest';
import {
  assertNavigationAllowed,
  defineAdapter,
  isNavigationAllowed,
  isValidPathPattern,
  matchesPathPattern,
  NavigationBlockedError,
} from '../src/index.js';
import type { NavigationBlockReason } from '../src/index.js';
import { adapterDefinition, helpdesk } from './fixtures.js';

const READ = 'tickets.list'; // allowedPaths: /tickets
const WRITE = 'tickets.close'; // allowedPaths: /tickets/:ticketId, /tickets/:ticketId/close

describe('isNavigationAllowed', () => {
  it.each([
    ['the exact allowed path', READ, 'https://app.example.test/tickets'],
    [
      'an allowed path with a query string',
      READ,
      'https://app.example.test/tickets?status=open&page=2',
    ],
    ['an allowed path with a fragment', READ, 'https://app.example.test/tickets#top'],
    ['a placeholder segment', WRITE, 'https://app.example.test/tickets/T-1001'],
    ['a placeholder followed by a literal', WRITE, 'https://app.example.test/tickets/T-1001/close'],
    ['any path on the origin when no operation is given', null, 'https://app.example.test/login'],
    ['the bare origin when no operation is given', null, 'https://app.example.test'],
  ])('allows %s', (_label, operation, url) => {
    expect(isNavigationAllowed(helpdesk, operation, url)).toEqual({ allowed: true });
  });

  it.each<[string, string, NavigationBlockReason]>([
    ['an empty string', '', 'empty_url'],
    [
      'the allowed host used as a subdomain prefix of an attacker domain',
      'https://app.example.test.evil.test/',
      'origin_not_allowed',
    ],
    [
      'the allowed host in the userinfo position',
      'https://app.example.test@evil.test/',
      'credentials_in_url',
    ],
    [
      'a username and password on the allowed host',
      'https://user:pw@app.example.test/tickets',
      'credentials_in_url',
    ],
    [
      'the allowed origin only inside the fragment of an attacker URL',
      'https://evil.test/#https://app.example.test',
      'origin_not_allowed',
    ],
    [
      'the allowed origin only inside the query of an attacker URL',
      'https://evil.test/?next=https://app.example.test/tickets',
      'origin_not_allowed',
    ],
    [
      'a different port on the allowed host',
      'https://app.example.test:8443/tickets',
      'origin_not_allowed',
    ],
    [
      'an explicit default port, which is a non-canonical spelling',
      'https://app.example.test:443/tickets',
      'non_canonical_url',
    ],
    [
      'an http downgrade of the https origin',
      'http://app.example.test/tickets',
      'scheme_not_allowed',
    ],
    ['a javascript: URL', 'javascript:alert(1)', 'scheme_not_allowed'],
    ['a data: URL', 'data:text/html,<h1>x</h1>', 'scheme_not_allowed'],
    ['a file: URL', 'file:///etc/passwd', 'scheme_not_allowed'],
    [
      'a blob: URL whose embedded origin is the allowed one',
      'blob:https://app.example.test/0b9f6f0e-2f0b-4c8e-9d43-0d9c1b1f7a11',
      'scheme_not_allowed',
    ],
    ['a websocket URL on the allowed host', 'wss://app.example.test/tickets', 'scheme_not_allowed'],
    ['a protocol-relative URL', '//evil.test/tickets', 'unparseable_url'],
    ['a relative path with no origin', '/tickets', 'unparseable_url'],
    [
      'a backslash before @ that some parsers read as a path',
      'https://app.example.test\\@evil.test/',
      'forbidden_characters',
    ],
    ['backslashes used as slashes', 'https:\\\\app.example.test\\tickets', 'forbidden_characters'],
    [
      'an embedded tab that parsers strip',
      'https://app.example.test/tick\tets',
      'forbidden_characters',
    ],
    ['a trailing newline', 'https://app.example.test/tickets\n', 'forbidden_characters'],
    ['a leading space', ' https://app.example.test/tickets', 'forbidden_characters'],
    [
      'an uppercase spelling of the allowed host',
      'https://APP.EXAMPLE.TEST/tickets',
      'non_canonical_url',
    ],
    ['an uppercase scheme', 'HTTPS://app.example.test/tickets', 'non_canonical_url'],
    ['a missing slash after the scheme', 'https:app.example.test/tickets', 'non_canonical_url'],
    [
      'an IDN lookalike host (Cyrillic a)',
      'https://аpp.example.test/tickets',
      'origin_not_allowed',
    ],
    [
      'an ASCII lookalike host (digit one for l)',
      'https://app.examp1e.test/tickets',
      'origin_not_allowed',
    ],
    ['a trailing-dot host', 'https://app.example.test./tickets', 'origin_not_allowed'],
    [
      'path traversal out of the allowed path',
      'https://app.example.test/tickets/../admin',
      'path_traversal',
    ],
    [
      'percent-encoded path traversal',
      'https://app.example.test/tickets/%2e%2e/admin',
      'path_traversal',
    ],
    [
      'mixed-case percent-encoded traversal',
      'https://app.example.test/tickets/%2E%2e/admin',
      'path_traversal',
    ],
    [
      'an encoded slash inside a segment',
      'https://app.example.test/tickets%2fadmin',
      'path_traversal',
    ],
    ['a single-dot segment', 'https://app.example.test/./tickets', 'path_traversal'],
    ['a path that is not in allowedPaths', 'https://app.example.test/admin', 'path_not_allowed'],
    [
      'a longer path with an allowed prefix',
      'https://app.example.test/tickets/export',
      'path_not_allowed',
    ],
    [
      'an allowed path with a trailing slash',
      'https://app.example.test/tickets/',
      'path_not_allowed',
    ],
    [
      'a doubled slash before an allowed path',
      'https://app.example.test//tickets',
      'path_not_allowed',
    ],
    [
      'the bare origin when the operation only allows a sub-path',
      'https://app.example.test',
      'path_not_allowed',
    ],
  ])('blocks %s', (_label, url, reason) => {
    expect(isNavigationAllowed(helpdesk, READ, url)).toEqual({ allowed: false, reason });
  });

  it('blocks another operation’s path for the operation being run', () => {
    expect(
      isNavigationAllowed(helpdesk, READ, 'https://app.example.test/tickets/T-1/close'),
    ).toEqual({ allowed: false, reason: 'path_not_allowed' });
    expect(isNavigationAllowed(helpdesk, WRITE, 'https://app.example.test/tickets')).toEqual({
      allowed: false,
      reason: 'path_not_allowed',
    });
  });

  it('blocks a placeholder segment that carries encoded or reserved characters', () => {
    for (const url of [
      'https://app.example.test/tickets/T-1%20x',
      'https://app.example.test/tickets/T-1;admin=1',
      'https://app.example.test/tickets/T-1,T-2',
    ]) {
      expect(isNavigationAllowed(helpdesk, WRITE, url)).toEqual({
        allowed: false,
        reason: 'path_not_allowed',
      });
    }
  });

  it('blocks an operation the adapter does not define, including prototype names', () => {
    for (const name of ['tickets.delete', 'constructor', '__proto__']) {
      expect(isNavigationAllowed(helpdesk, name, 'https://app.example.test/tickets')).toEqual({
        allowed: false,
        reason: 'unknown_operation',
      });
    }
  });

  it('still blocks foreign origins and traversal when no operation is given', () => {
    expect(isNavigationAllowed(helpdesk, null, 'https://evil.test/login')).toEqual({
      allowed: false,
      reason: 'origin_not_allowed',
    });
    expect(isNavigationAllowed(helpdesk, null, 'https://app.example.test/a/../b')).toEqual({
      allowed: false,
      reason: 'path_traversal',
    });
  });

  it('allows http only for a loopback origin that is on the allowlist', () => {
    const local = defineAdapter(adapterDefinition({ allowedOrigins: ['http://localhost:4100'] }));
    expect(isNavigationAllowed(local, READ, 'http://localhost:4100/tickets')).toEqual({
      allowed: true,
    });
    expect(isNavigationAllowed(local, READ, 'http://localhost:4101/tickets')).toEqual({
      allowed: false,
      reason: 'origin_not_allowed',
    });
    expect(isNavigationAllowed(local, READ, 'http://127.0.0.1:4100/tickets')).toEqual({
      allowed: false,
      reason: 'origin_not_allowed',
    });
    expect(isNavigationAllowed(local, READ, 'http://localhost.evil.test:4100/tickets')).toEqual({
      allowed: false,
      reason: 'scheme_not_allowed',
    });
  });
});

describe('assertNavigationAllowed', () => {
  it('throws a NavigationBlockedError that carries the reason but not the URL', () => {
    try {
      assertNavigationAllowed(helpdesk, READ, 'https://evil.test/?token=SYNTHETIC');
      throw new Error('expected navigation to be blocked');
    } catch (error) {
      expect(error).toBeInstanceOf(NavigationBlockedError);
      expect((error as NavigationBlockedError).reason).toBe('origin_not_allowed');
      expect((error as Error).message).not.toContain('SYNTHETIC');
    }
  });

  it('returns normally for an allowed URL', () => {
    expect(() =>
      assertNavigationAllowed(helpdesk, READ, 'https://app.example.test/tickets'),
    ).not.toThrow();
  });
});

describe('path patterns', () => {
  it.each(['/', '/tickets', '/tickets/:ticketId', '/api/v1/tickets/:ticketId/close', '/a.b_c~d-e'])(
    'accepts %s',
    (pattern) => {
      expect(isValidPathPattern(pattern)).toBe(true);
    },
  );

  it.each([
    '',
    'tickets',
    '/tickets/',
    '//tickets',
    '/tickets/*',
    '/tickets/.*',
    '/tickets/..',
    '/tickets/.',
    '/tickets/:',
    '/tickets/:1d',
    '/tickets?status=open',
    '/tickets/%2e%2e',
    'https://evil.test/tickets',
  ])('rejects %j', (pattern) => {
    expect(isValidPathPattern(pattern)).toBe(false);
  });

  it('matches exactly, segment by segment', () => {
    expect(matchesPathPattern('/', '/')).toBe(true);
    expect(matchesPathPattern('/tickets/:id', '/tickets/T-1')).toBe(true);
    expect(matchesPathPattern('/tickets/:id', '/tickets')).toBe(false);
    expect(matchesPathPattern('/tickets/:id', '/tickets/T-1/close')).toBe(false);
    expect(matchesPathPattern('/tickets/:id', '/tickets/')).toBe(false);
    expect(matchesPathPattern('/tickets/:id', '/tickets/..')).toBe(false);
    expect(matchesPathPattern('/tickets', '/Tickets')).toBe(false);
  });
});
