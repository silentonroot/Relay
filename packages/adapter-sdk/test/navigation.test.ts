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

  describe('dot segments, encoded and embedded (phase 3 B0.5 (b), TA-2)', () => {
    const ORIGIN = 'https://app.example.test';
    // Each is refused with path_traversal for every operation and with none. The comment
    // says what a browser or a server could turn the segment into.
    const TRAVERSALS: [string, string][] = [
      ['/tickets/..', 'a plain dot-dot segment'],
      ['/tickets/.', 'a plain single-dot segment'],
      ['/tickets/%2e%2e', 'percent-encoded dot-dot (the browser resolves it)'],
      ['/tickets/%2E%2E', 'uppercase percent-encoded dot-dot'],
      ['/tickets/%2E.', 'half-encoded dot-dot, uppercase first'],
      ['/tickets/.%2e', 'half-encoded dot-dot, encoded second'],
      ['/tickets/%2e', 'percent-encoded single dot'],
      ['/tickets/%2e%2e%2f', 'encoded dot-dot and encoded slash'],
      ['/tickets/%252e%252e', 'double-encoded dot-dot (a decoding proxy or server)'],
      ['/tickets/%252E%252e', 'double-encoded dot-dot, mixed case'],
      ['/tickets/%25252e%25252e', 'triple-encoded dot-dot'],
      ['/tickets/%2525252e%2525252e', 'quadruple-encoded dot-dot, the last layer looked at'],
      ['/tickets/%252525252e', 'more layers of encoding than the guard decodes'],
      ['/tickets%252fadmin', 'double-encoded slash'],
      ['/tickets%255cadmin', 'double-encoded backslash'],
      ['/tickets/..%252f', 'dot-dot and a double-encoded slash'],
      ['/tickets/..%5c', 'dot-dot and an encoded backslash'],
      ['/tickets/%5c..', 'an encoded backslash before dot-dot'],
      ['/tickets/..;', 'dot-dot with an empty path parameter (Tomcat, Jetty)'],
      ['/tickets/.;', 'single dot with an empty path parameter'],
      ['/tickets/..;x=1/admin', 'dot-dot with a path parameter, then a path'],
      ['/tickets/%2e%2e%3b', 'encoded dot-dot with an encoded semicolon'],
      ['/tickets/..%00', 'dot-dot with an encoded NUL a server may cut at'],
      ['/tickets/..%20', 'dot-dot with an encoded space a server may trim'],
      ['/tickets/...', 'a segment of dots only (trailing dots trimmed on some servers)'],
      ['/tickets/../admin', 'dot-dot inside an allowed prefix'],
      ['/tickets/%2e%2e/admin', 'encoded dot-dot inside an allowed prefix'],
      ['/tickets/%252e%252e/admin', 'double-encoded dot-dot inside an allowed prefix'],
      ['/tickets/T-1/..%2f..%2fadmin', 'dot-dots joined by encoded slashes after a placeholder'],
      ['/tickets/T-1/%2e%2e/close', 'encoded dot-dot between a placeholder and a literal'],
      ['/tickets/T-1/../close', 'dot-dot between a placeholder and a literal'],
      ['/admin/../tickets', 'dot-dot that resolves back into the allowed path'],
      ['/admin/%2e%2e/tickets', 'encoded dot-dot that resolves back into the allowed path'],
      // Overlong UTF-8: invalid, but a lenient decoder reads the lead bytes as the ASCII character.
      ['/tickets/%c0%ae%c0%ae', 'overlong UTF-8 dot-dot (two-byte, lead byte c0)'],
      ['/tickets/%C0%AE%C0%AE', 'overlong UTF-8 dot-dot, uppercase'],
      ['/tickets/%c0%af', 'overlong UTF-8 slash'],
      ['/tickets/%c1%9c', 'overlong UTF-8 backslash (lead byte c1)'],
      ['/tickets/%c1%1c', 'a c1 lead byte followed by a non-continuation byte'],
      ['/tickets/%c0', 'a lone c0 lead byte'],
      ['/tickets/%e0%80%ae%e0%80%ae', 'overlong three-byte UTF-8 dot-dot'],
      ['/tickets/%e0%80%af', 'overlong three-byte UTF-8 slash'],
      ['/tickets/%e0%9f%bf', 'e0 followed by a byte below a0 (overlong, no ASCII imitated)'],
      ['/tickets/%f0%80%80%ae', 'overlong four-byte UTF-8 dot'],
      ['/tickets/%f0%80%80%af', 'overlong four-byte UTF-8 slash'],
      [
        '/tickets/%25c0%25ae%25c0%25ae',
        'double-encoded overlong dot-dot, invalid at the second round',
      ],
      ['/tickets/%ff', 'a byte that is never valid UTF-8'],
      ['/tickets/%80', 'a lone continuation byte'],
      ['/tickets/%c3', 'a truncated two-byte sequence'],
      ['/tickets/%ed%a0%80', 'an encoded UTF-16 surrogate'],
      // IIS-style %u escapes.
      ['/tickets/%u002e%u002e', 'IIS %u escapes of dot-dot'],
      ['/tickets/%U002E%U002E', 'IIS %u escapes, uppercase'],
      ['/tickets/%u002f', 'IIS %u escape of a slash'],
      ['/tickets/%u005c', 'IIS %u escape of a backslash'],
      ['/tickets/%u2215', 'IIS %u escape of a division slash lookalike'],
      ['/tickets/%u0041', 'any %u escape, even of a harmless letter'],
      ['/tickets/%25u002e%25u002e', 'double-encoded IIS %u escapes'],
      // Unicode lookalikes: NFKC folds each of these to an ASCII dot or separator.
      ['/tickets/%ef%bc%8e%ef%bc%8e', 'fullwidth full stops U+FF0E, percent-encoded UTF-8'],
      ['/tickets/\uff0e\uff0e', 'fullwidth full stops written raw'],
      ['/tickets/\uff0e.', 'a fullwidth full stop beside an ASCII one'],
      ['/tickets/%e2%80%a4%e2%80%a4', 'one dot leaders U+2024'],
      ['/tickets/\u2024\u2024', 'one dot leaders written raw'],
      ['/tickets/%ef%b9%92%ef%b9%92', 'small full stops U+FE52'],
      ['/tickets/\ufe52\ufe52', 'small full stops written raw'],
      ['/tickets/%ef%bc%8fadmin', 'fullwidth solidus U+FF0F'],
      ['/tickets/a\uff0fb', 'fullwidth solidus written raw'],
      ['/tickets/%ef%bc%bcadmin', 'fullwidth reverse solidus U+FF3C'],
      ['/tickets/a\uff3cb', 'fullwidth reverse solidus written raw'],
      ['/tickets/%ef%bc%8e%ef%bc%8e%ef%bc%8f', 'fullwidth dot-dot and solidus'],
      ['/tickets/%25ef%25bc%258e%25ef%25bc%258e', 'double-encoded fullwidth dot-dot'],
      ['/tickets/\uff05\uff12\uff45\uff05\uff12\uff45', 'fullwidth percent-encoded dot-dot'],
      ['/tickets/\uff05\uff12\uff46', 'fullwidth percent-encoded slash'],
      // Dots followed by Unicode whitespace, which a server may trim.
      ['/tickets/..%c2%a0', 'dot-dot and a no-break space'],
      ['/tickets/.%c2%a0', 'a dot and a no-break space'],
      ['/tickets/..%e2%80%80', 'dot-dot and an en quad'],
      ['/tickets/..%e3%80%80', 'dot-dot and an ideographic space'],
      ['/tickets/..%c2%85', 'dot-dot and a next-line character'],
      ['/tickets/..%e2%80%8b', 'dot-dot and a zero-width space'],
      ['/tickets/%252e%25c2%25a0', 'double-encoded dot and no-break space'],
    ];

    it.each(TRAVERSALS)('blocks %s (%s)', (path) => {
      const url = `${ORIGIN}${path}`;
      for (const operation of [READ, WRITE, null]) {
        expect(isNavigationAllowed(helpdesk, operation, url)).toEqual({
          allowed: false,
          reason: 'path_traversal',
        });
      }
    });

    it.each<[string, string | null, string]>([
      ['/tickets/T-1.2', WRITE, 'a dot inside a placeholder value'],
      ['/tickets/T-1..', WRITE, 'trailing dots after other characters (not a dot segment)'],
      ['/.well-known/security.txt', null, 'a segment that starts with a dot'],
      ['/tickets/100%25', null, 'an encoded percent sign that encodes nothing further'],
      ['/tickets/100%2525', null, 'a double-encoded percent sign'],
      ['/tickets?path=../admin', READ, 'dot segments in the query string, which is not a path'],
      ['/tickets#../admin', READ, 'dot segments in the fragment'],
      ['/tickets/caf%C3%A9', null, 'valid UTF-8 for a letter that is no lookalike'],
      ['/caf%C3%A9', null, 'valid UTF-8 for a letter, no operation'],
      ['/tickets/caf\u00e9', null, 'the same letter written raw'],
      ['/tickets/%E4%B8%AD%E6%96%87', null, 'valid UTF-8 for CJK letters'],
      ['/tickets/%F0%9F%98%80', null, 'valid four-byte UTF-8 (an emoji)'],
      ['/tickets/T-1.2.3', null, 'dots between digits'],
      ['/tickets/..a', null, 'dots followed by a letter are a name, not a dot segment'],
      [
        '/tickets?x=%c0%ae%c0%ae&y=%u002e',
        READ,
        'lookalikes in the query string, which is not a path',
      ],
      ['/tickets#%ef%bc%8e%ef%bc%8e', READ, 'lookalikes in the fragment'],
    ])('still allows %s (%s)', (path, operation) => {
      expect(isNavigationAllowed(helpdesk, operation, `${ORIGIN}${path}`)).toEqual({
        allowed: true,
      });
    });

    it('refuses a path parameter carrying a dot segment wherever the adapter places it', () => {
      // Adapters build paths as text (`/tickets/${id}`) and the facade loads origin + path, so
      // the guard sees the value exactly where it was placed.
      for (const value of [
        '..',
        '.',
        '%2e%2e',
        '.%2E',
        '%252e%252e',
        '..%2fadmin',
        '..%252fadmin',
        '..;',
        '..%00',
      ]) {
        for (const path of [`/tickets/${value}`, `/tickets/${value}/close`]) {
          expect(isNavigationAllowed(helpdesk, WRITE, `${ORIGIN}${path}`)).toEqual({
            allowed: false,
            reason: 'path_traversal',
          });
          expect(matchesPathPattern('/tickets/:ticketId', path)).toBe(false);
          expect(matchesPathPattern('/tickets/:ticketId/close', path)).toBe(false);
        }
      }
    });

    it('refuses an encoded dot segment that the URL parser does not resolve, before matching', () => {
      // The parser leaves %252e%252e alone, so the pathname still looks like a placeholder
      // value; the guard refuses it on the raw text, not on the parsed pathname.
      expect(new URL(`${ORIGIN}/tickets/%252e%252e`).pathname).toBe('/tickets/%252e%252e');
      expect(isNavigationAllowed(helpdesk, WRITE, `${ORIGIN}/tickets/%252e%252e`)).toEqual({
        allowed: false,
        reason: 'path_traversal',
      });
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
