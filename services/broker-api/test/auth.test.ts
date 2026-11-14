import {
  AuditEventList,
  CSRF_HEADER,
  Routes,
  SESSION_COOKIE,
  SessionResponse,
} from '@aab/contracts';
import { hashToken, needsRehash, verifyPassword } from '@aab/crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Harness } from './helpers.js';
import {
  BASE_TIME,
  createHarness,
  eventually,
  expectError,
  expectNoSecretLeaks,
  login,
  path,
  seedOwner,
  seedTenant,
  sessionTokenFrom,
} from './helpers.js';

const owner = { email: 'owner@example.test', password: 'owner password for tests' };
const disabled = { email: 'disabled@example.test', password: 'disabled user password' };
const TTL_MINUTES = 60;

function cookieAttributes(setCookie: string): { value: string; attributes: string[] } {
  const [pair, ...attributes] = setCookie.split(';').map((part) => part.trim());
  return { value: pair!, attributes: attributes.sort() };
}

describe('login, sessions and logout', () => {
  let h: Harness;
  let organizationId: string;

  beforeAll(async () => {
    h = await createHarness({
      config: { sessionTtlMinutes: TTL_MINUTES },
      rateLimits: { loginMax: 1000, loginAddressMax: 1000 },
    });
    const seeded = await seedOwner(h, owner);
    organizationId = seeded.organization.id;
    // A disabled member of the same organization.
    const member = await seedTenant(h, disabled, 'unused', 'member', organizationId);
    await h.database.db.execute(
      `update users set status = 'disabled' where id = '${member.userId}'::uuid`,
    );
  });

  afterAll(async () => {
    await expectNoSecretLeaks(h);
    await h.close();
  });

  it('returns a session with the exact cookie attributes', async () => {
    const response = await h.inject({ method: 'POST', url: '/v1/auth/login', payload: owner });
    expect(response.statusCode).toBe(200);
    const body = SessionResponse.parse(response.json());
    expect(body.user.email).toBe(owner.email);
    expect(body.organization.id).toBe(organizationId);

    const header = response.headers['set-cookie'];
    expect(typeof header).toBe('string');
    const { value, attributes } = cookieAttributes(header as string);
    const token = sessionTokenFrom(response)!;
    expect(value).toBe(`${SESSION_COOKIE}=${token}`);
    expect(attributes).toEqual(
      [`Max-Age=${TTL_MINUTES * 60}`, 'Path=/', 'HttpOnly', 'Secure', 'SameSite=Strict'].sort(),
    );
    // Only the hash of the token is stored.
    expect(await h.repos.sessions.findValid(token, new Date(BASE_TIME))).toBeNull();
    expect(
      await h.repos.sessions.findValid(
        hashToken(token),
        new Date(Date.parse(body.expiresAt) - 1000),
      ),
    ).not.toBeNull();
    h.forbiddenInResponses.add(hashToken(token));
    h.forbiddenInLogs.add(token);
  });

  it('omits Secure only when configured for plain-HTTP development', async () => {
    const local = await createHarness({ config: { cookieSecure: false } });
    try {
      await seedOwner(local, owner);
      const response = await local.inject({
        method: 'POST',
        url: '/v1/auth/login',
        payload: owner,
      });
      const { attributes } = cookieAttributes(response.headers['set-cookie'] as string);
      expect(attributes).not.toContain('Secure');
      expect(attributes).toContain('HttpOnly');
      expect(attributes).toContain('SameSite=Strict');
    } finally {
      await local.close();
    }
  });

  it('mints a new token on every login and never adopts one the client brings', async () => {
    const first = await login(h, owner);
    const planted = 'A'.repeat(43);
    const response = await h.inject({
      method: 'POST',
      url: '/v1/auth/login',
      headers: { cookie: `${SESSION_COOKIE}=${first.token}` },
      payload: owner,
    });
    const second = sessionTokenFrom(response)!;
    h.forbiddenInResponses.add(hashToken(second));
    h.forbiddenInLogs.add(second);
    expect(second).not.toBe(first.token);
    // The session the browser already held was ended.
    expectError(
      await h.inject({
        method: 'GET',
        url: path(Routes.authSession),
        headers: { cookie: first.cookie },
      }),
      401,
      'unauthenticated',
    );

    const fixation = await h.inject({
      method: 'POST',
      url: '/v1/auth/login',
      headers: { cookie: `${SESSION_COOKIE}=${planted}` },
      payload: owner,
    });
    const third = sessionTokenFrom(fixation)!;
    h.forbiddenInResponses.add(hashToken(third));
    h.forbiddenInLogs.add(third);
    expect(third).not.toBe(planted);
    expect(third).not.toBe(second);
  });

  it('keeps the CSRF token stable for the life of the session', async () => {
    const session = await login(h, owner);
    for (let i = 0; i < 2; i += 1) {
      const response = await h.inject({
        method: 'GET',
        url: path(Routes.authSession),
        headers: { cookie: session.cookie },
      });
      expect(response.statusCode).toBe(200);
      expect(SessionResponse.parse(response.json()).csrfToken).toBe(session.csrfToken);
    }
    const other = await login(h, owner);
    expect(other.csrfToken).not.toBe(session.csrfToken);
  });

  it('gives one generic answer for an unknown account, a wrong password and a disabled account', async () => {
    const unknown = await h.inject({
      method: 'POST',
      url: '/v1/auth/login',
      payload: { email: 'nobody@example.test', password: owner.password },
    });
    const wrong = await h.inject({
      method: 'POST',
      url: '/v1/auth/login',
      payload: { email: owner.email, password: 'not the password at all' },
    });
    const inactive = await h.inject({ method: 'POST', url: '/v1/auth/login', payload: disabled });
    const bodies = [unknown, wrong, inactive].map((response) => {
      const error = expectError(response, 401, 'unauthenticated').error;
      expect(response.cookies).toHaveLength(0);
      return { code: error.code, message: error.message, keys: Object.keys(error).sort() };
    });
    expect(bodies[1]).toEqual(bodies[0]);
    expect(bodies[2]).toEqual(bodies[0]);
    // The email someone typed is never logged.
    expect(h.logs.join('')).not.toContain('nobody@example.test');
  });

  it('audits failed logins for known accounts only', async () => {
    const session = await login(h, owner);
    const events = await eventually(async () => {
      const response = await h.inject({
        method: 'GET',
        url: `${path(Routes.auditEvents)}?eventType=auth.login_failed`,
        headers: { cookie: session.cookie },
      });
      const list = AuditEventList.parse(response.json());
      // One for the wrong password, one for the disabled member; none for the unknown email.
      expect(list.items).toHaveLength(2);
      return list.items;
    });
    expect(events.map((event) => event.metadata.reason).sort()).toEqual([
      'account_disabled',
      'invalid_password',
    ]);
    expect(events.every((event) => event.decision === 'deny')).toBe(true);
    expect(h.logs.some((line) => line.includes('"reason":"unknown_account"'))).toBe(true);
  });

  it('rehashes a password stored with weaker parameters after a successful login', async () => {
    const before = await h.repos.users.findForLogin(owner.email);
    expect(needsRehash(before!.passwordHash)).toBe(true);
    await login(h, owner);
    await eventually(async () => {
      const after = await h.repos.users.findForLogin(owner.email);
      expect(after!.passwordHash).not.toBe(before!.passwordHash);
    });
    // The new hash still verifies.
    await login(h, owner);
  });

  it('expires sessions according to the clock', async () => {
    const session = await login(h, owner);
    h.clock.advance(TTL_MINUTES * 60_000 - 10_000);
    const alive = await h.inject({
      method: 'GET',
      url: path(Routes.authSession),
      headers: { cookie: session.cookie },
    });
    expect(alive.statusCode).toBe(200);
    h.clock.advance(20_000);
    const expired = await h.inject({
      method: 'GET',
      url: path(Routes.authSession),
      headers: { cookie: session.cookie },
    });
    expectError(expired, 401, 'unauthenticated');
    // The dead cookie is cleared.
    expect(expired.cookies.find((cookie) => cookie.name === SESSION_COOKIE)?.maxAge).toBe(0);
  });

  it('logout revokes the session and clears the cookie', async () => {
    const session = await login(h, owner);
    const response = await h.inject({
      method: 'POST',
      url: path(Routes.authLogout),
      headers: session.headers,
    });
    expect(response.statusCode).toBe(204);
    const cleared = response.cookies.find((cookie) => cookie.name === SESSION_COOKIE);
    expect(cleared?.value).toBe('');
    expect(cleared?.maxAge).toBe(0);

    for (const request of [
      {
        method: 'GET' as const,
        url: path(Routes.authSession),
        headers: { cookie: session.cookie },
      },
      { method: 'POST' as const, url: path(Routes.authLogout), headers: session.headers },
    ]) {
      expectError(await h.inject(request), 401, 'unauthenticated');
    }
  });

  it('rejects unknown and malformed session cookies', async () => {
    for (const value of ['B'.repeat(43), 'short', '']) {
      expectError(
        await h.inject({
          method: 'GET',
          url: path(Routes.authSession),
          headers: { cookie: `${SESSION_COOKIE}=${value}` },
        }),
        401,
        'unauthenticated',
      );
    }
  });

  it('requires a JSON body for login but no CSRF token', async () => {
    expectError(
      await h.inject({
        method: 'POST',
        url: '/v1/auth/login',
        headers: { 'content-type': 'text/plain' },
        payload: JSON.stringify(owner),
      }),
      415,
      'validation_failed',
    );
    expectError(
      await h.inject({
        method: 'POST',
        url: '/v1/auth/login',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        payload: `email=${encodeURIComponent(owner.email)}&password=x`,
      }),
      415,
      'validation_failed',
    );
    const ok = await h.inject({
      method: 'POST',
      url: '/v1/auth/login',
      headers: { 'content-type': 'application/json; charset=utf-8', [CSRF_HEADER]: 'ignored' },
      payload: JSON.stringify(owner),
    });
    expect(ok.statusCode).toBe(200);
    const token = sessionTokenFrom(ok)!;
    h.forbiddenInResponses.add(hashToken(token));
    h.forbiddenInLogs.add(token);
  });
});

describe('login rate limiting', () => {
  let h: Harness;

  beforeAll(async () => {
    h = await createHarness({ rateLimits: { loginMax: 3, loginAddressMax: 4 } });
    await seedOwner(h, owner);
  });

  afterAll(async () => {
    await expectNoSecretLeaks(h);
    await h.close();
  });

  it('limits attempts per address and email, then per address', async () => {
    const attempt = (email: string, password = 'wrong password here', ip = '127.0.0.1') =>
      h.inject({
        method: 'POST',
        url: '/v1/auth/login',
        payload: { email, password },
        remoteAddress: ip,
      });

    for (let i = 0; i < 3; i += 1) expectError(await attempt(owner.email), 401, 'unauthenticated');
    const limited = await attempt(owner.email);
    expectError(limited, 429, 'rate_limited');
    expect(Number(limited.headers['retry-after'])).toBeGreaterThan(0);
    // Even the right password is refused while limited.
    expectError(await attempt(owner.email, owner.password), 429, 'rate_limited');

    // Another client address is unaffected.
    const elsewhere = await attempt(owner.email, owner.password, '127.0.0.2');
    expect(elsewhere.statusCode).toBe(200);
    const token = sessionTokenFrom(elsewhere)!;
    h.forbiddenInResponses.add(hashToken(token));
    h.forbiddenInLogs.add(token);

    // Spraying other emails from the first address hits the per-address limit.
    expectError(await attempt('a@example.test'), 401, 'unauthenticated');
    expectError(await attempt('b@example.test'), 429, 'rate_limited');
  });

  it('applies the global rate limit to every route', async () => {
    const limited = await createHarness({ rateLimits: { globalMax: 3 } });
    try {
      const statuses: number[] = [];
      for (let i = 0; i < 4; i += 1) {
        statuses.push(
          (await limited.inject({ method: 'GET', url: path(Routes.health) })).statusCode,
        );
      }
      expect(statuses).toEqual([200, 200, 200, 429]);
      expectError(limited.responses.at(-1)!, 429, 'rate_limited');
    } finally {
      await limited.close();
    }
  });
});

describe('password work limiter (F-5)', () => {
  const user = { email: 'limited@example.test', password: 'limiter test password' };

  /** A verifier that holds every call until released, recording peak concurrency. */
  function slowVerifier() {
    let running = 0;
    let peak = 0;
    let calls = 0;
    const releases: (() => void)[] = [];
    const verify = async (password: string, encodedHash: string): Promise<boolean> => {
      calls += 1;
      running += 1;
      peak = Math.max(peak, running);
      await new Promise<void>((resolve) => releases.push(resolve));
      running -= 1;
      return verifyPassword(password, encodedHash);
    };
    return {
      verify,
      stats: () => ({ running, peak, calls }),
      releaseAll: () => releases.splice(0).forEach((release) => release()),
    };
  }

  it('answers excess concurrent logins 429 with Retry-After and runs one verification at a time', async () => {
    const slow = slowVerifier();
    const h = await createHarness({
      config: { passwordConcurrency: 1, passwordQueueLimit: 1 },
      rateLimits: { loginMax: 1000, loginAddressMax: 1000 },
      passwordVerifier: slow.verify,
    });
    try {
      await seedOwner(h, user);
      // One running, one queued, the rest refused; an unknown account takes the same path.
      const attempts = [
        user,
        user,
        user,
        { email: 'nobody@example.test', password: 'whatever password' },
        user,
      ].map((credentials) =>
        h.inject({ method: 'POST', url: path(Routes.authLogin), payload: credentials }),
      );
      await eventually(async () => {
        expect(h.responses.filter((response) => response.statusCode === 429)).toHaveLength(3);
      });
      expect(slow.stats()).toMatchObject({ running: 1, calls: 1 });

      // Release verifications one by one until the queue drains.
      while (slow.stats().calls < 2 || slow.stats().running > 0) {
        slow.releaseAll();
        await new Promise((resolve) => setTimeout(resolve, 5));
      }
      const responses = await Promise.all(attempts);
      const statuses = responses.map((response) => response.statusCode);
      expect(statuses.filter((status) => status === 200)).toHaveLength(2);
      expect(statuses.filter((status) => status === 429)).toHaveLength(3);
      for (const response of responses.filter((r) => r.statusCode === 429)) {
        expectError(response, 429, 'rate_limited');
        expect(Number(response.headers['retry-after'])).toBeGreaterThanOrEqual(1);
      }
      expect(slow.stats().peak).toBe(1);
      expect(slow.stats().calls).toBe(2);

      // With capacity free again, a normal login succeeds. The two successful logins each
      // scheduled a background rehash through the same limiter, so retry while one of those
      // still holds the slot.
      const loginOnce = async () => {
        const pending = h.inject({ method: 'POST', url: path(Routes.authLogin), payload: user });
        const before = slow.stats().calls;
        while (slow.stats().calls === before) {
          const settled = await Promise.race([
            pending,
            new Promise<null>((resolve) => setTimeout(() => resolve(null), 5)),
          ]);
          if (settled !== null) return settled;
        }
        slow.releaseAll();
        return pending;
      };
      let next = await loginOnce();
      for (let attempt = 0; next.statusCode === 429 && attempt < 50; attempt += 1) {
        await new Promise((resolve) => setTimeout(resolve, 20));
        next = await loginOnce();
      }
      expect(next.statusCode, next.body).toBe(200);
      expect(slow.stats().peak).toBe(1);
    } finally {
      slow.releaseAll();
      await h.close();
    }
  });

  it('refuses at once with no queue, and the dummy-hash path is limited too', async () => {
    const slow = slowVerifier();
    const h = await createHarness({
      config: { passwordConcurrency: 1, passwordQueueLimit: 0 },
      rateLimits: { loginMax: 1000, loginAddressMax: 1000 },
      passwordVerifier: slow.verify,
    });
    try {
      await seedOwner(h, user);
      const unknown = h.inject({
        method: 'POST',
        url: path(Routes.authLogin),
        payload: { email: 'ghost@example.test', password: 'ghost password' },
      });
      await eventually(async () => {
        expect(slow.stats().running).toBe(1);
      });
      const refused = await h.inject({
        method: 'POST',
        url: path(Routes.authLogin),
        payload: user,
      });
      expectError(refused, 429, 'rate_limited');
      expect(refused.headers['retry-after']).toBe('1');
      slow.releaseAll();
      expectError(await unknown, 401, 'unauthenticated');
      const ok = h.inject({ method: 'POST', url: path(Routes.authLogin), payload: user });
      await eventually(async () => {
        expect(slow.stats().running).toBe(1);
      });
      slow.releaseAll();
      expect((await ok).statusCode).toBe(200);
      expect(slow.stats().peak).toBe(1);
    } finally {
      slow.releaseAll();
      await h.close();
    }
  });
});
