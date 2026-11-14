import { createHmac } from 'node:crypto';
import { CSRF_HEADER, SESSION_COOKIE } from '@aab/contracts';
import { constantTimeEqual, hashToken } from '@aab/crypto';
import type { CookieSerializeOptions } from '@fastify/cookie';
import type { FastifyReply, FastifyRequest } from 'fastify';
import type { AppConfig } from '../config.js';
import type { AppContext, RequestAuth } from '../context.js';
import { AppError, unauthenticated } from '../errors.js';

/*
 * Dashboard session handling.
 *
 * The session token is 32 random bytes in an HttpOnly cookie; the database stores only its
 * SHA-256. The CSRF token is HMAC-SHA256(session token, fixed label): stable for the life of
 * the session (reloads and several tabs keep working), recomputable from the cookie alone,
 * and never stored in clear. The session row keeps hashToken(csrfToken) for comparison.
 */

const CSRF_LABEL = 'aab.csrf.v1';
/** generateToken(32) yields 43 base64url characters; anything else is not ours. */
const SESSION_TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
/** How stale last_seen_at may get before a request refreshes it. */
const TOUCH_INTERVAL_MS = 60_000;

export function deriveCsrfToken(sessionToken: string): string {
  return createHmac('sha256', sessionToken).update(CSRF_LABEL, 'utf8').digest('base64url');
}

export function sessionCookieOptions(config: AppConfig): CookieSerializeOptions {
  return {
    httpOnly: true,
    sameSite: 'strict',
    path: '/',
    secure: config.cookieSecure,
    maxAge: config.sessionTtlMinutes * 60,
  };
}

export function clearSessionCookie(reply: FastifyReply, config: AppConfig): void {
  reply.clearCookie(SESSION_COOKIE, {
    httpOnly: true,
    sameSite: 'strict',
    path: '/',
    secure: config.cookieSecure,
  });
}

export function isMutation(method: string): boolean {
  return !SAFE_METHODS.has(method.toUpperCase());
}

/** The session token from the cookie, if it has the shape of one we issue. */
export function sessionTokenOf(request: FastifyRequest): string | null {
  const value = request.cookies[SESSION_COOKIE];
  return typeof value === 'string' && SESSION_TOKEN_PATTERN.test(value) ? value : null;
}

export async function resolveSession(ctx: AppContext, token: string): Promise<RequestAuth | null> {
  const valid = await ctx.repos.sessions.findValid(hashToken(token), ctx.clock());
  if (valid === null) return null;
  return {
    token,
    session: valid,
    scope: { organizationId: valid.organization.id, userId: valid.user.id },
  };
}

/**
 * Mutations must declare a JSON body. A request without a body may omit the content type
 * (the dashboard sends none for logout, disable and grant revocation); anything that declares
 * another type, or sends a body without declaring one, is rejected before parsing.
 */
export function assertJsonContentType(request: FastifyRequest): void {
  const header = request.headers['content-type'];
  if (header === undefined) {
    const length = request.headers['content-length'];
    const hasBody =
      (length !== undefined && length !== '0') ||
      request.headers['transfer-encoding'] !== undefined;
    if (hasBody) throw new AppError(415, 'validation_failed', 'Send the body as application/json.');
    return;
  }
  const mediaType = header.split(';', 1)[0]!.trim().toLowerCase();
  if (mediaType !== 'application/json') {
    throw new AppError(415, 'validation_failed', 'Send the body as application/json.');
  }
}

function assertCsrf(request: FastifyRequest, auth: RequestAuth): void {
  const header = request.headers[CSRF_HEADER];
  const presented = typeof header === 'string' ? header : '';
  // Hash the presented value so both sides of the comparison are fixed-length hex digests.
  const matches =
    presented !== '' &&
    presented.length <= 256 &&
    constantTimeEqual(hashToken(presented), auth.session.csrfTokenHash);
  if (!matches) {
    throw new AppError(403, 'csrf_failed', 'Missing or invalid CSRF token.');
  }
}

/**
 * The single gate every request passes before parsing: session, then CSRF, then content type.
 * Routes opt out of the session check with `config: { auth: 'public' }`; nothing opts out of
 * the content-type rule.
 */
export function createRequestGuard(ctx: AppContext) {
  return async function guard(request: FastifyRequest, reply: FastifyReply): Promise<void> {
    // Unknown routes get a plain 404 from the not-found handler.
    if (request.is404) return;
    const mutation = isMutation(request.method);

    if (request.routeOptions.config.auth === 'public') {
      if (mutation) assertJsonContentType(request);
      return;
    }

    const token = sessionTokenOf(request);
    const auth = token === null ? null : await resolveSession(ctx, token);
    if (auth === null) {
      // Drop a dead cookie so the browser stops sending it.
      if (request.cookies[SESSION_COOKIE] !== undefined) clearSessionCookie(reply, ctx.config);
      throw unauthenticated();
    }
    request.auth = auth;

    if (mutation) {
      assertCsrf(request, auth);
      assertJsonContentType(request);
    }

    const now = ctx.clock();
    if (now.getTime() - Date.parse(auth.session.session.lastSeenAt) > TOUCH_INTERVAL_MS) {
      await ctx.repos.sessions.touch(auth.session.session.id, now);
    }
  };
}

/** The authenticated identity of a request that passed the guard. */
export function authOf(request: FastifyRequest): RequestAuth {
  if (request.auth === null) throw unauthenticated();
  return request.auth;
}
