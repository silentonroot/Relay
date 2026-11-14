import { LoginRequest, Routes, SESSION_COOKIE, SessionResponse } from '@aab/contracts';
import { generateToken, hashToken, needsRehash } from '@aab/crypto';
import { NotFoundError } from '@aab/database';
import type { FastifyRequest } from 'fastify';
import { auditAsUser } from '../audit.js';
import { DEFAULT_RATE_LIMITS } from '../context.js';
import type { AppContext, RateLimitSettings } from '../context.js';
import { AppError } from '../errors.js';
import type { ZodApp } from '../types.js';
import { PasswordLimiterBusyError } from './passwords.js';
import {
  authOf,
  clearSessionCookie,
  deriveCsrfToken,
  resolveSession,
  sessionCookieOptions,
  sessionTokenOf,
} from './session.js';

/** One message for every login failure, so the response never says which part was wrong. */
const LOGIN_FAILED = 'Invalid email or password.';

function submittedEmail(request: FastifyRequest): string {
  const body = request.body as { email?: unknown } | undefined;
  return typeof body?.email === 'string' ? body.email.trim().toLowerCase() : '';
}

export function registerAuthRoutes(
  app: ZodApp,
  ctx: AppContext,
  limits: RateLimitSettings = DEFAULT_RATE_LIMITS,
) {
  // Checked inside the handler, after body validation, so the email is part of the key.
  // Every attempt counts, successful or not.
  const perAccount = app.createRateLimit({
    max: limits.loginMax,
    timeWindow: limits.loginWindowMs,
    keyGenerator: (request) => `login:${request.ip}:${submittedEmail(request)}`,
  });
  const perAddress = app.createRateLimit({
    max: limits.loginAddressMax,
    timeWindow: limits.loginWindowMs,
    keyGenerator: (request) => `login-address:${request.ip}`,
  });

  app.post(
    Routes.authLogin,
    {
      config: { auth: 'public' },
      schema: { body: LoginRequest, response: { 200: SessionResponse } },
    },
    async (request, reply) => {
      for (const limiter of [perAccount, perAddress]) {
        const status = await limiter(request);
        if (!status.isAllowed && status.isExceeded) {
          reply.header('retry-after', String(status.ttlInSeconds));
          throw new AppError(429, 'rate_limited', 'Too many login attempts. Try again later.');
        }
      }

      const { email, password } = request.body;
      const record = await ctx.repos.users.findForLogin(email);
      // Unknown accounts still pay for one full verification, against a hash with the same
      // cost parameters, so response time does not reveal which emails exist.
      // Both paths go through the same limiter (F-5), so a full queue answers 429 for known
      // and unknown accounts alike and timing stays uniform.
      let passwordOk: boolean;
      try {
        passwordOk = await ctx.passwords.verify(
          password,
          record?.passwordHash ?? ctx.dummyPasswordHash,
        );
      } catch (error) {
        if (error instanceof PasswordLimiterBusyError) {
          reply.header('retry-after', String(error.retryAfterSeconds));
          throw new AppError(429, 'rate_limited', 'Too many login attempts. Try again later.');
        }
        throw error;
      }
      const membership = record?.memberships.find(
        (member) => member.organization.status === 'active',
      );
      const now = ctx.clock();

      if (
        record === null ||
        !passwordOk ||
        record.user.status !== 'active' ||
        membership === undefined
      ) {
        const reason =
          record === null
            ? 'unknown_account'
            : !passwordOk
              ? 'invalid_password'
              : record.user.status !== 'active'
                ? 'account_disabled'
                : 'no_active_membership';
        // The email is never logged: people type passwords into the wrong field.
        request.log.warn({ event: 'auth.login_failed', reason }, 'login failed');

        // A known account is audited in its organization. An unknown one has no organization
        // to attach the event to, so it is only logged (above). The write happens after the
        // response so both cases take the same time.
        const organizationId = record?.memberships[0]?.organization.id;
        if (record !== null && organizationId !== undefined) {
          const userId = record.user.id;
          ctx.runInBackground(request.log, 'audit failed login', () =>
            ctx.repos.audit.append({
              organizationId,
              actorType: 'user',
              actorId: userId,
              eventType: 'auth.login_failed',
              decision: 'deny',
              metadata: { reason },
              timestamp: now,
            }),
          );
        }
        throw new AppError(401, 'unauthenticated', LOGIN_FAILED);
      }

      // Never adopt a token the client brought (session fixation): always mint a new one.
      const token = generateToken();
      const csrfToken = deriveCsrfToken(token);
      const expiresAt = new Date(now.getTime() + ctx.config.sessionTtlMinutes * 60_000);
      const scope = { organizationId: membership.organization.id, userId: record.user.id };

      let session;
      try {
        session = await ctx.repos.transaction(async (tx) => {
          const created = await tx.sessions.create({
            ...scope,
            tokenHash: hashToken(token),
            csrfTokenHash: hashToken(csrfToken),
            expiresAt,
          });
          await auditAsUser(tx, scope, now, {
            eventType: 'auth.login_succeeded',
            decision: 'allow',
            metadata: { method: 'password' },
          });
          return created;
        });
      } catch (error) {
        // The membership or organization was disabled between lookup and insert.
        if (error instanceof NotFoundError)
          throw new AppError(401, 'unauthenticated', LOGIN_FAILED);
        throw error;
      }

      // A session the browser already held is ended rather than left alive beside the new one.
      const previousToken = sessionTokenOf(request);
      if (previousToken !== null) {
        const previous = await resolveSession(ctx, previousToken);
        if (previous !== null) await ctx.repos.sessions.revoke(previous.session.session.id, now);
      }

      if (needsRehash(record.passwordHash)) {
        const userId = record.user.id;
        const previousHash = record.passwordHash;
        ctx.runInBackground(request.log, 'password rehash', async () => {
          let nextHash: string;
          try {
            nextHash = await ctx.passwords.hash(password);
          } catch (error) {
            // Under load, skip it: the next successful login tries again.
            if (error instanceof PasswordLimiterBusyError) return;
            throw error;
          }
          // Compare-and-swap: a password changed in the meantime is never overwritten.
          await ctx.repos.users.updatePasswordHash(userId, nextHash, {
            expectedHash: previousHash,
            now: ctx.clock(),
          });
        });
      }

      reply.setCookie(SESSION_COOKIE, token, sessionCookieOptions(ctx.config));
      return {
        user: record.user,
        organization: membership.organization,
        csrfToken,
        expiresAt: session.expiresAt,
      };
    },
  );

  app.get(Routes.authSession, { schema: { response: { 200: SessionResponse } } }, (request) => {
    const auth = authOf(request);
    return {
      user: auth.session.user,
      organization: auth.session.organization,
      csrfToken: deriveCsrfToken(auth.token),
      expiresAt: auth.session.session.expiresAt,
    };
  });

  app.post(Routes.authLogout, {}, async (request, reply) => {
    const auth = authOf(request);
    const now = ctx.clock();
    await ctx.repos.transaction(async (tx) => {
      await tx.sessions.revoke(auth.session.session.id, now);
      await auditAsUser(tx, auth.scope, now, {
        eventType: 'auth.logout',
        metadata: { reason: 'user_logout' },
      });
    });
    clearSessionCookie(reply, ctx.config);
    return reply.code(204).send();
  });
}
