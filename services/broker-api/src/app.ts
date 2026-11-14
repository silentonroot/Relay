import { randomUUID } from 'node:crypto';
import { AdapterRegistry } from '@aab/adapter-sdk';
import { northstarAdapter } from '@aab/adapter-northstar';
import { API_PREFIX, REQUEST_ID_HEADER } from '@aab/contracts';
import { generateToken } from '@aab/crypto';
import type { ScryptParams } from '@aab/crypto';
import { createRepositories } from '@aab/database';
import type { DatabaseHandle } from '@aab/database';
import fastifyCookie from '@fastify/cookie';
import fastifyHelmet from '@fastify/helmet';
import fastifyRateLimit from '@fastify/rate-limit';
import fastifySwagger from '@fastify/swagger';
import Fastify from 'fastify';
import type { FastifyBaseLogger, FastifyInstance, FastifyReply } from 'fastify';
import {
  jsonSchemaTransform,
  serializerCompiler,
  validatorCompiler,
} from 'fastify-type-provider-zod';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { createPasswordService, PasswordLimiter } from './auth/passwords.js';
import type { PasswordHasher, PasswordVerifier } from './auth/passwords.js';
import { registerAuthRoutes } from './auth/routes.js';
import { createRequestGuard } from './auth/session.js';
import type { AppConfig } from './config.js';
import { DEFAULT_RATE_LIMITS } from './context.js';
import type { AppContext, RateLimitSettings } from './context.js';
import { AppError, errorBody, sendError } from './errors.js';
import { loggerOptions } from './logging.js';
import type { LogDestination } from './logging.js';
import { registerExecutionRoutes } from './routes/execution.js';
import { registerResourceRoutes } from './routes/resources.js';
import { registerSystemRoutes, SERVICE_VERSION } from './routes/system.js';

export interface BuildAppDeps {
  database: DatabaseHandle;
  config: AppConfig;
  /** Source of "now" for sessions, audit timestamps and grant expiry. Defaults to the system clock. */
  clock?: () => Date;
  /** Where structured logs go. Defaults to stdout. */
  logDestination?: LogDestination;
  /** scrypt cost for rehashing and for the dummy hash. Only tests should lower it. */
  passwordParams?: ScryptParams;
  rateLimits?: Partial<RateLimitSettings>;
  /** Replaces scrypt verification (still behind the limiter). Only tests should set it. */
  passwordVerifier?: PasswordVerifier;
  /** Replaces scrypt hashing (still behind the limiter). Only tests should set it. */
  passwordHasher?: PasswordHasher;
  /**
   * The adapters this API knows about, used as data only (descriptors, input schemas,
   * `loginPath`); the API never runs them. Defaults to a registry holding the Northstar adapter.
   */
  adapters?: AdapterRegistry;
}

function defaultAdapterRegistry(): AdapterRegistry {
  const registry = new AdapterRegistry();
  registry.register(northstarAdapter);
  return registry;
}

/** 64 KiB: control-plane payloads are small JSON documents. */
export const BODY_LIMIT_BYTES = 64 * 1024;
/** An inbound x-request-id is reused only when it is short and made of safe characters. */
const INBOUND_REQUEST_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/;

export function requestIdFor(header: string | string[] | undefined): string {
  return typeof header === 'string' && INBOUND_REQUEST_ID.test(header) ? header : randomUUID();
}

/**
 * Builds the broker API. The caller owns the database handle: closing the app waits for
 * background work but does not close the database.
 */
export async function buildApp(deps: BuildAppDeps): Promise<FastifyInstance> {
  const { config } = deps;
  const clock = deps.clock ?? (() => new Date());
  const limits: RateLimitSettings = { ...DEFAULT_RATE_LIMITS, ...deps.rateLimits };

  const app = Fastify({
    logger: loggerOptions(config.logLevel, deps.logDestination),
    trustProxy: config.trustProxy,
    bodyLimit: BODY_LIMIT_BYTES,
    requestIdHeader: false,
    genReqId: (request) => requestIdFor(request.headers[REQUEST_ID_HEADER]),
    // Errors raised before routing (a malformed URL, say) get the same error body.
    frameworkErrors: (error, request, rawReply) => {
      const reply = rawReply as unknown as FastifyReply;
      void reply
        .code(400)
        .header(REQUEST_ID_HEADER, request.id)
        .send(errorBody(request.id, 'validation_failed', 'The request is invalid.'));
      request.log.info({ errorCode: error.code }, 'request rejected before routing');
    },
  }).withTypeProvider<ZodTypeProvider>();

  app.setValidatorCompiler(validatorCompiler);
  app.setSerializerCompiler(serializerCompiler);

  const background = new Set<Promise<unknown>>();
  const passwords = createPasswordService({
    limiter: new PasswordLimiter({
      concurrency: config.passwordConcurrency,
      maxQueue: config.passwordQueueLimit,
    }),
    params: deps.passwordParams,
    ...(deps.passwordVerifier === undefined ? {} : { verifier: deps.passwordVerifier }),
    ...(deps.passwordHasher === undefined ? {} : { hasher: deps.passwordHasher }),
  });
  const ctx: AppContext = {
    db: deps.database.db,
    repos: createRepositories(deps.database.db),
    config,
    adapters: deps.adapters ?? defaultAdapterRegistry(),
    clock,
    passwordParams: deps.passwordParams,
    passwords,
    dummyPasswordHash: await passwords.hash(generateToken()),
    runInBackground(log: FastifyBaseLogger, label: string, work: () => Promise<unknown>) {
      const task = work()
        .catch((error: unknown) => log.error({ err: error, task: label }, 'background task failed'))
        .finally(() => background.delete(task));
      background.add(task);
    },
  };
  app.addHook('onClose', async () => {
    await Promise.allSettled([...background]);
  });

  app.decorate('routeTable', []);
  app.decorateRequest('auth', null);
  app.addHook('onRoute', (route) => {
    const methods = Array.isArray(route.method) ? route.method : [route.method];
    for (const method of methods) {
      app.routeTable.push({
        method: String(method).toUpperCase(),
        url: route.url,
        public: route.config?.auth === 'public',
      });
    }
  });

  // Only JSON bodies are accepted. Dropping the text/plain parser means no other parser
  // exists even if the content-type guard were bypassed.
  app.removeContentTypeParser(['text/plain']);

  await app.register(fastifyHelmet, { global: true });
  await app.register(fastifyCookie, { hook: 'onRequest' });
  await app.register(fastifyRateLimit, {
    global: true,
    max: limits.globalMax,
    timeWindow: 60_000,
    errorResponseBuilder: () =>
      new AppError(429, 'rate_limited', 'Too many requests. Try again later.'),
  });
  await app.register(fastifySwagger, {
    openapi: {
      openapi: '3.1.0',
      info: { title: 'Agent Access Broker API', version: SERVICE_VERSION },
      components: {
        securitySchemes: {
          sessionCookie: { type: 'apiKey', in: 'cookie', name: 'aab_session' },
        },
      },
    },
    transform: jsonSchemaTransform,
  });

  // Session, CSRF and content-type checks run before the body is even parsed.
  app.addHook('onRequest', createRequestGuard(ctx));

  app.addHook('onSend', async (request, reply, payload) => {
    reply.header(REQUEST_ID_HEADER, request.id);
    // Responses describe the caller's own resources and session; nothing may cache them.
    reply.header('cache-control', 'no-store');
    return payload;
  });

  app.setErrorHandler((error, request, reply) => sendError(request, reply, error));
  app.setNotFoundHandler({ preHandler: app.rateLimit() }, (request, reply) =>
    sendError(
      request,
      reply,
      new AppError(404, 'not_found', 'The requested resource was not found.'),
    ),
  );

  await app.register(
    async (api) => {
      const typed = api.withTypeProvider<ZodTypeProvider>();
      registerSystemRoutes(typed, ctx);
      registerAuthRoutes(typed, ctx, limits);
      registerResourceRoutes(typed, ctx);
      registerExecutionRoutes(typed, ctx, limits);
    },
    { prefix: API_PREFIX },
  );

  await app.ready();
  return app;
}
