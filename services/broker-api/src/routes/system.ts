import { HealthResponse, Routes } from '@aab/contracts';
import type { AppContext } from '../context.js';
import type { ZodApp } from '../types.js';

export const SERVICE_VERSION = '0.0.0';
export const OPENAPI_PATH = '/openapi.json';
const DATABASE_CHECK_TIMEOUT_MS = 2_000;

async function databaseReachable(ctx: AppContext): Promise<boolean> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<false>((resolve) => {
    timer = setTimeout(() => resolve(false), DATABASE_CHECK_TIMEOUT_MS);
  });
  try {
    return await Promise.race([ctx.db.execute('select 1').then(() => true), timeout]);
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
  }
}

export function registerSystemRoutes(app: ZodApp, ctx: AppContext) {
  /**
   * Unauthenticated liveness and dependency check. Always 200 with a HealthResponse: every
   * non-2xx body must be an ErrorResponse, and a degraded report is still a valid answer.
   */
  app.get(
    Routes.health,
    { config: { auth: 'public' }, schema: { response: { 200: HealthResponse } } },
    async (request) => {
      const ok = await databaseReachable(ctx);
      if (!ok) request.log.warn('health check: database unavailable');
      return {
        status: ok ? 'ok' : 'degraded',
        version: SERVICE_VERSION,
        checks: { database: ok ? 'ok' : 'unavailable' },
      } as const;
    },
  );

  /** The OpenAPI document generated from the Zod route schemas. Signed-in callers only. */
  app.get(OPENAPI_PATH, { schema: { hide: true } }, () => app.swagger());
}
