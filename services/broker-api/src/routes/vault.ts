import { Routes, StatusResult } from '@aab/contracts';
import { authOf } from '../auth/session.js';
import type { AppContext } from '../context.js';
import { AppError } from '../errors.js';
import type { ZodApp } from '../types.js';

/**
 * The vault's `status` for the owner's dashboard (ADR-014 section 12). The `api` role may call
 * it; it holds KEK version numbers, counts and counters, never a key, a token or a secret. Only
 * the organization's owner sees it: the installation's key state is not a member's business.
 * A vault that cannot be reached is a 503 with the usual error body and no detail of why.
 */
export function registerVaultRoutes(app: ZodApp, ctx: AppContext) {
  app.get(Routes.vaultStatus, { schema: { response: { 200: StatusResult } } }, async (request) => {
    if (authOf(request).session.role !== 'owner') {
      throw new AppError(403, 'forbidden', 'Only owners can see the vault status.');
    }
    if (ctx.vault === undefined) {
      throw new AppError(503, 'service_unavailable', 'The vault is not available.');
    }
    try {
      return await ctx.vault.status();
    } catch (error) {
      request.log.warn(
        { errorName: error instanceof Error ? error.name : 'unknown' },
        'vault status unavailable',
      );
      throw new AppError(503, 'service_unavailable', 'The vault is not available.');
    }
  });
}
