import { defineAdapter } from '@aab/adapter-sdk';
import type { ApplicationAdapter } from '@aab/adapter-sdk';
import { executeNorthstar } from './execute.js';
import { ordersGet, ordersList } from './operations.js';
import { NORTHSTAR_UI } from './selectors.js';
import { checkNorthstarSession } from './session.js';

export * from './operations.js';
export * from './selectors.js';
export { NORTHSTAR_DEFAULT_LIMIT, NORTHSTAR_ERRORS, NORTHSTAR_MAX_PAGES } from './execute.js';

/**
 * Adapter for the synthetic Northstar demo application.
 *
 * Declares what may be granted, validated and policy-checked, and implements `checkSession`
 * and the read operations. The write operations (`orders.proposeUpdate`,
 * `orders.applyApprovedUpdate`) arrive in Phase 4.
 */
const operations = {
  'orders.list': ordersList,
  'orders.get': ordersGet,
};

export const northstarAdapter: ApplicationAdapter<typeof operations> = defineAdapter({
  id: 'northstar',
  version: '0.1.0',
  displayName: 'Northstar (synthetic demo)',
  allowedOrigins: [NORTHSTAR_UI.defaultOrigin],
  authMode: 'browser_session',
  loginPath: NORTHSTAR_UI.paths.login,
  sessionCheckPaths: [NORTHSTAR_UI.paths.orders],
  operations,
  checkSession: (ctx) => checkNorthstarSession(ctx),
  execute: (ctx, operation) => executeNorthstar(northstarAdapter, ctx, operation),
});
