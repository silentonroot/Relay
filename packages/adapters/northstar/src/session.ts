import { ReauthRequiredError } from '@aab/adapter-sdk';
import type { SessionHealth, WorkerContext } from '@aab/adapter-sdk';
import { NORTHSTAR_UI } from './selectors.js';

/** The login form allows at most 64 characters in a username. */
const MAX_ACCOUNT_HINT_LENGTH = 64;

/**
 * Loads the orders page (a GET, no side effects) and reads who is signed in. The browser
 * facade raises `ReauthRequiredError` when the navigation ends on the login page.
 */
export async function checkNorthstarSession(ctx: WorkerContext): Promise<SessionHealth> {
  try {
    await ctx.browser.goto(NORTHSTAR_UI.paths.orders);
  } catch (error) {
    if (error instanceof ReauthRequiredError) return { state: 'expired' };
    throw error;
  }

  const username = (await ctx.browser.text(NORTHSTAR_UI.currentUser))?.trim() ?? '';
  if (username === '' || username.length > MAX_ACCOUNT_HINT_LENGTH) return { state: 'degraded' };
  return { state: 'active', externalAccountHint: username };
}
