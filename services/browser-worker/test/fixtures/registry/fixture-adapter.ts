import { defineAdapter, defineOperation, ReauthRequiredError } from '@aab/adapter-sdk';
import type { SanitizedResult, ValidatedOperation, WorkerContext } from '@aab/adapter-sdk';
import { z } from 'zod';
import { FIXTURE_ORIGIN } from './constants.js';

const empty = z.object({});

function read(
  name: string,
  allowedPaths: string[],
  output: z.ZodObject = z.object({ ok: z.boolean() }),
) {
  return defineOperation({
    name,
    description: `fixture operation ${name}`,
    input: empty,
    output,
    sensitivity: 'read',
    requiresApproval: false,
    idempotent: true,
    sideEffects: [],
    timeoutMs: 30_000,
    allowedPaths,
  });
}

const operations = {
  'account.read': read(
    'account.read',
    ['/orders'],
    z.object({
      account: z.string(),
      orders: z.array(z.object({ id: z.string(), total: z.string() })),
    }),
  ),
  'nav.redirectPath': read('nav.redirectPath', ['/redirect-path']),
  'nav.redirectOrigin': read('nav.redirectOrigin', ['/redirect-origin', '/orders']),
  'nav.metaRefresh': read('nav.metaRefresh', ['/meta-refresh']),
  'nav.script': read('nav.script', ['/script-nav']),
  'nav.form': read('nav.form', ['/form']),
  'nav.goLogin': read('nav.goLogin', ['/go-login']),
  'nav.disallowedGoto': read('nav.disallowedGoto', ['/orders']),
  'page.exfil': read('page.exfil', ['/exfil']),
  'page.big': read('page.big', ['/big'], z.object({ text: z.string().max(1000) })),
  'page.bigLength': read('page.bigLength', ['/big'], z.object({ length: z.number() })),
  'page.missing': read(
    'page.missing',
    ['/missing'],
    z.object({ status: z.string().nullable(), absent: z.string().nullable() }),
  ),
  'op.hang': read('op.hang', ['/orders']),
  'op.slow': read('op.slow', ['/orders']),
  'op.adapterFails': read('op.adapterFails', ['/orders']),
};

const ok: SanitizedResult = { status: 'succeeded', data: { ok: true } };

async function execute(
  ctx: WorkerContext,
  operation: ValidatedOperation,
): Promise<SanitizedResult> {
  const browser = ctx.browser;
  switch (operation.name) {
    case 'account.read': {
      await browser.goto('/orders');
      const rows = await browser.rows('tr.order', 'data-field');
      return {
        status: 'succeeded',
        data: {
          account: (await browser.text('#account')) ?? '',
          // `internal` is in each row but not in the schema; `secretNote` is undeclared.
          orders: rows,
          secretNote: 'must never reach the agent',
        },
      };
    }
    case 'nav.redirectPath':
      await browser.goto('/redirect-path');
      return ok;
    case 'nav.redirectOrigin':
      await browser.goto('/redirect-origin');
      return ok;
    case 'nav.metaRefresh':
      await browser.goto('/meta-refresh');
      await browser.waitFor('#never', { timeoutMs: 8_000 });
      return ok;
    case 'nav.script':
      await browser.goto('/script-nav');
      await browser.waitFor('#never', { timeoutMs: 8_000 });
      return ok;
    case 'nav.form':
      await browser.goto('/form');
      await browser.click('#go');
      await browser.waitFor('#never', { timeoutMs: 8_000 });
      return ok;
    case 'nav.goLogin':
      await browser.goto('/go-login');
      return ok;
    case 'nav.disallowedGoto':
      await browser.goto('/admin');
      return ok;
    case 'page.exfil':
      await browser.goto('/exfil');
      await browser.waitFor('#done', { timeoutMs: 10_000 });
      return ok;
    case 'page.big':
      await browser.goto('/big');
      return { status: 'succeeded', data: { text: (await browser.text('#big')) ?? '' } };
    case 'page.bigLength':
      await browser.goto('/big');
      return { status: 'succeeded', data: { length: ((await browser.text('#big')) ?? '').length } };
    case 'page.missing':
      await browser.goto('/missing');
      return {
        status: 'succeeded',
        data: {
          status: await browser.attribute('[data-testid="error-page"]', 'data-status'),
          absent: await browser.text('#does-not-exist'),
        },
      };
    case 'op.hang':
      await browser.goto('/orders');
      // Blocks the runner's event loop: only the supervisor's hard deadline can end this.
      for (;;) {
        // spin
      }
    case 'op.slow':
      await browser.goto('/orders');
      await browser.waitFor('#never', { timeoutMs: 60_000 });
      return ok;
    case 'op.adapterFails':
      return { status: 'failed', error: { code: 'not_found', message: 'page said: secret text' } };
    default:
      return { status: 'failed', error: { code: 'unknown', message: 'unknown' } };
  }
}

export const fixtureAdapter = defineAdapter({
  id: 'fixture-app',
  version: '1.0.0',
  displayName: 'Fixture app',
  allowedOrigins: [FIXTURE_ORIGIN],
  authMode: 'browser_session',
  loginPath: '/login',
  sessionCheckPaths: ['/account'],
  operations,
  async checkSession(ctx) {
    try {
      await ctx.browser.goto('/account');
    } catch (error) {
      if (error instanceof ReauthRequiredError) return { state: 'expired' };
      throw error;
    }
    const account = await ctx.browser.text('#account');
    return account === null
      ? { state: 'degraded' }
      : { state: 'active', externalAccountHint: account };
  },
  execute,
});
