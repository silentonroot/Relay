import { isNavigationAllowed } from '@aab/adapter-sdk';
import type { AdapterRegistry } from '@aab/adapter-sdk';
import type { JobErrorCode } from '@aab/contracts';
import type { z } from 'zod';
import { jobError } from '../protocol.js';
import type { ControlMessage, LoginJobMessage, RunnerLoginOutcome } from '../protocol.js';
import { diag, emit } from './io.js';
import { lookupAdapter, openBrowserJob } from './session.js';
import type { BrowserJob, RunnerEnvironment } from './session.js';

type Outcome = z.infer<typeof RunnerLoginOutcome>;

const failed = (code: JobErrorCode): Outcome => ({ status: 'failed', error: jobError(code) });

/**
 * The login handoff. Opens a headed browser on the adapter's login page and waits. The owner
 * signs in themselves; nothing here reads form fields, listens to input or takes screenshots.
 * Main-frame navigation stays on the allowed origins (any path).
 */
export async function runLogin(
  message: LoginJobMessage,
  registry: AdapterRegistry,
  env: RunnerEnvironment,
  nextControl: () => Promise<ControlMessage | null>,
): Promise<Outcome> {
  const job = message.job;
  const deadline = Date.now() + job.timeoutMs;
  const remainingMs = (): number => Math.max(0, deadline - Date.now());

  const found = lookupAdapter(registry, job.adapterId, job.adapterVersion, job.allowedOrigins);
  if (!found.ok) return failed(found.code);
  const { adapter, origins } = found;
  if (adapter.loginPath === undefined) return failed('adapter_unavailable');
  const loginUrl = `${origins[0] as string}${adapter.loginPath}`;
  if (!isNavigationAllowed(adapter, null, loginUrl).allowed) return failed('navigation_blocked');

  let browserJob: BrowserJob | null = null;
  let finishing = false;
  try {
    browserJob = await openBrowserJob({
      env,
      adapter,
      origins,
      mode: { kind: 'login' },
      headed: true,
    });
    const opened = browserJob;
    await opened.page.goto(loginUrl, { waitUntil: 'domcontentloaded', timeout: remainingMs() });
    diag('login_window_open');
    await emit({ type: 'login_ready' });

    type Ending = 'complete' | 'cancelled' | 'closed' | 'timeout';
    const ending = await new Promise<Ending>((resolve) => {
      const timer = setTimeout(() => resolve('timeout'), remainingMs());
      const done = (value: Ending): void => {
        clearTimeout(timer);
        resolve(value);
      };
      opened.page.once('close', () => {
        if (!finishing) done('closed');
      });
      opened.browser.once('disconnected', () => {
        if (!finishing) done('closed');
      });
      void (async () => {
        for (;;) {
          const control = await nextControl();
          if (control === null || control.type === 'cancel') {
            done('cancelled');
            return;
          }
          if (control.type === 'complete') {
            done('complete');
            return;
          }
        }
      })();
    });

    if (ending === 'cancelled') return failed('cancelled');
    if (ending === 'closed') return failed('login_window_closed');
    if (ending === 'timeout') return failed('timeout');

    // complete: confirm the sign-in with the adapter, then capture the session.
    if (adapter.checkSession === undefined) return failed('login_not_completed');
    opened.guard.setMode({ kind: 'session' });
    const ctx = opened.makeContext(job.connectionId, remainingMs);
    let health;
    try {
      health = await Promise.race([
        adapter.checkSession(ctx),
        opened.violation.then(() => null),
        new Promise<null>((resolve) => setTimeout(() => resolve(null), remainingMs())),
      ]);
    } catch {
      health = null;
    }
    if (health === null || health.state !== 'active' || opened.guard.violation !== null) {
      return failed('login_not_completed');
    }
    finishing = true;
    const state = await opened.context.storageState();
    return {
      status: 'succeeded',
      storageState: {
        cookies: state.cookies.map((cookie) => ({
          name: cookie.name,
          value: cookie.value,
          domain: cookie.domain,
          path: cookie.path,
          expires: cookie.expires,
          httpOnly: cookie.httpOnly,
          secure: cookie.secure,
          sameSite: cookie.sameSite,
        })),
        origins: state.origins.map((origin) => ({
          origin: origin.origin,
          localStorage: origin.localStorage.map((entry) => ({
            name: entry.name,
            value: entry.value,
          })),
        })),
      },
      externalAccountHint: health.externalAccountHint ?? null,
    };
  } catch {
    return failed('worker_failure');
  } finally {
    finishing = true;
    diag('login_finished');
    const current = browserJob as BrowserJob | null;
    await current?.close();
  }
}
