import { Origin } from '@aab/contracts';
import type { JobErrorCode } from '@aab/contracts';
import type { AdapterLogger, ApplicationAdapter, WorkerContext } from '@aab/adapter-sdk';
import type { Browser, BrowserContext, Page } from 'playwright-core';
import type { AdapterRegistry } from '@aab/adapter-sdk';
import { launchBrowser, startRelay } from './browser.js';
import type { Relay } from './browser.js';
import { closePopups, createBrowserSession, NavigationGuard } from './facade.js';
import type { GuardMode, Violation } from './facade.js';
import { diag } from './io.js';

/** Settings the launcher passes through the environment. Never secret, never from a job. */
export interface RunnerEnvironment {
  readonly chromiumPath: string;
  readonly chromiumSandbox: boolean;
  readonly registryModule: string;
  readonly egressSocket: string;
  readonly display: 'x11' | 'wayland' | null;
}

export function readRunnerEnvironment(env: NodeJS.ProcessEnv): RunnerEnvironment {
  const required = (name: string): string => {
    const value = env[name];
    if (value === undefined || value === '') throw new Error(`missing ${name}`);
    return value;
  };
  const display = env['AAB_RUNNER_DISPLAY'];
  return {
    chromiumPath: required('AAB_RUNNER_CHROMIUM'),
    chromiumSandbox: env['AAB_RUNNER_CHROMIUM_SANDBOX'] !== '0',
    registryModule: required('AAB_RUNNER_REGISTRY'),
    egressSocket: required('AAB_RUNNER_EGRESS_SOCKET'),
    display: display === 'x11' || display === 'wayland' ? display : null,
  };
}

export type AdapterLookup =
  | { readonly ok: true; readonly adapter: ApplicationAdapter; readonly origins: string[] }
  | { readonly ok: false; readonly code: JobErrorCode };

/**
 * Finds the adapter and checks the job's origins: every one must be a canonical origin the
 * adapter itself allows. The first is the primary origin `goto` paths resolve against.
 */
export function lookupAdapter(
  registry: AdapterRegistry,
  adapterId: string,
  adapterVersion: string,
  allowedOrigins: readonly string[],
): AdapterLookup {
  const adapter = registry.get(adapterId, adapterVersion);
  if (adapter === undefined) return { ok: false, code: 'adapter_unavailable' };
  const origins = [...new Set(allowedOrigins)];
  if (
    origins.length === 0 ||
    !origins.every(
      (origin) => Origin.safeParse(origin).success && adapter.allowedOrigins.includes(origin),
    )
  ) {
    return { ok: false, code: 'origin_not_allowed' };
  }
  return { ok: true, adapter, origins };
}

/** Adapter log calls go to stderr with fixed shape: the message is not forwarded. */
export const adapterLogger: AdapterLogger = {
  debug: () => diag('adapter_log', { code: 'debug' }),
  info: () => diag('adapter_log', { code: 'info' }),
  warn: () => diag('adapter_log', { code: 'warn' }),
  error: () => diag('adapter_log', { code: 'error' }),
};

export interface BrowserJob {
  readonly browser: Browser;
  readonly context: BrowserContext;
  readonly page: Page;
  readonly guard: NavigationGuard;
  /** Resolves with the first navigation violation. */
  readonly violation: Promise<Violation>;
  readonly controller: AbortController;
  makeContext(connectionId: string, remainingMs: () => number): WorkerContext;
  close(): Promise<void>;
}

export interface BrowserJobOptions {
  readonly env: RunnerEnvironment;
  readonly adapter: ApplicationAdapter;
  readonly origins: readonly string[];
  readonly mode: GuardMode;
  readonly headed: boolean;
  readonly storageState?: {
    cookies: {
      name: string;
      value: string;
      domain: string;
      path: string;
      expires: number;
      httpOnly: boolean;
      secure: boolean;
      sameSite: 'Strict' | 'Lax' | 'None';
    }[];
    origins: { origin: string; localStorage: { name: string; value: string }[] }[];
  };
}

/** Starts the relay and the browser, and makes one guarded page in a fresh context. */
export async function openBrowserJob(options: BrowserJobOptions): Promise<BrowserJob> {
  let relay: Relay | null = null;
  let browser: Browser | null = null;
  try {
    relay = await startRelay(options.env.egressSocket);
    browser = await launchBrowser({
      executablePath: options.env.chromiumPath,
      chromiumSandbox: options.env.chromiumSandbox,
      relayPort: relay.port,
      headed: options.headed ? (options.env.display ?? 'x11') : null,
    });
    diag('browser_launched');
    const context = await browser.newContext({
      acceptDownloads: false,
      serviceWorkers: 'block',
      permissions: [],
      ...(options.storageState === undefined ? {} : { storageState: options.storageState }),
    });
    closePopups(context);
    const page = await context.newPage();
    const controller = new AbortController();
    let reportViolation: (violation: Violation) => void = () => undefined;
    const violation = new Promise<Violation>((resolve) => {
      reportViolation = resolve;
    });
    const guard = new NavigationGuard(options.adapter, options.origins, options.mode, (found) => {
      controller.abort();
      reportViolation(found);
    });
    const cdp = await context.newCDPSession(page);
    await guard.install(page, cdp);

    const primaryOrigin = options.origins[0] as string;
    const openedBrowser = browser;
    const openedRelay = relay;
    return {
      browser,
      context,
      page,
      guard,
      violation,
      controller,
      makeContext(connectionId, remainingMs) {
        return {
          connectionId,
          signal: controller.signal,
          logger: adapterLogger,
          browser: createBrowserSession({
            page,
            guard,
            adapter: options.adapter,
            origin: primaryOrigin,
            signal: controller.signal,
            remainingMs,
          }),
        };
      },
      async close() {
        controller.abort();
        await Promise.race([
          openedBrowser.close().catch(() => undefined),
          new Promise((resolve) => setTimeout(resolve, 5_000)),
        ]);
        openedRelay.close();
      },
    };
  } catch (error) {
    diag('browser_launch_failed');
    await browser?.close().catch(() => undefined);
    relay?.close();
    throw error;
  }
}
