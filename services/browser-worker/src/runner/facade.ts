import {
  isNavigationAllowed,
  matchesPathPattern,
  NavigationBlockedError,
  ReauthRequiredError,
} from '@aab/adapter-sdk';
import type { ApplicationAdapter, BrowserSession, NavigationBlockReason } from '@aab/adapter-sdk';
import type { BrowserContext, CDPSession, Page } from 'playwright-core';
import { diag } from './io.js';

/*
 * The navigation guard and the `BrowserSession` facade adapters get.
 *
 * Main-frame navigations are checked by a CDP `Fetch` interception on the page's own target,
 * paused at the request stage for `Document` requests. Chromium pauses every redirect hop as
 * a new request, so the initial request and each hop are judged before they are sent, whatever
 * started them (`goto`, a click, a form, a meta refresh, script). A blocked hop is failed with
 * `BlockedByClient` and recorded as the job's violation, which ends the operation.
 *
 * As a second layer, every committed main-frame URL is checked again (this catches URLs that
 * never become a network request, such as `blob:`).
 */

export type GuardMode =
  | { readonly kind: 'operation'; readonly operation: string }
  | { readonly kind: 'session' }
  | { readonly kind: 'login' };

export type Violation = NavigationBlockedError | ReauthRequiredError;

/** Fixed-text error for a failed browser action; never carries Playwright or page text. */
export class BrowserActionError extends Error {
  override readonly name = 'BrowserActionError';
  constructor() {
    super('a browser action failed');
  }
}

/** The job was stopped (timeout or cancellation) while the adapter was running. */
export class JobStoppedError extends Error {
  override readonly name = 'JobStoppedError';
  constructor() {
    super('the job was stopped');
  }
}

export const MAX_TEXT_CHARS = 64 * 1024;
export const MAX_TOTAL_TEXT_CHARS = 512 * 1024;
export const MAX_ELEMENTS = 1000;
const MAX_SELECTOR_LENGTH = 1000;
const MAX_PATH_LENGTH = 2048;
const ATTRIBUTE_NAME = /^[A-Za-z_][A-Za-z0-9_.:-]{0,63}$/;

type Check =
  | { readonly allowed: true }
  | { readonly allowed: false; readonly violation: Violation; readonly code: string };

interface FetchPausedEvent {
  readonly requestId: string;
  readonly frameId: string;
  readonly resourceType: string;
  readonly request: { readonly url: string };
}

export class NavigationGuard {
  readonly #adapter: ApplicationAdapter;
  readonly #origins: ReadonlySet<string>;
  readonly #onViolation: (violation: Violation) => void;
  #mode: GuardMode;
  #mainFrameId: string | null = null;
  readonly #subFrames = new Set<string>();
  /** Set while the adapter itself navigates to the login path. */
  #loginRequested = false;
  #violation: Violation | null = null;

  constructor(
    adapter: ApplicationAdapter,
    allowedOrigins: readonly string[],
    mode: GuardMode,
    onViolation: (violation: Violation) => void,
  ) {
    this.#adapter = adapter;
    this.#origins = new Set(allowedOrigins);
    this.#mode = mode;
    this.#onViolation = onViolation;
  }

  get violation(): Violation | null {
    return this.#violation;
  }

  setMode(mode: GuardMode): void {
    this.#mode = mode;
  }

  setLoginRequested(value: boolean): void {
    this.#loginRequested = value;
  }

  /** Judges a main-frame URL in the current mode. */
  check(url: string): Check {
    const blocked = (reason: NavigationBlockReason): Check => ({
      allowed: false,
      violation: new NavigationBlockedError(reason),
      code: reason,
    });
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      return blocked('unparseable_url');
    }
    if (!this.#origins.has(parsed.origin)) return blocked('origin_not_allowed');
    const base = isNavigationAllowed(this.#adapter, null, url);
    if (!base.allowed) return blocked(base.reason);
    if (this.#mode.kind === 'login') return { allowed: true };

    const loginPath = this.#adapter.loginPath;
    if (loginPath !== undefined && parsed.pathname === loginPath && !this.#loginRequested) {
      return { allowed: false, violation: new ReauthRequiredError(), code: 'reauth' };
    }
    if (this.#mode.kind === 'session') {
      const paths = this.#adapter.sessionCheckPaths ?? [];
      const ok =
        paths.some((pattern) => matchesPathPattern(pattern, parsed.pathname)) ||
        (this.#loginRequested && parsed.pathname === loginPath);
      return ok ? { allowed: true } : blocked('path_not_allowed');
    }
    const decision = isNavigationAllowed(this.#adapter, this.#mode.operation, url);
    return decision.allowed ? { allowed: true } : blocked(decision.reason);
  }

  /** Sub-frames may load any path on an allowed origin, nothing else. */
  checkSubFrame(url: string): boolean {
    try {
      if (!this.#origins.has(new URL(url).origin)) return false;
    } catch {
      return false;
    }
    return isNavigationAllowed(this.#adapter, null, url).allowed;
  }

  /** Records the first violation and notifies the job. Login mode only blocks. */
  record(check: Check & { allowed: false }): void {
    if (check.violation instanceof ReauthRequiredError) diag('reauth_detected');
    else diag('navigation_blocked', { code: check.code });
    if (this.#mode.kind === 'login' || this.#violation !== null) return;
    this.#violation = check.violation;
    this.#onViolation(check.violation);
  }

  async install(page: Page, cdp: CDPSession): Promise<void> {
    cdp.on('Page.frameAttached', (event: { frameId: string }) => {
      this.#subFrames.add(event.frameId);
    });
    cdp.on('Page.frameDetached', (event: { frameId: string }) => {
      this.#subFrames.delete(event.frameId);
    });
    cdp.on('Page.frameNavigated', (event: { frame: { id: string; parentId?: string } }) => {
      if (event.frame.parentId === undefined) this.#mainFrameId = event.frame.id;
      else this.#subFrames.add(event.frame.id);
    });
    cdp.on('Fetch.requestPaused', (event: FetchPausedEvent) => {
      void this.#onPaused(cdp, event);
    });
    await cdp.send('Page.enable');
    const tree = (await cdp.send('Page.getFrameTree')) as { frameTree: { frame: { id: string } } };
    this.#mainFrameId = tree.frameTree.frame.id;
    await cdp.send('Fetch.enable', {
      patterns: [{ urlPattern: '*', resourceType: 'Document', requestStage: 'Request' }],
    });

    page.on('framenavigated', (frame) => {
      if (frame !== page.mainFrame()) return;
      const url = frame.url();
      if (url === 'about:blank' || url.startsWith('chrome-error://')) return;
      const check = this.check(url);
      if (!check.allowed) this.record(check);
    });
  }

  async #onPaused(cdp: CDPSession, event: FetchPausedEvent): Promise<void> {
    const url = event.request.url;
    // A frame we have not seen attach is treated as the main frame: the stricter rule.
    const isSubFrame = event.frameId !== this.#mainFrameId && this.#subFrames.has(event.frameId);
    let allow: boolean;
    if (isSubFrame) {
      allow = this.checkSubFrame(url);
      if (!allow) diag('subframe_blocked');
    } else {
      const check = this.check(url);
      allow = check.allowed;
      if (!check.allowed) this.record(check);
    }
    try {
      if (allow) await cdp.send('Fetch.continueRequest', { requestId: event.requestId });
      else
        await cdp.send('Fetch.failRequest', {
          requestId: event.requestId,
          errorReason: 'BlockedByClient',
        });
    } catch {
      // The page or the request went away.
    }
  }
}

/**
 * Closes every page except the first one (ours, created right after this is installed and
 * before anything has loaded), as soon as it appears.
 */
export function closePopups(context: BrowserContext): void {
  let first = true;
  context.on('page', (page) => {
    if (first) {
      first = false;
      return;
    }
    diag('popup_closed');
    void page.close().catch(() => undefined);
  });
}

/** A diagnostic code for a failed Playwright call: an error class, never its message text. */
function classifyActionError(error: unknown): string {
  if (!(error instanceof Error)) return 'unknown';
  if (error.name === 'TimeoutError') return 'timeout';
  const net = /net::(ERR_[A-Z_]{1,40})/.exec(error.message);
  if (net?.[1] !== undefined) return net[1].toLowerCase();
  if (/closed/i.test(error.message)) return 'target_closed';
  return 'other';
}

function clip(text: string | null, budget: { left: number }): string | null {
  if (text === null) return null;
  const max = Math.min(MAX_TEXT_CHARS, Math.max(0, budget.left));
  const result = text.length > max ? text.slice(0, max) : text;
  budget.left -= result.length;
  return result;
}

function checkSelector(selector: unknown): string {
  if (typeof selector !== 'string' || selector === '' || selector.length > MAX_SELECTOR_LENGTH) {
    throw new BrowserActionError();
  }
  return selector;
}

export interface FacadeOptions {
  readonly page: Page;
  readonly guard: NavigationGuard;
  readonly adapter: ApplicationAdapter;
  /** The job's primary allowed origin; `goto` paths are resolved against it. */
  readonly origin: string;
  readonly signal: AbortSignal;
  /** Milliseconds left in the job, for action timeouts. */
  readonly remainingMs: () => number;
}

/**
 * The `BrowserSession` given to adapters. No evaluate, no arbitrary URL, no cookie or storage
 * access, no page object. Every read is bounded.
 */
export function createBrowserSession(options: FacadeOptions): BrowserSession {
  const { page, guard, adapter, origin, signal } = options;

  const stopIfNeeded = (): void => {
    if (guard.violation !== null) throw guard.violation;
    if (signal.aborted) throw new JobStoppedError();
  };
  const timeout = (wanted = 30_000): number =>
    Math.max(1, Math.min(wanted, options.remainingMs(), 60_000));

  async function act<T>(action: () => Promise<T>): Promise<T> {
    stopIfNeeded();
    try {
      const result = await action();
      stopIfNeeded();
      return result;
    } catch (error) {
      stopIfNeeded();
      if (error instanceof NavigationBlockedError || error instanceof ReauthRequiredError) {
        throw error;
      }
      diag('browser_action_failed', { code: classifyActionError(error) });
      throw new BrowserActionError();
    }
  }

  return {
    async goto(path: string): Promise<void> {
      stopIfNeeded();
      if (
        typeof path !== 'string' ||
        !path.startsWith('/') ||
        path.startsWith('//') ||
        path.length > MAX_PATH_LENGTH
      ) {
        throw new NavigationBlockedError('non_canonical_url');
      }
      const url = `${origin}${path}`;
      const pathname = path.split(/[?#]/, 1)[0];
      const requestsLogin = adapter.loginPath !== undefined && pathname === adapter.loginPath;
      guard.setLoginRequested(requestsLogin);
      try {
        const check = guard.check(url);
        if (!check.allowed) {
          guard.record(check);
          throw check.violation;
        }
        await act(async () => {
          await page.goto(url, { waitUntil: 'load', timeout: timeout() });
        });
      } finally {
        guard.setLoginRequested(false);
      }
    },

    currentUrl(): string {
      return page.url();
    },

    async text(selector: string): Promise<string | null> {
      const locator = page.locator(checkSelector(selector));
      return act(async () => {
        if ((await locator.count()) === 0) return null;
        const text = await locator.first().textContent({ timeout: timeout(5_000) });
        return clip(text, { left: MAX_TEXT_CHARS });
      });
    },

    async texts(selector: string): Promise<string[]> {
      const locator = page.locator(checkSelector(selector));
      return act(async () => {
        const count = await locator.count();
        if (count > MAX_ELEMENTS) throw new BrowserActionError();
        const all = await locator.allTextContents();
        const budget = { left: MAX_TOTAL_TEXT_CHARS };
        return all.map((text) => clip(text, budget) ?? '');
      });
    },

    async attribute(selector: string, name: string): Promise<string | null> {
      const locator = page.locator(checkSelector(selector));
      if (typeof name !== 'string' || !ATTRIBUTE_NAME.test(name)) throw new BrowserActionError();
      return act(async () => {
        if ((await locator.count()) === 0) return null;
        const value = await locator.first().getAttribute(name, { timeout: timeout(5_000) });
        return clip(value, { left: MAX_TEXT_CHARS });
      });
    },

    async rows(rowSelector: string, fieldAttribute: string): Promise<Record<string, string>[]> {
      const rowsLocator = page.locator(checkSelector(rowSelector));
      if (typeof fieldAttribute !== 'string' || !ATTRIBUTE_NAME.test(fieldAttribute)) {
        throw new BrowserActionError();
      }
      return act(async () => {
        const count = await rowsLocator.count();
        if (count > MAX_ELEMENTS) throw new BrowserActionError();
        const budget = { left: MAX_TOTAL_TEXT_CHARS };
        const result: Record<string, string>[] = [];
        for (let index = 0; index < count; index += 1) {
          const fields = rowsLocator.nth(index).locator(`[${fieldAttribute}]`);
          const fieldCount = await fields.count();
          if (fieldCount > 100) throw new BrowserActionError();
          const record: Record<string, string> = Object.create(null) as Record<string, string>;
          for (let field = 0; field < fieldCount; field += 1) {
            const element = fields.nth(field);
            const key = await element.getAttribute(fieldAttribute, { timeout: timeout(5_000) });
            if (key === null || key.length > 128 || Object.hasOwn(record, key)) continue;
            if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
            record[key] =
              clip(await element.textContent({ timeout: timeout(5_000) }), budget) ?? '';
          }
          result.push({ ...record });
        }
        return result;
      });
    },

    async fill(selector: string, value: string): Promise<void> {
      const locator = page.locator(checkSelector(selector));
      if (typeof value !== 'string' || value.length > MAX_TEXT_CHARS) {
        throw new BrowserActionError();
      }
      await act(() => locator.first().fill(value, { timeout: timeout(10_000) }));
    },

    async click(selector: string): Promise<void> {
      const locator = page.locator(checkSelector(selector));
      await act(() => locator.first().click({ timeout: timeout(10_000) }));
    },

    async waitFor(selector: string, waitOptions?: { readonly timeoutMs?: number }): Promise<void> {
      const locator = page.locator(checkSelector(selector));
      await act(() =>
        locator.first().waitFor({ state: 'visible', timeout: timeout(waitOptions?.timeoutMs) }),
      );
    },
  };
}
