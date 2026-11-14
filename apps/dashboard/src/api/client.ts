import { API_PREFIX, CSRF_HEADER, ErrorResponse, REQUEST_ID_HEADER } from '@aab/contracts';
import type { ErrorCode } from '@aab/contracts';
import type { z } from 'zod';

/** Failures that never reached, or never came back intact from, the broker API. */
export type ClientErrorCode = 'network_error' | 'timeout' | 'invalid_response';
export type ApiErrorCode = ErrorCode | ClientErrorCode;

export interface ApiErrorDetail {
  path: string;
  message: string;
}

interface ApiErrorInit {
  code: ApiErrorCode;
  message: string;
  status: number | null;
  requestId: string | null;
  details?: readonly ApiErrorDetail[];
}

export class ApiError extends Error {
  readonly code: ApiErrorCode;
  /** HTTP status, or null when no response arrived. */
  readonly status: number | null;
  /** Server request id, quoted to the user so a failure can be traced in the audit log. */
  readonly requestId: string | null;
  readonly details: readonly ApiErrorDetail[];

  constructor(init: ApiErrorInit) {
    super(init.message);
    this.name = 'ApiError';
    this.code = init.code;
    this.status = init.status;
    this.requestId = init.requestId;
    this.details = init.details ?? [];
  }
}

export function toApiError(error: unknown): ApiError {
  if (error instanceof ApiError) return error;
  return new ApiError({
    code: 'network_error',
    message: 'Something went wrong while talking to the broker API.',
    status: null,
    requestId: null,
  });
}

export type HttpMethod = 'GET' | 'POST' | 'DELETE';
export type QueryParams = Record<string, string | number | undefined>;

export interface RequestOptions<S extends z.ZodType | null> {
  method?: HttpMethod;
  /** Path relative to API_PREFIX, e.g. `/connections`. */
  path: string;
  query?: QueryParams;
  body?: unknown;
  /** Schema for the success body. `null` means the body is ignored. */
  schema: S;
  signal?: AbortSignal | undefined;
  /**
   * Set for the session probe and for login, where a 401 is an ordinary answer rather than
   * evidence that an established session was lost.
   */
  unauthenticatedIsExpected?: boolean;
}

export type ResponseOf<S extends z.ZodType | null> = S extends z.ZodType ? z.output<S> : void;

export interface ApiClientConfig {
  /** Returns the in-memory CSRF token, or null before sign-in. */
  getCsrfToken: () => string | null;
  /** Called when an established session is rejected by the API. */
  onUnauthenticated: () => void;
  /** Defaults to the global fetch, looked up per call. */
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
}

export interface ApiClient {
  request<S extends z.ZodType | null>(options: RequestOptions<S>): Promise<ResponseOf<S>>;
}

const DEFAULT_TIMEOUT_MS = 15_000;

function buildUrl(path: string, query: QueryParams | undefined): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query ?? {})) {
    if (value !== undefined && value !== '') params.set(key, String(value));
  }
  const search = params.toString();
  return `${API_PREFIX}${path}${search === '' ? '' : `?${search}`}`;
}

function parseJson(text: string): unknown {
  if (text === '') return undefined;
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return undefined;
  }
}

export function createApiClient(config: ApiClientConfig): ApiClient {
  const timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  async function request<S extends z.ZodType | null>(
    options: RequestOptions<S>,
  ): Promise<ResponseOf<S>> {
    const method = options.method ?? 'GET';
    const headers = new Headers({ accept: 'application/json' });

    // A JSON content type with an empty body is rejected by the API, so only declare one
    // when there is a body to send.
    let body: string | undefined;
    if (options.body !== undefined) {
      headers.set('content-type', 'application/json');
      body = JSON.stringify(options.body);
    }

    if (method !== 'GET') {
      const token = config.getCsrfToken();
      if (token !== null) headers.set(CSRF_HEADER, token);
    }

    const controller = new AbortController();
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, timeoutMs);
    const forwardAbort = () => controller.abort();
    if (options.signal?.aborted) controller.abort();
    options.signal?.addEventListener('abort', forwardAbort, { once: true });

    let response: Response;
    let text: string;
    try {
      const doFetch = config.fetchImpl ?? globalThis.fetch;
      const init: RequestInit = {
        method,
        headers,
        credentials: 'same-origin',
        cache: 'no-store',
        redirect: 'error',
        signal: controller.signal,
      };
      if (body !== undefined) init.body = body;
      response = await doFetch(buildUrl(options.path, options.query), init);
      text = await response.text();
    } catch (cause) {
      if (timedOut) {
        throw new ApiError({
          code: 'timeout',
          message: 'The broker API took too long to respond.',
          status: null,
          requestId: null,
        });
      }
      // The caller cancelled (for example a query that is no longer needed): not a failure.
      if (options.signal?.aborted) throw cause;
      throw new ApiError({
        code: 'network_error',
        message: 'The broker API could not be reached.',
        status: null,
        requestId: null,
      });
    } finally {
      clearTimeout(timer);
      options.signal?.removeEventListener('abort', forwardAbort);
    }

    const headerRequestId = response.headers.get(REQUEST_ID_HEADER);

    if (!response.ok) {
      const parsed = ErrorResponse.safeParse(parseJson(text));
      const error = parsed.success
        ? new ApiError({
            code: parsed.data.error.code,
            message: parsed.data.error.message,
            status: response.status,
            requestId: parsed.data.error.requestId,
            details: parsed.data.error.details ?? [],
          })
        : new ApiError({
            code: response.status === 401 ? 'unauthenticated' : 'invalid_response',
            message:
              response.status === 401
                ? 'You are not signed in.'
                : `The broker API returned an unexpected response (HTTP ${response.status}).`,
            status: response.status,
            requestId: headerRequestId,
          });
      if (error.code === 'unauthenticated' && options.unauthenticatedIsExpected !== true) {
        config.onUnauthenticated();
      }
      throw error;
    }

    if (options.schema === null) return undefined as ResponseOf<S>;

    // Data that does not match the contract is never rendered.
    const parsed = options.schema.safeParse(parseJson(text));
    if (!parsed.success) {
      throw new ApiError({
        code: 'invalid_response',
        message: 'The broker API returned data in an unexpected format.',
        status: response.status,
        requestId: headerRequestId,
      });
    }
    return parsed.data as ResponseOf<S>;
  }

  return { request };
}
