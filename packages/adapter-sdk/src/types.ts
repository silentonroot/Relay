import type { AuthMode, JsonObject, OperationSensitivity } from '@aab/contracts';
import type { z } from 'zod';

/** Any Zod object schema, whatever its shape or unknown-key behavior. */
export type ObjectSchema = z.ZodObject<z.core.$ZodShape, z.core.$ZodObjectConfig>;

/**
 * One operation an adapter offers. Everything the broker needs to authorize, bound and
 * sanitize a call is declared here, so the policy engine never has to read adapter code.
 */
export interface OperationDefinition<
  Input extends ObjectSchema = ObjectSchema,
  Output extends ObjectSchema = ObjectSchema,
> {
  /** Dotted name such as `orders.list`; must equal the key it is registered under. */
  readonly name: string;
  readonly description: string;
  /** Arguments an agent may submit. Parsed strictly: unknown keys are rejected. */
  readonly input: Input;
  /** The only fields that may ever reach an agent. Anything else is dropped. */
  readonly output: Output;
  readonly sensitivity: OperationSensitivity;
  /** When true the operation needs human approval whatever the grant says. */
  readonly requiresApproval: boolean;
  /** Whether repeating the call with the same arguments is safe. */
  readonly idempotent: boolean;
  /** What the operation changes in the target application. Empty for reads. */
  readonly sideEffects: readonly string[];
  readonly timeoutMs: number;
  /**
   * URL paths this operation may visit, as path patterns: `/orders`, `/orders/:orderId`.
   * A `:name` segment matches exactly one unreserved path segment. Query strings are not
   * part of the pattern.
   */
  readonly allowedPaths: readonly string[];
  /** Input key that identifies the target resource, if the operation has one. */
  readonly resourceArgument?: string;
  /** Input key that bounds the result size, if the operation has one. */
  readonly limitArgument?: string;
}

export type OperationMap = Readonly<Record<string, OperationDefinition>>;

export interface AdapterLogFields {
  readonly [key: string]: string | number | boolean | null;
}

/** Minimal structured logger. Fields must never carry page content, cookies or credentials. */
export interface AdapterLogger {
  debug(message: string, fields?: AdapterLogFields): void;
  info(message: string, fields?: AdapterLogFields): void;
  warn(message: string, fields?: AdapterLogFields): void;
  error(message: string, fields?: AdapterLogFields): void;
}

/**
 * The only way adapter code touches a page. The worker implements it and applies the
 * navigation guard to every `goto` and every redirect hop.
 *
 * Deliberately absent: script evaluation, navigation to arbitrary URLs, cookie or storage
 * access, network interception, and the underlying page object.
 */
export interface BrowserSession {
  /** Navigates to a path (plus optional query) on the connection's own origin. */
  goto(path: string): Promise<void>;
  currentUrl(): string;
  /** Text of the first matching element, or null when nothing matches. */
  text(selector: string): Promise<string | null>;
  /** Text of every matching element, in document order. */
  texts(selector: string): Promise<string[]>;
  attribute(selector: string, name: string): Promise<string | null>;
  /**
   * For each element matching `rowSelector`, the text of its descendants that carry
   * `fieldAttribute`, keyed by that attribute's value. Used to read tables.
   */
  rows(rowSelector: string, fieldAttribute: string): Promise<Record<string, string>[]>;
  fill(selector: string, value: string): Promise<void>;
  click(selector: string): Promise<void>;
  waitFor(selector: string, options?: { readonly timeoutMs?: number }): Promise<void>;
}

/** What the worker hands an adapter for one job on one connection. */
export interface WorkerContext {
  readonly connectionId: string;
  /** Aborted on cancellation, timeout or revocation of the connection. */
  readonly signal: AbortSignal;
  readonly logger: AdapterLogger;
  readonly browser: BrowserSession;
}

export interface SessionHealth {
  readonly state: 'active' | 'degraded' | 'expired';
  /** Non-secret label of the signed-in account, used to confirm the session's identity. */
  readonly externalAccountHint?: string;
}

declare const validatedOperationBrand: unique symbol;

/**
 * Arguments that passed `validateOperationInput`. The brand keeps hand-built objects from
 * being passed to `execute`.
 */
export interface ValidatedOperation {
  readonly [validatedOperationBrand]: true;
  readonly adapterId: string;
  readonly adapterVersion: string;
  readonly name: string;
  readonly arguments: JsonObject;
}

/** The agent-visible result of an operation. `data` has passed `sanitizeOperationOutput`. */
export type SanitizedResult =
  | { readonly status: 'succeeded'; readonly data: JsonObject }
  | {
      readonly status: 'failed';
      readonly error: { readonly code: string; readonly message: string };
    }
  | { readonly status: 'reauth_required' }
  | { readonly status: 'outcome_unknown' };

export interface ApplicationAdapter<Operations extends OperationMap = OperationMap> {
  readonly id: string;
  readonly version: string;
  readonly displayName: string;
  /** Exact origins the adapter may navigate to. No wildcards. */
  readonly allowedOrigins: readonly string[];
  readonly authMode: AuthMode;
  /**
   * Path of the application's sign-in page, as a literal path with no placeholders. The login
   * handoff opens it, and a navigation that ends there during a job means the session expired:
   * the browser facade raises `ReauthRequiredError`. Required for `browser_session` adapters
   * that implement `checkSession` or `execute`.
   */
  readonly loginPath?: string;
  /** Path patterns `checkSession` may visit, in the same syntax as an operation's `allowedPaths`. */
  readonly sessionCheckPaths?: readonly string[];
  readonly operations: Operations;
  /*
   * `checkSession` and `execute` are optional for now so that a manifest-only adapter can be
   * registered, granted and policy-checked before the browser worker exists. An adapter
   * without `execute` cannot run operations; the worker must refuse it.
   */
  /** Must be side-effect free in the target application (spec §5.2). */
  checkSession?(ctx: WorkerContext): Promise<SessionHealth>;
  execute?(ctx: WorkerContext, operation: ValidatedOperation): Promise<SanitizedResult>;
}
