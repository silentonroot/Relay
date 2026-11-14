import { CreateGrantRequest, ExecuteOperationRequest } from '@aab/contracts';
import type { GrantEffect } from '@aab/contracts';
import type { z } from 'zod';

export type FieldErrors = Record<string, string>;

/** First message per top-level field. Issues without a path land under `_form`. */
export function fieldErrors(error: z.ZodError): FieldErrors {
  const errors: FieldErrors = {};
  for (const issue of error.issues) {
    const head = issue.path[0];
    const key = typeof head === 'string' ? head : '_form';
    errors[key] ??= issue.message;
  }
  return errors;
}

export interface GrantFormValues {
  connectionId: string;
  operation: string;
  effect: GrantEffect;
  requireApproval: boolean;
  /** Raw text of the result-limit input. */
  maxResults: string;
  /** Resource ids separated by commas or new lines. */
  resourceIds: string;
  /** Optional JSON object with further constraints. */
  extraConstraints: string;
  /** Value of a `datetime-local` input, in the viewer's time zone. */
  expiresAt: string;
}

export const EMPTY_GRANT_FORM: GrantFormValues = {
  connectionId: '',
  operation: '',
  effect: 'allow',
  requireApproval: false,
  maxResults: '',
  resourceIds: '',
  extraConstraints: '',
  expiresAt: '',
};

export type GrantFormResult =
  { ok: true; request: CreateGrantRequest } | { ok: false; errors: FieldErrors };

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Turns the add-grant form into a CreateGrantRequest. The contracts schema has the last word,
 * so anything the policy engine would not understand (an unknown constraint key, a malformed
 * operation name) is refused here rather than stored and silently ignored.
 */
export function buildGrantRequest(
  values: GrantFormValues,
  now: Date = new Date(),
): GrantFormResult {
  const errors: FieldErrors = {};
  const constraints: Record<string, unknown> = {};

  if (values.connectionId === '') errors.connectionId = 'Choose a connection.';

  const extra = values.extraConstraints.trim();
  if (extra !== '') {
    let parsed: unknown;
    try {
      parsed = JSON.parse(extra) as unknown;
    } catch {
      parsed = undefined;
    }
    if (isPlainObject(parsed)) {
      Object.assign(constraints, parsed);
    } else {
      errors.extraConstraints =
        'Enter a JSON object, for example {"argumentEquals": {"status": "held"}}.';
    }
  }

  const maxResults = values.maxResults.trim();
  if (maxResults !== '') {
    if ('maxResults' in constraints) {
      errors.maxResults = 'Set the result limit here or in the JSON, not in both.';
    } else {
      constraints.maxResults = Number(maxResults);
    }
  }

  const resourceIds = values.resourceIds
    .split(/[\n,]/)
    .map((id) => id.trim())
    .filter((id) => id !== '');
  if (resourceIds.length > 0) {
    if ('resourceIds' in constraints) {
      errors.resourceIds = 'List resources here or in the JSON, not in both.';
    } else {
      constraints.resourceIds = resourceIds;
    }
  }

  let expiresAt: string | undefined;
  if (values.expiresAt !== '') {
    const date = new Date(values.expiresAt);
    if (Number.isNaN(date.getTime())) {
      errors.expiresAt = 'Enter a valid date and time.';
    } else if (date.getTime() <= now.getTime()) {
      errors.expiresAt = 'Choose a time in the future.';
    } else {
      expiresAt = date.toISOString();
    }
  }

  const parsed = CreateGrantRequest.safeParse({
    connectionId: values.connectionId,
    operation: values.operation.trim(),
    effect: values.effect,
    // A deny grant refuses the operation outright, so approval has no meaning for it.
    approvalMode: values.effect === 'allow' && values.requireApproval ? 'required' : 'none',
    constraints,
    ...(expiresAt === undefined ? {} : { expiresAt }),
  });

  if (!parsed.success) {
    for (const issue of parsed.error.issues) {
      const [head, second] = issue.path;
      let key = typeof head === 'string' ? head : '_form';
      if (head === 'constraints') {
        key = second === 'maxResults' || second === 'resourceIds' ? second : 'extraConstraints';
      }
      errors[key] ??= issue.message;
    }
  }

  if (!parsed.success || Object.keys(errors).length > 0) return { ok: false, errors };
  return { ok: true, request: parsed.data };
}

export interface RunFormValues {
  /** Id of the chosen grant, or empty. */
  grantId: string;
  /** Raw text of the arguments textarea. */
  argumentsJson: string;
}

export type RunFormResult =
  { ok: true; request: ExecuteOperationRequest } | { ok: false; errors: FieldErrors };

/**
 * Turns the "run an operation" form into an ExecuteOperationRequest. The arguments must be a
 * JSON object; a bare number, string, array or null is refused before anything is sent. The
 * idempotency key is passed in so each send can use a fresh one.
 */
export function buildExecuteRequest(
  values: RunFormValues,
  grant: { agentId: string; connectionId: string; operation: string } | undefined,
  idempotencyKey: string,
): RunFormResult {
  const errors: FieldErrors = {};
  if (grant === undefined) errors.grantId = 'Choose a grant.';

  const text = values.argumentsJson.trim();
  let parsed: unknown;
  if (text === '') {
    errors.arguments = 'Enter a JSON object, for example {} for no arguments.';
  } else {
    try {
      parsed = JSON.parse(text) as unknown;
    } catch {
      errors.arguments = 'This is not valid JSON.';
    }
    if (errors.arguments === undefined && !isPlainObject(parsed)) {
      errors.arguments =
        'Arguments must be a JSON object such as {"limit": 5}, not a list or a single value.';
    }
  }
  if (grant === undefined || errors.arguments !== undefined) return { ok: false, errors };

  const request = ExecuteOperationRequest.safeParse({
    agentId: grant.agentId,
    connectionId: grant.connectionId,
    operation: grant.operation,
    arguments: parsed,
    idempotencyKey,
  });
  if (!request.success) {
    for (const issue of request.error.issues) {
      const head = issue.path[0];
      const key = head === 'arguments' ? 'arguments' : '_form';
      errors[key] ??= issue.message;
    }
    return { ok: false, errors };
  }
  return { ok: true, request: request.data };
}
