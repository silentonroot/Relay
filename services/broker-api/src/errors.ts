import type { ErrorCode, ErrorResponse } from '@aab/contracts';
import { RepositoryError } from '@aab/database';
import type { FastifyError, FastifyReply, FastifyRequest } from 'fastify';
import { hasZodFastifySchemaValidationErrors } from 'fastify-type-provider-zod';

export interface ErrorDetail {
  path: string;
  message: string;
}

/** An expected failure with a fixed, client-safe message. */
export class AppError extends Error {
  constructor(
    readonly statusCode: number,
    readonly code: ErrorCode,
    message: string,
    readonly details?: readonly ErrorDetail[],
  ) {
    super(message);
    this.name = 'AppError';
  }
}

export const unauthenticated = () =>
  new AppError(401, 'unauthenticated', 'Authentication is required.');
export const notFound = () =>
  new AppError(404, 'not_found', 'The requested resource was not found.');
export const conflict = (message: string) => new AppError(409, 'conflict', message);

const STATUS_DEFAULTS: Record<number, { code: ErrorCode; message: string }> = {
  400: { code: 'validation_failed', message: 'The request is invalid.' },
  401: { code: 'unauthenticated', message: 'Authentication is required.' },
  403: { code: 'forbidden', message: 'This action is not allowed.' },
  404: { code: 'not_found', message: 'The requested resource was not found.' },
  405: { code: 'not_found', message: 'The requested resource was not found.' },
  409: { code: 'conflict', message: 'The request conflicts with the current state.' },
  413: { code: 'validation_failed', message: 'The request body is too large.' },
  415: { code: 'validation_failed', message: 'Unsupported content type; send application/json.' },
  429: { code: 'rate_limited', message: 'Too many requests. Try again later.' },
  503: { code: 'service_unavailable', message: 'The service is temporarily unavailable.' },
};

const INTERNAL = { code: 'internal_error' as const, message: 'An unexpected error occurred.' };

export function errorBody(
  requestId: string,
  code: ErrorCode,
  message: string,
  details?: readonly ErrorDetail[],
): ErrorResponse {
  const error: ErrorResponse['error'] = { code, message, requestId };
  if (details !== undefined && details.length > 0) error.details = [...details];
  return { error };
}

interface Mapped {
  statusCode: number;
  code: ErrorCode;
  message: string;
  details?: readonly ErrorDetail[];
}

const CONTEXT_PREFIX: Record<string, string> = { querystring: 'query', params: 'params' };

/**
 * Validation details carry the field path and the schema's message only. Zod messages
 * describe the expectation ("Too big: expected ..."), never the submitted value, and the
 * issue's other properties (which may include the input) are deliberately dropped.
 */
function validationDetails(
  error: FastifyError & { validation: { instancePath: string; message?: string }[] },
): ErrorDetail[] {
  const prefix = CONTEXT_PREFIX[error.validationContext ?? ''];
  return error.validation.map((issue) => {
    const path = issue.instancePath.replace(/^\//, '').split('/').filter(Boolean).join('.');
    const full = prefix === undefined ? path : path === '' ? prefix : `${prefix}.${path}`;
    return {
      path: full === '' ? (error.validationContext ?? 'body') : full,
      message: issue.message ?? 'invalid',
    };
  });
}

/** Turns anything thrown during a request into a status and a client-safe error. */
export function mapError(error: unknown): Mapped {
  if (error instanceof AppError) {
    return {
      statusCode: error.statusCode,
      code: error.code,
      message: error.message,
      ...(error.details === undefined ? {} : { details: error.details }),
    };
  }

  if (hasZodFastifySchemaValidationErrors(error)) {
    return {
      statusCode: 400,
      code: 'validation_failed',
      message: 'The request is invalid.',
      details: validationDetails(error),
    };
  }

  if (error instanceof RepositoryError) {
    switch (error.code) {
      case 'not_found':
        // Same response for "missing" and "belongs to someone else".
        return { statusCode: 404, ...STATUS_DEFAULTS[404]! };
      case 'conflict':
      case 'invalid_transition':
        // Repository messages describe the rule ("connection is revoked"), never row contents.
        return { statusCode: 409, code: 'conflict', message: error.message };
      case 'validation_failed': {
        const issues = (error as RepositoryError & { issues?: readonly ErrorDetail[] }).issues;
        return {
          statusCode: 400,
          code: 'validation_failed',
          message: 'The request is invalid.',
          ...(issues === undefined ? {} : { details: issues }),
        };
      }
    }
  }

  // Framework errors (malformed JSON, body too large, rate limit, ...) carry a 4xx status.
  // Their own messages can quote the submitted body, so only fixed messages are used.
  const statusCode =
    typeof error === 'object' && error !== null && 'statusCode' in error
      ? Number((error as { statusCode: unknown }).statusCode)
      : 500;
  if (statusCode >= 400 && statusCode < 500) {
    const known = STATUS_DEFAULTS[statusCode] ?? STATUS_DEFAULTS[400]!;
    return { statusCode: STATUS_DEFAULTS[statusCode] === undefined ? 400 : statusCode, ...known };
  }
  return { statusCode: 500, ...INTERNAL };
}

export function sendError(request: FastifyRequest, reply: FastifyReply, error: unknown) {
  const mapped = mapError(error);
  if (mapped.statusCode >= 500) {
    request.log.error({ err: error }, 'request failed');
  } else {
    request.log.info({ errorCode: mapped.code, statusCode: mapped.statusCode }, 'request rejected');
  }
  return reply
    .code(mapped.statusCode)
    .type('application/json; charset=utf-8')
    .send(errorBody(request.id, mapped.code, mapped.message, mapped.details));
}
