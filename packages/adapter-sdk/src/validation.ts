import { canonicalJson, checkPlainJson, JsonObject } from '@aab/contracts';
import type { z } from 'zod';
import { AdapterContractError, OperationInputError } from './errors.js';
import { findUndeclaredOutput } from './schema-shape.js';
import type { FieldIssue } from './errors.js';
import type {
  ApplicationAdapter,
  ObjectSchema,
  OperationDefinition,
  ValidatedOperation,
} from './types.js';

export type InputValidationResult =
  | { readonly ok: true; readonly operation: ValidatedOperation }
  | { readonly ok: false; readonly error: OperationInputError };

const SAFE_PATH_SEGMENT = /^[A-Za-z0-9_-]{1,64}$/;

/** Fixed wording per issue kind, so that nothing an agent or a page submitted is echoed. */
const ISSUE_MESSAGES: Readonly<Record<string, string>> = {
  invalid_type: 'is missing or has the wrong type',
  too_big: 'is too large or too long',
  too_small: 'is too small or too short',
  invalid_format: 'has an invalid format',
  invalid_value: 'is not one of the allowed values',
  not_multiple_of: 'is not an allowed multiple',
  unrecognized_keys: 'contains fields that are not accepted',
};

function describeIssues(issues: readonly z.core.$ZodIssue[]): FieldIssue[] {
  return issues.map((issue) => {
    // Path segments normally come from the schema. A segment that does not look like an
    // identifier or index could be submitted data (a record key), so it is masked.
    const segments = issue.path.map((segment) => {
      if (typeof segment === 'number') return String(segment);
      return typeof segment === 'string' && SAFE_PATH_SEGMENT.test(segment) ? segment : '?';
    });
    return {
      path: segments.length === 0 ? '(root)' : segments.join('.'),
      message: ISSUE_MESSAGES[issue.code] ?? 'is invalid',
    };
  });
}

function summarize(issues: readonly FieldIssue[]): string {
  return issues.map((issue) => `${issue.path} ${issue.message}`).join('; ');
}

type JsonParseResult =
  | { readonly ok: true; readonly data: JsonObject }
  | { readonly ok: false; readonly issues: FieldIssue[] };

/** Parses with the operation schema, then confirms the result is plain JSON. */
function parseAsJson(schema: ObjectSchema, value: unknown): JsonParseResult {
  const parsed = schema.safeParse(value);
  if (!parsed.success) return { ok: false, issues: describeIssues(parsed.error.issues) };
  const json = JsonObject.safeParse(parsed.data);
  if (!json.success) return { ok: false, issues: describeIssues(json.error.issues) };
  return { ok: true, data: json.data };
}

function findOperation(
  adapter: ApplicationAdapter,
  operationName: string,
): OperationDefinition | undefined {
  return Object.hasOwn(adapter.operations, operationName)
    ? adapter.operations[operationName]
    : undefined;
}

function invalidArguments(
  definition: OperationDefinition,
  issues: FieldIssue[],
): OperationInputError {
  return new OperationInputError(
    'invalid_arguments',
    `invalid arguments for "${definition.name}": ${summarize(issues)}`,
    issues,
  );
}

/** Whether two values serialise to the same canonical JSON. Non-JSON input is never equal. */
function sameCanonicalJson(a: unknown, b: unknown): boolean {
  try {
    return canonicalJson(a) === canonicalJson(b);
  } catch {
    return false;
  }
}

/**
 * Validates arguments submitted for an operation. Parsing is strict: unknown keys are rejected
 * rather than dropped. Errors list field paths and a fixed description; submitted values and
 * unknown key names are never included.
 *
 * Validation is non-transforming (threat model F-3): policy is evaluated on the submitted
 * arguments, so the adapter must execute exactly those. The raw arguments must be plain JSON
 * without forbidden keys, and the parsed value must be canonically identical to them; a schema
 * that trims, lowercases, coerces, defaults or strips makes the call fail instead.
 */
export function validateOperationInput(
  adapter: ApplicationAdapter,
  operationName: string,
  args: unknown,
): InputValidationResult {
  const definition = findOperation(adapter, operationName);
  if (definition === undefined) {
    return {
      ok: false,
      error: new OperationInputError(
        'unknown_operation',
        `adapter "${adapter.id}" has no such operation`,
      ),
    };
  }

  if (checkPlainJson(args) !== null) {
    return {
      ok: false,
      error: invalidArguments(definition, [
        { path: '(root)', message: 'must be plain JSON without forbidden keys' },
      ]),
    };
  }

  const parsed = parseAsJson(definition.input.strict(), args);
  if (!parsed.ok) {
    return { ok: false, error: invalidArguments(definition, parsed.issues) };
  }

  if (!sameCanonicalJson(args, parsed.data)) {
    return {
      ok: false,
      error: invalidArguments(definition, [
        { path: '(root)', message: 'must be supplied in canonical form' },
      ]),
    };
  }

  const operation = Object.freeze({
    adapterId: adapter.id,
    adapterVersion: adapter.version,
    name: definition.name,
    arguments: parsed.data,
  }) as ValidatedOperation;
  return { ok: true, operation };
}

/**
 * The single gate between worker-internal data and agent-visible results. Parses `raw` with
 * the operation's output schema: fields the schema does not declare are dropped, and output
 * that does not satisfy the schema is a contract failure, never passed through as-is.
 *
 * Throws AdapterContractError.
 */
export function sanitizeOperationOutput(
  adapter: ApplicationAdapter,
  operationName: string,
  raw: unknown,
): JsonObject {
  const definition = findOperation(adapter, operationName);
  if (definition === undefined) {
    throw new AdapterContractError(`adapter "${adapter.id}" has no such operation`);
  }

  const parsed = parseAsJson(definition.output.strip(), raw);
  if (!parsed.ok) {
    const issues = parsed.issues;
    throw new AdapterContractError(
      `output of "${definition.name}" does not match its declared schema: ${summarize(issues)}`,
      issues,
    );
  }
  // Second, independent guarantee (F-1): even if a schema shape slipped past the definition
  // check, no key the schema does not declare may reach the agent.
  const undeclaredAt = findUndeclaredOutput(definition.output, parsed.data, 'output');
  if (undeclaredAt !== null) {
    throw new AdapterContractError(
      `output of "${definition.name}" contains data its schema does not declare under ${undeclaredAt}`,
    );
  }
  return parsed.data;
}
