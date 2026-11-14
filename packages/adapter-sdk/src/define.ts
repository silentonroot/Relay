import {
  AdapterId,
  AuthMode,
  DisplayName,
  OperationName,
  OperationSensitivity,
  Origin,
  SemVer,
} from '@aab/contracts';
import type { OperationDescriptor } from '@aab/contracts';
import { AdapterContractError } from './errors.js';
import { isValidPathPattern } from './paths.js';
import { findDisallowedSchemaNode } from './schema-shape.js';
import type { SchemaRole } from './schema-shape.js';
import type {
  ApplicationAdapter,
  ObjectSchema,
  OperationDefinition,
  OperationMap,
} from './types.js';

export const MIN_OPERATION_TIMEOUT_MS = 1_000;
export const MAX_OPERATION_TIMEOUT_MS = 120_000;

const definedAdapters = new WeakSet<object>();

/** Whether a value was produced, and therefore validated, by `defineAdapter`. */
export function isDefinedAdapter(value: unknown): value is ApplicationAdapter {
  return typeof value === 'object' && value !== null && definedAdapters.has(value);
}

function fail(subject: string, problem: string): never {
  throw new AdapterContractError(`invalid adapter definition: ${subject} ${problem}`);
}

function isObjectSchema(value: unknown): value is ObjectSchema {
  if (typeof value !== 'object' || value === null) return false;
  const def = (value as { def?: { type?: unknown } }).def;
  return def?.type === 'object';
}

/**
 * Output schemas must drop every undeclared field (F-1) and input schemas must not rewrite the
 * arguments policy judged (F-3), so both are limited to an allowlist of node kinds.
 */
function checkSchemaShape(subject: string, schema: unknown, role: SchemaRole): void {
  const problem = findDisallowedSchemaNode(schema, role);
  if (problem === null) return;
  if (problem.kind === 'loose object') {
    fail(subject, `has an ${role} schema that passes undeclared fields through at ${problem.path}`);
  }
  fail(
    subject,
    `has an ${role} schema with a disallowed node at ${problem.path}: ${problem.kind} ` +
      (role === 'output'
        ? '(output schemas may only use closed objects, arrays, tuples, primitives, literals, enums, optional, nullable and unions)'
        : '(input schemas must validate without transforming, defaulting or coercing)'),
  );
}

function validateOperation(definition: OperationDefinition): void {
  const subject = `operation "${String(definition.name)}"`;

  if (!OperationName.safeParse(definition.name).success) {
    fail(subject, 'needs a dotted name such as "orders.list"');
  }
  if (typeof definition.description !== 'string' || definition.description.trim() === '') {
    fail(subject, 'needs a description');
  }
  if (!isObjectSchema(definition.input) || !isObjectSchema(definition.output)) {
    fail(subject, 'needs Zod object schemas for input and output');
  }
  checkSchemaShape(subject, definition.output, 'output');
  checkSchemaShape(subject, definition.input, 'input');
  if (!OperationSensitivity.safeParse(definition.sensitivity).success) {
    fail(subject, 'has an unknown sensitivity');
  }
  if (
    typeof definition.requiresApproval !== 'boolean' ||
    typeof definition.idempotent !== 'boolean'
  ) {
    fail(subject, 'needs boolean requiresApproval and idempotent');
  }
  if (
    !Number.isInteger(definition.timeoutMs) ||
    definition.timeoutMs < MIN_OPERATION_TIMEOUT_MS ||
    definition.timeoutMs > MAX_OPERATION_TIMEOUT_MS
  ) {
    fail(
      subject,
      `needs a timeout between ${MIN_OPERATION_TIMEOUT_MS} and ${MAX_OPERATION_TIMEOUT_MS} ms`,
    );
  }

  if (
    !Array.isArray(definition.sideEffects) ||
    definition.sideEffects.some((effect) => typeof effect !== 'string' || effect.trim() === '')
  ) {
    fail(subject, 'needs sideEffects to be a list of non-empty strings');
  }
  if (definition.sensitivity === 'read' && definition.sideEffects.length > 0) {
    fail(subject, 'is a read and must not list side effects');
  }
  if (definition.sensitivity !== 'read' && definition.sideEffects.length === 0) {
    fail(
      subject,
      definition.idempotent
        ? 'is declared idempotent but lists no side effects; a write must state what it changes'
        : 'changes the target application and must list its side effects',
    );
  }
  if (definition.sensitivity === 'destructive' && !definition.requiresApproval) {
    fail(subject, 'is destructive and must require approval');
  }

  if (!Array.isArray(definition.allowedPaths) || definition.allowedPaths.length === 0) {
    fail(subject, 'needs at least one allowed path');
  }
  for (const pattern of definition.allowedPaths) {
    if (typeof pattern !== 'string' || !isValidPathPattern(pattern)) {
      fail(subject, 'has an allowed path that is not a pattern such as "/orders/:orderId"');
    }
  }

  const inputKeys = Object.keys(definition.input.shape);
  for (const field of ['resourceArgument', 'limitArgument'] as const) {
    const argument = definition[field];
    if (argument !== undefined && !inputKeys.includes(argument)) {
      fail(subject, `names a ${field} that is not a key of its input schema`);
    }
  }
}

function freezeOperation<Definition extends OperationDefinition>(
  definition: Definition,
): Definition {
  return Object.freeze({
    ...definition,
    sideEffects: Object.freeze([...definition.sideEffects]),
    allowedPaths: Object.freeze([...definition.allowedPaths]),
  });
}

/** Validates one operation definition and returns a frozen copy. Throws AdapterContractError. */
export function defineOperation<Input extends ObjectSchema, Output extends ObjectSchema>(
  definition: OperationDefinition<Input, Output>,
): OperationDefinition<Input, Output> {
  validateOperation(definition);
  return freezeOperation(definition);
}

/**
 * Validates a whole adapter and returns a deeply frozen copy. Only adapters returned from
 * here are accepted by `AdapterRegistry`. Throws AdapterContractError.
 */
export function defineAdapter<Operations extends OperationMap>(
  definition: ApplicationAdapter<Operations>,
): ApplicationAdapter<Operations> {
  if (!AdapterId.safeParse(definition.id).success) {
    fail('adapter', 'needs an id of lowercase letters, digits and dashes');
  }
  const subject = `adapter "${definition.id}"`;
  if (!SemVer.safeParse(definition.version).success) {
    fail(subject, 'needs a semantic version such as "1.2.3"');
  }
  if (!DisplayName.safeParse(definition.displayName).success) {
    fail(subject, 'needs a display name');
  }
  if (!AuthMode.safeParse(definition.authMode).success) {
    fail(subject, 'has an unknown authMode');
  }
  if (!Array.isArray(definition.allowedOrigins) || definition.allowedOrigins.length === 0) {
    fail(subject, 'needs at least one allowed origin');
  }
  for (const origin of definition.allowedOrigins) {
    if (!Origin.safeParse(origin).success) {
      fail(subject, 'has an allowed origin that is not an exact https (or loopback http) origin');
    }
  }
  if (new Set(definition.allowedOrigins).size !== definition.allowedOrigins.length) {
    fail(subject, 'lists the same allowed origin twice');
  }

  if (definition.loginPath !== undefined) {
    if (!isValidPathPattern(definition.loginPath) || definition.loginPath.includes(':')) {
      fail(subject, 'has a loginPath that is not a literal path such as "/login"');
    }
  }
  const sessionCheckPaths = definition.sessionCheckPaths ?? [];
  if (!Array.isArray(sessionCheckPaths) || !sessionCheckPaths.every(isValidPathPattern)) {
    fail(subject, 'has a sessionCheckPaths entry that is not a valid path pattern');
  }
  if (
    (definition.checkSession !== undefined || definition.execute !== undefined) &&
    definition.authMode === 'browser_session' &&
    definition.loginPath === undefined
  ) {
    fail(subject, 'implements checkSession or execute and so needs a loginPath');
  }
  if (definition.checkSession !== undefined && sessionCheckPaths.length === 0) {
    fail(subject, 'implements checkSession and so needs at least one sessionCheckPaths entry');
  }

  const entries = Object.entries(definition.operations ?? {});
  if (entries.length === 0) {
    fail(subject, 'needs at least one operation');
  }
  const operations: Record<string, OperationDefinition> = {};
  for (const [key, operation] of entries) {
    if (operation.name !== key) {
      fail(subject, `registers operation "${String(operation.name)}" under a different key`);
    }
    validateOperation(operation);
    operations[key] = freezeOperation(operation);
  }

  const adapter = Object.freeze({
    ...definition,
    allowedOrigins: Object.freeze([...definition.allowedOrigins]),
    ...(definition.sessionCheckPaths === undefined
      ? {}
      : { sessionCheckPaths: Object.freeze([...sessionCheckPaths]) }),
    operations: Object.freeze(operations) as Operations,
  });
  definedAdapters.add(adapter);
  return adapter;
}

/** The operation metadata the policy engine consumes, one descriptor per operation. */
export function toOperationDescriptors(adapter: ApplicationAdapter): OperationDescriptor[] {
  return Object.values(adapter.operations).map((operation) => ({
    name: operation.name,
    sensitivity: operation.sensitivity,
    requiresApproval: operation.requiresApproval,
    ...(operation.resourceArgument === undefined
      ? {}
      : { resourceArgument: operation.resourceArgument }),
    ...(operation.limitArgument === undefined ? {} : { limitArgument: operation.limitArgument }),
  }));
}
