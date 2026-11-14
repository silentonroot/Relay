/**
 * Structural checks on operation schemas (threat model F-1, F-3).
 *
 * Output schemas are the gate between worker-internal data and what an agent sees, and input
 * schemas must not change what policy judged. Both are therefore restricted to an allowlist of
 * Zod node kinds that are known to neither let undeclared data through nor rewrite values.
 * Every kind and every check that is not listed here, including kinds a future Zod version
 * adds, is rejected: unknown means rejected.
 *
 * The walk reads Zod's public `def` objects structurally so that it never depends on class
 * identity, and it treats anything it cannot read as a rejection.
 */

export type SchemaRole = 'input' | 'output';

export interface SchemaShapeProblem {
  /** Path built from schema keys only, e.g. `output.orders[].customer`. */
  readonly path: string;
  /** The rejected node kind, check kind or `loose object`. */
  readonly kind: string;
}

type Def = Readonly<Record<string, unknown>>;

function defOf(schema: unknown): Def | undefined {
  if (typeof schema !== 'object' || schema === null) return undefined;
  const def: unknown = (schema as { def?: unknown }).def;
  return typeof def === 'object' && def !== null ? (def as Def) : undefined;
}

function kindOf(def: Def | undefined): string {
  const type = def?.['type'];
  return typeof type === 'string' ? type : 'unrecognised';
}

/** Checks (refinements) that only validate and can neither add nor rewrite data. */
const ALLOWED_CHECKS: Readonly<Record<string, ReadonlySet<string>>> = {
  string: new Set(['min_length', 'max_length', 'length_equals', 'string_format']),
  number: new Set(['greater_than', 'less_than', 'multiple_of', 'number_format']),
  array: new Set(['min_length', 'max_length', 'length_equals']),
};

function checkKind(check: unknown): string {
  const zod: unknown = (check as { _zod?: unknown } | null)?._zod;
  const def = defOf(zod);
  const kind = def?.['check'];
  return typeof kind === 'string' ? kind : 'unrecognised';
}

/** The first check on a node that is not allowlisted for its kind, or null. */
function findDisallowedCheck(def: Def, kind: string): string | null {
  const checks = def['checks'];
  if (checks === undefined) return null;
  if (!Array.isArray(checks)) return 'unrecognised check';
  const allowed = ALLOWED_CHECKS[kind] ?? new Set<string>();
  for (const check of checks) {
    const name = checkKind(check);
    if (!allowed.has(name)) return `${name} check`;
  }
  return null;
}

/** Leaf kinds that hold a single JSON primitive. */
const PRIMITIVE_KINDS: ReadonlySet<string> = new Set([
  'string',
  'number',
  'boolean',
  'null',
  'literal',
  'enum',
]);

function walk(
  schema: unknown,
  path: string,
  role: SchemaRole,
  ancestors: Set<unknown>,
): SchemaShapeProblem | null {
  const def = defOf(schema);
  const kind = kindOf(def);
  if (def === undefined) return { path, kind };
  if (ancestors.has(schema)) return { path, kind: 'recursive schema' };
  if (def['coerce'] === true) return { path, kind: `coerced ${kind}` };
  const badCheck = findDisallowedCheck(def, kind);
  if (badCheck !== null) return { path, kind: badCheck };

  if (PRIMITIVE_KINDS.has(kind)) return null;

  ancestors.add(schema);
  try {
    switch (kind) {
      case 'object': {
        const catchall = def['catchall'];
        if (catchall !== undefined && kindOf(defOf(catchall)) !== 'never') {
          return { path, kind: 'loose object' };
        }
        const shape = def['shape'];
        if (typeof shape !== 'object' || shape === null) return { path, kind };
        for (const [key, child] of Object.entries(shape)) {
          const found = walk(child, `${path}.${key}`, role, ancestors);
          if (found !== null) return found;
        }
        return null;
      }
      case 'array':
        return walk(def['element'], `${path}[]`, role, ancestors);
      case 'tuple': {
        const items = def['items'];
        if (!Array.isArray(items)) return { path, kind };
        for (const [index, item] of items.entries()) {
          const found = walk(item, `${path}[${index}]`, role, ancestors);
          if (found !== null) return found;
        }
        const rest = def['rest'];
        return rest === undefined || rest === null
          ? null
          : walk(rest, `${path}[]`, role, ancestors);
      }
      case 'union': {
        const options = def['options'];
        if (!Array.isArray(options)) return { path, kind };
        for (const option of options) {
          const found = walk(option, path, role, ancestors);
          if (found !== null) return found;
        }
        return null;
      }
      case 'optional':
      case 'nullable':
        return walk(def['innerType'], path, role, ancestors);
      case 'record': {
        // Records accept arbitrary keys, so they are never allowed in an output schema. In an
        // input schema the keys are what the agent sent and policy judged, which is harmless.
        if (role === 'output') return { path, kind };
        const keyKind = kindOf(defOf(def['keyType']));
        if (keyKind !== 'string' && keyKind !== 'enum' && keyKind !== 'literal') {
          return { path: `${path}.<key>`, kind: keyKind };
        }
        return (
          walk(def['keyType'], `${path}.<key>`, role, ancestors) ??
          walk(def['valueType'], `${path}.?`, role, ancestors)
        );
      }
      default:
        return { path, kind };
    }
  } finally {
    ancestors.delete(schema);
  }
}

/**
 * Returns the first node of `schema` that is not on the allowlist, or null. Allowed: objects
 * that strip or reject unknown keys, arrays, tuples, string, number, boolean, null, literal,
 * enum, optional, nullable, unions of allowed nodes, length/format/range checks on strings,
 * numbers and arrays, and (inputs only) records with string, enum or literal keys. Rejected,
 * among others: loose objects, any, unknown, json, lazy, intersection, transform, pipe,
 * default, prefault, catch, coercion, overwrite (trim, toLowerCase) and custom refinements.
 */
export function findDisallowedSchemaNode(
  schema: unknown,
  role: SchemaRole,
): SchemaShapeProblem | null {
  return walk(schema, role, role, new Set<unknown>());
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Run-time counterpart for output (F-1): walks `value` against `schema` and returns the path of
 * the first object holding a key the schema does not declare, or of the first node the walk
 * cannot account for. Independent of `findDisallowedSchemaNode`, so a gap in the definition
 * check alone cannot leak a field. The returned path never contains the undeclared key itself.
 */
export function findUndeclaredOutput(schema: unknown, value: unknown, path: string): string | null {
  const def = defOf(schema);
  const kind = kindOf(def);
  if (def === undefined) return path;

  if (PRIMITIVE_KINDS.has(kind)) {
    return typeof value === 'object' && value !== null ? path : null;
  }
  switch (kind) {
    case 'object': {
      const shape = def['shape'];
      if (!isRecord(value) || typeof shape !== 'object' || shape === null) return path;
      for (const key of Object.keys(value)) {
        if (!Object.hasOwn(shape, key)) return path;
        const found = findUndeclaredOutput(
          (shape as Record<string, unknown>)[key],
          value[key],
          `${path}.${key}`,
        );
        if (found !== null) return found;
      }
      return null;
    }
    case 'array': {
      if (!Array.isArray(value)) return path;
      for (const item of value) {
        const found = findUndeclaredOutput(def['element'], item, `${path}[]`);
        if (found !== null) return found;
      }
      return null;
    }
    case 'tuple': {
      const items = def['items'];
      if (!Array.isArray(value) || !Array.isArray(items)) return path;
      const rest = def['rest'];
      for (const [index, item] of value.entries()) {
        const itemSchema: unknown = index < items.length ? items[index] : rest;
        if (itemSchema === undefined || itemSchema === null) return path;
        const found = findUndeclaredOutput(itemSchema, item, `${path}[${index}]`);
        if (found !== null) return found;
      }
      return null;
    }
    case 'union': {
      const options = def['options'];
      if (!Array.isArray(options) || options.length === 0) return path;
      let first: string | null = null;
      for (const option of options) {
        const found = findUndeclaredOutput(option, value, path);
        if (found === null) return null;
        first ??= found;
      }
      return first;
    }
    case 'optional':
      return value === undefined ? null : findUndeclaredOutput(def['innerType'], value, path);
    case 'nullable':
      return value === null ? null : findUndeclaredOutput(def['innerType'], value, path);
    default:
      return path;
  }
}
