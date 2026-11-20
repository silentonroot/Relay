/*
 * The "metadata only" rule for vault responses (ADR-014 section 12), as code.
 *
 * A field NAME is forbidden when it matches FORBIDDEN_FIELD_NAME, unless it is on the explicit
 * ALLOWED_FIELD_NAMES list. The pattern is deliberately wider than the cases the ADR names
 * (any `key`, `kek`, `dek`, `hash`, `salt` or `mac`), so a legitimate field has to be added to the
 * allow-list on purpose, in review, rather than slip past a narrow pattern.
 *
 * Two walkers: `walkSchema` reads the field names a Zod schema can produce, and `walkJson` reads
 * the field names and the string values of an actual response. Both return how many fields they
 * visited, so a test can refuse a walk that saw nothing.
 *
 * A schema that cannot name its fields proves nothing, so it is a violation too: `any`,
 * `unknown`, a loose object, and a catchall that is not `never`. A record whose keys are an enum
 * or literals has named fields (checked like any other); a record with free string or number keys
 * is listed in `dynamicKeyPaths`, and a test must assert that list is exactly the expected one,
 * so a new record is covered by a response test on purpose.
 */

export const FORBIDDEN_FIELD_NAME =
  /cipher|wrapped|dek|kek|key|token|mac|nonce|plaintext|secret_?value|salt|hash|password|credential|authtag|auth_?tag/i;

/** Field names that look forbidden but are metadata: version numbers of the installation key. */
export const ALLOWED_FIELD_NAMES: ReadonlySet<string> = new Set([
  'kekVersion', // the key version that wraps a stored version (a number)
  'kekVersions', // the key versions present on disk
  'currentKekVersion', // the highest key version present
  'missingKekVersions', // key versions that stored versions need but that are not on disk
  'versionsByKek', // counts of stored versions per key version
]);

export function isForbiddenFieldName(name: string): boolean {
  return !ALLOWED_FIELD_NAMES.has(name) && FORBIDDEN_FIELD_NAME.test(name);
}

/** A JSON string value that looks like key material, a hash, a MAC or an encoded blob. */
const HEX_64 = /^[0-9a-f]{64}$/i;
const BASE64ISH = /^[A-Za-z0-9+/_-]{32,}={0,2}$/;
const UUID_VALUE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Why `value` looks like a secret-bearing string, or null. Ids (UUIDs) are exempt. */
export function suspiciousValue(value: string): string | null {
  if (UUID_VALUE.test(value)) return null;
  if (HEX_64.test(value)) return '<value:64-hex>';
  if (BASE64ISH.test(value)) return '<value:base64>';
  return null;
}

export interface Walk {
  /** Every field name visited, with its path. */
  fields: { path: string; name: string }[];
  /** Fields whose name is forbidden. */
  violations: { path: string; name: string }[];
  /** Record schemas: their keys are chosen at run time, so only a response test can check them. */
  dynamicKeyPaths: string[];
}

interface ZodLike {
  _zod: { def: Record<string, unknown> };
}

const isZod = (value: unknown): value is ZodLike =>
  typeof value === 'object' && value !== null && '_zod' in value;

/** Walks a Zod 4 schema: objects, arrays, tuples, wrappers, unions, intersections, records, lazies. */
export function walkSchema(schema: unknown): Walk {
  const walk: Walk = { fields: [], violations: [], dynamicKeyPaths: [] };
  // Recursion guard for lazy schemas only: a shared sub-schema reached by a second path is
  // walked again, so each of its paths is checked and recorded.
  const activeLazy = new Set<unknown>();
  const field = (path: string, name: string) => {
    walk.fields.push({ path, name });
    if (isForbiddenFieldName(name)) walk.violations.push({ path, name });
  };
  const open = (path: string, kind: string) =>
    walk.violations.push({ path: path === '' ? '<root>' : path, name: `<open-ended:${kind}>` });
  const keyNames = (keyType: unknown): string[] | null => {
    if (!isZod(keyType)) return null;
    const keyDef = keyType._zod.def;
    if (keyDef.type === 'enum')
      return Object.values(keyDef.entries as Record<string, unknown>).map(String);
    if (keyDef.type === 'literal') return (keyDef.values as unknown[]).map(String);
    return null;
  };
  const visit = (node: unknown, path: string): void => {
    if (!isZod(node)) throw new Error(`not a Zod schema at ${path || '<root>'}`);
    const def = node._zod.def;
    const type = String(def.type);
    switch (type) {
      case 'object': {
        const shape = def.shape as Record<string, unknown>;
        for (const [name, child] of Object.entries(shape)) {
          const childPath = path === '' ? name : `${path}.${name}`;
          field(childPath, name);
          visit(child, childPath);
        }
        // `strictObject` has a `never` catchall; `object` has none (unknown keys are dropped);
        // anything else (looseObject, catchall(x)) lets undeclared fields through.
        if (isZod(def.catchall) && String(def.catchall._zod.def.type) !== 'never') {
          open(path, 'catchall');
          visit(def.catchall, `${path}.*`);
        }
        return;
      }
      case 'array':
        return visit(def.element, `${path}[]`);
      case 'set':
        return visit(def.valueType, `${path}[]`);
      case 'optional':
      case 'nullable':
      case 'default':
      case 'prefault':
      case 'nonoptional':
      case 'readonly':
      case 'catch':
      case 'promise':
        return visit(def.innerType, path);
      case 'union':
        for (const option of def.options as unknown[]) visit(option, path);
        return;
      case 'intersection':
        visit(def.left, path);
        return visit(def.right, path);
      case 'tuple':
        for (const item of def.items as unknown[]) visit(item, `${path}[]`);
        if (isZod(def.rest)) visit(def.rest, `${path}[]`);
        return;
      case 'record':
      case 'map': {
        const names = keyNames(def.keyType);
        if (names === null) {
          walk.dynamicKeyPaths.push(path);
          visit(def.valueType, `${path}.*`);
          return;
        }
        for (const name of names) {
          const childPath = path === '' ? name : `${path}.${name}`;
          field(childPath, name);
          visit(def.valueType, childPath);
        }
        return;
      }
      case 'pipe':
        visit(def.in, path);
        return visit(def.out, path);
      case 'lazy': {
        if (activeLazy.has(node)) return;
        activeLazy.add(node);
        visit((def.getter as () => unknown)(), path);
        activeLazy.delete(node);
        return;
      }
      case 'any':
      case 'unknown':
        open(path, type);
        return;
      case 'string':
      case 'number':
      case 'int':
      case 'boolean':
      case 'bigint':
      case 'literal':
      case 'enum':
      case 'null':
      case 'undefined':
      case 'date':
      case 'never':
      case 'void':
        return;
      default:
        // An unknown schema kind must not be skipped silently: that is how a walk goes vacuous.
        throw new Error(`walkSchema does not know the Zod kind "${type}" at ${path || '<root>'}`);
    }
  };
  visit(schema, '');
  return walk;
}

/** Walks a parsed JSON value and returns the field names it holds. */
export function walkJson(value: unknown): Walk {
  const walk: Walk = { fields: [], violations: [], dynamicKeyPaths: [] };
  const visit = (node: unknown, path: string): void => {
    if (Array.isArray(node)) {
      for (const item of node) visit(item, `${path}[]`);
      return;
    }
    if (typeof node === 'object' && node !== null) {
      for (const [name, child] of Object.entries(node)) {
        const childPath = path === '' ? name : `${path}.${name}`;
        walk.fields.push({ path: childPath, name });
        if (isForbiddenFieldName(name)) walk.violations.push({ path: childPath, name });
        visit(child, childPath);
      }
      return;
    }
    if (typeof node === 'string') {
      const why = suspiciousValue(node);
      if (why !== null) walk.violations.push({ path, name: why });
    }
  };
  visit(value, '');
  return walk;
}
