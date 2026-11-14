/**
 * Deterministic JSON serialization in the spirit of RFC 8785 (JCS): object keys sorted by
 * UTF-16 code unit, no insignificant whitespace, ECMAScript number formatting.
 *
 * Audit hash chains and approval action hashes are computed over this output, so two parties
 * serializing the same value must always get identical bytes. Anything that is not plain JSON
 * (undefined, NaN, Infinity, bigint, Date, Map, class instances, cycles) throws instead of
 * being coerced, because a silent coercion would let two different payloads share a hash.
 */
export function canonicalJson(value: unknown): string {
  return serialize(value, new Set<object>(), '$');
}

function serialize(value: unknown, ancestors: Set<object>, path: string): string {
  if (value === null) return 'null';

  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';
    case 'string':
      return JSON.stringify(value);
    case 'number':
      if (!Number.isFinite(value)) {
        throw new TypeError(`canonicalJson: non-finite number at ${path}`);
      }
      return JSON.stringify(value);
    case 'object':
      break;
    default:
      throw new TypeError(`canonicalJson: unsupported ${typeof value} at ${path}`);
  }

  if (ancestors.has(value)) {
    throw new TypeError(`canonicalJson: cyclic reference at ${path}`);
  }
  ancestors.add(value);
  try {
    if (Object.getOwnPropertySymbols(value).length > 0) {
      throw new TypeError(`canonicalJson: symbol key at ${path}`);
    }

    if (Array.isArray(value)) {
      // Array.prototype.map skips holes, which would serialize [1, , 3] as "[1,,3]".
      for (let index = 0; index < value.length; index += 1) {
        if (!(index in value)) {
          throw new TypeError(`canonicalJson: sparse array at ${path}[${index}]`);
        }
      }
      const items = value.map((item, index) => serialize(item, ancestors, `${path}[${index}]`));
      return `[${items.join(',')}]`;
    }

    const prototype: unknown = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError(`canonicalJson: non-plain object at ${path}`);
    }

    const record = value as Record<string, unknown>;
    const members = Object.keys(record)
      .sort()
      .map(
        (key) => `${JSON.stringify(key)}:${serialize(record[key], ancestors, `${path}.${key}`)}`,
      );
    return `{${members.join(',')}}`;
  } finally {
    ancestors.delete(value);
  }
}
