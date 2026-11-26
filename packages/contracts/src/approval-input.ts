import { MAX_JSON_DEPTH } from './plain-json.js';

/*
 * The strict input check for approval inputs (Phase 4, P4-20, ADR-015 section 9).
 *
 * `canonicalJson` is deliberately unchanged: it still accepts integers beyond the safe range,
 * `-0` and lone surrogates, because audit hashing and other callers depend on its behavior.
 * Approval inputs are stricter. An approved action is hashed, stored and later run by three
 * components (API, vault, supervisor); a value that two parsers or two serializers could read
 * differently would let what was approved differ from what runs. So these values are refused at
 * the edge, with a stable code, before validation and before hashing.
 *
 * Two spellings of one value (`1` and `1.0`) are the same value after `JSON.parse` and are not
 * refused: they hash and run identically.
 */

/** Stable codes. A caller maps them to an API error and an audit reason; never to a value. */
export const ApprovalInputErrorCodes = [
  /** An integer outside plus or minus `Number.MAX_SAFE_INTEGER`. */
  'unsafe_integer',
  /** Negative zero, which `JSON.stringify` writes as `0`. */
  'negative_zero',
  /** A string or object key holding an unpaired UTF-16 surrogate. */
  'lone_surrogate',
  /** NaN or an infinity. */
  'non_finite_number',
  /** The raw body names one key twice in one object (found by `findRawJsonIssue`). */
  'duplicate_key',
  /** The raw body is not valid JSON (found by `findRawJsonIssue`). */
  'invalid_json',
  /**
   * More than `MAX_JSON_DEPTH` levels of arrays and objects: the same boundary and the same code
   * as `checkPlainJson` (64 levels pass, 65 are refused).
   */
  'too_deep',
  /** A value that is not JSON (undefined, bigint, function, symbol). */
  'not_json',
  /**
   * `targetResourceId` or `expectedResourceVersion` differ from the values of the descriptor's
   * `resourceArgument` and `versionArgument` in the arguments (`actionHashInput`).
   */
  'argument_mismatch',
] as const;
export type ApprovalInputErrorCode = (typeof ApprovalInputErrorCodes)[number];

export interface ApprovalInputIssue {
  code: ApprovalInputErrorCode;
  /**
   * Where the issue is, as `$`, `.key` and `[index]` segments. Key names, never values. Each key
   * segment is cut to `MAX_PATH_SEGMENT` characters and the whole path to `MAX_PATH_LENGTH`, with
   * an ellipsis, so attacker-chosen keys cannot bloat an error message or an audit record.
   */
  path: string;
}

export const MAX_PATH_SEGMENT = 40;
export const MAX_PATH_LENGTH = 200;
const ELLIPSIS = '…';

function segment(key: string): string {
  // Whole code points, and never a lone surrogate in the path itself.
  const points = Array.from(key.toWellFormed());
  return points.length > MAX_PATH_SEGMENT
    ? points.slice(0, MAX_PATH_SEGMENT).join('') + ELLIPSIS
    : points.join('');
}

function child(path: string, key: string): string {
  return `${path}.${segment(key)}`;
}

function found(code: ApprovalInputErrorCode, path: string): ApprovalInputIssue {
  const capped =
    path.length > MAX_PATH_LENGTH ? path.slice(0, MAX_PATH_LENGTH).toWellFormed() + ELLIPSIS : path;
  return { code, path: capped };
}

/** Thrown by hashing functions that are given an input the strict check refuses. */
export class ApprovalInputError extends Error {
  readonly code: ApprovalInputErrorCode;
  readonly path: string;

  constructor(issue: ApprovalInputIssue) {
    super(`approval input refused: ${issue.code}`);
    this.name = 'ApprovalInputError';
    this.code = issue.code;
    this.path = issue.path;
  }
}

function hasLoneSurrogate(text: string): boolean {
  // Well-formed means every surrogate code unit is half of a valid pair (ES2024).
  return !text.isWellFormed();
}

/**
 * Returns the first issue found in an already-parsed value, or null when it is acceptable.
 * Visits every nested array element, object key and object value. Object keys are visited in
 * insertion order. Nothing is coerced: a value that is not JSON (undefined, bigint, a function,
 * a symbol) is `not_json`.
 */
export function checkApprovalInput(value: unknown): ApprovalInputIssue | null {
  return walk(value, '$', 0);
}

function walk(value: unknown, path: string, depth: number): ApprovalInputIssue | null {
  if (value === null || typeof value === 'boolean') return null;

  switch (typeof value) {
    case 'string':
      return hasLoneSurrogate(value) ? found('lone_surrogate', path) : null;
    case 'number':
      if (!Number.isFinite(value)) return found('non_finite_number', path);
      if (Object.is(value, -0)) return found('negative_zero', path);
      if (Number.isInteger(value) && Math.abs(value) > Number.MAX_SAFE_INTEGER) {
        return found('unsafe_integer', path);
      }
      return null;
    case 'object':
      break;
    default:
      return found('not_json', path);
  }

  // Containers count from 0 at the root; the 65th level is refused, as `checkPlainJson` does.
  if (depth >= MAX_JSON_DEPTH) return found('too_deep', path);

  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) {
      const issue = walk(value[index], `${path}[${index}]`, depth + 1);
      if (issue !== null) return issue;
    }
    return null;
  }

  for (const key of Object.keys(value)) {
    const keyPath = child(path, key);
    if (hasLoneSurrogate(key)) return found('lone_surrogate', keyPath);
    const issue = walk((value as Record<string, unknown>)[key], keyPath, depth + 1);
    if (issue !== null) return issue;
  }
  return null;
}

// ---------------------------------------------------------------------------------------------
// Raw body: duplicate keys.
//
// `JSON.parse` and the body parser keep the last of two equal keys, so a body that names a key
// twice has one value for a parser that keeps the first and another for one that keeps the last.
// This is parsing, not cryptography: a small recursive-descent scanner over the exact RFC 8259
// grammar. Keys are compared after decoding (`"a"` and `"\u0061"` are one key). It looks at
// structure only and never builds the value.

const WHITESPACE = new Set([0x20, 0x09, 0x0a, 0x0d]);
const NUMBER = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;
const SIMPLE_ESCAPES = new Set(['"', '\\', '/', 'b', 'f', 'n', 'r', 't']);
const HEX = /^[0-9a-fA-F]{4}$/;

class Scanner {
  private position = 0;

  constructor(private readonly text: string) {}

  /** Scans the whole text. Returns the first issue, or null for valid JSON with unique keys. */
  scan(): ApprovalInputIssue | null {
    try {
      this.skipWhitespace();
      this.value('$', 0);
      this.skipWhitespace();
      if (this.position !== this.text.length) throw invalid('$');
      return null;
    } catch (error) {
      if (error instanceof ScanIssue) return error.issue;
      throw error;
    }
  }

  private skipWhitespace(): void {
    while (
      this.position < this.text.length &&
      WHITESPACE.has(this.text.charCodeAt(this.position))
    ) {
      this.position += 1;
    }
  }

  private value(path: string, depth: number): void {
    const char = this.text[this.position];
    if (char === '{' || char === '[') {
      // The same boundary as `checkApprovalInput` and `checkPlainJson`: 64 levels pass, 65 do not.
      if (depth >= MAX_JSON_DEPTH) throw new ScanIssue(found('too_deep', path));
      return char === '{' ? this.object(path, depth) : this.array(path, depth);
    }
    if (char === '"') {
      this.string(path);
      return;
    }
    for (const literal of ['true', 'false', 'null']) {
      if (this.text.startsWith(literal, this.position)) {
        this.position += literal.length;
        return;
      }
    }
    NUMBER.lastIndex = this.position;
    const match = NUMBER.exec(this.text);
    if (match === null || match.index !== this.position) throw invalid(path);
    this.position += match[0].length;
  }

  private array(path: string, depth: number): void {
    this.position += 1; // [
    this.skipWhitespace();
    if (this.text[this.position] === ']') {
      this.position += 1;
      return;
    }
    for (let index = 0; ; index += 1) {
      this.skipWhitespace();
      this.value(`${path}[${index}]`, depth + 1);
      this.skipWhitespace();
      const next = this.text[this.position];
      this.position += 1;
      if (next === ']') return;
      if (next !== ',') throw invalid(path);
    }
  }

  private object(path: string, depth: number): void {
    this.position += 1; // {
    this.skipWhitespace();
    if (this.text[this.position] === '}') {
      this.position += 1;
      return;
    }
    const seen = new Set<string>();
    for (;;) {
      this.skipWhitespace();
      if (this.text[this.position] !== '"') throw invalid(path);
      const key = this.string(path);
      const keyPath = child(path, key);
      if (seen.has(key)) throw new ScanIssue(found('duplicate_key', keyPath));
      seen.add(key);
      this.skipWhitespace();
      if (this.text[this.position] !== ':') throw invalid(keyPath);
      this.position += 1;
      this.skipWhitespace();
      this.value(keyPath, depth + 1);
      this.skipWhitespace();
      const next = this.text[this.position];
      this.position += 1;
      if (next === '}') return;
      if (next !== ',') throw invalid(path);
    }
  }

  /** Validates one string token and returns its decoded value. */
  private string(path: string): string {
    const start = this.position;
    this.position += 1; // opening quote
    for (;;) {
      if (this.position >= this.text.length) throw invalid(path);
      const code = this.text.charCodeAt(this.position);
      if (code === 0x22) {
        this.position += 1;
        // The token is valid by construction here, so JSON.parse only decodes the escapes.
        return JSON.parse(this.text.slice(start, this.position)) as string;
      }
      if (code < 0x20) throw invalid(path); // raw control characters are not allowed
      if (code === 0x5c) {
        const escape = this.text[this.position + 1];
        if (escape === undefined) throw invalid(path);
        if (escape === 'u') {
          if (!HEX.test(this.text.slice(this.position + 2, this.position + 6))) throw invalid(path);
          this.position += 6;
        } else if (SIMPLE_ESCAPES.has(escape)) {
          this.position += 2;
        } else {
          throw invalid(path);
        }
        continue;
      }
      this.position += 1;
    }
  }
}

class ScanIssue extends Error {
  constructor(readonly issue: ApprovalInputIssue) {
    super(issue.code);
  }
}

function invalid(path: string): ScanIssue {
  return new ScanIssue(found('invalid_json', path));
}

/**
 * Checks the raw text of a request body before it is parsed. Returns `duplicate_key` when an
 * object names one key twice (after decoding escapes, at any depth), `invalid_json` when the text
 * is not JSON, `too_deep` past `MAX_JSON_DEPTH`; null otherwise. A body that returns anything
 * but null is refused.
 */
export function findRawJsonIssue(rawJson: string): ApprovalInputIssue | null {
  return new Scanner(rawJson).scan();
}
